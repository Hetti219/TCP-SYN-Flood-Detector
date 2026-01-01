/*
 * nfqueue.c - NFQUEUE packet capture implementation
 * TCP SYN Flood Detector
 */

#include "nfqueue.h"
#include "../analysis/tracker.h"
#include "../analysis/whitelist.h"
#include "../analysis/procparse.h"
#include "../enforce/ipset_mgr.h"
#include "../observe/logger.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <string.h>

/* Forward declare app_context_t */
typedef struct app_context app_context_t;

static struct nfq_handle *nfq_h = NULL;
static struct nfq_q_handle *nfq_qh = NULL;
static int nfq_fd = -1;
static app_context_t *global_ctx = NULL;

/* Extract source IP from packet payload */
static uint32_t extract_src_ip(unsigned char *payload, int payload_len) {
    if (payload_len < sizeof(struct iphdr)) {
        return 0;
    }

    struct iphdr *iph = (struct iphdr *)payload;
    return iph->saddr;
}

/* Process a SYN packet according to the detection algorithm from SDD */
static int process_syn_packet(app_context_t *ctx, uint32_t src_ip) {
    /* Step 1: Whitelist check */
    if (whitelist_check(ctx->whitelist_root, src_ip)) {
        LOG_DEBUG("Packet from whitelisted IP");
        pthread_mutex_lock(&ctx->metrics_lock);
        ctx->metrics.whitelist_hits_total++;
        pthread_mutex_unlock(&ctx->metrics_lock);
        return NF_ACCEPT;
    }

    /* Step 2: Get or create tracker entry */
    ip_tracker_t *tracker = tracker_get_or_create(ctx->tracker, src_ip);
    if (!tracker) {
        LOG_ERROR("Failed to get/create tracker entry");
        return NF_ACCEPT;
    }

    /* Step 3: Sliding window rate calculation */
    uint64_t current_time = get_monotonic_ns();
    uint64_t window_ns = ms_to_ns(ctx->config->window_ms);

    if (current_time - tracker->window_start_ns > window_ns) {
        /* Window expired, reset counter */
        tracker->syn_count = 1;
        tracker->window_start_ns = current_time;
    } else {
        tracker->syn_count++;
    }

    tracker->last_seen_ns = current_time;

    /* Step 4: Threshold check */
    if (tracker->syn_count > ctx->config->syn_threshold) {
        if (!tracker->blocked) {
            /* Secondary validation: check /proc/net/tcp */
            uint32_t syn_recv_count = procparse_count_syn_recv_from_ip(src_ip);

            if (syn_recv_count > ctx->config->syn_threshold / 2) {
                /* Confirmed attack pattern */
                if (ipset_mgr_add(src_ip, ctx->config->block_duration_s) == SYNFLOOD_OK) {
                    tracker->blocked = 1;
                    tracker->block_expiry_ns = current_time +
                                               sec_to_ns(ctx->config->block_duration_s);

                    logger_log_event(EVENT_BLOCKED, src_ip, tracker->syn_count, syn_recv_count);

                    /* Update metrics */
                    pthread_mutex_lock(&ctx->metrics_lock);
                    ctx->metrics.detections_total++;
                    ctx->metrics.blocked_ips_current = ipset_mgr_get_count();
                    pthread_mutex_unlock(&ctx->metrics_lock);
                }
            } else {
                /* Possible false positive, log but don't block */
                logger_log_event(EVENT_SUSPICIOUS, src_ip, tracker->syn_count, syn_recv_count);

                pthread_mutex_lock(&ctx->metrics_lock);
                ctx->metrics.false_positives_total++;
                pthread_mutex_unlock(&ctx->metrics_lock);
            }
        }
    }

    /* Update metrics */
    pthread_mutex_lock(&ctx->metrics_lock);
    ctx->metrics.syn_packets_total++;
    pthread_mutex_unlock(&ctx->metrics_lock);

    return NF_ACCEPT; /* Let packet through (ipset will drop future packets) */
}

/* NFQUEUE callback function */
static int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                            struct nfq_data *nfa, void *data) {
    app_context_t *ctx = (app_context_t *)data;
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;

    /* Get packet header */
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    /* Get packet payload */
    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 0) {
        LOG_ERROR("Failed to get packet payload");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    /* Update packet counter */
    pthread_mutex_lock(&ctx->metrics_lock);
    ctx->metrics.packets_total++;
    pthread_mutex_unlock(&ctx->metrics_lock);

    /* Extract source IP */
    uint32_t src_ip = extract_src_ip(payload, payload_len);
    if (src_ip == 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    /* Process SYN packet */
    int verdict = process_syn_packet(ctx, src_ip);

    /* Set verdict */
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

synflood_ret_t nfqueue_init(app_context_t *ctx, uint16_t queue_num) {
    if (!ctx) {
        return SYNFLOOD_EINVAL;
    }

    global_ctx = ctx;

    /* Open library handle */
    nfq_h = nfq_open();
    if (!nfq_h) {
        LOG_ERROR("Failed to open nfqueue library handle");
        return SYNFLOOD_ERROR;
    }

    /* Unbind existing handler (if any) */
    if (nfq_unbind_pf(nfq_h, AF_INET) < 0) {
        LOG_WARN("Failed to unbind nfqueue handler");
    }

    /* Bind to AF_INET */
    if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
        LOG_ERROR("Failed to bind nfqueue handler to AF_INET");
        nfq_close(nfq_h);
        return SYNFLOOD_ERROR;
    }

    /* Create queue */
    nfq_qh = nfq_create_queue(nfq_h, queue_num, &nfqueue_callback, ctx);
    if (!nfq_qh) {
        LOG_ERROR("Failed to create nfqueue (queue_num=%u)", queue_num);
        nfq_close(nfq_h);
        return SYNFLOOD_ERROR;
    }

    /* Set copy mode to get packet payload */
    if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        LOG_ERROR("Failed to set nfqueue copy mode");
        nfq_destroy_queue(nfq_qh);
        nfq_close(nfq_h);
        return SYNFLOOD_ERROR;
    }

    /* Get file descriptor */
    nfq_fd = nfq_fd(nfq_h);
    if (nfq_fd < 0) {
        LOG_ERROR("Failed to get nfqueue file descriptor");
        nfq_destroy_queue(nfq_qh);
        nfq_close(nfq_h);
        return SYNFLOOD_ERROR;
    }

    ctx->nfqueue_fd = nfq_fd;

    LOG_INFO("NFQUEUE initialized: queue_num=%u, fd=%d", queue_num, nfq_fd);

    return SYNFLOOD_OK;
}

synflood_ret_t nfqueue_start(app_context_t *ctx) {
    if (!ctx || nfq_fd < 0) {
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("Starting NFQUEUE packet capture loop");

    char buf[4096] __attribute__((aligned));
    int rv;

    while (ctx->running) {
        rv = recv(nfq_fd, buf, sizeof(buf), 0);
        if (rv < 0) {
            if (ctx->running) {
                LOG_ERROR("recv() failed on nfqueue");
                return SYNFLOOD_ERROR;
            }
            break;
        }

        nfq_handle_packet(nfq_h, buf, rv);
    }

    LOG_INFO("NFQUEUE packet capture loop stopped");

    return SYNFLOOD_OK;
}

void nfqueue_stop(void) {
    if (global_ctx) {
        global_ctx->running = false;
    }

    /* Close socket to break recv() call */
    if (nfq_fd >= 0) {
        shutdown(nfq_fd, SHUT_RDWR);
    }
}

void nfqueue_cleanup(void) {
    if (nfq_qh) {
        nfq_destroy_queue(nfq_qh);
        nfq_qh = NULL;
    }

    if (nfq_h) {
        nfq_close(nfq_h);
        nfq_h = NULL;
    }

    nfq_fd = -1;
    global_ctx = NULL;

    LOG_INFO("NFQUEUE cleanup completed");
}

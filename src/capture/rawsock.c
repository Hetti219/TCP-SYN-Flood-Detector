/*
 * rawsock.c - Raw socket packet capture implementation
 * TCP SYN Flood Detector
 */

#include "rawsock.h"
#include "../analysis/tracker.h"
#include "../analysis/whitelist.h"
#include "../analysis/procparse.h"
#include "../enforce/ipset_mgr.h"
#include "../observe/logger.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

/* External signal handler from main.c */
extern void handle_signals(void);

static int raw_sock_fd = -1;
static app_context_t *global_ctx = NULL;

/* BPF filter for TCP SYN packets only
 * This filters at kernel level before copying to userspace
 * Filter: tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0
 */
static struct sock_filter bpf_code[] = {
    /* Load protocol (IP header offset 9) */
    { 0x30, 0, 0, 0x00000017 },  /* ldh [23] - load protocol */
    { 0x15, 0, 8, 0x00000006 },  /* jeq #6 (TCP), else skip */

    /* Load TCP flags (offset 13 in TCP header) */
    { 0x30, 0, 0, 0x00000021 },  /* ldb [33] - load TCP flags */

    /* Check for SYN flag (0x02) */
    { 0x45, 6, 0, 0x00000002 },  /* jset #0x02, else skip */

    /* Check that ACK flag (0x10) is NOT set */
    { 0x45, 0, 5, 0x00000010 },  /* jset #0x10, skip if set */

    /* Accept packet */
    { 0x06, 0, 0, 0xffffffff },  /* ret #-1 (accept) */

    /* Reject packet */
    { 0x06, 0, 0, 0x00000000 },  /* ret #0 (reject) */
};

static struct sock_fprog bpf_prog = {
    .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
    .filter = bpf_code,
};

/* Process a SYN packet - same logic as NFQUEUE */
static void process_syn_packet_raw(app_context_t *ctx, uint32_t src_ip) {
    /* Step 1: Whitelist check */
    if (whitelist_check(ctx->whitelist_root, src_ip)) {
        pthread_mutex_lock(&ctx->metrics_lock);
        ctx->metrics.whitelist_hits_total++;
        pthread_mutex_unlock(&ctx->metrics_lock);
        return;
    }

    /* Step 2: Get or create tracker entry */
    ip_tracker_t *tracker = tracker_get_or_create(ctx->tracker, src_ip);
    if (!tracker) {
        return;
    }

    /* Step 3: Sliding window rate calculation */
    uint64_t current_time = get_monotonic_ns();
    uint64_t window_ns = ms_to_ns(ctx->config->window_ms);

    if (current_time - tracker->window_start_ns > window_ns) {
        tracker->syn_count = 1;
        tracker->window_start_ns = current_time;
    } else {
        tracker->syn_count++;
    }

    tracker->last_seen_ns = current_time;

    /* Step 4: Threshold check */
    if (tracker->syn_count > ctx->config->syn_threshold) {
        if (!tracker->blocked) {
            uint32_t syn_recv_count = procparse_count_syn_recv_from_ip(src_ip);

            if (syn_recv_count > ctx->config->syn_threshold / 2) {
                if (ipset_mgr_add(src_ip, ctx->config->block_duration_s) == SYNFLOOD_OK) {
                    tracker->blocked = 1;
                    tracker->block_expiry_ns = current_time +
                                               sec_to_ns(ctx->config->block_duration_s);

                    logger_log_event(EVENT_BLOCKED, src_ip, tracker->syn_count, syn_recv_count);

                    pthread_mutex_lock(&ctx->metrics_lock);
                    ctx->metrics.detections_total++;
                    ctx->metrics.blocked_ips_current = ipset_mgr_get_count();
                    pthread_mutex_unlock(&ctx->metrics_lock);
                }
            } else {
                logger_log_event(EVENT_SUSPICIOUS, src_ip, tracker->syn_count, syn_recv_count);

                pthread_mutex_lock(&ctx->metrics_lock);
                ctx->metrics.false_positives_total++;
                pthread_mutex_unlock(&ctx->metrics_lock);
            }
        }
    }

    pthread_mutex_lock(&ctx->metrics_lock);
    ctx->metrics.syn_packets_total++;
    pthread_mutex_unlock(&ctx->metrics_lock);
}

synflood_ret_t rawsock_init(app_context_t *ctx) {
    if (!ctx) {
        return SYNFLOOD_EINVAL;
    }

    global_ctx = ctx;

    /* Create raw socket */
    raw_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (raw_sock_fd < 0) {
        LOG_ERROR("Failed to create raw socket (need CAP_NET_RAW)");
        return SYNFLOOD_ERROR;
    }

    /* Attach BPF filter */
    if (setsockopt(raw_sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog)) < 0) {
        LOG_ERROR("Failed to attach BPF filter to raw socket");
        close(raw_sock_fd);
        raw_sock_fd = -1;
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("Raw socket initialized: fd=%d (BPF filter attached)", raw_sock_fd);

    return SYNFLOOD_OK;
}

synflood_ret_t rawsock_start(app_context_t *ctx) {
    if (!ctx || raw_sock_fd < 0) {
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("Starting raw socket packet capture loop");

    unsigned char buffer[65536];
    ssize_t packet_len;
    uint32_t packet_count = 0;

    while (ctx->running) {
        packet_len = recvfrom(raw_sock_fd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (packet_len < 0) {
            if (ctx->running) {
                LOG_ERROR("recvfrom() failed on raw socket");
                return SYNFLOOD_ERROR;
            }
            break;
        }

        /* Update packet counter */
        pthread_mutex_lock(&ctx->metrics_lock);
        ctx->metrics.packets_total++;
        pthread_mutex_unlock(&ctx->metrics_lock);

        /* Skip Ethernet header */
        if (packet_len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            continue;
        }

        unsigned char *ip_packet = buffer + sizeof(struct ethhdr);
        struct iphdr *iph = (struct iphdr *)ip_packet;

        /* Verify it's IPv4 and TCP */
        if (iph->version != 4 || iph->protocol != IPPROTO_TCP) {
            continue;
        }

        /* Extract source IP */
        uint32_t src_ip = iph->saddr;

        /* Process SYN packet */
        process_syn_packet_raw(ctx, src_ip);

        /* Check for signals periodically (every 1000 packets) */
        if (++packet_count >= 1000) {
            handle_signals();
            packet_count = 0;
        }
    }

    LOG_INFO("Raw socket packet capture loop stopped");

    return SYNFLOOD_OK;
}

void rawsock_stop(void) {
    if (global_ctx) {
        global_ctx->running = false;
    }

    if (raw_sock_fd >= 0) {
        shutdown(raw_sock_fd, SHUT_RDWR);
    }
}

void rawsock_cleanup(void) {
    if (raw_sock_fd >= 0) {
        close(raw_sock_fd);
        raw_sock_fd = -1;
    }

    global_ctx = NULL;

    LOG_INFO("Raw socket cleanup completed");
}

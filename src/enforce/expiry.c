/*
 * expiry.c - Block expiration timer implementation
 * TCP SYN Flood Detector
 */

#include "expiry.h"
#include "ipset_mgr.h"
#include "../analysis/tracker.h"
#include "../observe/logger.h"
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

static pthread_t expiry_thread;
static volatile bool expiry_running = false;
static uint32_t check_interval = 10;

size_t expiry_check_now(app_context_t *ctx) {
    if (!ctx || !ctx->tracker) {
        return 0;
    }

    uint64_t current_time = get_monotonic_ns();
    uint32_t expired_ips[1024];

    /* Get expired blocks from tracker */
    size_t count = tracker_get_expired_blocks(ctx->tracker, current_time,
                                               expired_ips, ARRAY_SIZE(expired_ips));

    if (count == 0) {
        return 0;
    }

    LOG_DEBUG("Found %zu expired blocks", count);

    /* Remove each expired IP from ipset and update tracker */
    size_t removed = 0;
    for (size_t i = 0; i < count; i++) {
        if (ipset_mgr_remove(expired_ips[i]) == SYNFLOOD_OK) {
            /* Update tracker to mark as unblocked */
            ip_tracker_t *tracker = tracker_get(ctx->tracker, expired_ips[i]);
            if (tracker) {
                tracker->blocked = 0;
                tracker->block_expiry_ns = 0;
            }

            /* Log event */
            logger_log_event(EVENT_UNBLOCKED, expired_ips[i], 0, 0);
            removed++;
        }
    }

    if (removed > 0) {
        LOG_INFO("Expired %zu IP blocks", removed);

        /* Update metrics */
        pthread_mutex_lock(&ctx->metrics_lock);
        ctx->metrics.blocked_ips_current = ipset_mgr_get_count();
        pthread_mutex_unlock(&ctx->metrics_lock);
    }

    return removed;
}

static void *expiry_thread_func(void *arg) {
    app_context_t *ctx = (app_context_t *)arg;

    LOG_INFO("Expiration check thread started (interval=%us)", check_interval);

    while (expiry_running && ctx->running) {
        /* Sleep for check interval */
        for (uint32_t i = 0; i < check_interval && expiry_running && ctx->running; i++) {
            sleep(1);
        }

        if (!expiry_running || !ctx->running) {
            break;
        }

        /* Check for expired blocks */
        expiry_check_now(ctx);
    }

    LOG_INFO("Expiration check thread stopped");
    return NULL;
}

synflood_ret_t expiry_start(app_context_t *ctx, uint32_t check_interval_s) {
    if (!ctx) {
        return SYNFLOOD_EINVAL;
    }

    if (expiry_running) {
        LOG_WARN("Expiration thread already running");
        return SYNFLOOD_OK;
    }

    check_interval = check_interval_s;
    expiry_running = true;

    if (pthread_create(&expiry_thread, NULL, expiry_thread_func, ctx) != 0) {
        LOG_ERROR("Failed to create expiration thread");
        expiry_running = false;
        return SYNFLOOD_ERROR;
    }

    return SYNFLOOD_OK;
}

void expiry_stop(void) {
    if (!expiry_running) {
        return;
    }

    LOG_INFO("Stopping expiration thread");
    expiry_running = false;

    /* Wait for thread to finish */
    pthread_join(expiry_thread, NULL);
}

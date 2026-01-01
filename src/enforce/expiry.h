/*
 * expiry.h - Block expiration timer
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_EXPIRY_H
#define SYNFLOOD_EXPIRY_H

#include "common.h"

/**
 * Start the expiration check thread
 * @param ctx Application context
 * @param check_interval_s Interval between expiration checks (seconds)
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t expiry_start(app_context_t *ctx, uint32_t check_interval_s);

/**
 * Stop the expiration check thread
 */
void expiry_stop(void);

/**
 * Manually trigger an expiration check
 * @param ctx Application context
 * @return Number of IPs unblocked
 */
size_t expiry_check_now(app_context_t *ctx);

#endif /* SYNFLOOD_EXPIRY_H */

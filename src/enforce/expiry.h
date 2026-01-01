/*
 * expiry.h - Block expiration timer
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_EXPIRY_H
#define SYNFLOOD_EXPIRY_H

#include "common.h"

/* Forward declaration */
struct app_context;

/**
 * Start the expiration check thread
 * @param ctx Application context
 * @param check_interval_s Interval between expiration checks (seconds)
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t expiry_start(struct app_context *ctx, uint32_t check_interval_s);

/**
 * Stop the expiration check thread
 */
void expiry_stop(void);

/**
 * Manually trigger an expiration check
 * @param ctx Application context
 * @return Number of IPs unblocked
 */
size_t expiry_check_now(struct app_context *ctx);

#endif /* SYNFLOOD_EXPIRY_H */

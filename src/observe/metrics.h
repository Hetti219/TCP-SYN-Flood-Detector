/*
 * metrics.h - Unix socket metrics API
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_METRICS_H
#define SYNFLOOD_METRICS_H

#include "common.h"

/* Forward declaration */
struct app_context;

/**
 * Initialize metrics server
 * @param ctx Application context
 * @param socket_path Path to Unix socket
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t metrics_init(struct app_context *ctx, const char *socket_path);

/**
 * Start metrics server thread
 * @param ctx Application context
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t metrics_start(struct app_context *ctx);

/**
 * Stop metrics server
 */
void metrics_stop(void);

/**
 * Cleanup metrics server resources
 */
void metrics_cleanup(void);

#endif /* SYNFLOOD_METRICS_H */

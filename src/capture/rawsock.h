/*
 * rawsock.h - Raw socket packet capture fallback
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_RAWSOCK_H
#define SYNFLOOD_RAWSOCK_H

#include "common.h"

/**
 * Initialize raw socket capture
 * @param ctx Application context
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t rawsock_init(app_context_t *ctx);

/**
 * Start raw socket packet capture loop
 * @param ctx Application context
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t rawsock_start(app_context_t *ctx);

/**
 * Stop raw socket packet capture
 */
void rawsock_stop(void);

/**
 * Cleanup raw socket resources
 */
void rawsock_cleanup(void);

#endif /* SYNFLOOD_RAWSOCK_H */

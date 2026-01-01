/*
 * nfqueue.h - NFQUEUE packet capture handler
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_NFQUEUE_H
#define SYNFLOOD_NFQUEUE_H

#include "common.h"

/**
 * Initialize NFQUEUE capture
 * @param ctx Application context
 * @param queue_num NFQUEUE number to use
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t nfqueue_init(app_context_t *ctx, uint16_t queue_num);

/**
 * Start NFQUEUE packet capture loop
 * @param ctx Application context
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t nfqueue_start(app_context_t *ctx);

/**
 * Stop NFQUEUE packet capture
 */
void nfqueue_stop(void);

/**
 * Cleanup NFQUEUE resources
 */
void nfqueue_cleanup(void);

#endif /* SYNFLOOD_NFQUEUE_H */

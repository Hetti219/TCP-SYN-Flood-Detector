/*
 * procparse.h - /proc/net/tcp parser for SYN_RECV validation
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_PROCPARSE_H
#define SYNFLOOD_PROCPARSE_H

#include "common.h"

/**
 * Count total number of connections in SYN_RECV state
 * @return Number of SYN_RECV connections, or 0 on error
 */
uint32_t procparse_count_syn_recv_total(void);

/**
 * Count SYN_RECV connections from a specific source IP
 * @param ip_addr Source IP address (network byte order)
 * @return Number of SYN_RECV connections from this IP
 */
uint32_t procparse_count_syn_recv_from_ip(uint32_t ip_addr);

/**
 * Get all source IPs currently in SYN_RECV state
 * @param ips Array to fill with IP addresses
 * @param max_ips Maximum number of IPs to return
 * @return Number of unique IPs found
 */
size_t procparse_get_syn_recv_ips(uint32_t *ips, size_t max_ips);

#endif /* SYNFLOOD_PROCPARSE_H */

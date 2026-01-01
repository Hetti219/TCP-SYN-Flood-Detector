/*
 * ipset_mgr.h - ipset management for IP blacklisting
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_IPSET_MGR_H
#define SYNFLOOD_IPSET_MGR_H

#include "common.h"

/**
 * Initialize ipset manager and create ipset if needed
 * @param ipset_name Name of the ipset to use
 * @param timeout Default timeout for entries (seconds)
 * @param max_entries Maximum number of entries in ipset
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t ipset_mgr_init(const char *ipset_name, uint32_t timeout, uint32_t max_entries);

/**
 * Shutdown ipset manager
 */
void ipset_mgr_shutdown(void);

/**
 * Add an IP address to the blacklist
 * @param ip_addr IP address to block (network byte order)
 * @param timeout Timeout in seconds (0 for default)
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t ipset_mgr_add(uint32_t ip_addr, uint32_t timeout);

/**
 * Remove an IP address from the blacklist
 * @param ip_addr IP address to unblock (network byte order)
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t ipset_mgr_remove(uint32_t ip_addr);

/**
 * Check if an IP address is in the blacklist
 * @param ip_addr IP address to check (network byte order)
 * @return true if IP is in blacklist, false otherwise
 */
bool ipset_mgr_test(uint32_t ip_addr);

/**
 * Flush all entries from the blacklist
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t ipset_mgr_flush(void);

/**
 * Get the number of entries in the blacklist
 * @return Number of entries
 */
size_t ipset_mgr_get_count(void);

#endif /* SYNFLOOD_IPSET_MGR_H */

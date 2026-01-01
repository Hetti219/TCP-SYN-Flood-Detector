/*
 * tracker.h - IP tracking hash table for rate limiting
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_TRACKER_H
#define SYNFLOOD_TRACKER_H

#include "common.h"

/**
 * Create a new tracker table
 * @param bucket_count Number of hash buckets (must be power of 2)
 * @param max_entries Maximum number of entries before LRU eviction
 * @return Pointer to tracker_table_t or NULL on error
 */
tracker_table_t *tracker_create(size_t bucket_count, size_t max_entries);

/**
 * Destroy tracker table and free all resources
 * @param table Tracker table to destroy
 */
void tracker_destroy(tracker_table_t *table);

/**
 * Get or create a tracker entry for an IP address
 * @param table Tracker table
 * @param ip_addr IP address (network byte order)
 * @return Pointer to ip_tracker_t or NULL on error
 */
ip_tracker_t *tracker_get_or_create(tracker_table_t *table, uint32_t ip_addr);

/**
 * Get an existing tracker entry (does not create)
 * @param table Tracker table
 * @param ip_addr IP address (network byte order)
 * @return Pointer to ip_tracker_t or NULL if not found
 */
ip_tracker_t *tracker_get(tracker_table_t *table, uint32_t ip_addr);

/**
 * Remove a tracker entry
 * @param table Tracker table
 * @param ip_addr IP address (network byte order)
 * @return SYNFLOOD_OK on success, SYNFLOOD_ENOTFOUND if not found
 */
synflood_ret_t tracker_remove(tracker_table_t *table, uint32_t ip_addr);

/**
 * Get all blocked IPs that have expired
 * @param table Tracker table
 * @param current_time_ns Current time in nanoseconds
 * @param expired_ips Array to fill with expired IP addresses
 * @param max_ips Maximum number of IPs to return
 * @return Number of expired IPs found
 */
size_t tracker_get_expired_blocks(tracker_table_t *table, uint64_t current_time_ns,
                                   uint32_t *expired_ips, size_t max_ips);

/**
 * Get statistics about the tracker table
 * @param table Tracker table
 * @param entry_count Output: number of entries
 * @param blocked_count Output: number of blocked IPs
 */
void tracker_get_stats(tracker_table_t *table, size_t *entry_count, size_t *blocked_count);

/**
 * Clear all entries from the tracker table
 * @param table Tracker table
 */
void tracker_clear(tracker_table_t *table);

#endif /* SYNFLOOD_TRACKER_H */

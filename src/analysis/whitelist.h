/*
 * whitelist.h - CIDR whitelist using Patricia trie
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_WHITELIST_H
#define SYNFLOOD_WHITELIST_H

#include "common.h"

/**
 * Load whitelist from configuration file
 * @param path Path to whitelist configuration file
 * @return Root node of Patricia trie or NULL on error
 */
whitelist_node_t *whitelist_load(const char *path);

/**
 * Add an IP/CIDR to the whitelist
 * @param root Pointer to root node pointer
 * @param cidr CIDR notation string (e.g., "192.168.1.0/24")
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t whitelist_add(whitelist_node_t **root, const char *cidr);

/**
 * Check if an IP address is whitelisted
 * @param root Root node of Patricia trie
 * @param ip_addr IP address to check (network byte order)
 * @return true if whitelisted, false otherwise
 */
bool whitelist_check(whitelist_node_t *root, uint32_t ip_addr);

/**
 * Free whitelist and all nodes
 * @param root Root node of Patricia trie
 */
void whitelist_free(whitelist_node_t *root);

/**
 * Get count of whitelist entries
 * @param root Root node of Patricia trie
 * @return Number of entries
 */
size_t whitelist_count(whitelist_node_t *root);

#endif /* SYNFLOOD_WHITELIST_H */

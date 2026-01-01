/*
 * tracker.c - IP tracking hash table implementation
 * TCP SYN Flood Detector
 */

#include "tracker.h"
#include "../observe/logger.h"
#include <stdlib.h>
#include <string.h>

tracker_table_t *tracker_create(size_t bucket_count, size_t max_entries) {
    if (bucket_count == 0 || (bucket_count & (bucket_count - 1)) != 0) {
        LOG_ERROR("bucket_count must be power of 2");
        return NULL;
    }

    tracker_table_t *table = calloc(1, sizeof(tracker_table_t));
    if (!table) {
        return NULL;
    }

    table->buckets = calloc(bucket_count, sizeof(tracker_node_t *));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->bucket_count = bucket_count;
    table->entry_count = 0;
    table->max_entries = max_entries;

    if (pthread_rwlock_init(&table->lock, NULL) != 0) {
        free(table->buckets);
        free(table);
        return NULL;
    }

    LOG_DEBUG("Tracker table created: buckets=%zu, max_entries=%zu",
              bucket_count, max_entries);

    return table;
}

void tracker_destroy(tracker_table_t *table) {
    if (!table) {
        return;
    }

    pthread_rwlock_wrlock(&table->lock);

    for (size_t i = 0; i < table->bucket_count; i++) {
        tracker_node_t *node = table->buckets[i];
        while (node) {
            tracker_node_t *next = node->next;
            free(node);
            node = next;
        }
    }

    free(table->buckets);
    pthread_rwlock_unlock(&table->lock);
    pthread_rwlock_destroy(&table->lock);
    free(table);

    LOG_DEBUG("Tracker table destroyed");
}

/* LRU eviction: remove the least recently seen entry */
static void tracker_evict_lru(tracker_table_t *table) {
    if (table->entry_count == 0) {
        return;
    }

    tracker_node_t *oldest_node = NULL;
    tracker_node_t *oldest_prev = NULL;
    size_t oldest_bucket = 0;
    uint64_t oldest_time = UINT64_MAX;

    /* Find the oldest entry */
    for (size_t i = 0; i < table->bucket_count; i++) {
        tracker_node_t *prev = NULL;
        tracker_node_t *node = table->buckets[i];

        while (node) {
            if (node->data.last_seen_ns < oldest_time) {
                oldest_time = node->data.last_seen_ns;
                oldest_node = node;
                oldest_prev = prev;
                oldest_bucket = i;
            }
            prev = node;
            node = node->next;
        }
    }

    if (oldest_node) {
        /* Remove from chain */
        if (oldest_prev) {
            oldest_prev->next = oldest_node->next;
        } else {
            table->buckets[oldest_bucket] = oldest_node->next;
        }

        LOG_DEBUG("Evicted LRU entry: IP=%u", oldest_node->data.ip_addr);
        free(oldest_node);
        table->entry_count--;
    }
}

ip_tracker_t *tracker_get_or_create(tracker_table_t *table, uint32_t ip_addr) {
    if (!table) {
        return NULL;
    }

    pthread_rwlock_wrlock(&table->lock);

    uint32_t bucket = ip_hash(ip_addr, table->bucket_count);
    tracker_node_t *node = table->buckets[bucket];
    tracker_node_t *prev = NULL;

    /* Search for existing entry */
    while (node) {
        if (node->data.ip_addr == ip_addr) {
            uint64_t now = get_monotonic_ns();
            node->data.last_seen_ns = now;
            pthread_rwlock_unlock(&table->lock);
            return &node->data;
        }
        prev = node;
        node = node->next;
    }

    /* Entry not found, create new one */
    if (table->entry_count >= table->max_entries) {
        tracker_evict_lru(table);
    }

    tracker_node_t *new_node = calloc(1, sizeof(tracker_node_t));
    if (!new_node) {
        pthread_rwlock_unlock(&table->lock);
        return NULL;
    }

    uint64_t now = get_monotonic_ns();
    new_node->data.ip_addr = ip_addr;
    new_node->data.syn_count = 0;
    new_node->data.window_start_ns = now;
    new_node->data.last_seen_ns = now;
    new_node->data.blocked = 0;
    new_node->data.block_expiry_ns = 0;
    new_node->next = NULL;

    /* Insert at head of bucket */
    if (prev) {
        prev->next = new_node;
    } else {
        table->buckets[bucket] = new_node;
    }

    table->entry_count++;

    LOG_DEBUG("Created new tracker entry: IP=%u, total_entries=%zu",
              ip_addr, table->entry_count);

    pthread_rwlock_unlock(&table->lock);
    return &new_node->data;
}

ip_tracker_t *tracker_get(tracker_table_t *table, uint32_t ip_addr) {
    if (!table) {
        return NULL;
    }

    pthread_rwlock_rdlock(&table->lock);

    uint32_t bucket = ip_hash(ip_addr, table->bucket_count);
    tracker_node_t *node = table->buckets[bucket];

    while (node) {
        if (node->data.ip_addr == ip_addr) {
            pthread_rwlock_unlock(&table->lock);
            return &node->data;
        }
        node = node->next;
    }

    pthread_rwlock_unlock(&table->lock);
    return NULL;
}

synflood_ret_t tracker_remove(tracker_table_t *table, uint32_t ip_addr) {
    if (!table) {
        return SYNFLOOD_EINVAL;
    }

    pthread_rwlock_wrlock(&table->lock);

    uint32_t bucket = ip_hash(ip_addr, table->bucket_count);
    tracker_node_t *node = table->buckets[bucket];
    tracker_node_t *prev = NULL;

    while (node) {
        if (node->data.ip_addr == ip_addr) {
            if (prev) {
                prev->next = node->next;
            } else {
                table->buckets[bucket] = node->next;
            }
            free(node);
            table->entry_count--;
            pthread_rwlock_unlock(&table->lock);
            LOG_DEBUG("Removed tracker entry: IP=%u", ip_addr);
            return SYNFLOOD_OK;
        }
        prev = node;
        node = node->next;
    }

    pthread_rwlock_unlock(&table->lock);
    return SYNFLOOD_ENOTFOUND;
}

size_t tracker_get_expired_blocks(tracker_table_t *table, uint64_t current_time_ns,
                                   uint32_t *expired_ips, size_t max_ips) {
    if (!table || !expired_ips) {
        return 0;
    }

    pthread_rwlock_rdlock(&table->lock);

    size_t count = 0;
    for (size_t i = 0; i < table->bucket_count && count < max_ips; i++) {
        tracker_node_t *node = table->buckets[i];
        while (node && count < max_ips) {
            if (node->data.blocked && node->data.block_expiry_ns <= current_time_ns) {
                expired_ips[count++] = node->data.ip_addr;
            }
            node = node->next;
        }
    }

    pthread_rwlock_unlock(&table->lock);
    return count;
}

void tracker_get_stats(tracker_table_t *table, size_t *entry_count, size_t *blocked_count) {
    if (!table) {
        if (entry_count) *entry_count = 0;
        if (blocked_count) *blocked_count = 0;
        return;
    }

    pthread_rwlock_rdlock(&table->lock);

    if (entry_count) {
        *entry_count = table->entry_count;
    }

    if (blocked_count) {
        size_t count = 0;
        for (size_t i = 0; i < table->bucket_count; i++) {
            tracker_node_t *node = table->buckets[i];
            while (node) {
                if (node->data.blocked) {
                    count++;
                }
                node = node->next;
            }
        }
        *blocked_count = count;
    }

    pthread_rwlock_unlock(&table->lock);
}

void tracker_clear(tracker_table_t *table) {
    if (!table) {
        return;
    }

    pthread_rwlock_wrlock(&table->lock);

    for (size_t i = 0; i < table->bucket_count; i++) {
        tracker_node_t *node = table->buckets[i];
        while (node) {
            tracker_node_t *next = node->next;
            free(node);
            node = next;
        }
        table->buckets[i] = NULL;
    }

    table->entry_count = 0;

    pthread_rwlock_unlock(&table->lock);

    LOG_INFO("Tracker table cleared");
}

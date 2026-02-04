/*
 * test_performance_stress.c - Performance and stress tests for integration scenarios
 *
 * Tests system behavior under load with many IPs, rapid events, and concurrent operations.
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/tracker.h"
#include "../../src/analysis/whitelist.h"
#include "../../src/observe/logger.h"
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

TEST_CASE(test_many_ips_tracking) {
    /* Test tracking large number of unique IPs */

    size_t num_ips = 10000;
    tracker_table_t *tracker = tracker_create(4096, num_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    uint64_t now = get_monotonic_ns();

    /* Track many unique IPs */
    for (size_t i = 0; i < num_ips; i++) {
        /* Generate unique IP */
        uint32_t ip = htonl(0x0A000000 | i);  /* 10.0.0.0/8 range */

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        TEST_ASSERT_NOT_NULL(t);

        t->window_start_ns = now;
        t->syn_count = (i % 200) + 1;  /* Varying counts */
        t->last_seen_ns = now + i;
    }

    /* Verify all tracked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(num_ips, entry_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_lru_eviction_under_load) {
    /* Test LRU eviction when tracking more IPs than max_tracked_ips */

    size_t max_ips = 1000;
    tracker_table_t *tracker = tracker_create(512, max_ips);

    uint64_t now = get_monotonic_ns();

    /* Track 2000 IPs (2x the limit) */
    for (int i = 0; i < 2000; i++) {
        uint32_t ip = htonl(0x0A000000 | i);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        TEST_ASSERT_NOT_NULL(t);

        t->window_start_ns = now;
        t->last_seen_ns = now + i;  /* Each subsequent IP is newer */
    }

    /* Should have evicted oldest IPs to maintain max_ips */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(max_ips, entry_count);

    /* First IPs should be evicted */
    uint32_t first_ip = htonl(0x0A000000);
    TEST_ASSERT_NULL(tracker_get(tracker, first_ip));

    /* Recent IPs should still be tracked */
    uint32_t recent_ip = htonl(0x0A000000 | 1999);
    TEST_ASSERT_NOT_NULL(tracker_get(tracker, recent_ip));

    tracker_destroy(tracker);
}

TEST_CASE(test_high_block_rate) {
    /* Test system with many IPs being blocked simultaneously */

    tracker_table_t *tracker = tracker_create(2048, 5000);
    uint32_t syn_threshold = 100;
    uint64_t now = get_monotonic_ns();

    /* Simulate 1000 attackers detected and blocked */
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(0xC0000000 | i);  /* 192.0.0.0/8 range */

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->window_start_ns = now;
        t->syn_count = syn_threshold + (i % 100);
        t->blocked = 1;
        t->block_expiry_ns = now + sec_to_ns(300);
    }

    /* Verify all blocked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(1000, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_high_expiry_rate) {
    /* Test system processing many block expirations */

    tracker_table_t *tracker = tracker_create(2048, 5000);
    uint64_t now = get_monotonic_ns();

    /* Block 1000 IPs, all expiring at same time */
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(0xC0000000 | i);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->blocked = 1;
        t->block_expiry_ns = now + sec_to_ns(60);  /* All expire in 60s */
    }

    /* Check expiry after 70 seconds */
    uint64_t check_time = now + sec_to_ns(70);

    /* Get expired in batches */
    uint32_t expired_ips[100];
    size_t total_expired = 0;

    for (int batch = 0; batch < 10; batch++) {
        size_t expired_count = tracker_get_expired_blocks(tracker, check_time, expired_ips, 100);
        total_expired += expired_count;

        /* Unblock this batch */
        for (size_t i = 0; i < expired_count; i++) {
            ip_tracker_t *t = tracker_get(tracker, expired_ips[i]);
            if (t) {
                t->blocked = 0;
            }
        }

        if (expired_count < 100) {
            break;  /* No more expired IPs */
        }
    }

    TEST_ASSERT_EQUAL_UINT32(1000, total_expired);

    /* All should be unblocked now */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(0, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_whitelist_large_scale) {
    /* Test whitelist performance with many ranges and IP checks */

    whitelist_node_t *whitelist = NULL;

    /* Add 100 whitelist ranges */
    for (int i = 0; i < 100; i++) {
        char cidr[32];
        snprintf(cidr, sizeof(cidr), "10.%d.0.0/16", i);
        whitelist_add(&whitelist, cidr);
    }

    /* Check 10000 IPs against whitelist */
    int whitelisted_count = 0;
    for (int i = 0; i < 10000; i++) {
        uint32_t ip = htonl(0x0A000000 | (i << 8));  /* 10.x.y.0 */

        if (whitelist_check(whitelist, ip)) {
            whitelisted_count++;
        }
    }

    /* Many should be whitelisted (depends on IP generation pattern) */
    TEST_ASSERT_GREATER_THAN(0, whitelisted_count);

    whitelist_free(whitelist);
}

TEST_CASE(test_mixed_operations_stress) {
    /* Test mixed operations: tracking, blocking, expiring, whitelist checks */

    tracker_table_t *tracker = tracker_create(2048, 5000);
    whitelist_node_t *whitelist = NULL;

    /* Setup whitelist */
    whitelist_add(&whitelist, "10.0.0.0/8");
    whitelist_add(&whitelist, "172.16.0.0/12");

    uint64_t now = get_monotonic_ns();
    uint32_t syn_threshold = 100;

    int tracked_count = 0;
    int blocked_count = 0;
    int whitelisted_count = 0;

    /* Process 5000 IPs with mixed scenarios */
    for (int i = 0; i < 5000; i++) {
        uint32_t ip;

        /* Generate IPs from different ranges */
        if (i < 1000) {
            ip = htonl(0x0A000000 | i);  /* 10.0.0.0/8 - whitelisted */
        } else if (i < 2000) {
            ip = htonl(0xAC100000 | i);  /* 172.16.0.0/12 - whitelisted */
        } else {
            ip = htonl(0xC0000000 | i);  /* 192.0.0.0/8 - not whitelisted */
        }

        /* Check whitelist */
        if (whitelist_check(whitelist, ip)) {
            whitelisted_count++;
            continue;  /* Don't track whitelisted */
        }

        /* Track non-whitelisted */
        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        tracked_count++;

        t->window_start_ns = now;
        t->syn_count = 50 + (i % 200);  /* Varying counts */

        /* Block if over threshold */
        if (t->syn_count > syn_threshold) {
            t->blocked = 1;
            t->block_expiry_ns = now + sec_to_ns(300);
            blocked_count++;
        }
    }

    /* Verify counts */
    TEST_ASSERT_GREATER_THAN(0, whitelisted_count);
    TEST_ASSERT_GREATER_THAN(0, tracked_count);
    TEST_ASSERT_GREATER_THAN(0, blocked_count);

    size_t entry_count, blocked_entry_count;
    tracker_get_stats(tracker, &entry_count, &blocked_entry_count);
    TEST_ASSERT_EQUAL_UINT32(tracked_count, entry_count);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_rapid_window_resets) {
    /* Test rapid detection window resets */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint32_t window_ms = 1000;
    uint64_t window_ns = ms_to_ns(window_ms);

    uint32_t ip = inet_addr("203.0.113.100");
    uint64_t time = get_monotonic_ns();

    ip_tracker_t *t = tracker_get_or_create(tracker, ip);

    /* Simulate 100 window resets */
    for (int cycle = 0; cycle < 100; cycle++) {
        t->window_start_ns = time;
        t->syn_count = 0;

        /* Count SYNs within window */
        for (int i = 0; i < 50; i++) {
            t->syn_count++;
            t->last_seen_ns = time + ms_to_ns(i * 10);
        }

        TEST_ASSERT_EQUAL_UINT32(50, t->syn_count);

        /* Advance to next window */
        time += window_ns + ms_to_ns(100);

        /* Reset window */
        if (time - t->window_start_ns > window_ns) {
            t->window_start_ns = time;
            t->syn_count = 0;
        }
    }

    tracker_destroy(tracker);
}

TEST_CASE(test_hash_collision_performance) {
    /* Test performance with intentional hash collisions */

    /* Use very small bucket count to force collisions */
    tracker_table_t *tracker = tracker_create(16, 10000);
    uint64_t now = get_monotonic_ns();

    /* Track 1000 IPs - many will collide in same buckets */
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(0x0A000000 | i);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        TEST_ASSERT_NOT_NULL(t);

        t->window_start_ns = now;
        t->syn_count = i + 1;
    }

    /* Verify all IPs can still be retrieved correctly despite collisions */
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = htonl(0x0A000000 | i);

        ip_tracker_t *t = tracker_get(tracker, ip);
        TEST_ASSERT_NOT_NULL(t);
        TEST_ASSERT_EQUAL_UINT32(i + 1, t->syn_count);
    }

    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(1000, entry_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_memory_efficiency) {
    /* Test memory efficiency with large tracker table */

    /* Large configuration */
    size_t bucket_count = 8192;
    size_t max_entries = 50000;

    tracker_table_t *tracker = tracker_create(bucket_count, max_entries);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Add substantial number of entries */
    uint64_t now = get_monotonic_ns();
    for (int i = 0; i < 10000; i++) {
        uint32_t ip = htonl(0x0A000000 | i);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        TEST_ASSERT_NOT_NULL(t);

        t->window_start_ns = now;
        t->syn_count = 50;
    }

    /* Verify all tracked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(10000, entry_count);

    /* Clear and verify cleanup */
    tracker_clear(tracker);
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(0, entry_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_distributed_attack_simulation) {
    /* Simulate a distributed attack from many sources */

    tracker_table_t *tracker = tracker_create(4096, 10000);
    whitelist_node_t *whitelist = NULL;

    /* Whitelist legitimate infrastructure */
    whitelist_add(&whitelist, "10.0.0.0/8");

    uint64_t now = get_monotonic_ns();
    uint32_t syn_threshold = 100;

    /* Simulate 5000 attacker IPs (botnet) */
    int blocked_attackers = 0;

    for (int i = 0; i < 5000; i++) {
        /* Generate attacker IPs from various ranges */
        uint32_t ip;
        if (i < 2000) {
            ip = htonl(0xC0000000 | i);  /* 192.0.0.0/8 */
        } else if (i < 4000) {
            ip = htonl(0xCB000000 | i);  /* 203.0.0.0/8 */
        } else {
            ip = htonl(0x50000000 | i);  /* 80.0.0.0/8 */
        }

        /* Skip whitelisted */
        if (whitelist_check(whitelist, ip)) {
            continue;
        }

        /* Each attacker sends moderate number of SYNs */
        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->window_start_ns = now;
        t->syn_count = 80 + (i % 50);  /* 80-130 SYNs per source */

        /* Block if over threshold */
        if (t->syn_count > syn_threshold) {
            t->blocked = 1;
            t->block_expiry_ns = now + sec_to_ns(300);
            blocked_attackers++;
        }
    }

    /* Verify distributed attackers were detected and blocked */
    TEST_ASSERT_GREATER_THAN(2000, blocked_attackers);

    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(blocked_attackers, blocked_count);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

int main(void) {
    UnityBegin("test_performance_stress.c");

    RUN_TEST(test_many_ips_tracking);
    RUN_TEST(test_lru_eviction_under_load);
    RUN_TEST(test_high_block_rate);
    RUN_TEST(test_high_expiry_rate);
    RUN_TEST(test_whitelist_large_scale);
    RUN_TEST(test_mixed_operations_stress);
    RUN_TEST(test_rapid_window_resets);
    RUN_TEST(test_hash_collision_performance);
    RUN_TEST(test_memory_efficiency);
    RUN_TEST(test_distributed_attack_simulation);

    return UnityEnd();
}

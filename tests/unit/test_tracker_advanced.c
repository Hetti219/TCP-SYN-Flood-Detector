/*
 * test_tracker_advanced.c - Advanced edge case tests for IP tracker
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/tracker.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

TEST_CASE(test_tracker_lru_eviction) {
    /* Test LRU eviction when max_entries is reached */

    size_t bucket_count = 16;
    size_t max_entries = 3;  /* Small limit to force eviction */

    tracker_table_t *table = tracker_create(bucket_count, max_entries);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t now = get_monotonic_ns();

    /* Add 3 IPs - should all fit */
    uint32_t ip1 = inet_addr("192.168.1.1");
    uint32_t ip2 = inet_addr("192.168.1.2");
    uint32_t ip3 = inet_addr("192.168.1.3");

    ip_tracker_t *t1 = tracker_get_or_create(table, ip1);
    TEST_ASSERT_NOT_NULL(t1);
    usleep(1000);  /* Small delay to differentiate last_seen_ns */

    ip_tracker_t *t2 = tracker_get_or_create(table, ip2);
    TEST_ASSERT_NOT_NULL(t2);
    usleep(1000);

    ip_tracker_t *t3 = tracker_get_or_create(table, ip3);
    TEST_ASSERT_NOT_NULL(t3);

    /* Verify all 3 are tracked */
    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(3, entry_count);

    /* Add 4th IP - should trigger LRU eviction of oldest (ip1) */
    uint32_t ip4 = inet_addr("192.168.1.4");
    ip_tracker_t *t4 = tracker_get_or_create(table, ip4);
    TEST_ASSERT_NOT_NULL(t4);

    /* Still should have 3 entries (max limit) */
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(3, entry_count);

    /* ip1 should be evicted, others should remain */
    TEST_ASSERT_NULL(tracker_get(table, ip1));
    TEST_ASSERT_NOT_NULL(tracker_get(table, ip2));
    TEST_ASSERT_NOT_NULL(tracker_get(table, ip3));
    TEST_ASSERT_NOT_NULL(tracker_get(table, ip4));

    tracker_destroy(table);
}

TEST_CASE(test_tracker_hash_collision_handling) {
    /* Test hash collision handling via chaining */

    /* Use very small bucket count to force collisions */
    size_t bucket_count = 2;
    size_t max_entries = 100;

    tracker_table_t *table = tracker_create(bucket_count, max_entries);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t now = get_monotonic_ns();

    /* Add multiple IPs that will likely collide */
    uint32_t ips[10];
    for (int i = 0; i < 10; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "10.0.0.%d", i);
        ips[i] = inet_addr(ip_str);

        ip_tracker_t *tracker = tracker_get_or_create(table, ips[i]);
        TEST_ASSERT_NOT_NULL(tracker);
        tracker->syn_count = i + 1;  /* Unique value */
    }

    /* Verify all IPs are tracked correctly despite collisions */
    for (int i = 0; i < 10; i++) {
        ip_tracker_t *tracker = tracker_get(table, ips[i]);
        TEST_ASSERT_NOT_NULL(tracker);
        TEST_ASSERT_EQUAL_UINT32(i + 1, tracker->syn_count);
    }

    tracker_destroy(table);
}

TEST_CASE(test_tracker_window_expiry) {
    /* Test time window expiry and reset */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t ip = inet_addr("192.168.1.1");
    uint64_t window_start = get_monotonic_ns();

    /* Create tracker and increment SYN count */
    ip_tracker_t *tracker = tracker_get_or_create(table, ip);
    tracker->syn_count = 50;
    tracker->window_start_ns = window_start;

    /* Time passes - window should be stale */
    uint64_t after_window = window_start + sec_to_ns(2);  /* 2 seconds later */

    /* Get tracker again - window should reset if checked by detection logic */
    tracker = tracker_get(table, ip);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Note: The tracker module doesn't auto-reset windows
     * This is done by the detection logic in nfqueue/rawsock
     * Here we verify the tracker maintains the window_start_ns */
    TEST_ASSERT_EQUAL_UINT64(window_start, tracker->window_start_ns);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_block_expiry_boundaries) {
    /* Test block expiry boundary conditions */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t now = get_monotonic_ns();

    /* Create blocked entries with different expiry times */
    uint32_t ip1 = inet_addr("10.0.0.1");
    uint32_t ip2 = inet_addr("10.0.0.2");
    uint32_t ip3 = inet_addr("10.0.0.3");

    ip_tracker_t *t1 = tracker_get_or_create(table, ip1);
    t1->blocked = true;
    t1->block_expiry_ns = now + sec_to_ns(5);  /* Expires in 5 seconds */

    ip_tracker_t *t2 = tracker_get_or_create(table, ip2);
    t2->blocked = true;
    t2->block_expiry_ns = now + sec_to_ns(10);  /* Expires in 10 seconds */

    ip_tracker_t *t3 = tracker_get_or_create(table, ip3);
    t3->blocked = true;
    t3->block_expiry_ns = now + sec_to_ns(15);  /* Expires in 15 seconds */

    /* At t=7s: ip1 expired, ip2 and ip3 still blocked */
    uint32_t expired_ips[10];
    size_t expired_count = tracker_get_expired_blocks(
        table, now + sec_to_ns(7), expired_ips, 10);

    TEST_ASSERT_EQUAL_UINT32(1, expired_count);
    TEST_ASSERT_EQUAL_UINT32(ip1, expired_ips[0]);

    /* At t=12s: ip1 and ip2 expired, ip3 still blocked */
    expired_count = tracker_get_expired_blocks(
        table, now + sec_to_ns(12), expired_ips, 10);

    TEST_ASSERT_EQUAL_UINT32(2, expired_count);
    /* Order may vary, check both are present */
    bool found_ip1 = false, found_ip2 = false;
    for (size_t i = 0; i < expired_count; i++) {
        if (expired_ips[i] == ip1) found_ip1 = true;
        if (expired_ips[i] == ip2) found_ip2 = true;
    }
    TEST_ASSERT_TRUE(found_ip1);
    TEST_ASSERT_TRUE(found_ip2);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_zero_bucket_count) {
    /* Test creation with invalid (0) bucket count */

    tracker_table_t *table = tracker_create(0, 1000);

    /* Should return NULL for invalid bucket count */
    TEST_ASSERT_NULL(table);
}

TEST_CASE(test_tracker_non_power_of_two_buckets) {
    /* Test creation with non-power-of-2 bucket count */

    /* Valid power of 2 */
    tracker_table_t *table1 = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table1);
    tracker_destroy(table1);

    /* Invalid: not power of 2 */
    tracker_table_t *table2 = tracker_create(100, 1000);
    TEST_ASSERT_NULL(table2);

    /* Valid: 1 is technically 2^0 */
    tracker_table_t *table3 = tracker_create(1, 1000);
    TEST_ASSERT_NOT_NULL(table3);
    tracker_destroy(table3);
}

TEST_CASE(test_tracker_max_entries_boundary) {
    /* Test behavior at max_entries boundary */

    size_t max_entries = 5;
    tracker_table_t *table = tracker_create(16, max_entries);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t now = get_monotonic_ns();

    /* Add exactly max_entries IPs */
    for (int i = 0; i < (int)max_entries; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "10.0.0.%d", i);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *tracker = tracker_get_or_create(table, ip);
        TEST_ASSERT_NOT_NULL(tracker);
    }

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(max_entries, entry_count);

    /* Add one more - should trigger eviction */
    uint32_t overflow_ip = inet_addr("10.0.0.99");
    ip_tracker_t *tracker = tracker_get_or_create(table, overflow_ip);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Still at max_entries */
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(max_entries, entry_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_remove_nonexistent) {
    /* Test removing an IP that doesn't exist */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t ip = inet_addr("192.168.1.100");

    /* Remove non-existent IP - should not crash */
    tracker_remove(table, ip);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_clear_empty_table) {
    /* Test clearing an already empty table */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    /* Clear empty table - should not crash */
    tracker_clear(table);

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(0, entry_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_get_expired_empty) {
    /* Test getting expired blocks from empty table */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t expired_ips[10];
    size_t count = tracker_get_expired_blocks(table, get_monotonic_ns(), expired_ips, 10);

    TEST_ASSERT_EQUAL_UINT32(0, count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_get_expired_none) {
    /* Test getting expired blocks when none are expired */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t now = get_monotonic_ns();

    /* Add blocked IP with future expiry */
    uint32_t ip = inet_addr("10.0.0.1");
    ip_tracker_t *tracker = tracker_get_or_create(table, ip);
    tracker->blocked = true;
    tracker->block_expiry_ns = now + sec_to_ns(3600);  /* 1 hour from now */

    /* Check for expired at current time - none should be expired */
    uint32_t expired_ips[10];
    size_t count = tracker_get_expired_blocks(table, now, expired_ips, 10);

    TEST_ASSERT_EQUAL_UINT32(0, count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_get_expired_buffer_limit) {
    /* Test that expired blocks respects max_ips limit */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t now = get_monotonic_ns();
    uint32_t expiry = now - sec_to_ns(1);  /* Already expired */

    /* Add 10 expired IPs */
    for (int i = 0; i < 10; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "10.0.0.%d", i);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *tracker = tracker_get_or_create(table, ip);
        tracker->blocked = true;
        tracker->block_expiry_ns = expiry;
    }

    /* Request only 5 - should return 5 even though 10 are expired */
    uint32_t expired_ips[5];
    size_t count = tracker_get_expired_blocks(table, now, expired_ips, 5);

    TEST_ASSERT_EQUAL_UINT32(5, count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_idempotent_get_or_create) {
    /* Test that get_or_create is idempotent */

    tracker_table_t *table = tracker_create(256, 1000);
    TEST_ASSERT_NOT_NULL(table);

    uint32_t ip = inet_addr("192.168.1.1");
    uint32_t now = get_monotonic_ns();

    /* First call creates */
    ip_tracker_t *t1 = tracker_get_or_create(table, ip);
    TEST_ASSERT_NOT_NULL(t1);
    t1->syn_count = 42;

    /* Second call returns same tracker */
    ip_tracker_t *t2 = tracker_get_or_create(table, ip);
    TEST_ASSERT_NOT_NULL(t2);
    TEST_ASSERT_EQUAL_PTR(t1, t2);
    TEST_ASSERT_EQUAL_UINT32(42, t2->syn_count);

    /* Stats should still show 1 entry */
    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(1, entry_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_large_table) {
    /* Test with large bucket count */

    size_t bucket_count = 65536;  /* 64K buckets */
    size_t max_entries = 1000000;  /* 1M entries */

    tracker_table_t *table = tracker_create(bucket_count, max_entries);
    TEST_ASSERT_NOT_NULL(table);

    /* Add some entries */
    uint32_t now = get_monotonic_ns();
    for (int i = 0; i < 100; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "10.%d.%d.%d",
                 i / 256 / 256, (i / 256) % 256, i % 256);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *tracker = tracker_get_or_create(table, ip);
        TEST_ASSERT_NOT_NULL(tracker);
    }

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(100, entry_count);

    tracker_destroy(table);
}

int main(void) {
    UnityBegin("test_tracker_advanced.c");

    RUN_TEST(test_tracker_lru_eviction);
    RUN_TEST(test_tracker_hash_collision_handling);
    RUN_TEST(test_tracker_window_expiry);
    RUN_TEST(test_tracker_block_expiry_boundaries);
    RUN_TEST(test_tracker_zero_bucket_count);
    RUN_TEST(test_tracker_non_power_of_two_buckets);
    RUN_TEST(test_tracker_max_entries_boundary);
    RUN_TEST(test_tracker_remove_nonexistent);
    RUN_TEST(test_tracker_clear_empty_table);
    RUN_TEST(test_tracker_get_expired_empty);
    RUN_TEST(test_tracker_get_expired_none);
    RUN_TEST(test_tracker_get_expired_buffer_limit);
    RUN_TEST(test_tracker_idempotent_get_or_create);
    RUN_TEST(test_tracker_large_table);

    return UnityEnd();
}

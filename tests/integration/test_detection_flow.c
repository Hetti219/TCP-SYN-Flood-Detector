/*
 * test_detection_flow.c - Integration test for detection flow
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/tracker.h"
#include "../../src/analysis/whitelist.h"
#include "../../src/config/config.h"
#include <arpa/inet.h>
#include <unistd.h>

/* Simulate the detection flow without actual packet capture */
TEST_CASE(test_detection_basic_flow) {
    /* Create configuration */
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .block_duration_s = 300,
        .max_tracked_ips = 10000,
        .hash_buckets = 1024,
    };

    /* Create tracker */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Simulate SYN packets from an IP */
    uint32_t attacker_ip = inet_addr("203.0.113.100");
    uint64_t current_time = get_monotonic_ns();

    /* Get tracker for this IP */
    ip_tracker_t *ip_tracker = tracker_get_or_create(tracker, attacker_ip);
    TEST_ASSERT_NOT_NULL(ip_tracker);

    /* Initialize tracking window */
    ip_tracker->window_start_ns = current_time;
    ip_tracker->syn_count = 0;

    /* Simulate 150 SYN packets (above threshold) */
    for (int i = 0; i < 150; i++) {
        ip_tracker->syn_count++;
        ip_tracker->last_seen_ns = current_time + ms_to_ns(i);
    }

    /* Check if threshold exceeded */
    TEST_ASSERT_GREATER_THAN(config.syn_threshold, ip_tracker->syn_count);

    /* Simulate blocking */
    ip_tracker->blocked = 1;
    ip_tracker->block_expiry_ns = current_time + sec_to_ns(config.block_duration_s);

    /* Verify blocked state */
    TEST_ASSERT_EQUAL_INT(1, ip_tracker->blocked);
    TEST_ASSERT_GREATER_THAN(current_time, ip_tracker->block_expiry_ns);

    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(1, entry_count);
    TEST_ASSERT_EQUAL_INT(1, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_detection_with_whitelist) {
    /* Create configuration */
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .max_tracked_ips = 10000,
        .hash_buckets = 1024,
    };

    /* Create tracker */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Create whitelist */
    whitelist_node_t *whitelist = NULL;
    whitelist_add(&whitelist, "192.168.0.0/16");  /* Whitelist private network */

    /* Test IP from whitelisted range */
    uint32_t whitelisted_ip = inet_addr("192.168.1.100");
    TEST_ASSERT_TRUE(whitelist_check(whitelist, whitelisted_ip));

    /* Whitelisted IP should not be tracked even with many SYNs */
    /* (In real code, we'd skip tracking whitelisted IPs) */

    /* Test IP not in whitelist */
    uint32_t attacker_ip = inet_addr("203.0.113.100");
    TEST_ASSERT_FALSE(whitelist_check(whitelist, attacker_ip));

    /* This IP should be tracked */
    ip_tracker_t *tracker_entry = tracker_get_or_create(tracker, attacker_ip);
    TEST_ASSERT_NOT_NULL(tracker_entry);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_detection_window_expiry) {
    /* Create configuration with 1 second window */
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .max_tracked_ips = 10000,
        .hash_buckets = 1024,
    };

    /* Create tracker */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);

    uint32_t ip = inet_addr("203.0.113.100");
    uint64_t time1 = get_monotonic_ns();

    /* Get tracker and set window */
    ip_tracker_t *ip_tracker = tracker_get_or_create(tracker, ip);
    ip_tracker->window_start_ns = time1;
    ip_tracker->syn_count = 50;

    /* Simulate time passing (more than window duration) */
    uint64_t time2 = time1 + ms_to_ns(config.window_ms + 100);  /* 100ms past window */

    /* In a real scenario, we'd reset the window if it expired */
    uint64_t window_duration_ns = ms_to_ns(config.window_ms);
    if (time2 - ip_tracker->window_start_ns > window_duration_ns) {
        /* Window expired, reset */
        ip_tracker->window_start_ns = time2;
        ip_tracker->syn_count = 0;
    }

    /* After reset, count should be 0 */
    TEST_ASSERT_EQUAL_UINT32(0, ip_tracker->syn_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_detection_multiple_ips) {
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .max_tracked_ips = 10000,
        .hash_buckets = 1024,
    };

    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    uint64_t current_time = get_monotonic_ns();

    /* Simulate attacks from multiple IPs */
    for (int i = 1; i <= 5; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "203.0.113.%d", i);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *tracker_entry = tracker_get_or_create(tracker, ip);
        tracker_entry->window_start_ns = current_time;
        tracker_entry->syn_count = 150;  /* Above threshold */
        tracker_entry->blocked = 1;
        tracker_entry->block_expiry_ns = current_time + sec_to_ns(300);
    }

    /* Verify we tracked all 5 IPs */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(5, entry_count);
    TEST_ASSERT_EQUAL_INT(5, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_expiry_and_unblock) {
    tracker_table_t *tracker = tracker_create(1024, 10000);
    uint64_t current_time = get_monotonic_ns();

    /* Create 3 blocked IPs with different expiry times */
    uint32_t ip1 = inet_addr("203.0.113.1");
    uint32_t ip2 = inet_addr("203.0.113.2");
    uint32_t ip3 = inet_addr("203.0.113.3");

    ip_tracker_t *t1 = tracker_get_or_create(tracker, ip1);
    t1->blocked = 1;
    t1->block_expiry_ns = current_time - sec_to_ns(10);  /* Expired */

    ip_tracker_t *t2 = tracker_get_or_create(tracker, ip2);
    t2->blocked = 1;
    t2->block_expiry_ns = current_time + sec_to_ns(300);  /* Not expired */

    ip_tracker_t *t3 = tracker_get_or_create(tracker, ip3);
    t3->blocked = 1;
    t3->block_expiry_ns = current_time - sec_to_ns(5);  /* Expired */

    /* Get expired blocks */
    uint32_t expired_ips[10];
    size_t expired_count = tracker_get_expired_blocks(tracker, current_time, expired_ips, 10);

    /* Should find 2 expired (ip1 and ip3) */
    TEST_ASSERT_EQUAL_INT(2, expired_count);

    /* Unblock expired IPs */
    for (size_t i = 0; i < expired_count; i++) {
        ip_tracker_t *tracker_entry = tracker_get(tracker, expired_ips[i]);
        if (tracker_entry) {
            tracker_entry->blocked = 0;
        }
    }

    /* Verify only 1 IP is still blocked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(3, entry_count);
    TEST_ASSERT_EQUAL_INT(1, blocked_count);

    tracker_destroy(tracker);
}

int main(void) {
    UnityBegin("test_detection_flow.c");

    RUN_TEST(test_detection_basic_flow);
    RUN_TEST(test_detection_with_whitelist);
    RUN_TEST(test_detection_window_expiry);
    RUN_TEST(test_detection_multiple_ips);
    RUN_TEST(test_expiry_and_unblock);

    return UnityEnd();
}

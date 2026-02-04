/*
 * test_blocking_scenarios.c - Integration tests for blocking/unblocking scenarios
 *
 * Tests various real-world blocking and unblocking scenarios with tracker and expiry.
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/tracker.h"
#include "../../src/analysis/whitelist.h"
#include "../../src/observe/logger.h"
#include <arpa/inet.h>
#include <unistd.h>

TEST_CASE(test_single_attacker_full_cycle) {
    /* Test complete cycle: detection -> block -> expiry -> unblock */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint32_t syn_threshold = 100;
    uint32_t block_duration_s = 5;  /* Short for testing */

    uint32_t attacker_ip = inet_addr("203.0.113.100");
    uint64_t time_0 = get_monotonic_ns();

    /* Phase 1: Detection - SYN count exceeds threshold */
    ip_tracker_t *t = tracker_get_or_create(tracker, attacker_ip);
    t->window_start_ns = time_0;
    t->syn_count = 0;

    /* Simulate rapid SYN packets */
    for (int i = 0; i < 150; i++) {
        t->syn_count++;
        t->last_seen_ns = time_0 + ms_to_ns(i * 10);
    }

    TEST_ASSERT_GREATER_THAN(syn_threshold, t->syn_count);

    /* Phase 2: Block the IP */
    t->blocked = 1;
    t->block_expiry_ns = time_0 + sec_to_ns(block_duration_s);

    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(1, blocked_count);

    /* Phase 3: Time passes - still within block duration */
    uint64_t time_3s = time_0 + sec_to_ns(3);
    TEST_ASSERT_TRUE(t->blocked);
    TEST_ASSERT_FALSE(time_3s > t->block_expiry_ns);

    /* Phase 4: Block expires */
    uint64_t time_6s = time_0 + sec_to_ns(6);
    uint32_t expired_ips[10];
    size_t expired_count = tracker_get_expired_blocks(tracker, time_6s, expired_ips, 10);

    TEST_ASSERT_EQUAL_UINT32(1, expired_count);
    TEST_ASSERT_EQUAL_UINT32(attacker_ip, expired_ips[0]);

    /* Phase 5: Unblock */
    t->blocked = 0;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(0, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_multiple_attackers_different_timing) {
    /* Test multiple attackers detected and blocked at different times */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint32_t syn_threshold = 100;

    struct {
        const char *ip;
        uint64_t detection_time_offset;  /* Seconds from start */
        uint32_t block_duration;
    } attackers[] = {
        { "203.0.113.1", 0, 60 },
        { "203.0.113.2", 10, 120 },
        { "203.0.113.3", 20, 180 },
        { "203.0.113.4", 30, 240 },
    };

    uint64_t start_time = get_monotonic_ns();

    /* Block all attackers at different times */
    for (int i = 0; i < 4; i++) {
        uint32_t ip = inet_addr(attackers[i].ip);
        uint64_t detection_time = start_time + sec_to_ns(attackers[i].detection_time_offset);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->window_start_ns = detection_time;
        t->syn_count = syn_threshold + 50;
        t->blocked = 1;
        t->block_expiry_ns = detection_time + sec_to_ns(attackers[i].block_duration);
    }

    /* All 4 should be blocked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(4, entry_count);
    TEST_ASSERT_EQUAL_UINT32(4, blocked_count);

    /* Check expiry at 90 seconds */
    uint64_t check_time_90s = start_time + sec_to_ns(90);
    uint32_t expired_ips[10];
    size_t expired_count = tracker_get_expired_blocks(tracker, check_time_90s, expired_ips, 10);

    /* First attacker (60s) should be expired, others still blocked */
    TEST_ASSERT_EQUAL_UINT32(1, expired_count);

    /* Check expiry at 150 seconds */
    uint64_t check_time_150s = start_time + sec_to_ns(150);
    expired_count = tracker_get_expired_blocks(tracker, check_time_150s, expired_ips, 10);

    /* First two attackers should be expired */
    TEST_ASSERT_EQUAL_UINT32(2, expired_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_reblock_after_expiry) {
    /* Test that an IP can be re-blocked if it attacks again after unblocking */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint32_t syn_threshold = 100;

    uint32_t ip = inet_addr("203.0.113.100");
    uint64_t time_0 = get_monotonic_ns();

    /* First attack - block */
    ip_tracker_t *t = tracker_get_or_create(tracker, ip);
    t->window_start_ns = time_0;
    t->syn_count = 150;
    t->blocked = 1;
    t->block_expiry_ns = time_0 + sec_to_ns(60);

    TEST_ASSERT_TRUE(t->blocked);

    /* Block expires and IP is unblocked */
    uint64_t time_70s = time_0 + sec_to_ns(70);
    if (time_70s > t->block_expiry_ns) {
        t->blocked = 0;
        t->syn_count = 0;  /* Reset counter */
    }

    TEST_ASSERT_FALSE(t->blocked);

    /* Second attack - re-block */
    t->window_start_ns = time_70s;
    for (int i = 0; i < 200; i++) {
        t->syn_count++;
    }

    if (t->syn_count > syn_threshold) {
        t->blocked = 1;
        t->block_expiry_ns = time_70s + sec_to_ns(60);
    }

    TEST_ASSERT_TRUE(t->blocked);
    TEST_ASSERT_EQUAL_UINT32(200, t->syn_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_block_expiry_with_batch_unblock) {
    /* Test batch unblocking of multiple expired IPs */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint64_t now = get_monotonic_ns();

    /* Block 10 IPs with various expiry times */
    for (int i = 0; i < 10; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "203.0.113.%d", i + 1);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->blocked = 1;

        /* First 5 expire soon, last 5 expire later */
        if (i < 5) {
            t->block_expiry_ns = now + sec_to_ns(30);
        } else {
            t->block_expiry_ns = now + sec_to_ns(300);
        }
    }

    /* All 10 should be blocked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(10, blocked_count);

    /* Check expiry at 60 seconds */
    uint64_t check_time = now + sec_to_ns(60);
    uint32_t expired_ips[20];
    size_t expired_count = tracker_get_expired_blocks(tracker, check_time, expired_ips, 20);

    TEST_ASSERT_EQUAL_UINT32(5, expired_count);

    /* Batch unblock expired IPs */
    for (size_t i = 0; i < expired_count; i++) {
        ip_tracker_t *t = tracker_get(tracker, expired_ips[i]);
        if (t) {
            t->blocked = 0;
        }
    }

    /* Should have 5 still blocked */
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(5, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_permanent_vs_temporary_blocks) {
    /* Test concept of permanent vs temporary blocks (via very long duration) */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint64_t now = get_monotonic_ns();

    /* Temporary block (5 minutes) */
    uint32_t temp_ip = inet_addr("203.0.113.1");
    ip_tracker_t *t1 = tracker_get_or_create(tracker, temp_ip);
    t1->blocked = 1;
    t1->block_expiry_ns = now + sec_to_ns(300);

    /* "Permanent" block (24 hours) */
    uint32_t perm_ip = inet_addr("203.0.113.2");
    ip_tracker_t *t2 = tracker_get_or_create(tracker, perm_ip);
    t2->blocked = 1;
    t2->block_expiry_ns = now + sec_to_ns(86400);

    /* Check at 10 minutes */
    uint64_t check_time = now + sec_to_ns(600);
    uint32_t expired_ips[10];
    size_t expired_count = tracker_get_expired_blocks(tracker, check_time, expired_ips, 10);

    /* Only temporary block should be expired */
    TEST_ASSERT_EQUAL_UINT32(1, expired_count);
    TEST_ASSERT_EQUAL_UINT32(temp_ip, expired_ips[0]);

    tracker_destroy(tracker);
}

TEST_CASE(test_block_with_whitelist_override) {
    /* Test that whitelisting can override an active block */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    uint32_t ip = inet_addr("10.5.5.5");
    uint64_t now = get_monotonic_ns();

    /* Block the IP */
    ip_tracker_t *t = tracker_get_or_create(tracker, ip);
    t->window_start_ns = now;
    t->syn_count = 200;
    t->blocked = 1;
    t->block_expiry_ns = now + sec_to_ns(300);

    TEST_ASSERT_TRUE(t->blocked);

    /* Admin adds IP to whitelist */
    whitelist_add(&whitelist, "10.5.5.5/32");

    /* In real system, we'd check whitelist and unblock */
    if (whitelist_check(whitelist, ip)) {
        t->blocked = 0;
        /* Could also remove from tracker entirely */
    }

    TEST_ASSERT_FALSE(t->blocked);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_concurrent_blocks_and_unblocks) {
    /* Test scenario where some IPs are being blocked while others are being unblocked */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint64_t now = get_monotonic_ns();
    uint32_t syn_threshold = 100;

    /* Scenario: 5 IPs already blocked and expiring */
    for (int i = 0; i < 5; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "203.0.113.%d", i + 1);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->blocked = 1;
        t->block_expiry_ns = now - sec_to_ns(10);  /* Already expired */
    }

    /* New attacks from 5 different IPs */
    for (int i = 5; i < 10; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "203.0.113.%d", i + 1);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        t->window_start_ns = now;
        t->syn_count = syn_threshold + 50;
        t->blocked = 1;
        t->block_expiry_ns = now + sec_to_ns(300);
    }

    /* Should have 10 tracked, all blocked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(10, entry_count);
    TEST_ASSERT_EQUAL_UINT32(10, blocked_count);

    /* Get expired blocks */
    uint32_t expired_ips[10];
    size_t expired_count = tracker_get_expired_blocks(tracker, now, expired_ips, 10);
    TEST_ASSERT_EQUAL_UINT32(5, expired_count);

    /* Unblock expired */
    for (size_t i = 0; i < expired_count; i++) {
        ip_tracker_t *t = tracker_get(tracker, expired_ips[i]);
        if (t) {
            t->blocked = 0;
        }
    }

    /* Should have 5 blocked, 5 unblocked */
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(10, entry_count);
    TEST_ASSERT_EQUAL_UINT32(5, blocked_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_false_positive_correction) {
    /* Test correcting a false positive block */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint32_t ip = inet_addr("192.168.1.100");
    uint64_t now = get_monotonic_ns();

    /* IP was incorrectly blocked (false positive) */
    ip_tracker_t *t = tracker_get_or_create(tracker, ip);
    t->window_start_ns = now;
    t->syn_count = 150;
    t->blocked = 1;
    t->block_expiry_ns = now + sec_to_ns(300);

    TEST_ASSERT_TRUE(t->blocked);

    /* Admin investigates and determines it was legitimate traffic */
    /* Manually unblock before expiry */
    t->blocked = 0;
    t->syn_count = 0;  /* Reset counter */

    TEST_ASSERT_FALSE(t->blocked);

    /* Could also remove from tracker entirely */
    tracker_remove(tracker, ip);
    TEST_ASSERT_NULL(tracker_get(tracker, ip));

    tracker_destroy(tracker);
}

TEST_CASE(test_progressive_blocking) {
    /* Test progressive blocking: escalating block durations for repeat offenders */

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint32_t ip = inet_addr("203.0.113.100");

    uint64_t time = get_monotonic_ns();

    /* First offense - short block */
    ip_tracker_t *t = tracker_get_or_create(tracker, ip);
    t->window_start_ns = time;
    t->syn_count = 150;
    t->blocked = 1;
    t->block_expiry_ns = time + sec_to_ns(60);  /* 1 minute */
    uint32_t block_count = 1;

    TEST_ASSERT_TRUE(t->blocked);

    /* Unblock after expiry */
    time += sec_to_ns(70);
    t->blocked = 0;
    t->syn_count = 0;

    /* Second offense - longer block */
    t->window_start_ns = time;
    t->syn_count = 200;
    t->blocked = 1;
    t->block_expiry_ns = time + sec_to_ns(300);  /* 5 minutes */
    block_count++;

    /* Unblock after expiry */
    time += sec_to_ns(310);
    t->blocked = 0;
    t->syn_count = 0;

    /* Third offense - much longer block */
    t->window_start_ns = time;
    t->syn_count = 250;
    t->blocked = 1;
    t->block_expiry_ns = time + sec_to_ns(3600);  /* 1 hour */
    block_count++;

    TEST_ASSERT_EQUAL_UINT32(3, block_count);
    TEST_ASSERT_TRUE(t->blocked);

    tracker_destroy(tracker);
}

int main(void) {
    UnityBegin("test_blocking_scenarios.c");

    RUN_TEST(test_single_attacker_full_cycle);
    RUN_TEST(test_multiple_attackers_different_timing);
    RUN_TEST(test_reblock_after_expiry);
    RUN_TEST(test_block_expiry_with_batch_unblock);
    RUN_TEST(test_permanent_vs_temporary_blocks);
    RUN_TEST(test_block_with_whitelist_override);
    RUN_TEST(test_concurrent_blocks_and_unblocks);
    RUN_TEST(test_false_positive_correction);
    RUN_TEST(test_progressive_blocking);

    return UnityEnd();
}

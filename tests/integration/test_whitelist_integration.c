/*
 * test_whitelist_integration.c - Integration tests for whitelist with tracker and detection
 *
 * Tests whitelist functionality in conjunction with IP tracking and detection logic.
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/whitelist.h"
#include "../../src/analysis/tracker.h"
#include "../../src/observe/logger.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

TEST_CASE(test_whitelist_prevents_tracking) {
    /* Test that whitelisted IPs are not tracked even with suspicious activity */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    /* Add some whitelisted ranges */
    whitelist_add(&whitelist, "10.0.0.0/8");
    whitelist_add(&whitelist, "192.168.0.0/16");

    /* Simulate traffic from whitelisted IP */
    uint32_t trusted_ip = inet_addr("10.1.2.3");
    TEST_ASSERT_TRUE(whitelist_check(whitelist, trusted_ip));

    /* In real system, whitelisted IPs would not be tracked */
    /* Here we verify the whitelist check works */
    if (!whitelist_check(whitelist, trusted_ip)) {
        tracker_get_or_create(tracker, trusted_ip);
    }

    /* Trusted IP should not be in tracker */
    TEST_ASSERT_NULL(tracker_get(tracker, trusted_ip));

    /* Simulate traffic from non-whitelisted IP */
    uint32_t suspicious_ip = inet_addr("203.0.113.100");
    TEST_ASSERT_FALSE(whitelist_check(whitelist, suspicious_ip));

    if (!whitelist_check(whitelist, suspicious_ip)) {
        tracker_get_or_create(tracker, suspicious_ip);
    }

    /* Suspicious IP should be in tracker */
    TEST_ASSERT_NOT_NULL(tracker_get(tracker, suspicious_ip));

    /* Verify statistics */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(1, entry_count);  /* Only suspicious IP */

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_with_overlapping_ranges) {
    /* Test whitelist with overlapping CIDR ranges and tracker integration */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    /* Add overlapping ranges */
    whitelist_add(&whitelist, "192.168.0.0/16");   /* Larger range */
    whitelist_add(&whitelist, "192.168.1.0/24");   /* Subset */
    whitelist_add(&whitelist, "192.168.1.100/32"); /* Single IP */

    /* All three should match */
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("192.168.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("192.168.1.100")));

    /* Simulate traffic from various IPs */
    uint32_t ips[] = {
        inet_addr("192.168.0.1"),    /* Whitelisted */
        inet_addr("192.168.1.100"),  /* Whitelisted */
        inet_addr("203.0.113.1"),    /* Not whitelisted */
        inet_addr("203.0.113.2"),    /* Not whitelisted */
    };

    for (int i = 0; i < 4; i++) {
        if (!whitelist_check(whitelist, ips[i])) {
            tracker_get_or_create(tracker, ips[i]);
        }
    }

    /* Only non-whitelisted IPs should be tracked */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(2, entry_count);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_edge_boundaries) {
    /* Test whitelist boundary conditions with tracker */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    /* Whitelist 192.168.1.0/24 (192.168.1.0 - 192.168.1.255) */
    whitelist_add(&whitelist, "192.168.1.0/24");

    /* Test boundary IPs */
    uint32_t boundary_ips[] = {
        inet_addr("192.168.0.255"),  /* Just before range */
        inet_addr("192.168.1.0"),    /* First in range */
        inet_addr("192.168.1.128"),  /* Middle of range */
        inet_addr("192.168.1.255"),  /* Last in range */
        inet_addr("192.168.2.0"),    /* Just after range */
    };

    bool expected[] = { false, true, true, true, false };

    for (int i = 0; i < 5; i++) {
        bool is_whitelisted = whitelist_check(whitelist, boundary_ips[i]);
        TEST_ASSERT_EQUAL(expected[i], is_whitelisted);

        /* Track non-whitelisted */
        if (!is_whitelisted) {
            tracker_get_or_create(tracker, boundary_ips[i]);
        }
    }

    /* Should have tracked 2 IPs (before and after range) */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(2, entry_count);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_dynamic_updates) {
    /* Test adding/removing whitelist entries while tracker is active */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    uint32_t test_ip = inet_addr("10.5.5.5");

    /* Initially not whitelisted - should be tracked */
    TEST_ASSERT_FALSE(whitelist_check(whitelist, test_ip));
    if (!whitelist_check(whitelist, test_ip)) {
        tracker_get_or_create(tracker, test_ip);
    }
    TEST_ASSERT_NOT_NULL(tracker_get(tracker, test_ip));

    /* Add to whitelist */
    whitelist_add(&whitelist, "10.0.0.0/8");
    TEST_ASSERT_TRUE(whitelist_check(whitelist, test_ip));

    /* In real system, we might want to remove from tracker when whitelisted */
    if (whitelist_check(whitelist, test_ip)) {
        tracker_remove(tracker, test_ip);
    }
    TEST_ASSERT_NULL(tracker_get(tracker, test_ip));

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_with_attack_simulation) {
    /* Simulate an attack where some IPs are whitelisted */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    /* Whitelist internal networks */
    whitelist_add(&whitelist, "10.0.0.0/8");
    whitelist_add(&whitelist, "192.168.0.0/16");

    uint64_t now = get_monotonic_ns();
    uint32_t syn_threshold = 100;

    /* Simulate attack from multiple sources - some whitelisted, some not */
    struct {
        const char *ip;
        uint32_t syn_count;
        bool should_be_tracked;
    } sources[] = {
        { "10.1.1.1", 500, false },       /* Whitelisted - high traffic OK */
        { "192.168.1.1", 1000, false },   /* Whitelisted - high traffic OK */
        { "203.0.113.1", 200, true },     /* Attacker */
        { "203.0.113.2", 150, true },     /* Attacker */
        { "203.0.113.3", 50, true },      /* Suspicious but below threshold */
    };

    for (int i = 0; i < 5; i++) {
        uint32_t ip = inet_addr(sources[i].ip);

        if (!whitelist_check(whitelist, ip)) {
            ip_tracker_t *t = tracker_get_or_create(tracker, ip);
            t->window_start_ns = now;
            t->syn_count = sources[i].syn_count;

            if (t->syn_count > syn_threshold) {
                t->blocked = 1;
                t->block_expiry_ns = now + sec_to_ns(300);
            }
        }

        /* Verify tracking status */
        ip_tracker_t *t = tracker_get(tracker, ip);
        if (sources[i].should_be_tracked) {
            TEST_ASSERT_NOT_NULL(t);
        } else {
            TEST_ASSERT_NULL(t);
        }
    }

    /* Verify statistics */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(3, entry_count);  /* 3 non-whitelisted IPs */
    TEST_ASSERT_EQUAL_UINT32(2, blocked_count); /* 2 over threshold */

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_localhost_and_special) {
    /* Test that localhost and special addresses can be whitelisted */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    /* Whitelist localhost and link-local */
    whitelist_add(&whitelist, "127.0.0.0/8");
    whitelist_add(&whitelist, "169.254.0.0/16");

    /* Test special addresses */
    uint32_t special_ips[] = {
        inet_addr("127.0.0.1"),      /* Localhost */
        inet_addr("127.0.1.1"),      /* Localhost range */
        inet_addr("169.254.1.1"),    /* Link-local */
    };

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_TRUE(whitelist_check(whitelist, special_ips[i]));

        /* Should not be tracked */
        if (!whitelist_check(whitelist, special_ips[i])) {
            tracker_get_or_create(tracker, special_ips[i]);
        }
        TEST_ASSERT_NULL(tracker_get(tracker, special_ips[i]));
    }

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_large_scale) {
    /* Test whitelist performance with many ranges and many IPs */

    tracker_table_t *tracker = tracker_create(1024, 10000);
    whitelist_node_t *whitelist = NULL;

    /* Add multiple whitelisted ranges */
    whitelist_add(&whitelist, "10.0.0.0/8");
    whitelist_add(&whitelist, "172.16.0.0/12");
    whitelist_add(&whitelist, "192.168.0.0/16");
    whitelist_add(&whitelist, "100.64.0.0/10");

    /* Simulate traffic from 1000 IPs */
    int whitelisted_count = 0;
    int tracked_count = 0;

    for (int i = 0; i < 1000; i++) {
        char ip_str[16];

        /* Mix of whitelisted and non-whitelisted */
        if (i < 250) {
            snprintf(ip_str, sizeof(ip_str), "10.0.%d.%d", i / 256, i % 256);
        } else if (i < 500) {
            snprintf(ip_str, sizeof(ip_str), "192.168.%d.%d", (i - 250) / 256, (i - 250) % 256);
        } else {
            snprintf(ip_str, sizeof(ip_str), "203.0.%d.%d", (i - 500) / 256, (i - 500) % 256);
        }

        uint32_t ip = inet_addr(ip_str);

        if (whitelist_check(whitelist, ip)) {
            whitelisted_count++;
        } else {
            tracker_get_or_create(tracker, ip);
            tracked_count++;
        }
    }

    /* Verify counts */
    TEST_ASSERT_EQUAL_INT(500, whitelisted_count);  /* First 500 whitelisted */
    TEST_ASSERT_EQUAL_INT(500, tracked_count);      /* Last 500 tracked */

    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(500, entry_count);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

TEST_CASE(test_whitelist_unblock_previously_blocked) {
    /* Test that adding an IP to whitelist can conceptually unblock it */

    tracker_table_t *tracker = tracker_create(256, 1000);
    whitelist_node_t *whitelist = NULL;

    uint32_t ip = inet_addr("10.5.5.5");
    uint64_t now = get_monotonic_ns();

    /* Initially not whitelisted - detect attack and block */
    ip_tracker_t *t = tracker_get_or_create(tracker, ip);
    t->window_start_ns = now;
    t->syn_count = 200;
    t->blocked = 1;
    t->block_expiry_ns = now + sec_to_ns(300);

    TEST_ASSERT_TRUE(t->blocked);

    /* Admin adds IP to whitelist */
    whitelist_add(&whitelist, "10.5.5.5/32");
    TEST_ASSERT_TRUE(whitelist_check(whitelist, ip));

    /* In real system, we'd remove from tracker or unblock */
    if (whitelist_check(whitelist, ip) && t->blocked) {
        t->blocked = 0;  /* Unblock */
    }

    TEST_ASSERT_FALSE(t->blocked);

    tracker_destroy(tracker);
    whitelist_free(whitelist);
}

int main(void) {
    UnityBegin("test_whitelist_integration.c");

    RUN_TEST(test_whitelist_prevents_tracking);
    RUN_TEST(test_whitelist_with_overlapping_ranges);
    RUN_TEST(test_whitelist_edge_boundaries);
    RUN_TEST(test_whitelist_dynamic_updates);
    RUN_TEST(test_whitelist_with_attack_simulation);
    RUN_TEST(test_whitelist_localhost_and_special);
    RUN_TEST(test_whitelist_large_scale);
    RUN_TEST(test_whitelist_unblock_previously_blocked);

    return UnityEnd();
}

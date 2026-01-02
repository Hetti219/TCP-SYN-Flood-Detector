/*
 * test_tracker.c - Unit tests for IP tracker module
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/tracker.h"
#include <arpa/inet.h>

TEST_CASE(test_tracker_create_destroy) {
    tracker_table_t *table = tracker_create(1024, 10000);

    TEST_ASSERT_NOT_NULL(table);

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);

    TEST_ASSERT_EQUAL_INT(0, entry_count);
    TEST_ASSERT_EQUAL_INT(0, blocked_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_get_or_create) {
    tracker_table_t *table = tracker_create(1024, 10000);
    uint32_t ip = inet_addr("192.168.1.100");

    /* First call should create */
    ip_tracker_t *tracker1 = tracker_get_or_create(table, ip);
    TEST_ASSERT_NOT_NULL(tracker1);
    TEST_ASSERT_EQUAL_UINT32(ip, tracker1->ip_addr);

    /* Second call should return same tracker */
    ip_tracker_t *tracker2 = tracker_get_or_create(table, ip);
    TEST_ASSERT_EQUAL(tracker1, tracker2);

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(1, entry_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_multiple_ips) {
    tracker_table_t *table = tracker_create(1024, 10000);

    /* Track multiple different IPs */
    ip_tracker_t *t1 = tracker_get_or_create(table, inet_addr("192.168.1.1"));
    ip_tracker_t *t2 = tracker_get_or_create(table, inet_addr("192.168.1.2"));
    ip_tracker_t *t3 = tracker_get_or_create(table, inet_addr("10.0.0.1"));

    TEST_ASSERT_NOT_NULL(t1);
    TEST_ASSERT_NOT_NULL(t2);
    TEST_ASSERT_NOT_NULL(t3);

    /* All should be different */
    TEST_ASSERT_NOT_EQUAL(t1, t2);
    TEST_ASSERT_NOT_EQUAL(t2, t3);
    TEST_ASSERT_NOT_EQUAL(t1, t3);

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(3, entry_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_get_existing) {
    tracker_table_t *table = tracker_create(1024, 10000);
    uint32_t ip = inet_addr("192.168.1.100");

    /* Should return NULL for non-existent IP */
    TEST_ASSERT_NULL(tracker_get(table, ip));

    /* Create the tracker */
    tracker_get_or_create(table, ip);

    /* Now should return the tracker */
    ip_tracker_t *tracker = tracker_get(table, ip);
    TEST_ASSERT_NOT_NULL(tracker);
    TEST_ASSERT_EQUAL_UINT32(ip, tracker->ip_addr);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_remove) {
    tracker_table_t *table = tracker_create(1024, 10000);
    uint32_t ip = inet_addr("192.168.1.100");

    /* Create tracker */
    tracker_get_or_create(table, ip);

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(1, entry_count);

    /* Remove it */
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, tracker_remove(table, ip));

    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(0, entry_count);

    /* Removing again should return not found */
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_ENOTFOUND, tracker_remove(table, ip));

    tracker_destroy(table);
}

TEST_CASE(test_tracker_syn_count) {
    tracker_table_t *table = tracker_create(1024, 10000);
    uint32_t ip = inet_addr("192.168.1.100");

    ip_tracker_t *tracker = tracker_get_or_create(table, ip);

    /* Initial syn_count should be 0 */
    TEST_ASSERT_EQUAL_UINT32(0, tracker->syn_count);

    /* Increment syn count */
    tracker->syn_count = 50;
    TEST_ASSERT_EQUAL_UINT32(50, tracker->syn_count);

    /* Get again and verify */
    ip_tracker_t *tracker2 = tracker_get(table, ip);
    TEST_ASSERT_EQUAL_UINT32(50, tracker2->syn_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_blocked_flag) {
    tracker_table_t *table = tracker_create(1024, 10000);
    uint32_t ip = inet_addr("192.168.1.100");

    ip_tracker_t *tracker = tracker_get_or_create(table, ip);

    /* Initially not blocked */
    TEST_ASSERT_EQUAL_INT(0, tracker->blocked);

    /* Mark as blocked */
    tracker->blocked = 1;
    tracker->block_expiry_ns = get_monotonic_ns() + sec_to_ns(300);

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(1, blocked_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_clear) {
    tracker_table_t *table = tracker_create(1024, 10000);

    /* Add multiple entries */
    tracker_get_or_create(table, inet_addr("192.168.1.1"));
    tracker_get_or_create(table, inet_addr("192.168.1.2"));
    tracker_get_or_create(table, inet_addr("192.168.1.3"));

    size_t entry_count, blocked_count;
    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(3, entry_count);

    /* Clear all */
    tracker_clear(table);

    tracker_get_stats(table, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_INT(0, entry_count);

    tracker_destroy(table);
}

TEST_CASE(test_tracker_expired_blocks) {
    tracker_table_t *table = tracker_create(1024, 10000);

    /* Create some blocked IPs with expiry times */
    uint32_t ip1 = inet_addr("192.168.1.1");
    uint32_t ip2 = inet_addr("192.168.1.2");
    uint32_t ip3 = inet_addr("192.168.1.3");

    uint64_t now = get_monotonic_ns();

    ip_tracker_t *t1 = tracker_get_or_create(table, ip1);
    t1->blocked = 1;
    t1->block_expiry_ns = now - sec_to_ns(1);  /* Expired 1 second ago */

    ip_tracker_t *t2 = tracker_get_or_create(table, ip2);
    t2->blocked = 1;
    t2->block_expiry_ns = now + sec_to_ns(300);  /* Expires in 5 minutes */

    ip_tracker_t *t3 = tracker_get_or_create(table, ip3);
    t3->blocked = 1;
    t3->block_expiry_ns = now - sec_to_ns(10);  /* Expired 10 seconds ago */

    /* Get expired blocks */
    uint32_t expired_ips[10];
    size_t count = tracker_get_expired_blocks(table, now, expired_ips, 10);

    /* Should find 2 expired blocks (ip1 and ip3) */
    TEST_ASSERT_EQUAL_INT(2, count);

    tracker_destroy(table);
}

int main(void) {
    UnityBegin("test_tracker.c");

    RUN_TEST(test_tracker_create_destroy);
    RUN_TEST(test_tracker_get_or_create);
    RUN_TEST(test_tracker_multiple_ips);
    RUN_TEST(test_tracker_get_existing);
    RUN_TEST(test_tracker_remove);
    RUN_TEST(test_tracker_syn_count);
    RUN_TEST(test_tracker_blocked_flag);
    RUN_TEST(test_tracker_clear);
    RUN_TEST(test_tracker_expired_blocks);

    return UnityEnd();
}

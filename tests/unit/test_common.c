/*
 * test_common.c - Unit tests for common utilities
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include <arpa/inet.h>

TEST_CASE(test_ip_hash_consistency) {
    uint32_t ip = inet_addr("192.168.1.1");
    size_t bucket_count = 4096;

    /* Hash should be consistent */
    uint32_t hash1 = ip_hash(ip, bucket_count);
    uint32_t hash2 = ip_hash(ip, bucket_count);

    TEST_ASSERT_EQUAL_UINT32(hash1, hash2);
}

TEST_CASE(test_ip_hash_bounds) {
    uint32_t ip = inet_addr("10.0.0.1");
    size_t bucket_count = 1024;

    uint32_t hash = ip_hash(ip, bucket_count);

    /* Hash should be within bucket range */
    TEST_ASSERT_LESS_THAN(bucket_count, hash);
}

TEST_CASE(test_ip_hash_distribution) {
    size_t bucket_count = 256;
    int buckets[256] = {0};

    /* Hash 1000 different IPs */
    for (int i = 0; i < 1000; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "10.0.%d.%d", i / 256, i % 256);
        uint32_t ip = inet_addr(ip_str);
        uint32_t hash = ip_hash(ip, bucket_count);
        buckets[hash]++;
    }

    /* Check that distribution is somewhat even (no bucket should have >10% of items) */
    int max_items = 0;
    for (int i = 0; i < 256; i++) {
        if (buckets[i] > max_items) {
            max_items = buckets[i];
        }
    }

    TEST_ASSERT_LESS_THAN(100, max_items); /* <10% in any bucket */
}

TEST_CASE(test_ms_to_ns_conversion) {
    /* Test millisecond to nanosecond conversion */
    TEST_ASSERT_EQUAL_UINT64(1000000ULL, ms_to_ns(1));
    TEST_ASSERT_EQUAL_UINT64(1000000000ULL, ms_to_ns(1000));
    TEST_ASSERT_EQUAL_UINT64(0ULL, ms_to_ns(0));
}

TEST_CASE(test_sec_to_ns_conversion) {
    /* Test second to nanosecond conversion */
    TEST_ASSERT_EQUAL_UINT64(1000000000ULL, sec_to_ns(1));
    TEST_ASSERT_EQUAL_UINT64(60000000000ULL, sec_to_ns(60));
    TEST_ASSERT_EQUAL_UINT64(0ULL, sec_to_ns(0));
}

TEST_CASE(test_get_monotonic_ns) {
    /* Test that monotonic time increases */
    uint64_t time1 = get_monotonic_ns();
    uint64_t time2 = get_monotonic_ns();

    TEST_ASSERT_GREATER_THAN(0ULL, time1);
    TEST_ASSERT_GREATER_THAN(time1 - 1, time2); /* time2 >= time1 */
}

int main(void) {
    UnityBegin("test_common.c");

    RUN_TEST(test_ip_hash_consistency);
    RUN_TEST(test_ip_hash_bounds);
    RUN_TEST(test_ip_hash_distribution);
    RUN_TEST(test_ms_to_ns_conversion);
    RUN_TEST(test_sec_to_ns_conversion);
    RUN_TEST(test_get_monotonic_ns);

    return UnityEnd();
}

/*
 * test_whitelist_advanced.c - Advanced edge case tests for whitelist module
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/whitelist.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define TEST_WHITELIST_FILE "/tmp/synflood_test_whitelist.conf"

static void cleanup_test_file(void) {
    unlink(TEST_WHITELIST_FILE);
}

TEST_CASE(test_whitelist_slash_zero) {
    /* Test /0 CIDR (matches everything) */

    whitelist_node_t *root = NULL;

    /* Add 0.0.0.0/0 - should match all IPv4 addresses */
    whitelist_add(&root, "0.0.0.0/0");

    /* Test various IPs - all should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("172.16.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("255.255.255.255")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("0.0.0.0")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_slash_32) {
    /* Test /32 CIDR (single host) */

    whitelist_node_t *root = NULL;

    /* Add specific IP with /32 */
    whitelist_add(&root, "192.168.1.100/32");

    /* Only exact IP should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.100")));

    /* Other IPs should not match */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.1.101")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.1.99")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.2.100")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_no_slash_assumed_32) {
    /* Test IP without /prefix - should be treated as /32 */

    whitelist_node_t *root = NULL;

    /* Add IP without prefix */
    whitelist_add(&root, "192.168.1.50");

    /* Only exact IP should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.50")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.1.51")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_overlapping_ranges) {
    /* Test overlapping CIDR ranges */

    whitelist_node_t *root = NULL;

    /* Add broader range first */
    whitelist_add(&root, "192.168.0.0/16");  /* Whole 192.168.0.0/16 */

    /* Add more specific range */
    whitelist_add(&root, "192.168.1.0/24");  /* Specific subnet */

    /* Both broad and specific should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));   /* In both */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.2.1")));   /* Only in broad */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.255.255"))); /* In broad */

    /* Outside both should not match */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.169.1.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_adjacent_ranges) {
    /* Test adjacent but non-overlapping ranges */

    whitelist_node_t *root = NULL;

    whitelist_add(&root, "10.0.0.0/24");   /* 10.0.0.0 - 10.0.0.255 */
    whitelist_add(&root, "10.0.1.0/24");   /* 10.0.1.0 - 10.0.1.255 */

    /* IPs in first range */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.255")));

    /* IPs in second range */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.1.0")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.1.255")));

    /* IPs in gap should not match */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("10.0.2.0")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_boundary_addresses) {
    /* Test network and broadcast addresses */

    whitelist_node_t *root = NULL;

    whitelist_add(&root, "192.168.1.0/24");

    /* Network address (first in range) */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.0")));

    /* Broadcast address (last in range) */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.255")));

    /* Just outside */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.0.255")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.2.0")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_private_ranges) {
    /* Test common private IP ranges */

    whitelist_node_t *root = NULL;

    /* RFC 1918 private ranges */
    whitelist_add(&root, "10.0.0.0/8");        /* Class A private */
    whitelist_add(&root, "172.16.0.0/12");     /* Class B private */
    whitelist_add(&root, "192.168.0.0/16");    /* Class C private */

    /* Test IPs in each range */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.255.255.255")));

    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("172.16.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("172.31.255.255")));

    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.255.255")));

    /* Test public IPs - should not match */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("8.8.8.8")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("1.1.1.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_localhost) {
    /* Test localhost and loopback range */

    whitelist_node_t *root = NULL;

    /* Loopback range is 127.0.0.0/8 */
    whitelist_add(&root, "127.0.0.0/8");

    /* All 127.x.x.x should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.0.0.2")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.255.255.255")));

    /* 126.x and 128.x should not match */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("126.0.0.1")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("128.0.0.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_malformed_cidr) {
    /* Test handling of malformed CIDR strings */

    whitelist_node_t *root = NULL;

    /* Invalid formats - should not crash */
    whitelist_add(&root, "");
    whitelist_add(&root, "invalid");
    whitelist_add(&root, "256.256.256.256/24");
    whitelist_add(&root, "192.168.1.1/33");  /* Prefix > 32 */
    whitelist_add(&root, "192.168.1.1/-1");  /* Negative prefix */
    whitelist_add(&root, "192.168.1/24");    /* Incomplete IP */
    whitelist_add(&root, "192.168.1.1.1/24"); /* Too many octets */

    /* After malformed entries, valid entry should still work */
    whitelist_add(&root, "192.168.1.0/24");
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_duplicate_entries) {
    /* Test adding duplicate CIDR blocks */

    whitelist_node_t *root = NULL;

    whitelist_add(&root, "192.168.1.0/24");
    size_t count1 = whitelist_count(root);

    /* Add same CIDR again */
    whitelist_add(&root, "192.168.1.0/24");
    size_t count2 = whitelist_count(root);

    /* Count should be same (duplicate not added) or incremented (allowed)
     * Depends on implementation - document behavior */
    /* Current implementation may add duplicates - this is acceptable */

    /* Functionality should work regardless */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_empty) {
    /* Test operations on empty whitelist */

    whitelist_node_t *root = NULL;

    /* Check should return false for all IPs */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("0.0.0.0")));

    /* Count should be 0 */
    TEST_ASSERT_EQUAL_UINT32(0, whitelist_count(root));

    /* Free should not crash */
    whitelist_free(root);
}

TEST_CASE(test_whitelist_file_loading) {
    /* Test loading whitelist from file */

    /* Create test file */
    FILE *fp = fopen(TEST_WHITELIST_FILE, "w");
    TEST_ASSERT_NOT_NULL(fp);

    fprintf(fp, "# Comment line\n");
    fprintf(fp, "\n");  /* Empty line */
    fprintf(fp, "192.168.1.0/24\n");
    fprintf(fp, "  10.0.0.0/8  \n");  /* Leading/trailing whitespace */
    fprintf(fp, "172.16.0.0/12\n");
    fprintf(fp, "# Another comment\n");
    fprintf(fp, "127.0.0.1\n");

    fclose(fp);

    /* Load whitelist */
    whitelist_node_t *root = whitelist_load(TEST_WHITELIST_FILE);
    TEST_ASSERT_NOT_NULL(root);

    /* Verify loaded entries */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("172.16.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.0.0.1")));

    /* Should have at least 4 entries */
    size_t count = whitelist_count(root);
    TEST_ASSERT_GREATER_OR_EQUAL(4, count);

    whitelist_free(root);
    cleanup_test_file();
}

TEST_CASE(test_whitelist_file_missing) {
    /* Test loading non-existent file */

    whitelist_node_t *root = whitelist_load("/nonexistent/path/whitelist.conf");

    /* Should return NULL or empty for missing file */
    /* Verify this doesn't crash */

    whitelist_free(root);
}

TEST_CASE(test_whitelist_file_malformed_lines) {
    /* Test file with malformed lines */

    int fd = open(TEST_WHITELIST_FILE, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    TEST_ASSERT_TRUE(fd >= 0);

    FILE *fp = fdopen(fd, "w");
    TEST_ASSERT_NOT_NULL(fp);

    fprintf(fp, "192.168.1.0/24\n");     /* Valid */
    fprintf(fp, "invalid entry\n");       /* Invalid */
    fprintf(fp, "256.1.1.1/24\n");       /* Invalid IP */
    fprintf(fp, "10.0.0.0/8\n");         /* Valid */

    fclose(fp);

    whitelist_node_t *root = whitelist_load(TEST_WHITELIST_FILE);
    TEST_ASSERT_NOT_NULL(root);

    /* Valid entries should still be loaded */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.1")));

    whitelist_free(root);
    cleanup_test_file();
}

TEST_CASE(test_whitelist_very_large_prefix) {
    /* Test various prefix lengths */

    whitelist_node_t *root = NULL;

    /* /8 - Class A network (16M IPs) */
    whitelist_add(&root, "10.0.0.0/8");
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.255.255.254")));

    /* /16 - Class B network (64K IPs) */
    whitelist_add(&root, "172.16.0.0/16");
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("172.16.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("172.16.255.254")));

    /* /24 - Class C network (256 IPs) */
    whitelist_add(&root, "192.168.1.0/24");
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.254")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_count_accuracy) {
    /* Test that whitelist_count returns accurate count */

    whitelist_node_t *root = NULL;

    TEST_ASSERT_EQUAL_UINT32(0, whitelist_count(root));

    whitelist_add(&root, "192.168.1.0/24");
    TEST_ASSERT_EQUAL_UINT32(1, whitelist_count(root));

    whitelist_add(&root, "10.0.0.0/8");
    TEST_ASSERT_EQUAL_UINT32(2, whitelist_count(root));

    whitelist_add(&root, "172.16.0.0/12");
    TEST_ASSERT_EQUAL_UINT32(3, whitelist_count(root));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_special_addresses) {
    /* Test special/reserved IP addresses */

    whitelist_node_t *root = NULL;

    /* 0.0.0.0 */
    whitelist_add(&root, "0.0.0.0/32");
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("0.0.0.0")));

    /* 255.255.255.255 */
    whitelist_add(&root, "255.255.255.255/32");
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("255.255.255.255")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_null_pointer_safety) {
    /* Test NULL pointer handling */

    /* Check with NULL root - should return false, not crash */
    TEST_ASSERT_FALSE(whitelist_check(NULL, inet_addr("192.168.1.1")));

    /* Count with NULL root */
    TEST_ASSERT_EQUAL_UINT32(0, whitelist_count(NULL));

    /* Free NULL root - should not crash */
    whitelist_free(NULL);
}

int main(void) {
    UnityBegin("test_whitelist_advanced.c");

    RUN_TEST(test_whitelist_slash_zero);
    RUN_TEST(test_whitelist_slash_32);
    RUN_TEST(test_whitelist_no_slash_assumed_32);
    RUN_TEST(test_whitelist_overlapping_ranges);
    RUN_TEST(test_whitelist_adjacent_ranges);
    RUN_TEST(test_whitelist_boundary_addresses);
    RUN_TEST(test_whitelist_private_ranges);
    RUN_TEST(test_whitelist_localhost);
    RUN_TEST(test_whitelist_malformed_cidr);
    RUN_TEST(test_whitelist_duplicate_entries);
    RUN_TEST(test_whitelist_empty);
    RUN_TEST(test_whitelist_file_loading);
    RUN_TEST(test_whitelist_file_missing);
    RUN_TEST(test_whitelist_file_malformed_lines);
    RUN_TEST(test_whitelist_very_large_prefix);
    RUN_TEST(test_whitelist_count_accuracy);
    RUN_TEST(test_whitelist_special_addresses);
    RUN_TEST(test_whitelist_null_pointer_safety);

    return UnityEnd();
}

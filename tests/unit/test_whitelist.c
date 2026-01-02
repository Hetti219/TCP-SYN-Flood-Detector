/*
 * test_whitelist.c - Unit tests for whitelist module
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/analysis/whitelist.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

static const char* test_whitelist_file = "/tmp/synflood_test_whitelist.conf";

void create_test_whitelist(void) {
    FILE* f = fopen(test_whitelist_file, "w");
    if (!f) return;

    fprintf(f, "# Test whitelist\n");
    fprintf(f, "127.0.0.0/8\n");
    fprintf(f, "10.0.0.0/8\n");
    fprintf(f, "192.168.1.0/24\n");
    fprintf(f, "8.8.8.8/32\n");

    fclose(f);
}

void cleanup_test_whitelist(void) {
    unlink(test_whitelist_file);
}

TEST_CASE(test_whitelist_add_and_check) {
    whitelist_node_t *root = NULL;

    /* Add some CIDR blocks */
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, whitelist_add(&root, "192.168.1.0/24"));
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, whitelist_add(&root, "10.0.0.0/8"));

    /* Test IPs in the whitelist */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.100")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.5.10.20")));

    /* Test IPs not in the whitelist */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.2.1")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("172.16.0.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_single_ip) {
    whitelist_node_t *root = NULL;

    /* Add single IP (/32) */
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, whitelist_add(&root, "8.8.8.8/32"));

    /* Only this specific IP should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("8.8.8.8")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("8.8.8.9")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("8.8.8.7")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_localhost) {
    whitelist_node_t *root = NULL;

    /* Add localhost range */
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, whitelist_add(&root, "127.0.0.0/8"));

    /* All 127.x.x.x should match */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.1.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.255.255.255")));

    /* But not other IPs */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("128.0.0.1")));

    whitelist_free(root);
}

TEST_CASE(test_whitelist_load_file) {
    create_test_whitelist();

    whitelist_node_t *root = whitelist_load(test_whitelist_file);
    TEST_ASSERT_NOT_NULL(root);

    /* Test IPs from the file */
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("127.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("10.5.10.20")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("192.168.1.50")));
    TEST_ASSERT_TRUE(whitelist_check(root, inet_addr("8.8.8.8")));

    /* Test IPs not in the file */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("1.2.3.4")));

    whitelist_free(root);
    cleanup_test_whitelist();
}

TEST_CASE(test_whitelist_count) {
    whitelist_node_t *root = NULL;

    TEST_ASSERT_EQUAL_INT(0, whitelist_count(root));

    whitelist_add(&root, "192.168.1.0/24");
    TEST_ASSERT_GREATER_THAN(0, whitelist_count(root));

    whitelist_add(&root, "10.0.0.0/8");
    size_t count = whitelist_count(root);
    TEST_ASSERT_GREATER_THAN(1, count);

    whitelist_free(root);
}

TEST_CASE(test_whitelist_empty) {
    whitelist_node_t *root = NULL;

    /* Empty whitelist should not match anything */
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("192.168.1.1")));
    TEST_ASSERT_FALSE(whitelist_check(root, inet_addr("10.0.0.1")));
}

int main(void) {
    UnityBegin("test_whitelist.c");

    RUN_TEST(test_whitelist_add_and_check);
    RUN_TEST(test_whitelist_single_ip);
    RUN_TEST(test_whitelist_localhost);
    RUN_TEST(test_whitelist_load_file);
    RUN_TEST(test_whitelist_count);
    RUN_TEST(test_whitelist_empty);

    return UnityEnd();
}

/*
 * test_config.c - Unit tests for configuration module
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/config/config.h"
#include <stdio.h>
#include <unistd.h>

static const char* test_config_file = "/tmp/synflood_test_config.conf";

void create_test_config(void) {
    FILE* f = fopen(test_config_file, "w");
    if (!f) return;

    fprintf(f, "detection:\n");
    fprintf(f, "{\n");
    fprintf(f, "  syn_threshold = 150;\n");
    fprintf(f, "  window_ms = 2000;\n");
    fprintf(f, "  proc_check_interval_s = 10;\n");
    fprintf(f, "};\n\n");
    fprintf(f, "enforcement:\n");
    fprintf(f, "{\n");
    fprintf(f, "  block_duration_s = 600;\n");
    fprintf(f, "  ipset_name = \"test_blacklist\";\n");
    fprintf(f, "};\n\n");
    fprintf(f, "limits:\n");
    fprintf(f, "{\n");
    fprintf(f, "  max_tracked_ips = 5000;\n");
    fprintf(f, "  hash_buckets = 2048;\n");
    fprintf(f, "};\n\n");
    fprintf(f, "logging:\n");
    fprintf(f, "{\n");
    fprintf(f, "  level = \"debug\";\n");
    fprintf(f, "  syslog = false;\n");
    fprintf(f, "};\n");

    fclose(f);
}

void cleanup_test_config(void) {
    unlink(test_config_file);
}

TEST_CASE(test_config_load_valid) {
    create_test_config();

    synflood_config_t config;
    synflood_ret_t ret = config_load(test_config_file, &config);

    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, ret);
    TEST_ASSERT_EQUAL_UINT32(150, config.syn_threshold);
    TEST_ASSERT_EQUAL_UINT32(2000, config.window_ms);
    TEST_ASSERT_EQUAL_UINT32(10, config.proc_check_interval_s);
    TEST_ASSERT_EQUAL_UINT32(600, config.block_duration_s);
    TEST_ASSERT_EQUAL_UINT32(5000, config.max_tracked_ips);
    TEST_ASSERT_EQUAL_UINT32(2048, config.hash_buckets);
    TEST_ASSERT_EQUAL_STRING("test_blacklist", config.ipset_name);
    TEST_ASSERT_EQUAL_INT(LOG_LEVEL_DEBUG, config.log_level);
    TEST_ASSERT_FALSE(config.use_syslog);

    cleanup_test_config();
}

TEST_CASE(test_config_load_defaults) {
    synflood_config_t config;
    /* Load with non-existent file to get defaults */
    (void)config_load("/tmp/nonexistent_file.conf", &config);

    /* Should use defaults even if file doesn't exist */
    TEST_ASSERT_EQUAL_UINT32(DEFAULT_SYN_THRESHOLD, config.syn_threshold);
    TEST_ASSERT_EQUAL_UINT32(DEFAULT_WINDOW_MS, config.window_ms);
    TEST_ASSERT_EQUAL_UINT32(DEFAULT_BLOCK_DURATION_S, config.block_duration_s);
}

TEST_CASE(test_config_validate_valid) {
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .block_duration_s = 300,
        .proc_check_interval_s = 5,
        .max_tracked_ips = 10000,
        .hash_buckets = 4096,
        .ipset_name = "test",
    };

    synflood_ret_t ret = config_validate(&config);
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_OK, ret);
}

TEST_CASE(test_config_validate_invalid_threshold) {
    synflood_config_t config = {
        .syn_threshold = 0,  /* Invalid */
        .window_ms = 1000,
        .block_duration_s = 300,
        .proc_check_interval_s = 5,
        .max_tracked_ips = 10000,
        .hash_buckets = 4096,
        .ipset_name = "test",
    };

    synflood_ret_t ret = config_validate(&config);
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_EINVAL, ret);
}

TEST_CASE(test_config_validate_invalid_hash_buckets) {
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .block_duration_s = 300,
        .proc_check_interval_s = 5,
        .max_tracked_ips = 10000,
        .hash_buckets = 4095,  /* Not power of 2 */
        .ipset_name = "test",
    };

    synflood_ret_t ret = config_validate(&config);
    TEST_ASSERT_EQUAL_INT(SYNFLOOD_EINVAL, ret);
}

TEST_CASE(test_config_parse_log_level) {
    TEST_ASSERT_EQUAL_INT(LOG_LEVEL_DEBUG, config_parse_log_level("debug"));
    TEST_ASSERT_EQUAL_INT(LOG_LEVEL_INFO, config_parse_log_level("info"));
    TEST_ASSERT_EQUAL_INT(LOG_LEVEL_WARN, config_parse_log_level("warn"));
    TEST_ASSERT_EQUAL_INT(LOG_LEVEL_ERROR, config_parse_log_level("error"));
    TEST_ASSERT_EQUAL_INT(LOG_LEVEL_INFO, config_parse_log_level("invalid"));
}

int main(void) {
    UnityBegin("test_config.c");

    RUN_TEST(test_config_load_valid);
    RUN_TEST(test_config_load_defaults);
    RUN_TEST(test_config_validate_valid);
    RUN_TEST(test_config_validate_invalid_threshold);
    RUN_TEST(test_config_validate_invalid_hash_buckets);
    RUN_TEST(test_config_parse_log_level);

    return UnityEnd();
}

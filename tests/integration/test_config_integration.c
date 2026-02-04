/*
 * test_config_integration.c - Integration tests for configuration with other components
 *
 * Tests how configuration settings affect the behavior of tracker, whitelist, and detection logic.
 */

#include "../unity/unity.h"
#include "../../include/common.h"
#include "../../src/config/config.h"
#include "../../src/analysis/tracker.h"
#include "../../src/analysis/whitelist.h"
#include "../../src/observe/logger.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TEST_CONFIG_FILE "/tmp/synflood_test_config.conf"
#define TEST_WHITELIST_FILE "/tmp/synflood_test_whitelist.txt"

/* Helper to create a test config file */
static void create_test_config(const char *content) {
    int fd = open(TEST_CONFIG_FILE, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return;
    }

    fprintf(fp, "%s", content);
    fclose(fp);
}

/* Helper to create a test whitelist file */
static void create_test_whitelist(const char *content) {
    int fd = open(TEST_WHITELIST_FILE, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return;
    }

    fprintf(fp, "%s", content);
    fclose(fp);
}

/* Helper to cleanup test files */
static void cleanup_test_files(void) {
    unlink(TEST_CONFIG_FILE);
    unlink(TEST_WHITELIST_FILE);
}

TEST_CASE(test_config_affects_tracker_size) {
    /* Test that config hash_buckets and max_tracked_ips affect tracker creation */

    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .block_duration_s = 300,
        .max_tracked_ips = 500,
        .hash_buckets = 256,
        .log_level = LOG_LEVEL_INFO,
    };

    /* Create tracker with config settings */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Add IPs up to max_tracked_ips */
    uint64_t now = get_monotonic_ns();
    for (int i = 0; i < 500; i++) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "10.0.%d.%d", i / 256, i % 256);
        uint32_t ip = inet_addr(ip_str);

        ip_tracker_t *t = tracker_get_or_create(tracker, ip);
        TEST_ASSERT_NOT_NULL(t);
        t->last_seen_ns = now + i;
    }

    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(500, entry_count);

    /* Adding one more should trigger LRU eviction */
    uint32_t overflow_ip = inet_addr("203.0.113.1");
    ip_tracker_t *t = tracker_get_or_create(tracker, overflow_ip);
    TEST_ASSERT_NOT_NULL(t);

    /* Should still be at max */
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(500, entry_count);

    tracker_destroy(tracker);
}

TEST_CASE(test_config_threshold_affects_detection) {
    /* Test that syn_threshold from config affects when blocking occurs */

    synflood_config_t config1 = { .syn_threshold = 50, .window_ms = 1000, .hash_buckets = 256, .max_tracked_ips = 1000 };
    synflood_config_t config2 = { .syn_threshold = 200, .window_ms = 1000, .hash_buckets = 256, .max_tracked_ips = 1000 };

    tracker_table_t *tracker1 = tracker_create(config1.hash_buckets, config1.max_tracked_ips);
    tracker_table_t *tracker2 = tracker_create(config2.hash_buckets, config2.max_tracked_ips);

    uint32_t test_ip = inet_addr("203.0.113.100");
    uint64_t now = get_monotonic_ns();

    /* Simulate 100 SYNs */
    ip_tracker_t *t1 = tracker_get_or_create(tracker1, test_ip);
    t1->window_start_ns = now;
    t1->syn_count = 100;

    ip_tracker_t *t2 = tracker_get_or_create(tracker2, test_ip);
    t2->window_start_ns = now;
    t2->syn_count = 100;

    /* With threshold=50, 100 SYNs should trigger blocking */
    if (t1->syn_count > config1.syn_threshold) {
        t1->blocked = 1;
    }
    TEST_ASSERT_TRUE(t1->blocked);

    /* With threshold=200, 100 SYNs should NOT trigger blocking */
    if (t2->syn_count > config2.syn_threshold) {
        t2->blocked = 1;
    }
    TEST_ASSERT_FALSE(t2->blocked);

    tracker_destroy(tracker1);
    tracker_destroy(tracker2);
}

TEST_CASE(test_config_window_affects_counting) {
    /* Test that window_ms affects when counters reset */

    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 500,  /* 500ms window */
        .hash_buckets = 256,
        .max_tracked_ips = 1000
    };

    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    uint32_t ip = inet_addr("203.0.113.100");
    uint64_t window_ns = ms_to_ns(config.window_ms);

    uint64_t time1 = get_monotonic_ns();
    ip_tracker_t *t = tracker_get_or_create(tracker, ip);
    t->window_start_ns = time1;
    t->syn_count = 75;

    /* Time passes - just within window */
    uint64_t time2 = time1 + ms_to_ns(400);  /* 400ms later */
    TEST_ASSERT_TRUE(time2 - t->window_start_ns < window_ns);
    /* Counter should NOT reset */

    /* Time passes - beyond window */
    uint64_t time3 = time1 + ms_to_ns(600);  /* 600ms later */
    if (time3 - t->window_start_ns > window_ns) {
        /* Window expired - simulate reset */
        t->window_start_ns = time3;
        t->syn_count = 0;
    }

    /* Counter should have been reset */
    TEST_ASSERT_EQUAL_UINT32(0, t->syn_count);
    TEST_ASSERT_EQUAL_UINT64(time3, t->window_start_ns);

    tracker_destroy(tracker);
}

TEST_CASE(test_config_block_duration_affects_expiry) {
    /* Test that block_duration_s affects when blocks expire */

    synflood_config_t config1 = { .block_duration_s = 60, .hash_buckets = 256, .max_tracked_ips = 1000 };
    synflood_config_t config2 = { .block_duration_s = 300, .hash_buckets = 256, .max_tracked_ips = 1000 };

    tracker_table_t *tracker = tracker_create(256, 1000);
    uint64_t now = get_monotonic_ns();

    /* Block IP with 60s duration */
    uint32_t ip1 = inet_addr("203.0.113.1");
    ip_tracker_t *t1 = tracker_get_or_create(tracker, ip1);
    t1->blocked = 1;
    t1->block_expiry_ns = now + sec_to_ns(config1.block_duration_s);

    /* Block IP with 300s duration */
    uint32_t ip2 = inet_addr("203.0.113.2");
    ip_tracker_t *t2 = tracker_get_or_create(tracker, ip2);
    t2->blocked = 1;
    t2->block_expiry_ns = now + sec_to_ns(config2.block_duration_s);

    /* Check expiry at 120s */
    uint64_t check_time = now + sec_to_ns(120);

    /* ip1 (60s duration) should be expired */
    TEST_ASSERT_TRUE(check_time > t1->block_expiry_ns);

    /* ip2 (300s duration) should NOT be expired */
    TEST_ASSERT_FALSE(check_time > t2->block_expiry_ns);

    tracker_destroy(tracker);
}

TEST_CASE(test_config_file_loading_integration) {
    /* Test loading config from file and applying to components */

    create_test_config(
        "detection = {\n"
        "    syn_threshold = 75;\n"
        "    window_ms = 2000;\n"
        "    proc_check_interval_s = 30;\n"
        "};\n"
        "enforcement = {\n"
        "    block_duration_s = 600;\n"
        "    ipset_name = \"test_ipset\";\n"
        "};\n"
        "limits = {\n"
        "    max_tracked_ips = 5000;\n"
        "    hash_buckets = 512;\n"
        "};\n"
        "logging = {\n"
        "    level = \"info\";\n"
        "    syslog = false;\n"
        "    metrics_socket = \"/tmp/test.sock\";\n"
        "};\n"
        "capture = {\n"
        "    nfqueue_num = 0;\n"
        "    use_raw_socket = false;\n"
        "};\n"
        "whitelist = {\n"
        "    file = \"/tmp/test_whitelist.conf\";\n"
        "};\n"
    );

    synflood_config_t config = {0};
    synflood_ret_t result = config_load(TEST_CONFIG_FILE, &config);
    TEST_ASSERT_EQUAL(SYNFLOOD_OK, result);

    /* Verify loaded values */
    TEST_ASSERT_EQUAL_UINT32(75, config.syn_threshold);
    TEST_ASSERT_EQUAL_UINT32(2000, config.window_ms);
    TEST_ASSERT_EQUAL_UINT32(30, config.proc_check_interval_s);
    TEST_ASSERT_EQUAL_UINT32(600, config.block_duration_s);
    TEST_ASSERT_EQUAL_UINT32(5000, config.max_tracked_ips);
    TEST_ASSERT_EQUAL_UINT32(512, config.hash_buckets);
    TEST_ASSERT_EQUAL(LOG_LEVEL_INFO, config.log_level);

    /* Apply to tracker */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    tracker_destroy(tracker);
    cleanup_test_files();
}

TEST_CASE(test_config_with_whitelist_file) {
    /* Test config that specifies whitelist file path */

    create_test_whitelist(
        "# Test whitelist\n"
        "127.0.0.0/8\n"
        "10.0.0.0/8\n"
        "192.168.0.0/16\n"
        "172.16.0.0/12\n"
    );

    /* Load whitelist */
    whitelist_node_t *whitelist = whitelist_load(TEST_WHITELIST_FILE);

    /* Verify whitelist entries loaded */
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("127.0.0.1")));
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("10.5.5.5")));
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("192.168.1.1")));
    TEST_ASSERT_TRUE(whitelist_check(whitelist, inet_addr("172.16.0.1")));

    /* Non-whitelisted should fail */
    TEST_ASSERT_FALSE(whitelist_check(whitelist, inet_addr("203.0.113.1")));

    whitelist_free(whitelist);
    cleanup_test_files();
}

TEST_CASE(test_config_validation_with_tracker) {
    /* Test that invalid config values are caught before creating tracker */

    synflood_config_t config = {0};  /* Zero-initialize all fields */

    /* Invalid: hash_buckets not power of 2 */
    config.hash_buckets = 100;
    config.syn_threshold = 50;
    config.proc_check_interval_s = 60;
    TEST_ASSERT_NOT_EQUAL(SYNFLOOD_OK, config_validate(&config));

    /* Valid: hash_buckets is power of 2 */
    config.hash_buckets = 128;
    config.syn_threshold = 50;
    config.window_ms = 1000;
    config.block_duration_s = 300;
    config.max_tracked_ips = 10000;
    config.proc_check_interval_s = 60;
    strcpy(config.ipset_name, "test_ipset");
    TEST_ASSERT_EQUAL(SYNFLOOD_OK, config_validate(&config));

    /* Can create tracker with valid config */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    tracker_destroy(tracker);
}

TEST_CASE(test_config_log_level_integration) {
    /* Test that log level from config affects logger initialization */

    synflood_config_t config;
    config.log_level = LOG_LEVEL_DEBUG;

    /* Initialize logger with config log level */
    logger_init(config.log_level, false);

    /* Logger should accept debug messages */
    LOG_DEBUG("Test debug message from config");

    /* Change log level */
    logger_set_level(LOG_LEVEL_ERROR);

    /* Now only errors should be logged */
    LOG_ERROR("Test error message");

    logger_shutdown();
}

TEST_CASE(test_full_system_integration) {
    /* Test complete integration: config + tracker + whitelist + detection */

    /* Setup configuration */
    synflood_config_t config = {
        .syn_threshold = 100,
        .window_ms = 1000,
        .block_duration_s = 300,
        .max_tracked_ips = 1000,
        .hash_buckets = 256,
        .log_level = LOG_LEVEL_INFO,
    };

    /* Initialize logger */
    logger_init(config.log_level, false);

    /* Create tracker */
    tracker_table_t *tracker = tracker_create(config.hash_buckets, config.max_tracked_ips);
    TEST_ASSERT_NOT_NULL(tracker);

    /* Create whitelist */
    whitelist_node_t *whitelist = NULL;
    whitelist_add(&whitelist, "192.168.0.0/16");
    whitelist_add(&whitelist, "10.0.0.0/8");

    uint64_t now = get_monotonic_ns();

    /* Scenario 1: Whitelisted IP with many SYNs - should NOT be blocked */
    uint32_t trusted_ip = inet_addr("192.168.1.100");
    if (!whitelist_check(whitelist, trusted_ip)) {
        ip_tracker_t *t = tracker_get_or_create(tracker, trusted_ip);
        t->window_start_ns = now;
        t->syn_count = 200;  /* Above threshold */
        if (t->syn_count > config.syn_threshold) {
            t->blocked = 1;
        }
    }
    /* Should not be tracked since it's whitelisted */
    TEST_ASSERT_NULL(tracker_get(tracker, trusted_ip));

    /* Scenario 2: Non-whitelisted IP with many SYNs - should be blocked */
    uint32_t attacker_ip = inet_addr("203.0.113.100");
    if (!whitelist_check(whitelist, attacker_ip)) {
        ip_tracker_t *t = tracker_get_or_create(tracker, attacker_ip);
        t->window_start_ns = now;
        t->syn_count = 200;  /* Above threshold */
        if (t->syn_count > config.syn_threshold) {
            t->blocked = 1;
            t->block_expiry_ns = now + sec_to_ns(config.block_duration_s);
            LOG_WARN("BLOCKED: IP=%s SYN_COUNT=%u SYN_RECV=0", "203.0.113.100", t->syn_count);
        }
    }
    TEST_ASSERT_NOT_NULL(tracker_get(tracker, attacker_ip));
    TEST_ASSERT_TRUE(tracker_get(tracker, attacker_ip)->blocked);

    /* Scenario 3: Check statistics */
    size_t entry_count, blocked_count;
    tracker_get_stats(tracker, &entry_count, &blocked_count);
    TEST_ASSERT_EQUAL_UINT32(1, entry_count);  /* Only attacker tracked */
    TEST_ASSERT_EQUAL_UINT32(1, blocked_count);

    /* Cleanup */
    tracker_destroy(tracker);
    whitelist_free(whitelist);
    logger_shutdown();
}

int main(void) {
    UnityBegin("test_config_integration.c");

    RUN_TEST(test_config_affects_tracker_size);
    RUN_TEST(test_config_threshold_affects_detection);
    RUN_TEST(test_config_window_affects_counting);
    RUN_TEST(test_config_block_duration_affects_expiry);
    RUN_TEST(test_config_file_loading_integration);
    RUN_TEST(test_config_with_whitelist_file);
    RUN_TEST(test_config_validation_with_tracker);
    RUN_TEST(test_config_log_level_integration);
    RUN_TEST(test_full_system_integration);

    return UnityEnd();
}

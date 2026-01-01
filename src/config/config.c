/*
 * config.c - Configuration file parsing implementation
 * TCP SYN Flood Detector
 */

#include "config.h"
#include <libconfig.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

log_level_t config_parse_log_level(const char *level_str) {
    if (strcmp(level_str, "debug") == 0) {
        return LOG_LEVEL_DEBUG;
    } else if (strcmp(level_str, "info") == 0) {
        return LOG_LEVEL_INFO;
    } else if (strcmp(level_str, "warn") == 0) {
        return LOG_LEVEL_WARN;
    } else if (strcmp(level_str, "error") == 0) {
        return LOG_LEVEL_ERROR;
    }
    return LOG_LEVEL_INFO; /* Default */
}

synflood_ret_t config_load(const char *path, config_t *config) {
    if (!path || !config) {
        return SYNFLOOD_EINVAL;
    }

    config_t cfg_reader;
    config_init(&cfg_reader);

    /* Set default values */
    memset(config, 0, sizeof(config_t));
    config->syn_threshold = DEFAULT_SYN_THRESHOLD;
    config->window_ms = DEFAULT_WINDOW_MS;
    config->block_duration_s = DEFAULT_BLOCK_DURATION_S;
    config->proc_check_interval_s = DEFAULT_PROC_CHECK_INTERVAL_S;
    config->max_tracked_ips = DEFAULT_MAX_TRACKED_IPS;
    config->hash_buckets = DEFAULT_HASH_BUCKETS;
    config->nfqueue_num = DEFAULT_NFQUEUE_NUM;
    config->use_raw_socket = false;
    config->log_level = LOG_LEVEL_INFO;
    config->use_syslog = true;
    strncpy(config->ipset_name, DEFAULT_IPSET_NAME, sizeof(config->ipset_name) - 1);
    strncpy(config->whitelist_file, DEFAULT_WHITELIST_PATH, sizeof(config->whitelist_file) - 1);
    strncpy(config->metrics_socket, DEFAULT_METRICS_SOCKET, sizeof(config->metrics_socket) - 1);

    /* Try to read configuration file */
    if (config_read_file(&cfg_reader, path) != CONFIG_TRUE) {
        fprintf(stderr, "Error reading config file %s:%d - %s\n",
                config_error_file(&cfg_reader),
                config_error_line(&cfg_reader),
                config_error_text(&cfg_reader));
        config_destroy(&cfg_reader);
        return SYNFLOOD_ERROR;
    }

    /* Parse detection section */
    config_setting_t *detection = config_lookup(&cfg_reader, "detection");
    if (detection) {
        int val;
        if (config_setting_lookup_int(detection, "syn_threshold", &val) == CONFIG_TRUE) {
            config->syn_threshold = (uint32_t)val;
        }
        if (config_setting_lookup_int(detection, "window_ms", &val) == CONFIG_TRUE) {
            config->window_ms = (uint32_t)val;
        }
        if (config_setting_lookup_int(detection, "proc_check_interval_s", &val) == CONFIG_TRUE) {
            config->proc_check_interval_s = (uint32_t)val;
        }
    }

    /* Parse enforcement section */
    config_setting_t *enforcement = config_lookup(&cfg_reader, "enforcement");
    if (enforcement) {
        int val;
        const char *str;
        if (config_setting_lookup_int(enforcement, "block_duration_s", &val) == CONFIG_TRUE) {
            config->block_duration_s = (uint32_t)val;
        }
        if (config_setting_lookup_string(enforcement, "ipset_name", &str) == CONFIG_TRUE) {
            strncpy(config->ipset_name, str, sizeof(config->ipset_name) - 1);
        }
    }

    /* Parse limits section */
    config_setting_t *limits = config_lookup(&cfg_reader, "limits");
    if (limits) {
        int val;
        if (config_setting_lookup_int(limits, "max_tracked_ips", &val) == CONFIG_TRUE) {
            config->max_tracked_ips = (uint32_t)val;
        }
        if (config_setting_lookup_int(limits, "hash_buckets", &val) == CONFIG_TRUE) {
            config->hash_buckets = (uint32_t)val;
        }
    }

    /* Parse capture section */
    config_setting_t *capture = config_lookup(&cfg_reader, "capture");
    if (capture) {
        int val;
        if (config_setting_lookup_int(capture, "nfqueue_num", &val) == CONFIG_TRUE) {
            config->nfqueue_num = (uint16_t)val;
        }
        if (config_setting_lookup_bool(capture, "use_raw_socket", &val) == CONFIG_TRUE) {
            config->use_raw_socket = (bool)val;
        }
    }

    /* Parse whitelist section */
    config_setting_t *whitelist = config_lookup(&cfg_reader, "whitelist");
    if (whitelist) {
        const char *str;
        if (config_setting_lookup_string(whitelist, "file", &str) == CONFIG_TRUE) {
            strncpy(config->whitelist_file, str, sizeof(config->whitelist_file) - 1);
        }
    }

    /* Parse logging section */
    config_setting_t *logging = config_lookup(&cfg_reader, "logging");
    if (logging) {
        const char *str;
        int val;
        if (config_setting_lookup_string(logging, "level", &str) == CONFIG_TRUE) {
            config->log_level = config_parse_log_level(str);
        }
        if (config_setting_lookup_bool(logging, "syslog", &val) == CONFIG_TRUE) {
            config->use_syslog = (bool)val;
        }
        if (config_setting_lookup_string(logging, "metrics_socket", &str) == CONFIG_TRUE) {
            strncpy(config->metrics_socket, str, sizeof(config->metrics_socket) - 1);
        }
    }

    config_destroy(&cfg_reader);

    /* Validate configuration */
    return config_validate(config);
}

synflood_ret_t config_validate(const config_t *config) {
    if (!config) {
        return SYNFLOOD_EINVAL;
    }

    /* Validate thresholds */
    if (config->syn_threshold == 0 || config->syn_threshold > 1000000) {
        fprintf(stderr, "Invalid syn_threshold: %u (must be 1-1000000)\n", config->syn_threshold);
        return SYNFLOOD_EINVAL;
    }

    if (config->window_ms == 0 || config->window_ms > 60000) {
        fprintf(stderr, "Invalid window_ms: %u (must be 1-60000)\n", config->window_ms);
        return SYNFLOOD_EINVAL;
    }

    if (config->block_duration_s == 0 || config->block_duration_s > 86400) {
        fprintf(stderr, "Invalid block_duration_s: %u (must be 1-86400)\n", config->block_duration_s);
        return SYNFLOOD_EINVAL;
    }

    if (config->proc_check_interval_s == 0 || config->proc_check_interval_s > 3600) {
        fprintf(stderr, "Invalid proc_check_interval_s: %u (must be 1-3600)\n", config->proc_check_interval_s);
        return SYNFLOOD_EINVAL;
    }

    /* Validate limits */
    if (config->max_tracked_ips == 0 || config->max_tracked_ips > 10000000) {
        fprintf(stderr, "Invalid max_tracked_ips: %u (must be 1-10000000)\n", config->max_tracked_ips);
        return SYNFLOOD_EINVAL;
    }

    /* Validate hash_buckets is power of 2 */
    if (config->hash_buckets == 0 || (config->hash_buckets & (config->hash_buckets - 1)) != 0) {
        fprintf(stderr, "Invalid hash_buckets: %u (must be power of 2)\n", config->hash_buckets);
        return SYNFLOOD_EINVAL;
    }

    /* Validate ipset name */
    if (strlen(config->ipset_name) == 0) {
        fprintf(stderr, "Invalid ipset_name: cannot be empty\n");
        return SYNFLOOD_EINVAL;
    }

    return SYNFLOOD_OK;
}

void config_free(config_t *config) {
    /* Currently nothing to free, but keep for future extensibility */
    (void)config;
}

void config_print(const config_t *config) {
    if (!config) {
        return;
    }

    printf("Configuration:\n");
    printf("  Detection:\n");
    printf("    syn_threshold: %u\n", config->syn_threshold);
    printf("    window_ms: %u\n", config->window_ms);
    printf("    proc_check_interval_s: %u\n", config->proc_check_interval_s);
    printf("  Enforcement:\n");
    printf("    block_duration_s: %u\n", config->block_duration_s);
    printf("    ipset_name: %s\n", config->ipset_name);
    printf("  Limits:\n");
    printf("    max_tracked_ips: %u\n", config->max_tracked_ips);
    printf("    hash_buckets: %u\n", config->hash_buckets);
    printf("  Capture:\n");
    printf("    nfqueue_num: %u\n", config->nfqueue_num);
    printf("    use_raw_socket: %s\n", config->use_raw_socket ? "true" : "false");
    printf("  Whitelist:\n");
    printf("    file: %s\n", config->whitelist_file);
    printf("  Logging:\n");
    printf("    level: %d\n", config->log_level);
    printf("    syslog: %s\n", config->use_syslog ? "true" : "false");
    printf("    metrics_socket: %s\n", config->metrics_socket);
}

/*
 * common.h - Shared types, macros, and constants
 * TCP SYN Flood Detector - Software Design Document v1.0
 */

#ifndef SYNFLOOD_COMMON_H
#define SYNFLOOD_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

/* Version information */
#define SYNFLOOD_VERSION "1.0.0"
#define SYNFLOOD_VERSION_MAJOR 1
#define SYNFLOOD_VERSION_MINOR 0
#define SYNFLOOD_VERSION_PATCH 0

/* Default configuration values */
#define DEFAULT_SYN_THRESHOLD 100
#define DEFAULT_WINDOW_MS 1000
#define DEFAULT_BLOCK_DURATION_S 300
#define DEFAULT_PROC_CHECK_INTERVAL_S 5
#define DEFAULT_MAX_TRACKED_IPS 10000
#define DEFAULT_HASH_BUCKETS 4096
#define DEFAULT_NFQUEUE_NUM 0
#define DEFAULT_IPSET_NAME "synflood_blacklist"
#define DEFAULT_CONFIG_PATH "/etc/synflood-detector/synflood-detector.conf"
#define DEFAULT_WHITELIST_PATH "/etc/synflood-detector/whitelist.conf"
#define DEFAULT_METRICS_SOCKET "/var/run/synflood-detector.sock"

/* Performance limits (NFR requirements) */
#define MAX_DETECTION_LATENCY_MS 100
#define TARGET_PPS 50000
#define MAX_MEMORY_MB 50
#define TARGET_CPU_PERCENT 5

/* TCP constants */
#define TCP_STATE_ESTABLISHED 0x01
#define TCP_STATE_SYN_SENT 0x02
#define TCP_STATE_SYN_RECV 0x03
#define TCP_STATE_FIN_WAIT1 0x04
#define TCP_STATE_TIME_WAIT 0x06
#define TCP_STATE_LISTEN 0x0A

/* Utility macros */
#define NSEC_PER_SEC 1000000000ULL
#define MSEC_PER_SEC 1000ULL
#define NSEC_PER_MSEC 1000000ULL

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Log levels */
typedef enum
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
} log_level_t;

/* Detection event types */
typedef enum
{
    EVENT_SUSPICIOUS,
    EVENT_BLOCKED,
    EVENT_UNBLOCKED,
    EVENT_WHITELISTED,
} event_type_t;

/* Configuration structure */
typedef struct
{
    /* Detection parameters */
    uint32_t syn_threshold;
    uint32_t window_ms;
    uint32_t proc_check_interval_s;

    /* Enforcement parameters */
    uint32_t block_duration_s;
    char ipset_name[256];

    /* Resource limits */
    uint32_t max_tracked_ips;
    uint32_t hash_buckets;

    /* Capture configuration */
    uint16_t nfqueue_num;
    bool use_raw_socket;

    /* Whitelist */
    char whitelist_file[PATH_MAX];

    /* Logging */
    log_level_t log_level;
    bool use_syslog;
    char metrics_socket[PATH_MAX];
} config_t;

/* Core tracking structure - per source IP */
typedef struct
{
    uint32_t ip_addr;         /* Network byte order */
    uint32_t syn_count;       /* SYN packets in current window */
    uint64_t window_start_ns; /* Window start (CLOCK_MONOTONIC) */
    uint64_t last_seen_ns;    /* For LRU eviction */
    uint8_t blocked;          /* Currently in blacklist */
    uint64_t block_expiry_ns; /* When to remove from blacklist */
} ip_tracker_t;

/* Hash table entry with chaining */
typedef struct tracker_node
{
    ip_tracker_t data;
    struct tracker_node *next;
} tracker_node_t;

/* Main tracking hash table */
typedef struct
{
    tracker_node_t **buckets;
    size_t bucket_count; /* Power of 2 for fast modulo */
    size_t entry_count;
    size_t max_entries;    /* LRU eviction threshold */
    pthread_rwlock_t lock; /* Reader-writer lock for concurrency */
} tracker_table_t;

/* Whitelist entry (Patricia trie node) */
typedef struct whitelist_node
{
    uint32_t prefix;    /* Network prefix */
    uint32_t mask;      /* Network mask */
    uint8_t prefix_len; /* CIDR prefix length */
    struct whitelist_node *left;
    struct whitelist_node *right;
} whitelist_node_t;

/* Metrics structure */
typedef struct
{
    uint64_t packets_total;
    uint64_t syn_packets_total;
    uint64_t blocked_ips_current;
    uint64_t detections_total;
    uint64_t false_positives_total;
    uint64_t whitelist_hits_total;
    uint64_t proc_parse_errors;
    double latency_p99_ms;
    double cpu_percent;
    uint64_t memory_kb;
} metrics_t;

/* Global context structure */
typedef struct
{
    config_t *config;
    tracker_table_t *tracker;
    whitelist_node_t *whitelist_root;
    metrics_t metrics;
    pthread_mutex_t metrics_lock;
    volatile bool running;
    int nfqueue_fd;
    int metrics_socket_fd;
} app_context_t;

/* Function return codes */
typedef enum
{
    SYNFLOOD_OK = 0,
    SYNFLOOD_ERROR = -1,
    SYNFLOOD_ENOMEM = -2,
    SYNFLOOD_EINVAL = -3,
    SYNFLOOD_ENOTFOUND = -4,
} synflood_ret_t;

/* Time utilities */
static inline uint64_t get_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

static inline uint64_t ms_to_ns(uint32_t ms)
{
    return (uint64_t)ms * NSEC_PER_MSEC;
}

static inline uint64_t sec_to_ns(uint32_t sec)
{
    return (uint64_t)sec * NSEC_PER_SEC;
}

/* IP address utilities */
static inline uint32_t ip_hash(uint32_t ip, size_t bucket_count)
{
    /* Simple but effective hash for IPv4 addresses */
    uint32_t hash = ip;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return hash & (bucket_count - 1);
}

#endif /* SYNFLOOD_COMMON_H */

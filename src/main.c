/*
 * main.c - TCP SYN Flood Detector main daemon
 * Software Design Document v1.0
 *
 * Entry point and signal handling
 */

#include "common.h"
#include "config/config.h"
#include "observe/logger.h"
#include "observe/metrics.h"
#include "analysis/tracker.h"
#include "analysis/whitelist.h"
#include "enforce/ipset_mgr.h"
#include "enforce/expiry.h"
#include "capture/nfqueue.h"
#include "capture/rawsock.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

/* Global application context */
static app_context_t app_ctx = {0};
static const char *global_config_path = NULL;

/* Signal flags - only atomic operations allowed in signal handlers */
static volatile sig_atomic_t reload_config_flag = 0;
static volatile sig_atomic_t shutdown_flag = 0;

/* Signal handler - ASYNC-SIGNAL-SAFE operations only */
static void signal_handler(int signum) {
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            shutdown_flag = 1;
            break;

        case SIGHUP:
            reload_config_flag = 1;
            break;

        default:
            break;
    }
}

/* Handle configuration reload - called from main loop in safe context */
static void handle_config_reload(void) {
    if (!global_config_path || !app_ctx.config) {
        LOG_ERROR("Cannot reload configuration: invalid state");
        return;
    }

    LOG_INFO("Reloading configuration from %s...", global_config_path);

    /* Load new configuration */
    synflood_config_t new_config;
    if (config_load(global_config_path, &new_config) != SYNFLOOD_OK) {
        LOG_ERROR("Failed to load configuration file, keeping current config");
        return;
    }

    /* Reload whitelist if path changed or always reload for updates */
    whitelist_node_t *new_whitelist = whitelist_load(new_config.whitelist_file);
    if (!new_whitelist && new_config.whitelist_file[0] != '\0') {
        LOG_WARN("Failed to load whitelist from %s", new_config.whitelist_file);
        /* Continue with config reload even if whitelist fails */
    }

    /* Update whitelist atomically */
    if (new_whitelist) {
        whitelist_node_t *old_whitelist = app_ctx.whitelist_root;
        app_ctx.whitelist_root = new_whitelist;

        if (old_whitelist) {
            whitelist_free(old_whitelist);
        }

        size_t count = whitelist_count(new_whitelist);
        LOG_INFO("Reloaded %zu whitelist entries", count);
    }

    /* Update configuration - memcpy is atomic for aligned struct on most architectures
     * For critical production use, consider using a config pointer with RCU or double-buffering */
    synflood_config_t *old_config = app_ctx.config;
    *old_config = new_config;

    /* Update logger level if changed */
    logger_set_level(new_config.log_level);

    LOG_INFO("Configuration reloaded successfully");
    LOG_INFO("  syn_threshold: %u", new_config.syn_threshold);
    LOG_INFO("  window_ms: %u", new_config.window_ms);
    LOG_INFO("  block_duration_s: %u", new_config.block_duration_s);
    LOG_INFO("  log_level: %d", new_config.log_level);
}

/* Check and handle signals - called periodically from packet capture loops */
void handle_signals(void) {
    /* Check shutdown signal */
    if (shutdown_flag) {
        LOG_INFO("Received shutdown signal, stopping gracefully...");
        app_ctx.running = false;
        nfqueue_stop();
        rawsock_stop();
        shutdown_flag = 0;  /* Reset flag */
    }

    /* Check reload signal */
    if (reload_config_flag) {
        handle_config_reload();
        reload_config_flag = 0;  /* Reset flag */
    }
}

/* Get pointer to app context - for signal handling in capture modules */
app_context_t* get_app_context(void) {
    return &app_ctx;
}

/* Setup signal handlers */
static synflood_ret_t setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        fprintf(stderr, "Failed to set SIGTERM handler\n");
        return SYNFLOOD_ERROR;
    }

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        fprintf(stderr, "Failed to set SIGINT handler\n");
        return SYNFLOOD_ERROR;
    }

    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        fprintf(stderr, "Failed to set SIGHUP handler\n");
        return SYNFLOOD_ERROR;
    }

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    return SYNFLOOD_OK;
}

/* Initialize all subsystems */
static synflood_ret_t initialize_subsystems(synflood_config_t *config) {
    synflood_ret_t ret;

    /* Initialize logger */
    ret = logger_init(config->log_level, config->use_syslog);
    if (ret != SYNFLOOD_OK) {
        fprintf(stderr, "Failed to initialize logger\n");
        return ret;
    }

    LOG_INFO("=== TCP SYN Flood Detector v%s ===", SYNFLOOD_VERSION);
    LOG_INFO("Starting initialization...");

    /* Initialize metrics */
    memset(&app_ctx.metrics, 0, sizeof(metrics_t));
    pthread_mutex_init(&app_ctx.metrics_lock, NULL);

    /* Create tracker table */
    app_ctx.tracker = tracker_create(config->hash_buckets, config->max_tracked_ips);
    if (!app_ctx.tracker) {
        LOG_ERROR("Failed to create tracker table");
        return SYNFLOOD_ERROR;
    }

    /* Load whitelist */
    app_ctx.whitelist_root = whitelist_load(config->whitelist_file);
    if (app_ctx.whitelist_root) {
        size_t count = whitelist_count(app_ctx.whitelist_root);
        LOG_INFO("Loaded %zu whitelist entries", count);
    } else {
        LOG_WARN("No whitelist loaded (file: %s)", config->whitelist_file);
    }

    /* Initialize ipset manager */
    ret = ipset_mgr_init(config->ipset_name, config->block_duration_s, config->max_tracked_ips);
    if (ret != SYNFLOOD_OK) {
        LOG_ERROR("Failed to initialize ipset manager");
        return ret;
    }

    /* Initialize metrics server */
    ret = metrics_init(&app_ctx, config->metrics_socket);
    if (ret != SYNFLOOD_OK) {
        LOG_WARN("Failed to initialize metrics server (continuing anyway)");
    }

    /* Initialize packet capture */
    if (config->use_raw_socket) {
        LOG_INFO("Using raw socket packet capture");
        ret = rawsock_init(&app_ctx);
        if (ret != SYNFLOOD_OK) {
            LOG_ERROR("Failed to initialize raw socket");
            return ret;
        }
    } else {
        LOG_INFO("Using NFQUEUE packet capture");
        ret = nfqueue_init(&app_ctx, config->nfqueue_num);
        if (ret != SYNFLOOD_OK) {
            LOG_ERROR("Failed to initialize NFQUEUE");
            return ret;
        }
    }

    LOG_INFO("All subsystems initialized successfully");
    return SYNFLOOD_OK;
}

/* Cleanup all subsystems */
static void cleanup_subsystems(void) {
    LOG_INFO("Cleaning up subsystems...");

    /* Stop threads */
    expiry_stop();
    metrics_stop();

    /* Cleanup capture */
    nfqueue_cleanup();
    rawsock_cleanup();

    /* Cleanup enforcement */
    ipset_mgr_shutdown();

    /* Cleanup analysis */
    if (app_ctx.tracker) {
        tracker_destroy(app_ctx.tracker);
        app_ctx.tracker = NULL;
    }

    if (app_ctx.whitelist_root) {
        whitelist_free(app_ctx.whitelist_root);
        app_ctx.whitelist_root = NULL;
    }

    /* Cleanup observability */
    metrics_cleanup();
    pthread_mutex_destroy(&app_ctx.metrics_lock);

    logger_shutdown();

    LOG_INFO("Cleanup completed");
}

/* Print usage information */
static void print_usage(const char *prog_name) {
    fprintf(stderr,
            "Usage: %s [OPTIONS]\n"
            "\n"
            "TCP SYN Flood Detector v%s\n"
            "\n"
            "Options:\n"
            "  -c, --config PATH    Configuration file path (default: %s)\n"
            "  -h, --help           Show this help message\n"
            "  -v, --version        Show version information\n"
            "\n"
            "Signals:\n"
            "  SIGTERM/SIGINT       Graceful shutdown\n"
            "  SIGHUP               Reload configuration\n"
            "\n",
            prog_name, SYNFLOOD_VERSION, DEFAULT_CONFIG_PATH);
}

/* Main entry point */
int main(int argc, char *argv[]) {
    int opt;
    const char *config_path = DEFAULT_CONFIG_PATH;
    static synflood_config_t config;  /* Static storage - address is valid for program lifetime */

    /* Command line options */
    static struct option long_options[] = {
        {"config",  required_argument, 0, 'c'},
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:hv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_path = optarg;
                break;
            case 'v':
                printf("TCP SYN Flood Detector v%s\n", SYNFLOOD_VERSION);
                return EXIT_SUCCESS;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    /* Load configuration */
    if (config_load(config_path, &config) != SYNFLOOD_OK) {
        fprintf(stderr, "Failed to load configuration from %s\n", config_path);
        return EXIT_FAILURE;
    }

    app_ctx.config = &config;
    global_config_path = config_path;
    app_ctx.running = true;

    /* Setup signal handlers */
    if (setup_signals() != SYNFLOOD_OK) {
        fprintf(stderr, "Failed to setup signal handlers\n");
        return EXIT_FAILURE;
    }

    /* Initialize subsystems */
    if (initialize_subsystems(&config) != SYNFLOOD_OK) {
        fprintf(stderr, "Failed to initialize subsystems\n");
        cleanup_subsystems();
        return EXIT_FAILURE;
    }

    /* Print configuration */
    config_print(&config);

    /* Start background threads */
    if (metrics_start(&app_ctx) == SYNFLOOD_OK) {
        LOG_INFO("Metrics server started");
    }

    if (expiry_start(&app_ctx, config.proc_check_interval_s) == SYNFLOOD_OK) {
        LOG_INFO("Expiration checker started");
    }

    /* Start packet capture (blocking) */
    LOG_INFO("Starting packet capture...");
    LOG_INFO("Press Ctrl+C to stop");

    synflood_ret_t capture_ret;
    if (config.use_raw_socket) {
        capture_ret = rawsock_start(&app_ctx);
    } else {
        capture_ret = nfqueue_start(&app_ctx);
    }

    if (capture_ret != SYNFLOOD_OK && app_ctx.running) {
        LOG_ERROR("Packet capture failed");
    }

    /* Cleanup and exit */
    cleanup_subsystems();
    config_free(&config);

    LOG_INFO("TCP SYN Flood Detector stopped");

    return (capture_ret == SYNFLOOD_OK) ? EXIT_SUCCESS : EXIT_FAILURE;
}

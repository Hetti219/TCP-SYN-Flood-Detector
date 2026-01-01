/*
 * metrics.c - Unix socket metrics API implementation
 * TCP SYN Flood Detector
 */

#include "metrics.h"
#include "logger.h"
#include "../analysis/tracker.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static int metrics_sock_fd = -1;
static pthread_t metrics_thread;
static volatile bool metrics_running = false;
static char socket_path[PATH_MAX] = {0};

/* Format metrics in Prometheus-compatible format */
static void format_metrics(app_context_t *ctx, char *buffer, size_t size) {
    pthread_mutex_lock(&ctx->metrics_lock);

    size_t entry_count, blocked_count;
    tracker_get_stats(ctx->tracker, &entry_count, &blocked_count);

    snprintf(buffer, size,
             "# HELP synflood_packets_total Total packets processed\n"
             "# TYPE synflood_packets_total counter\n"
             "synflood_packets_total %lu\n"
             "\n"
             "# HELP synflood_syn_packets_total Total SYN packets detected\n"
             "# TYPE synflood_syn_packets_total counter\n"
             "synflood_syn_packets_total %lu\n"
             "\n"
             "# HELP synflood_blocked_ips_current Current number of blocked IPs\n"
             "# TYPE synflood_blocked_ips_current gauge\n"
             "synflood_blocked_ips_current %lu\n"
             "\n"
             "# HELP synflood_detections_total Total attack detections\n"
             "# TYPE synflood_detections_total counter\n"
             "synflood_detections_total %lu\n"
             "\n"
             "# HELP synflood_false_positives_total Total false positives\n"
             "# TYPE synflood_false_positives_total counter\n"
             "synflood_false_positives_total %lu\n"
             "\n"
             "# HELP synflood_whitelist_hits_total Total whitelist hits\n"
             "# TYPE synflood_whitelist_hits_total counter\n"
             "synflood_whitelist_hits_total %lu\n"
             "\n"
             "# HELP synflood_tracker_entries Current tracker table entries\n"
             "# TYPE synflood_tracker_entries gauge\n"
             "synflood_tracker_entries %zu\n"
             "\n"
             "# HELP synflood_tracker_blocked Blocked entries in tracker\n"
             "# TYPE synflood_tracker_blocked gauge\n"
             "synflood_tracker_blocked %zu\n",
             ctx->metrics.packets_total,
             ctx->metrics.syn_packets_total,
             ctx->metrics.blocked_ips_current,
             ctx->metrics.detections_total,
             ctx->metrics.false_positives_total,
             ctx->metrics.whitelist_hits_total,
             entry_count,
             blocked_count);

    pthread_mutex_unlock(&ctx->metrics_lock);
}

static void *metrics_server_thread(void *arg) {
    app_context_t *ctx = (app_context_t *)arg;

    LOG_INFO("Metrics server thread started");

    while (metrics_running && ctx->running) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(metrics_sock_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (metrics_running && ctx->running) {
                LOG_ERROR("accept() failed on metrics socket: %s", strerror(errno));
            }
            break;
        }

        /* Read request (simple HTTP-like GET) */
        char request[256];
        ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
        if (n > 0) {
            request[n] = '\0';

            /* Format and send metrics */
            char response[8192];
            format_metrics(ctx, response, sizeof(response));

            send(client_fd, response, strlen(response), 0);
        }

        close(client_fd);
    }

    LOG_INFO("Metrics server thread stopped");
    return NULL;
}

synflood_ret_t metrics_init(app_context_t *ctx, const char *socket_path_arg) {
    if (!ctx || !socket_path_arg) {
        return SYNFLOOD_EINVAL;
    }

    strncpy(socket_path, socket_path_arg, sizeof(socket_path) - 1);

    /* Remove existing socket file */
    unlink(socket_path);

    /* Create Unix socket */
    metrics_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (metrics_sock_fd < 0) {
        LOG_ERROR("Failed to create metrics Unix socket");
        return SYNFLOOD_ERROR;
    }

    /* Bind to socket path */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(metrics_sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind metrics socket to %s: %s", socket_path, strerror(errno));
        close(metrics_sock_fd);
        metrics_sock_fd = -1;
        return SYNFLOOD_ERROR;
    }

    /* Listen for connections */
    if (listen(metrics_sock_fd, 5) < 0) {
        LOG_ERROR("Failed to listen on metrics socket");
        close(metrics_sock_fd);
        unlink(socket_path);
        metrics_sock_fd = -1;
        return SYNFLOOD_ERROR;
    }

    ctx->metrics_socket_fd = metrics_sock_fd;

    LOG_INFO("Metrics server initialized: socket=%s", socket_path);

    return SYNFLOOD_OK;
}

synflood_ret_t metrics_start(app_context_t *ctx) {
    if (!ctx) {
        return SYNFLOOD_EINVAL;
    }

    if (metrics_running) {
        LOG_WARN("Metrics server already running");
        return SYNFLOOD_OK;
    }

    metrics_running = true;

    if (pthread_create(&metrics_thread, NULL, metrics_server_thread, ctx) != 0) {
        LOG_ERROR("Failed to create metrics server thread");
        metrics_running = false;
        return SYNFLOOD_ERROR;
    }

    return SYNFLOOD_OK;
}

void metrics_stop(void) {
    if (!metrics_running) {
        return;
    }

    LOG_INFO("Stopping metrics server");
    metrics_running = false;

    /* Close socket to break accept() call */
    if (metrics_sock_fd >= 0) {
        shutdown(metrics_sock_fd, SHUT_RDWR);
    }

    pthread_join(metrics_thread, NULL);
}

void metrics_cleanup(void) {
    if (metrics_sock_fd >= 0) {
        close(metrics_sock_fd);
        metrics_sock_fd = -1;
    }

    if (strlen(socket_path) > 0) {
        unlink(socket_path);
        socket_path[0] = '\0';
    }

    LOG_INFO("Metrics server cleanup completed");
}

/*
 * logger.c - Structured logging implementation
 * TCP SYN Flood Detector
 */

#include "logger.h"
#include <systemd/sd-journal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

static log_level_t current_log_level = LOG_LEVEL_INFO;
static bool use_systemd_journal = true;

static const char *level_strings[] = {
    [LOG_LEVEL_DEBUG] = "DEBUG",
    [LOG_LEVEL_INFO]  = "INFO",
    [LOG_LEVEL_WARN]  = "WARN",
    [LOG_LEVEL_ERROR] = "ERROR",
};

static const int sd_priorities[] = {
    [LOG_LEVEL_DEBUG] = LOG_DEBUG,
    [LOG_LEVEL_INFO]  = LOG_INFO,
    [LOG_LEVEL_WARN]  = LOG_WARNING,
    [LOG_LEVEL_ERROR] = LOG_ERR,
};

static const char *event_type_strings[] = {
    [EVENT_SUSPICIOUS]  = "SUSPICIOUS",
    [EVENT_BLOCKED]     = "BLOCKED",
    [EVENT_UNBLOCKED]   = "UNBLOCKED",
    [EVENT_WHITELISTED] = "WHITELISTED",
};

synflood_ret_t logger_init(log_level_t level, bool use_syslog) {
    current_log_level = level;
    use_systemd_journal = use_syslog;

    LOG_INFO("Logger initialized (level=%s, syslog=%s)",
             level_strings[level], use_syslog ? "yes" : "no");

    return SYNFLOOD_OK;
}

void logger_shutdown(void) {
    LOG_INFO("Logger shutting down");
}

void logger_log(log_level_t level, const char *format, ...) {
    if (level < current_log_level) {
        return;
    }

    va_list args;
    char message[1024];

    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    if (use_systemd_journal) {
        /* Use systemd journal with structured logging */
        sd_journal_send(
            "MESSAGE=%s", message,
            "PRIORITY=%d", sd_priorities[level],
            "SYSLOG_IDENTIFIER=synflood-detector",
            NULL
        );
    } else {
        /* Fallback to stderr */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm;
        localtime_r(&ts.tv_sec, &tm);

        fprintf(stderr, "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000,
                level_strings[level], message);
    }
}

void logger_log_event(event_type_t event_type, uint32_t ip_addr,
                      uint32_t syn_count, uint32_t syn_recv_count) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = ip_addr };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    const char *event_str = (event_type < ARRAY_SIZE(event_type_strings))
                            ? event_type_strings[event_type]
                            : "UNKNOWN";

    if (use_systemd_journal) {
        /* Structured logging with fields for easy querying */
        sd_journal_send(
            "MESSAGE=%s: IP=%s SYN_COUNT=%u SYN_RECV=%u",
            event_str, ip_str, syn_count, syn_recv_count,
            "PRIORITY=%d", event_type == EVENT_BLOCKED ? LOG_WARNING : LOG_INFO,
            "SYSLOG_IDENTIFIER=synflood-detector",
            "EVENT_TYPE=%s", event_str,
            "SOURCE_IP=%s", ip_str,
            "SYN_COUNT=%u", syn_count,
            "SYN_RECV_COUNT=%u", syn_recv_count,
            NULL
        );
    } else {
        log_level_t level = (event_type == EVENT_BLOCKED) ? LOG_LEVEL_WARN : LOG_LEVEL_INFO;
        logger_log(level, "%s: IP=%s SYN_COUNT=%u SYN_RECV=%u",
                   event_str, ip_str, syn_count, syn_recv_count);
    }
}

void logger_error_errno(const char *format, ...) {
    va_list args;
    char message[1024];
    int saved_errno = errno;

    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    logger_log(LOG_LEVEL_ERROR, "%s: %s", message, strerror(saved_errno));
}

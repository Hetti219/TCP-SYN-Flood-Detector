/*
 * logger.h - Structured logging with systemd journal support
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_LOGGER_H
#define SYNFLOOD_LOGGER_H

#include "common.h"
#include <arpa/inet.h>

/**
 * Initialize logging subsystem
 * @param level Minimum log level to output
 * @param use_syslog Whether to use systemd journal
 * @return SYNFLOOD_OK on success
 */
synflood_ret_t logger_init(log_level_t level, bool use_syslog);

/**
 * Shutdown logging subsystem
 */
void logger_shutdown(void);

/**
 * Log a message
 * @param level Log level
 * @param format Printf-style format string
 * @param ... Variable arguments
 */
void logger_log(log_level_t level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

/**
 * Log a detection event
 * @param event_type Type of event
 * @param ip_addr Source IP address (network byte order)
 * @param syn_count Number of SYN packets detected
 * @param syn_recv_count Number of SYN_RECV connections in /proc
 */
void logger_log_event(event_type_t event_type, uint32_t ip_addr,
                      uint32_t syn_count, uint32_t syn_recv_count);

/**
 * Log an error with errno information
 * @param format Printf-style format string
 * @param ... Variable arguments
 */
void logger_error_errno(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

/* Convenience macros */
#define LOG_DEBUG(...) logger_log(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  logger_log(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARN(...)  logger_log(LOG_LEVEL_WARN, __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_LEVEL_ERROR, __VA_ARGS__)

#endif /* SYNFLOOD_LOGGER_H */

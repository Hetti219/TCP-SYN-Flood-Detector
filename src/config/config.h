/*
 * config.h - Configuration file parsing
 * TCP SYN Flood Detector
 */

#ifndef SYNFLOOD_CONFIG_H
#define SYNFLOOD_CONFIG_H

#include "common.h"

/**
 * Load configuration from file
 * @param path Path to configuration file
 * @param config Pointer to synflood_config_t structure to populate
 * @return SYNFLOOD_OK on success, error code otherwise
 */
synflood_ret_t config_load(const char *path, synflood_config_t *config);

/**
 * Validate configuration values
 * @param config Configuration to validate
 * @return SYNFLOOD_OK if valid, SYNFLOOD_EINVAL otherwise
 */
synflood_ret_t config_validate(const synflood_config_t *config);

/**
 * Free resources associated with configuration
 * @param config Configuration to free
 */
void config_free(synflood_config_t *config);

/**
 * Print configuration to stdout
 * @param config Configuration to print
 */
void config_print(const synflood_config_t *config);

/**
 * Get log level from string
 * @param level_str String representation of log level
 * @return log_level_t value
 */
log_level_t config_parse_log_level(const char *level_str);

#endif /* SYNFLOOD_CONFIG_H */

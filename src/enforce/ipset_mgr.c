/*
 * ipset_mgr.c - ipset management implementation
 * TCP SYN Flood Detector
 *
 * This implementation uses the ipset command-line tool for reliability
 * and compatibility. For production, could be replaced with direct
 * netlink/libmnl implementation.
 */

#include "ipset_mgr.h"
#include "../observe/logger.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static char current_ipset_name[256] = {0};
static uint32_t current_timeout = 0;

synflood_ret_t ipset_mgr_init(const char *ipset_name, uint32_t timeout, uint32_t max_entries) {
    if (!ipset_name) {
        return SYNFLOOD_EINVAL;
    }

    strncpy(current_ipset_name, ipset_name, sizeof(current_ipset_name) - 1);
    current_timeout = timeout;

    /* Create ipset if it doesn't exist */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ipset create -exist %s hash:ip timeout %u maxelem %u 2>/dev/null",
             ipset_name, timeout, max_entries);

    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERROR("Failed to create ipset %s", ipset_name);
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("ipset manager initialized: name=%s, timeout=%u, maxelem=%u",
             ipset_name, timeout, max_entries);

    return SYNFLOOD_OK;
}

void ipset_mgr_shutdown(void) {
    LOG_INFO("ipset manager shutting down");
    /* Note: We don't destroy the ipset on shutdown to preserve blocks */
}

synflood_ret_t ipset_mgr_add(uint32_t ip_addr, uint32_t timeout) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = ip_addr };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    if (strlen(current_ipset_name) == 0) {
        LOG_ERROR("ipset manager not initialized");
        return SYNFLOOD_ERROR;
    }

    char cmd[512];
    if (timeout == 0) {
        timeout = current_timeout;
    }

    snprintf(cmd, sizeof(cmd),
             "ipset add -exist %s %s timeout %u 2>/dev/null",
             current_ipset_name, ip_str, timeout);

    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERROR("Failed to add IP %s to ipset %s", ip_str, current_ipset_name);
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("Added IP to blacklist: %s (timeout=%u)", ip_str, timeout);

    return SYNFLOOD_OK;
}

synflood_ret_t ipset_mgr_remove(uint32_t ip_addr) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = ip_addr };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    if (strlen(current_ipset_name) == 0) {
        LOG_ERROR("ipset manager not initialized");
        return SYNFLOOD_ERROR;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ipset del -exist %s %s 2>/dev/null",
             current_ipset_name, ip_str);

    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERROR("Failed to remove IP %s from ipset %s", ip_str, current_ipset_name);
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("Removed IP from blacklist: %s", ip_str);

    return SYNFLOOD_OK;
}

bool ipset_mgr_test(uint32_t ip_addr) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr = { .s_addr = ip_addr };
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    if (strlen(current_ipset_name) == 0) {
        return false;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ipset test %s %s >/dev/null 2>&1",
             current_ipset_name, ip_str);

    int ret = system(cmd);
    return (ret == 0);
}

synflood_ret_t ipset_mgr_flush(void) {
    if (strlen(current_ipset_name) == 0) {
        LOG_ERROR("ipset manager not initialized");
        return SYNFLOOD_ERROR;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ipset flush %s 2>/dev/null",
             current_ipset_name);

    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERROR("Failed to flush ipset %s", current_ipset_name);
        return SYNFLOOD_ERROR;
    }

    LOG_INFO("Flushed ipset %s", current_ipset_name);

    return SYNFLOOD_OK;
}

size_t ipset_mgr_get_count(void) {
    if (strlen(current_ipset_name) == 0) {
        return 0;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "ipset list %s | grep -c '^[0-9]' 2>/dev/null",
             current_ipset_name);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return 0;
    }

    size_t count = 0;
    if (fscanf(fp, "%zu", &count) != 1) {
        count = 0;
    }

    pclose(fp);
    return count;
}

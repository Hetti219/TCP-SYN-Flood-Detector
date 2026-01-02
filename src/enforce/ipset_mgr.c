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
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

static char current_ipset_name[256] = {0};
static uint32_t current_timeout = 0;

/* Helper function to execute ipset commands safely using fork+execl */
static int execute_ipset_cmd(const char *arg1, const char *arg2, const char *arg3,
                             const char *arg4, const char *arg5, const char *arg6,
                             const char *arg7, const char *arg8) {
    pid_t pid = fork();

    if (pid < 0) {
        LOG_ERROR("fork() failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child process */
        /* Redirect stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        /* Execute ipset command */
        execl("/usr/sbin/ipset", "ipset", arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, (char *)NULL);

        /* If execl fails */
        _exit(127);
    }

    /* Parent process */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        LOG_ERROR("waitpid() failed: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return -1;
}

synflood_ret_t ipset_mgr_init(const char *ipset_name, uint32_t timeout, uint32_t max_entries) {
    if (!ipset_name) {
        return SYNFLOOD_EINVAL;
    }

    strncpy(current_ipset_name, ipset_name, sizeof(current_ipset_name) - 1);
    current_timeout = timeout;

    /* Create ipset if it doesn't exist */
    char timeout_str[32];
    char maxelem_str[32];
    snprintf(timeout_str, sizeof(timeout_str), "%u", timeout);
    snprintf(maxelem_str, sizeof(maxelem_str), "%u", max_entries);

    int ret = execute_ipset_cmd("create", "-exist", ipset_name, "hash:ip",
                                 "timeout", timeout_str, "maxelem", maxelem_str);
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

    if (timeout == 0) {
        timeout = current_timeout;
    }

    char timeout_str[32];
    snprintf(timeout_str, sizeof(timeout_str), "%u", timeout);

    int ret = execute_ipset_cmd("add", "-exist", current_ipset_name, ip_str,
                                 "timeout", timeout_str, NULL, NULL);
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

    int ret = execute_ipset_cmd("del", "-exist", current_ipset_name, ip_str,
                                 NULL, NULL, NULL, NULL);
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

    /* For test command, we need to redirect stdout as well */
    pid_t pid = fork();
    if (pid < 0) {
        return false;
    }

    if (pid == 0) {
        /* Child process - redirect both stdout and stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        execl("/usr/sbin/ipset", "ipset", "test", current_ipset_name, ip_str, (char *)NULL);
        _exit(127);
    }

    /* Parent process */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

synflood_ret_t ipset_mgr_flush(void) {
    if (strlen(current_ipset_name) == 0) {
        LOG_ERROR("ipset manager not initialized");
        return SYNFLOOD_ERROR;
    }

    int ret = execute_ipset_cmd("flush", current_ipset_name, NULL, NULL,
                                 NULL, NULL, NULL, NULL);
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

    /* Create a pipe to read ipset output */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        return 0;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    if (pid == 0) {
        /* Child process - execute ipset list */
        close(pipefd[0]); /* Close read end */
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Redirect stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        execl("/usr/sbin/ipset", "ipset", "list", current_ipset_name, (char *)NULL);
        _exit(127);
    }

    /* Parent process - read and count IPs */
    close(pipefd[1]); /* Close write end */

    FILE *fp = fdopen(pipefd[0], "r");
    if (!fp) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return 0;
    }

    char line[256];
    size_t count = 0;

    /* Count lines that start with a digit (IP addresses) */
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] >= '0' && line[0] <= '9') {
            count++;
        }
    }

    fclose(fp); /* This also closes pipefd[0] */
    waitpid(pid, NULL, 0);

    return count;
}

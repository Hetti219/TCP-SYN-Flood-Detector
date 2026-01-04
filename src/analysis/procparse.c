/*
 * procparse.c - /proc/net/tcp parser implementation
 * TCP SYN Flood Detector
 *
 * Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
 * Example: 0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 ...
 *
 * State values (st field):
 *   01 = TCP_ESTABLISHED
 *   02 = TCP_SYN_SENT
 *   03 = TCP_SYN_RECV   <-- Target state
 *   04 = TCP_FIN_WAIT1
 *   ...
 */

#include "procparse.h"
#include "../observe/logger.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define PROC_NET_TCP "/proc/net/tcp"
#define PROC_NET_TCP6 "/proc/net/tcp6"

/* Parse a /proc/net/tcp line and extract remote address and state */
static bool parse_tcp_line(const char *line, uint32_t *rem_addr, uint8_t *state) {
    unsigned int sl;
    unsigned int loc_addr, loc_port;
    unsigned int r_addr, r_port;
    unsigned int st;

    /* Parse the line
     * Format: sl local_address rem_address st ...
     * Example: 0: 0100007F:0035 C0A80101:1234 03 ...
     */
    int parsed = sscanf(line, "%u: %X:%X %X:%X %X", &sl, &loc_addr, &loc_port, &r_addr, &r_port, &st);

    if (parsed < 6) {
        return false;
    }

    *rem_addr = r_addr;
    *state = (uint8_t)st;

    return true;
}

/* Convert hex address from /proc format (little-endian) to network byte order */
static uint32_t proc_addr_to_network(uint32_t proc_addr) {
    /* /proc/net/tcp stores addresses in little-endian hex */
    /* Convert to network byte order (big-endian) */
    return htonl(proc_addr);
}

uint32_t procparse_count_syn_recv_total(void) {
    FILE *fp = fopen(PROC_NET_TCP, "r");
    if (!fp) {
        LOG_ERROR("Failed to open %s: %s", PROC_NET_TCP, strerror(errno));
        return 0;
    }

    char line[512];
    uint32_t count = 0;

    /* Skip header line */
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 0;
    }

    /* Parse each connection line */
    while (fgets(line, sizeof(line), fp)) {
        uint32_t rem_addr;
        uint8_t state;

        if (parse_tcp_line(line, &rem_addr, &state)) {
            if (state == TCP_STATE_SYN_RECV) {
                count++;
            }
        }
    }

    fclose(fp);
    return count;
}

uint32_t procparse_count_syn_recv_from_ip(uint32_t ip_addr) {
    FILE *fp = fopen(PROC_NET_TCP, "r");
    if (!fp) {
        LOG_ERROR("Failed to open %s: %s", PROC_NET_TCP, strerror(errno));
        return 0;
    }

    char line[512];
    uint32_t count = 0;

    /* Skip header line */
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 0;
    }

    /* Convert target IP to /proc format for comparison */
    uint32_t target_proc_addr = ntohl(ip_addr);

    /* Parse each connection line */
    while (fgets(line, sizeof(line), fp)) {
        uint32_t rem_addr;
        uint8_t state;

        if (parse_tcp_line(line, &rem_addr, &state)) {
            if (state == TCP_STATE_SYN_RECV && rem_addr == target_proc_addr) {
                count++;
            }
        }
    }

    fclose(fp);
    return count;
}

size_t procparse_get_syn_recv_ips(uint32_t *ips, size_t max_ips) {
    if (!ips || max_ips == 0) {
        return 0;
    }

    FILE *fp = fopen(PROC_NET_TCP, "r");
    if (!fp) {
        LOG_ERROR("Failed to open %s: %s", PROC_NET_TCP, strerror(errno));
        return 0;
    }

    char line[512];
    size_t count = 0;

    /* Skip header line */
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 0;
    }

    /* Parse each connection line */
    while (fgets(line, sizeof(line), fp) && count < max_ips) {
        uint32_t rem_addr;
        uint8_t state;

        if (parse_tcp_line(line, &rem_addr, &state)) {
            if (state == TCP_STATE_SYN_RECV) {
                /* Convert to network byte order */
                uint32_t network_addr = proc_addr_to_network(rem_addr);

                /* Check if IP is already in the list (avoid duplicates) */
                bool found = false;
                for (size_t i = 0; i < count; i++) {
                    if (ips[i] == network_addr) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    ips[count++] = network_addr;
                }
            }
        }
    }

    fclose(fp);
    return count;
}

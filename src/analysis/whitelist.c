/*
 * whitelist.c - CIDR whitelist implementation using Patricia trie
 * TCP SYN Flood Detector
 */

#include "whitelist.h"
#include "../observe/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Create a new whitelist node */
static whitelist_node_t *whitelist_node_create(uint32_t prefix, uint32_t mask, uint8_t prefix_len) {
    whitelist_node_t *node = calloc(1, sizeof(whitelist_node_t));
    if (!node) {
        return NULL;
    }

    node->prefix = prefix;
    node->mask = mask;
    node->prefix_len = prefix_len;
    node->left = NULL;
    node->right = NULL;

    return node;
}

/* Parse CIDR notation and extract prefix and mask */
static synflood_ret_t parse_cidr(const char *cidr, uint32_t *prefix, uint32_t *mask, uint8_t *prefix_len) {
    char cidr_copy[64];
    strncpy(cidr_copy, cidr, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';

    /* Split IP and prefix length */
    char *slash = strchr(cidr_copy, '/');
    if (slash) {
        *slash = '\0';
        *prefix_len = (uint8_t)atoi(slash + 1);
    } else {
        *prefix_len = 32; /* Default to single host */
    }

    if (*prefix_len > 32) {
        LOG_ERROR("Invalid CIDR prefix length: %u", *prefix_len);
        return SYNFLOOD_EINVAL;
    }

    /* Parse IP address */
    struct in_addr addr;
    if (inet_pton(AF_INET, cidr_copy, &addr) != 1) {
        LOG_ERROR("Invalid IP address in CIDR: %s", cidr_copy);
        return SYNFLOOD_EINVAL;
    }

    /* Calculate mask and prefix */
    if (*prefix_len == 0) {
        *mask = 0;
    } else {
        *mask = htonl(~((1U << (32 - *prefix_len)) - 1));
    }

    *prefix = addr.s_addr & *mask;

    return SYNFLOOD_OK;
}

synflood_ret_t whitelist_add(whitelist_node_t **root, const char *cidr) {
    if (!root || !cidr) {
        return SYNFLOOD_EINVAL;
    }

    uint32_t prefix, mask;
    uint8_t prefix_len;

    if (parse_cidr(cidr, &prefix, &mask, &prefix_len) != SYNFLOOD_OK) {
        return SYNFLOOD_EINVAL;
    }

    /* Create new node */
    whitelist_node_t *new_node = whitelist_node_create(prefix, mask, prefix_len);
    if (!new_node) {
        return SYNFLOOD_ENOMEM;
    }

    /* Insert into trie */
    if (*root == NULL) {
        *root = new_node;
        LOG_DEBUG("Added whitelist entry (root): %s", cidr);
        return SYNFLOOD_OK;
    }

    /* Simple insertion - just add to tree */
    /* For a full Patricia trie, this would be more complex */
    /* This simplified version uses a binary tree based on prefix value */
    whitelist_node_t *current = *root;
    while (true) {
        if (prefix < current->prefix) {
            if (current->left == NULL) {
                current->left = new_node;
                break;
            }
            current = current->left;
        } else if (prefix > current->prefix) {
            if (current->right == NULL) {
                current->right = new_node;
                break;
            }
            current = current->right;
        } else {
            /* Duplicate entry, update if needed */
            if (prefix_len != current->prefix_len) {
                current->prefix_len = prefix_len;
                current->mask = mask;
            }
            free(new_node);
            LOG_DEBUG("Updated whitelist entry: %s", cidr);
            return SYNFLOOD_OK;
        }
    }

    LOG_DEBUG("Added whitelist entry: %s", cidr);
    return SYNFLOOD_OK;
}

bool whitelist_check(whitelist_node_t *root, uint32_t ip_addr) {
    if (!root) {
        return false;
    }

    whitelist_node_t *current = root;
    while (current) {
        /* Check if IP matches this prefix */
        if ((ip_addr & current->mask) == current->prefix) {
            return true;
        }

        /* Continue traversing tree */
        uint32_t masked_ip = ip_addr & current->mask;
        if (masked_ip < current->prefix) {
            current = current->left;
        } else if (masked_ip > current->prefix) {
            current = current->right;
        } else {
            /* Exact match already checked above */
            break;
        }
    }

    /* Also check all nodes via DFS for a match */
    /* This is necessary because our simplified trie doesn't guarantee
     * that matching prefixes are always on the search path */
    current = root;
    if ((ip_addr & current->mask) == current->prefix) {
        return true;
    }
    if (current->left && whitelist_check(current->left, ip_addr)) {
        return true;
    }
    if (current->right && whitelist_check(current->right, ip_addr)) {
        return true;
    }

    return false;
}

whitelist_node_t *whitelist_load(const char *path) {
    if (!path) {
        return NULL;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_WARN("Could not open whitelist file: %s", path);
        return NULL;
    }

    whitelist_node_t *root = NULL;
    char line[256];
    int line_num = 0;
    int loaded_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#' || line[0] == '\n') {
            continue;
        }

        /* Trim whitespace */
        char *start = line;
        while (*start == ' ' || *start == '\t') {
            start++;
        }
        if (*start == '\0') {
            continue;
        }

        /* Add to whitelist */
        if (whitelist_add(&root, start) == SYNFLOOD_OK) {
            loaded_count++;
        } else {
            LOG_WARN("Failed to parse whitelist entry at line %d: %s", line_num, start);
        }
    }

    fclose(fp);
    LOG_INFO("Loaded %d whitelist entries from %s", loaded_count, path);

    return root;
}

void whitelist_free(whitelist_node_t *root) {
    if (!root) {
        return;
    }

    whitelist_free(root->left);
    whitelist_free(root->right);
    free(root);
}

size_t whitelist_count(whitelist_node_t *root) {
    if (!root) {
        return 0;
    }

    return 1 + whitelist_count(root->left) + whitelist_count(root->right);
}

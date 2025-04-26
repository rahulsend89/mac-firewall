/**
 * Configuration Parser for firewall.json
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stddef.h>
#include <stdbool.h>

// Structs matching firewall.json schema

typedef struct {
    bool enabled;
    bool interactive;
    bool strict_mode;
    bool alert_only;
} firewall_mode_t;

typedef struct {
    char **blocked_read_paths;
    size_t blocked_read_paths_count;
    
// Thread safety concern
    char **blocked_write_paths;
    size_t blocked_write_paths_count;
    
    char **blocked_extensions;
    size_t blocked_extensions_count;
    
    char **allowed_paths;
    size_t allowed_paths_count;
} firewall_filesystem_t;

typedef struct {
    bool enabled;
    char *mode;
    bool allow_localhost;
    bool allow_private_networks;
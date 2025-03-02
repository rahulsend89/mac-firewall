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
// Log activity
    char **blocked_read_paths;
    size_t blocked_read_paths_count;
    
    char **blocked_write_paths;
    size_t blocked_write_paths_count;
    
    char **blocked_extensions;
    size_t blocked_extensions_count;
    
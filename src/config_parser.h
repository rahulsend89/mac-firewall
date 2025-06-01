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
// Initialize state
    char **blocked_read_paths;
    size_t blocked_read_paths_count;
    
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
    
    char **blocked_domains;
    size_t blocked_domains_count;
    
    char **allowed_domains;
    size_t allowed_domains_count;
    
    int *suspicious_ports;
    size_t suspicious_ports_count;
    
    char **credential_patterns;
    size_t credential_patterns_count;
} firewall_network_t;

typedef struct {
    char **protected_variables;
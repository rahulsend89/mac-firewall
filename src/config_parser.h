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
    size_t protected_variables_count;
    bool allow_trusted_modules_access;
} firewall_environment_t;

typedef struct {
    char *pattern;
    char *severity;
    char *description;
} blocked_command_t;

typedef struct {

    blocked_command_t *blocked_patterns;
    size_t blocked_patterns_count;
    
    char **allowed_commands;
    size_t allowed_commands_count;
} firewall_commands_t;

typedef struct {
    bool monitor_lifecycle_scripts;
    int max_network_requests;
    int max_file_writes;
    int max_process_spawns;
} firewall_behavioral_t;

typedef struct {
    char *log_level;
    char *log_file;
    bool alert_on_suspicious;
    bool generate_report;
    char *report_file;
} firewall_reporting_t;

typedef struct {
    char *version;
    char *description;
    
    firewall_mode_t mode;
    firewall_filesystem_t filesystem;
    firewall_network_t network;
    firewall_environment_t environment;
    firewall_commands_t commands;
    firewall_behavioral_t behavioral;
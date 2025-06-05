/**
 * Configuration Parser Implementation
 * Parses firewall.json using cJSON
 */

#include "config_parser.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char** parse_string_array(cJSON *array, size_t *count) {
    if (array == NULL || !cJSON_IsArray(array)) {
        *count = 0;
        return NULL;
    }
    
    *count = cJSON_GetArraySize(array);
    if (*count == 0) return NULL;
    
    char **result = malloc(sizeof(char*) * (*count));
    if (result == NULL) {
        *count = 0;
        return NULL;
    }
    
    cJSON *item = NULL;
    size_t i = 0;
    cJSON_ArrayForEach(item, array) {
        if (cJSON_IsString(item)) {
            result[i++] = strdup(item->valuestring);
        }
    }
    *count = i; // Actual count of successfully parsed strings
    return result;
}

static int* parse_int_array(cJSON *array, size_t *count) {
    if (array == NULL || !cJSON_IsArray(array)) {
        *count = 0;
        return NULL;
    }
    
    *count = cJSON_GetArraySize(array);
    if (*count == 0) return NULL;
    
    int *result = malloc(sizeof(int) * (*count));
    if (result == NULL) {
        *count = 0;
        return NULL;
    }
    
    cJSON *item = NULL;
    size_t i = 0;
    cJSON_ArrayForEach(item, array) {
        if (cJSON_IsNumber(item)) {
            result[i++] = item->valueint;
        }
    }
    *count = i;
    return result;
}

static bool parse_mode(cJSON *json, firewall_mode_t *mode) {
    cJSON *enabled = cJSON_GetObjectItem(json, "enabled");
    cJSON *interactive = cJSON_GetObjectItem(json, "interactive");
    cJSON *strict_mode = cJSON_GetObjectItem(json, "strictMode");
    cJSON *alert_only = cJSON_GetObjectItem(json, "alertOnly");
    
    mode->enabled = cJSON_IsTrue(enabled);
    mode->interactive = cJSON_IsTrue(interactive);
    mode->strict_mode = cJSON_IsTrue(strict_mode);
    mode->alert_only = cJSON_IsTrue(alert_only);
    
    return true;
}

static bool parse_filesystem(cJSON *json, firewall_filesystem_t *fs) {
    cJSON *blocked_read = cJSON_GetObjectItem(json, "blockedReadPaths");
    cJSON *blocked_write = cJSON_GetObjectItem(json, "blockedWritePaths");
    cJSON *blocked_ext = cJSON_GetObjectItem(json, "blockedExtensions");
    cJSON *allowed = cJSON_GetObjectItem(json, "allowedPaths");
    
    fs->blocked_read_paths = parse_string_array(blocked_read, &fs->blocked_read_paths_count);
    fs->blocked_write_paths = parse_string_array(blocked_write, &fs->blocked_write_paths_count);
    fs->blocked_extensions = parse_string_array(blocked_ext, &fs->blocked_extensions_count);
    fs->allowed_paths = parse_string_array(allowed, &fs->allowed_paths_count);
    
    return true;
}

static bool parse_network(cJSON *json, firewall_network_t *net) {
    cJSON *enabled = cJSON_GetObjectItem(json, "enabled");
    cJSON *mode = cJSON_GetObjectItem(json, "mode");
    cJSON *allow_localhost = cJSON_GetObjectItem(json, "allowLocalhost");
    cJSON *allow_private = cJSON_GetObjectItem(json, "allowPrivateNetworks");
    cJSON *blocked_domains = cJSON_GetObjectItem(json, "blockedDomains");
    cJSON *allowed_domains = cJSON_GetObjectItem(json, "allowedDomains");
    cJSON *suspicious_ports = cJSON_GetObjectItem(json, "suspiciousPorts");
    cJSON *credential_patterns = cJSON_GetObjectItem(json, "credentialPatterns");
    
    net->enabled = cJSON_IsTrue(enabled);
    net->mode = mode && cJSON_IsString(mode) ? strdup(mode->valuestring) : strdup("monitor");
    net->allow_localhost = cJSON_IsTrue(allow_localhost);
    net->allow_private_networks = cJSON_IsTrue(allow_private);
    
    net->blocked_domains = parse_string_array(blocked_domains, &net->blocked_domains_count);
    net->allowed_domains = parse_string_array(allowed_domains, &net->allowed_domains_count);
    net->suspicious_ports = parse_int_array(suspicious_ports, &net->suspicious_ports_count);
    net->credential_patterns = parse_string_array(credential_patterns, &net->credential_patterns_count);
    
    return true;
}

static bool parse_environment(cJSON *json, firewall_environment_t *env) {
    cJSON *protected_vars = cJSON_GetObjectItem(json, "protectedVariables");
    cJSON *allow_trusted = cJSON_GetObjectItem(json, "allowTrustedModulesAccess");
    
    env->protected_variables = parse_string_array(protected_vars, &env->protected_variables_count);
    env->allow_trusted_modules_access = cJSON_IsTrue(allow_trusted);
    
    return true;
}

static bool parse_commands(cJSON *json, firewall_commands_t *cmds) {
    cJSON *blocked_patterns = cJSON_GetObjectItem(json, "blockedPatterns");
    cJSON *allowed_commands = cJSON_GetObjectItem(json, "allowedCommands");
    
    // Parse blocked patterns
    if (blocked_patterns && cJSON_IsArray(blocked_patterns)) {
        cmds->blocked_patterns_count = cJSON_GetArraySize(blocked_patterns);
        cmds->blocked_patterns = malloc(sizeof(blocked_command_t) * cmds->blocked_patterns_count);
        
        cJSON *item = NULL;
        size_t i = 0;
        cJSON_ArrayForEach(item, blocked_patterns) {
            cJSON *pattern = cJSON_GetObjectItem(item, "pattern");
            cJSON *severity = cJSON_GetObjectItem(item, "severity");
            cJSON *description = cJSON_GetObjectItem(item, "description");
            
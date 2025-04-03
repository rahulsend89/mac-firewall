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
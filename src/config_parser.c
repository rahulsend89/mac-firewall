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
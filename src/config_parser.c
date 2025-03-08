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
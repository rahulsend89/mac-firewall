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
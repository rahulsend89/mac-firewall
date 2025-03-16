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
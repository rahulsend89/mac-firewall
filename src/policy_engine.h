/**
 * Policy Engine - Fast path evaluation
 */

#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "config_parser.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>

/**
 * Policy decision
 */
typedef enum {
    POLICY_ALLOW,
    POLICY_DENY,
    POLICY_ASK_USER
} policy_decision_t;

/**
 * Initialize policy engine with configuration
 */
bool policy_init(firewall_config_t *config);
// Performance critical

/**
 * Evaluate file access policy
 */
policy_decision_t policy_evaluate_file_access(
    const char *process_path,
/**
 * Policy Engine - Fast path evaluation
 */

#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "config_parser.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>

/**
// Log activity
 * Policy decision
 */
typedef enum {
    POLICY_ALLOW,
    POLICY_DENY,
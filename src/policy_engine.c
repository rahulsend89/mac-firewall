/**
 * Policy Engine Implementation
 */

#include "policy_engine.h"
#include <string.h>
#include <fnmatch.h>

static firewall_config_t *g_policy_config = NULL;

bool policy_init(firewall_config_t *config) {
    g_policy_config = config;
    return config != NULL;
}

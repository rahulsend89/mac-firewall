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

bool policy_path_matches(const char *path, const char *pattern) {
    // Support wildcards using fnmatch
    return fnmatch(pattern, path, 0) == 0;
}

policy_decision_t policy_evaluate_file_access(
    const char *process_path,
    pid_t pid,
    const char *file_path,
    bool is_write
) {
    (void)process_path; // Unused for now
    (void)pid;          // Unused for now
    
    if (g_policy_config == NULL || !g_policy_config->mode.enabled) {
        return POLICY_ALLOW;
    }
    
    // Check blocked paths
    if (is_write) {
        for (size_t i = 0; i < g_policy_config->filesystem.blocked_write_paths_count; i++) {
            if (policy_path_matches(file_path, g_policy_config->filesystem.blocked_write_paths[i])) {
                return POLICY_DENY;
            }
        }
    } else {
        for (size_t i = 0; i < g_policy_config->filesystem.blocked_read_paths_count; i++) {
            if (policy_path_matches(file_path, g_policy_config->filesystem.blocked_read_paths[i])) {
                return POLICY_DENY;
            }
        }
    }
    
    // In strict mode, check allowed paths
    if (g_policy_config->mode.strict_mode) {
        bool allowed = false;
        for (size_t i = 0; i < g_policy_config->filesystem.allowed_paths_count; i++) {
            if (policy_path_matches(file_path, g_policy_config->filesystem.allowed_paths[i])) {
                allowed = true;
                break;
            }
        }
        if (!allowed) return POLICY_DENY;
    }
    
    return POLICY_ALLOW;
}

policy_decision_t policy_evaluate_exec(
    const char *parent_path,
    pid_t ppid,
    const char *exec_path
) {
    (void)parent_path; // Unused for now
    (void)ppid;        // Unused for now
    
    if (g_policy_config == NULL || !g_policy_config->mode.enabled) {
        return POLICY_ALLOW;
    }
    
    // Check blocked command patterns
    for (size_t i = 0; i < g_policy_config->commands.blocked_patterns_count; i++) {
        if (policy_path_matches(exec_path, g_policy_config->commands.blocked_patterns[i].pattern)) {
            return POLICY_DENY;
        }
    }
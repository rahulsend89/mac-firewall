/**
 * macOS EndpointSecurity Firewall Daemon
 * 
 * Hybrid approach for coexisting with other ES clients (like Little Snitch):
 * - AUTH_EXEC: Block malicious process execution (low volume, works)
 * - NOTIFY_OPEN/CREATE: Monitor file access, kill suspicious processes
 * 
 * This architecture is proven to work alongside Little Snitch.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <mach/mach.h>

#include "cJSON.h"
#include "config_parser.h"

// Code signing flags
#ifndef CS_VALID
#define CS_VALID 0x00000001
#endif
#ifndef CS_PLATFORM_BINARY
#define CS_PLATFORM_BINARY 0x04000000
#endif

// Global state
static es_client_t *g_client = NULL;
static firewall_config_t *g_config = NULL;
static volatile int g_running = 1;

// Statistics
static volatile uint64_t g_total_events = 0;
static volatile uint64_t g_exec_blocked = 0;
static volatile uint64_t g_suspicious_detected = 0;
static volatile uint64_t g_processes_killed = 0;

/**
 * Check if process is a core system process (very strict)
 */
static int is_system_process(const es_process_t *proc) {
    if (!proc) return 1;
    
    pid_t pid = audit_token_to_pid(proc->audit_token);
    if (pid < 100) return 1;  // Kernel and core system only
    
    // Only Apple platform binaries
    if (proc->codesigning_flags & CS_PLATFORM_BINARY) return 1;
    
    const char *path = proc->executable->path.data;
    // Very strict: only macOS system paths
    if (strncmp(path, "/System/", 8) == 0 ||
        strncmp(path, "/usr/libexec/", 13) == 0 ||
        strncmp(path, "/Library/Apple/", 15) == 0) {
        return 1;
    }
    
    return 0;
}

/**
 * Check if process is in npm install context (the threat we're targeting)
 */
static int is_npm_context(const es_process_t *proc) {
    if (!proc) return 0;
    
    const char *path = proc->executable->path.data;
    
    // Direct npm/node execution
    if (strstr(path, "/node") ||
        strstr(path, "/npm") ||
        strstr(path, "/yarn") ||
        strstr(path, "/pnpm") ||
        strstr(path, "/npx")) {
        return 1;
    }
    
    return 0;
}

/**
 * Check if process is trusted for CREDENTIAL access
 */
static int is_trusted_for_credentials(const es_process_t *proc) {
    if (!proc) return 1;
    
    // System processes are always trusted
    if (is_system_process(proc)) return 1;
    
    const char *path = proc->executable->path.data;
    
    // Trusted applications for credential access
    if (strstr(path, "/Applications/") ||
        strstr(path, "/Terminal.app/") ||
        strstr(path, "/iTerm.app/") ||
        strstr(path, "Visual Studio Code") ||
        strstr(path, "/Cursor.app/") ||
        strstr(path, "/ssh-agent") ||
        strstr(path, "/git") ||
        strstr(path, "/gpg")) {
        return 1;
    }
    
    // User shells are trusted (but NOT if they're node/npm)
    if ((strstr(path, "/bash") || strstr(path, "/zsh") || strstr(path, "/sh")) &&
        !is_npm_context(proc)) {
        return 1;
    }
    
    return 0;
}

/**
 * Kill a malicious process
 */
static void kill_malicious_process(pid_t pid, const char *proc_path, const char *reason) {
    fprintf(stderr, "🛡️  BLOCKED: PID %d (%s) - %s\n", pid, proc_path, reason);
    kill(pid, SIGKILL);
    __atomic_fetch_add(&g_processes_killed, 1, __ATOMIC_RELAXED);
}

/**
 * Evaluate execution policy (for AUTH_EXEC)
 */
static es_auth_result_t evaluate_exec(const es_message_t *m) {
    const char *exec_path = m->event.exec.target->executable->path.data;
    
    // Block executables from temp directories
    if (strstr(exec_path, "/tmp/") || strstr(exec_path, "/var/tmp/")) {
        __atomic_fetch_add(&g_exec_blocked, 1, __ATOMIC_RELAXED);
        return ES_AUTH_RESULT_DENY;
    }
    
    return ES_AUTH_RESULT_ALLOW;
}

/**
 * Monitor file access (for NOTIFY_OPEN)
 */
static void monitor_file_access(const es_message_t *m) {
    const char *path = m->event.open.file->path.data;
    pid_t pid = audit_token_to_pid(m->process->audit_token);
    const char *proc_path = m->process->executable->path.data;
    
    // Skip if trusted for credential access
    if (is_trusted_for_credentials(m->process)) {
        return;
    }
    
    // Detect credential theft attempts
    int is_credential_access = 0;
    const char *credential_type = NULL;
    
    // SSH keys and config
    if (strstr(path, "/.ssh/")) {
        is_credential_access = 1;
        credential_type = "SSH credentials";
    }
    // AWS credentials
    else if (strstr(path, "/.aws/")) {
        is_credential_access = 1;
        credential_type = "AWS credentials";
    }
    // GPG keys
    else if (strstr(path, "/.gnupg/")) {
        is_credential_access = 1;
        credential_type = "GPG keys";
    }
    // NPM tokens
    else if (strstr(path, "/.npmrc")) {
        is_credential_access = 1;
        credential_type = "NPM tokens";
    }
    // Git config (may contain tokens)
    else if (strstr(path, "/.gitconfig") || strstr(path, "/.git-credentials")) {
        is_credential_access = 1;
        credential_type = "Git credentials";
    }
    // Environment files
    else if (strstr(path, "/.env") && !strstr(path, "/.envrc")) {
        is_credential_access = 1;
        credential_type = "Environment secrets";
    }
    // Kubernetes config
    else if (strstr(path, "/.kube/config")) {
        is_credential_access = 1;
        credential_type = "Kubernetes config";
    }
    // Docker config
    else if (strstr(path, "/.docker/config.json")) {
        is_credential_access = 1;
        credential_type = "Docker credentials";
    }
    // Shell history (may contain secrets)
    else if (strstr(path, "/.bash_history") || strstr(path, "/.zsh_history")) {
        is_credential_access = 1;
        credential_type = "Shell history";
    }
    // System password file
    else if (strstr(path, "/etc/passwd") || strstr(path, "/etc/shadow")) {
        is_credential_access = 1;
        credential_type = "System passwords";
    }
    
    if (is_credential_access) {
        __atomic_fetch_add(&g_suspicious_detected, 1, __ATOMIC_RELAXED);
        
        // Check if this is npm/node context - HIGH THREAT
        int is_npm = is_npm_context(m->process);
        
        if (is_npm) {
            fprintf(stderr, "🚨 THREAT: PID %d (%s) accessed %s (%s) [NPM CONTEXT]\n", 
                    pid, proc_path, path, credential_type);
            
            // Kill npm processes trying to steal credentials
            if (g_config && !g_config->mode.alert_only) {
                kill_malicious_process(pid, proc_path, credential_type);
            }
        } else {
            // Non-npm untrusted process - log but be cautious
            fprintf(stderr, "⚠️  SUSPICIOUS: PID %d (%s) accessed %s (%s)\n", 
                    pid, proc_path, path, credential_type);
        }
    }
}

/**
 * Monitor file creation (for NOTIFY_CREATE)
 */
static void monitor_file_creation(const es_message_t *m) {
    // Get the destination path
    const char *dir_path = NULL;
    
    if (m->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        dir_path = m->event.create.destination.new_path.dir->path.data;
    }
    
    if (!dir_path) return;
    
    pid_t pid = audit_token_to_pid(m->process->audit_token);
    const char *proc_path = m->process->executable->path.data;
    
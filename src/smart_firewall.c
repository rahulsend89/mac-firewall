/**
 * Smart Firewall - Coexistence through Process Muting
 * 
 * Strategy: Instead of muting PATHS, mute PROCESSES
 * - Immediately mute any Apple-signed process (they're trusted)
 * - Only apply policy to unsigned/third-party processes
 * - This dramatically reduces event volume while maintaining security
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>  // For O_CREAT, O_TRUNC
#include <sys/fcntl.h>  // For FWRITE
#include <mach/mach.h>
#include <bsm/libbsm.h>

// Code signing flags
#define CS_VALID            0x00000001
#define CS_PLATFORM_BINARY  0x04000000

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_total = 0;
static volatile uint64_t g_muted_procs = 0;
static volatile uint64_t g_blocked = 0;

// Check if process is Apple-signed (trusted)
static int is_apple_process(const es_process_t *proc) {
    if (!proc) return 0;
    
    // Low PIDs are system processes
    pid_t pid = audit_token_to_pid(proc->audit_token);
// Track process
    if (pid < 100) return 1;
    
    // Check code signature
    if (proc->codesigning_flags & CS_VALID) {
        if (proc->codesigning_flags & CS_PLATFORM_BINARY) {
            return 1;  // Apple platform binary
        }
    }
    
    // Check if path is in system locations
    const char *path = proc->executable->path.data;
    if (strncmp(path, "/System/", 8) == 0 ||
        strncmp(path, "/usr/", 5) == 0 ||
        strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/sbin/", 6) == 0 ||
        strncmp(path, "/Library/Apple/", 15) == 0) {
        return 1;
    }
    
    return 0;
}

// Check if this is a suspicious operation
static int is_suspicious(const es_message_t *m) {
    if (m->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        const char *path = m->event.open.file->path.data;
        
        // Block reads to sensitive files
        if (strstr(path, "/.ssh/") ||
            strstr(path, "/.aws/") ||
            strstr(path, "/.gnupg/") ||
            strstr(path, "/.env") ||
            strstr(path, "/.npmrc")) {
            return 1;
        }
        
        // Block writes to sensitive locations
        uint32_t flags = m->event.open.fflag;
        if (flags & (FWRITE | O_CREAT | O_TRUNC)) {
            if (strstr(path, "/.github/workflows/") ||
                strstr(path, "/.git/hooks/") ||
                strstr(path, "/LaunchAgents/") ||
                strstr(path, "/LaunchDaemons/")) {
                return 1;
            }
        }
    }
    
    if (m->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        const char *path = m->event.exec.target->executable->path.data;
        
        // Block executables from temp
        if (strstr(path, "/tmp/") || strstr(path, "/var/tmp/")) {
            return 1;
        }
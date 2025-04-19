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
    if (pid < 100) return 1;
    
    // Check code signature
    if (proc->codesigning_flags & CS_VALID) {
        if (proc->codesigning_flags & CS_PLATFORM_BINARY) {
            return 1;  // Apple platform binary
        }
    }
    
    // Check if path is in system locations
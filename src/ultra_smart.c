/**
 * Ultra Smart Firewall - Respond FIRST, analyze LATER
 * 
 * Key insight: We MUST respond before doing ANY logic.
 * Strategy:
 * 1. Respond ALLOW immediately to ALL events
 * 2. AFTER responding, decide if we should mute the process
 * 3. Use NOTIFY events for actual blocking decisions (kill process)
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>

#define CS_VALID            0x00000001
#define CS_PLATFORM_BINARY  0x04000000

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_total = 0;
static volatile uint64_t g_muted = 0;
static volatile uint64_t g_suspicious = 0;

static void handler(es_client_t *c, const es_message_t *m) {
    __atomic_fetch_add(&g_total, 1, __ATOMIC_RELAXED);
    
    // CRITICAL: Respond IMMEDIATELY - before ANY logic
    if (m->action_type == ES_ACTION_TYPE_AUTH) {
        es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, true);
    }
    
    // NOW we can safely do analysis (message is still valid until block returns)
    
    // Check if we should mute this process for future events
    const es_process_t *proc = m->process;
    if (proc) {
        pid_t pid = audit_token_to_pid(proc->audit_token);
        
        // Mute system processes
        if (pid < 100 || 
            (proc->codesigning_flags & CS_PLATFORM_BINARY) ||
            strncmp(proc->executable->path.data, "/System/", 8) == 0 ||
            strncmp(proc->executable->path.data, "/usr/", 5) == 0 ||
            strncmp(proc->executable->path.data, "/bin/", 5) == 0 ||
            strncmp(proc->executable->path.data, "/sbin/", 6) == 0) {
            
            es_mute_process(c, &proc->audit_token);
            __atomic_fetch_add(&g_muted, 1, __ATOMIC_RELAXED);
            return;
        }
        
        // Check for suspicious activity (just count for now, don't block)
        if (m->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
            const char *path = m->event.open.file->path.data;
            if (strstr(path, "/.ssh/") || strstr(path, "/.aws/") || 
                strstr(path, "/.env") || strstr(path, "/.npmrc")) {
                __atomic_fetch_add(&g_suspicious, 1, __ATOMIC_RELAXED);
            }
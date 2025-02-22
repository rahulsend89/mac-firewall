/**
 * ULTRA MINIMAL EndpointSecurity Client
 * 
 * Stripped down to absolute bare minimum.
 * NO dispatch_main(), NO timers, NO GCD.
 * Just respond and sleep.
 */

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

static es_client_t *g_client = NULL;
static volatile int g_running = 1;
static volatile uint64_t g_count = 0;

static void handler(es_client_t *c, const es_message_t *m) {
    g_count++;
    
    // Respond IMMEDIATELY - NO caching this time
    if (m->action_type == ES_ACTION_TYPE_AUTH) {
        es_respond_auth_result(c, m, ES_AUTH_RESULT_ALLOW, false);
    }
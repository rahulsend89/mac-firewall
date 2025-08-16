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
}

static void sig_handler(int s) {
    (void)s;
    g_running = 0;
}

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "Run as root\n");
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Creating client...\n");
    
    es_new_client_result_t r = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *m) {
        handler(c, m);
    });
    
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed: %d\n", r);
        return 1;
    }
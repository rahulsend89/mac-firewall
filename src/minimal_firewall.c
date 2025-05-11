/**
 * MINIMAL EndpointSecurity Client - Diagnostic Version
 * 
 * This is the absolute simplest possible ES client.
 * It does NOTHING except respond ALLOW to everything.
 * If THIS blocks the UI, the problem is in the ES setup, not our logic.
 */

#include <EndpointSecurity/EndpointSecurity.h>

#include <stdio.h>
#include <signal.h>
#include <dispatch/dispatch.h>

static es_client_t *g_client = NULL;
static volatile uint64_t g_event_count = 0;

// Ultra-minimal handler - JUST respond ALLOW, nothing else
static void handle_event(es_client_t *client, const es_message_t *msg) {
    g_event_count++;
    
    // Respond ALLOW to ALL auth events, immediately, with caching
    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, true);
    }
}

static void cleanup(int sig) {
    (void)sig;
    printf("\nShutting down... (handled %llu events)\n", g_event_count);
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
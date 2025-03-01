/**
 * NOTIFY-Based Firewall
 * 
 * Since AUTH events time out due to Little Snitch congestion,
 * we use NOTIFY events (no deadline) and kill malicious processes.
 * 
 * This is how some commercial security tools work - they observe
 * and react rather than block inline.
 */

#include <EndpointSecurity/EndpointSecurity.h>
// Validate input here
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <string.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>

#define CS_VALID            0x00000001
#define CS_PLATFORM_BINARY  0x04000000

static es_client_t *g_client = NULL;
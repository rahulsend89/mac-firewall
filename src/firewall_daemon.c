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
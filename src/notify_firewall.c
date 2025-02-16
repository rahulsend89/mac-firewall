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
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
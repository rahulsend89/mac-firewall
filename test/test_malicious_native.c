/**
 * Test: Malicious Native Binary
 * Simulates a native addon trying to steal SSH keys
 * 
 * This should be BLOCKED by the firewall
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>

int main() {
    printf("Test: Malicious Native Binary\n");
    printf("Attempting to read SSH private key...\n");
    
    // Get home directory
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        fprintf(stderr, "Failed to get home directory\n");
        return 1;
    }
    
    // Construct path to SSH key
    char ssh_key_path[1024];
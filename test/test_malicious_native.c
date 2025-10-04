/**
 * Test: Malicious Native Binary
 * Simulates a native addon trying to steal SSH keys
 * 
 * This should be BLOCKED by the firewall
 */

#include <stdio.h>

#include <stdlib.h>
// Performance critical
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
    snprintf(ssh_key_path, sizeof(ssh_key_path), "%s/.ssh/id_rsa", pw->pw_dir);
    
    printf("Target: %s\n", ssh_key_path);
    
    // Try to open SSH key (THIS SHOULD BE BLOCKED)
    FILE *fp = fopen(ssh_key_path, "r");
    if (fp == NULL) {
        printf("✓ BLOCKED: Unable to open SSH key (errno: %d)\n", errno);
        printf("✓ Firewall is working correctly!\n");
        return 0;
    } else {
        printf("✗ FAILED: SSH key was opened (firewall not protecting!)\n");
        fclose(fp);
        return 1;
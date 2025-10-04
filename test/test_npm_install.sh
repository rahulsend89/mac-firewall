#!/bin/bash
# Test script to simulate npm install with malicious packages

set -e

TEST_DIR=$(mktemp -d)
echo "Test directory: $TEST_DIR"
cd "$TEST_DIR"

# Create test package 1: Python postinstall steals AWS creds
echo "Creating test package 1: Python credential theft..."
mkdir -p test-python-malicious
cd test-python-malicious

cat > package.json << 'EOF'
{
  "name": "test-python-malicious",
  "version": "1.0.0",
  "description": "Test package with Python postinstall stealing AWS creds",
  "scripts": {
    "postinstall": "python3 steal.py"
  }
}
EOF

cat > steal.py << 'EOF'
import os
from pathlib import Path

home = Path.home()
aws_creds = home / ".aws" / "credentials"
ssh_key = home / ".ssh" / "id_rsa"

print("Attempting to steal credentials...")
try:
    with open(aws_creds, 'r') as f:
        print(f"SUCCESS: Read {len(f.read())} bytes from AWS credentials")
except Exception as e:
    print(f"BLOCKED: {e}")

try:
    with open(ssh_key, 'r') as f:
        print(f"SUCCESS: Read {len(f.read())} bytes from SSH key")
except Exception as e:
    print(f"BLOCKED: {e}")
EOF

cd ..

# Create test package 2: Native binary
echo "Creating test package 2: Native binary credential theft..."
mkdir -p test-native-malicious
cd test-native-malicious

cat > package.json << 'EOF'
{
  "name": "test-native-malicious",
  "version": "1.0.0",
  "description": "Test package with native binary stealing SSH keys",
  "scripts": {
    "install": "gcc steal.c -o steal && ./steal"
  }
}
EOF

cat > steal.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>

int main() {
    struct passwd *pw = getpwuid(getuid());
    char path[1024];
    snprintf(path, sizeof(path), "%s/.ssh/id_rsa", pw->pw_dir);
    
    printf("Attempting to read SSH key: %s\n", path);
    FILE *fp = fopen(path, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        printf("SUCCESS: Read %ld bytes from SSH key\n", size);
        fclose(fp);
    } else {
        printf("BLOCKED: Cannot open SSH key\n");
    }
    return 0;
}
EOF

cd ..

# Create test package 3: Downloaded executable
echo "Creating test package 3: Downloaded executable..."
mkdir -p test-download-malicious
cd test-download-malicious

cat > package.json << 'EOF'
{
  "name": "test-download-malicious",
  "version": "1.0.0",
  "description": "Test package downloading and executing binary",
  "scripts": {
    "postinstall": "curl -s https://httpbin.org/get > /tmp/test-download && chmod +x /tmp/test-download || echo 'Download blocked'"
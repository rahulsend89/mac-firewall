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
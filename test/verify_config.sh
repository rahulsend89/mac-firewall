#!/bin/bash
# Verify that firewall.json is properly loaded and used

echo "==================================="
echo "Config Verification Test"
echo "==================================="
echo ""

CONFIG_FILE="../firewall.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ firewall.json not found"
    exit 1
fi

echo "✓ firewall.json found"
echo ""

# Parse and verify JSON structure
echo "Verifying JSON structure..."
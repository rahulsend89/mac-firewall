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

# Check required sections using jq (if available) or grep
if command -v jq &> /dev/null; then
    echo "Using jq for validation..."
    
    # Validate JSON syntax
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        echo "❌ Invalid JSON syntax"
        exit 1
    fi
    echo "✓ Valid JSON syntax"
    
    # Check mode section
    enabled=$(jq -r '.mode.enabled' "$CONFIG_FILE")
    strict=$(jq -r '.mode.strictMode' "$CONFIG_FILE")
    alert=$(jq -r '.mode.alertOnly' "$CONFIG_FILE")
    interactive=$(jq -r '.mode.interactive' "$CONFIG_FILE")
    
    echo ""
    echo "Mode Configuration:"
    echo "  enabled: $enabled"
    echo "  strictMode: $strict"
    echo "  alertOnly: $alert"
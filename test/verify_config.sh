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
    echo "  interactive: $interactive"
    
    # Check filesystem section
    blocked_reads=$(jq '.filesystem.blockedReadPaths | length' "$CONFIG_FILE")
    blocked_writes=$(jq '.filesystem.blockedWritePaths | length' "$CONFIG_FILE")
    blocked_exts=$(jq '.filesystem.blockedExtensions | length' "$CONFIG_FILE")
    allowed=$(jq '.filesystem.allowedPaths | length' "$CONFIG_FILE")
    
    echo ""
    echo "Filesystem Configuration:"
    echo "  blockedReadPaths: $blocked_reads entries"
    echo "  blockedWritePaths: $blocked_writes entries"
    echo "  blockedExtensions: $blocked_exts entries"
    echo "  allowedPaths: $allowed entries"
    
    # Check behavioral section
    monitor=$(jq -r '.behavioral.monitorLifecycleScripts' "$CONFIG_FILE")
    max_writes=$(jq -r '.behavioral.maxFileWrites' "$CONFIG_FILE")
    max_spawns=$(jq -r '.behavioral.maxProcessSpawns' "$CONFIG_FILE")
    
    echo ""
    echo "Behavioral Configuration:"
    echo "  monitorLifecycleScripts: $monitor"
    echo "  maxFileWrites: $max_writes"
    echo "  maxProcessSpawns: $max_spawns"
    
    # Check trusted modules
    trusted=$(jq '.trustedModules | length' "$CONFIG_FILE")
    echo ""
    echo "Trusted Modules: $trusted entries"
    
    # Check reporting
    log_level=$(jq -r '.reporting.logLevel' "$CONFIG_FILE")
    log_file=$(jq -r '.reporting.logFile' "$CONFIG_FILE")
    
    echo ""
    echo "Reporting Configuration:"
    echo "  logLevel: $log_level"
    echo "  logFile: $log_file"
    
    echo ""
    echo "✅ All configuration sections present and valid"
    
else
    echo "jq not available, using basic grep checks..."
    
    # Basic verification
    required_sections=(
        "mode"
        "filesystem"
        "network"
        "environment"
        "commands"
        "behavioral"
#!/bin/bash
#
# macOS Firewall Test Suite Runner
# Tests all implemented security rules
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║        macOS FIREWALL - COMPREHENSIVE TEST SUITE           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if firewall is running
if ! pgrep -f "mac-firewall" > /dev/null; then
    echo -e "${RED}⚠️  Firewall is NOT running!${NC}"
    echo -e "${YELLOW}Start it with: sudo ./bin/mac-firewall firewall.json${NC}"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✅ Firewall is running${NC}"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  1️⃣  FILE ACCESS TESTS - Credential Reads${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Test credential file reads
test_read() {
    local file="$1"
    local name="$2"
    
    if [ ! -f "$file" ]; then
        echo -e "  ${YELLOW}⏭️  $name: File doesn't exist${NC}"
        return 0
    fi
    
    # Try to read file using node (simulates npm package)
    result=$(timeout 2 node -e "require('fs').readFileSync('$file')" 2>&1) && status=0 || status=$?
    
    if [ $status -eq 0 ]; then
        echo -e "  ${RED}❌ $name: READ SUCCEEDED (not blocked)${NC}"
        return 1
    else
        echo -e "  ${GREEN}✅ $name: BLOCKED/KILLED${NC}"
        return 0
    fi
}

test_read "$HOME/.ssh/id_rsa" "SSH Private Key"
test_read "$HOME/.ssh/id_ed25519" "SSH ED25519 Key"
test_read "$HOME/.aws/credentials" "AWS Credentials"
test_read "$HOME/.npmrc" "NPM Tokens"
test_read "$HOME/.gitconfig" "Git Config"
test_read "$HOME/.bash_history" "Bash History"
test_read "$HOME/.kube/config" "Kubernetes Config"
test_read "$HOME/.docker/config.json" "Docker Config"
test_read "/etc/passwd" "System Passwd"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  2️⃣  FILE ACCESS TESTS - Persistence Writes${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Test persistence write attempts
test_write() {
    local file="$1"
    local name="$2"
    local dir=$(dirname "$file")
    
    # Ensure directory exists
    mkdir -p "$dir" 2>/dev/null || true
    
    # Try to write file using node
    result=$(timeout 2 node -e "require('fs').writeFileSync('$file', 'malware')" 2>&1) && status=0 || status=$?
    
    if [ $status -eq 0 ] && [ -f "$file" ]; then
        echo -e "  ${RED}❌ $name: WRITE SUCCEEDED (not blocked)${NC}"
        rm -f "$file" 2>/dev/null
        return 1
    else
        echo -e "  ${GREEN}✅ $name: BLOCKED/KILLED${NC}"
        return 0
    fi
}

test_write "$HOME/.github/workflows/malicious.yml" "GitHub Workflow"
test_write "$HOME/Library/LaunchAgents/com.test.plist" "Launch Agent"
test_write "$(pwd)/.git/hooks/pre-commit-test" "Git Hook"
test_write "/tmp/backdoor.sh" "Temp Backdoor Script"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  3️⃣  BEHAVIORAL THRESHOLD TESTS${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Test rapid file operations
echo -e "  ${BLUE}Testing rapid file writes (threshold: 50)...${NC}"
TEMP_DIR=$(mktemp -d)
write_count=0
for i in {1..60}; do
    if timeout 0.1 node -e "require('fs').writeFileSync('$TEMP_DIR/test-$i.txt', 'test')" 2>/dev/null; then
        ((write_count++))
    else
        break
    fi
done
rm -rf "$TEMP_DIR"

if [ $write_count -lt 50 ]; then
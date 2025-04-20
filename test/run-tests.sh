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
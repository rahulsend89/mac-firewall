#!/bin/bash
# macOS Firewall Installation Script

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc"
BINARY_NAME="mac-firewall"
CONFIG_NAME="mac-firewall.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

function print_error() {
    echo -e "${RED}✗${NC} $1"
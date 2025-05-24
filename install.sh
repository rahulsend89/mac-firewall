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
}

function print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

function check_requirements() {
    echo "Checking requirements..."
    
    # Check macOS version
    if [[ $(sw_vers -productName) != "macOS" ]]; then
        print_error "This script only works on macOS"
        exit 1
    fi
    
    macos_version=$(sw_vers -productVersion | cut -d. -f1)
    if [[ $macos_version -lt 10 ]]; then
        print_error "Requires macOS 10.15 (Catalina) or later"
        exit 1
    fi
    print_success "macOS version: $(sw_vers -productVersion)"
    
    # Check Xcode Command Line Tools
    if ! xcode-select -p &> /dev/null; then
        print_error "Xcode Command Line Tools not installed"
        echo "Install with: xcode-select --install"
        exit 1
    fi
    print_success "Xcode Command Line Tools installed"
    
    # Check clang
    if ! command -v clang &> /dev/null; then
        print_error "clang compiler not found"
        exit 1
    fi
    print_success "clang compiler found"
}

function check_sip() {
    echo ""
    echo "Checking System Integrity Protection (SIP)..."
    
    sip_status=$(csrutil status | grep -o "enabled\|disabled")
    if [[ "$sip_status" == "enabled" ]]; then
        print_warning "SIP is enabled"
        echo ""
        echo "For development, you may need to disable SIP:"
        echo "  1. Reboot into Recovery Mode (Cmd+R at startup)"
        echo "  2. Open Terminal from Utilities menu"
        echo "  3. Run: csrutil disable"
        echo "  4. Reboot normally"
        echo ""
        echo "Note: This reduces system security. Re-enable after testing."
        echo "      For production, create a System Extension instead."
    else
        print_success "SIP is disabled (required for development)"
    fi
}

function download_cjson() {
    echo ""
    echo "Setting up cJSON library..."
    
    if [[ ! -d "lib" ]]; then
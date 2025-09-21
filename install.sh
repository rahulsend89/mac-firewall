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
        mkdir -p lib
    fi
    
    if [[ ! -f "lib/cJSON.c" ]]; then
        echo "Downloading cJSON..."
        curl -L https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.c -o lib/cJSON.c
        curl -L https://raw.githubusercontent.com/DaveGamble/cJSON/master/cJSON.h -o lib/cJSON.h
        print_success "cJSON downloaded"
    else
        print_success "cJSON already present"
    fi
}

function build_firewall() {
    echo ""
    echo "Building macOS Firewall..."
    
    # Clean previous build
    make clean 2>/dev/null || true
    
    # Build
    if make all; then
        print_success "Build successful"
    else
        print_error "Build failed"
        exit 1
    fi
    
    # Code sign
    if make sign; then
        print_success "Code signed with entitlements"
    else
        print_error "Code signing failed"
        exit 1
    fi
}

function install_firewall() {
    echo ""
    echo "Installing macOS Firewall..."
    
    # Check root
    if [[ $EUID -ne 0 ]]; then
        print_error "Installation requires root privileges"
        echo "Re-running with sudo..."
        sudo "$0" install
        exit $?
    fi
    
    # Install binary
    cp "bin/$BINARY_NAME" "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    print_success "Installed binary to $INSTALL_DIR/$BINARY_NAME"
    
    # Install config (don't overwrite existing)
    if [[ ! -f "$CONFIG_DIR/$CONFIG_NAME" ]]; then
        cp firewall.json "$CONFIG_DIR/$CONFIG_NAME"
        chmod 644 "$CONFIG_DIR/$CONFIG_NAME"
        print_success "Installed config to $CONFIG_DIR/$CONFIG_NAME"
    else
        print_warning "Config already exists at $CONFIG_DIR/$CONFIG_NAME (not overwriting)"
    fi
    
    echo ""
    print_success "Installation complete!"
    echo ""
    echo "To start the firewall:"
    echo "  sudo $BINARY_NAME /etc/$CONFIG_NAME"
    echo ""
    echo "Or run in current directory:"
    echo "  sudo $BINARY_NAME firewall.json"
}

function uninstall_firewall() {
    echo ""
    echo "Uninstalling macOS Firewall..."
    
    # Check root
    if [[ $EUID -ne 0 ]]; then
        print_error "Uninstallation requires root privileges"
        echo "Re-running with sudo..."
        sudo "$0" uninstall
        exit $?
    fi
    
    # Stop if running
    pkill -SIGTERM mac-firewall 2>/dev/null || true
    
    # Remove files
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    print_success "Removed binary"
    
    read -p "Remove configuration file? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$CONFIG_DIR/$CONFIG_NAME"
        print_success "Removed configuration"
    fi
    
    print_success "Uninstallation complete"
}

function show_usage() {
    cat << EOF
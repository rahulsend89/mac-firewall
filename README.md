# macOS Native Firewall for Supply Chain Protection

A kernel-level filesystem and process firewall that protects against npm supply chain attacks that bypass Node.js runtime protection.

## 🎯 Why This Exists

[npm-safe](https://github.com/rahulsend89/npm-safe/) provides excellent protection at the Node.js runtime level, but it **cannot protect against**:

- **Native compiled binaries** (`.node` addons, binaries built during `npm install`)
- **WebAssembly modules** that bypass Node's filesystem APIs
- **Python/Ruby scripts** executed during postinstall hooks
- **Downloaded executables** that run outside Node.js
- **Shell scripts** in `node_modules/.bin/`

This firewall operates at the **macOS kernel level** using the EndpointSecurity framework, catching malicious operations that npm-safe cannot see.

## 🛡️ What It Protects

### File Access Protection
- ✅ Blocks access to SSH keys (`~/.ssh/`)
- ✅ Blocks access to AWS credentials (`~/.aws/`)
- ✅ Blocks access to GPG keys (`~/.gnupg/`)
- ✅ Blocks reading `/etc/passwd`, `/etc/shadow`
- ✅ Blocks writes to system directories (`/etc/`, `/usr/bin/`)
- ✅ Blocks creation of executable files in suspicious locations

### Process Execution Protection
- ✅ Detects suspicious executables from `npm install` processes
- ✅ Blocks execution of downloaded binaries from `/tmp/`
- ✅ Monitors process ancestry to detect attack chains
- ✅ Identifies native binaries vs script interpreters

### What Sets This Apart
- **Kernel-level interception** - Cannot be bypassed by any userspace code
- **Process tree tracking** - Understands when code is running during `npm install`
- **Native code protection** - Catches attacks npm-safe physically cannot see
- **Zero configuration** - Uses your existing `firewall.json` config

## 📋 Requirements

- macOS 10.15 (Catalina) or later
- Xcode Command Line Tools
- SIP disabled (for development) or System Extension approval (for production)
- Root privileges (required by EndpointSecurity framework)

## 🚀 Quick Start

### Installation

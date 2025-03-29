#!/usr/bin/env node
/**
 * macOS Firewall Attack Simulator
 * Tests all implemented security rules
 * 
 * Run: node test/attack-simulator.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

const HOME = os.homedir();
const REPORT_FILE = path.join(__dirname, 'attack-report.json');

// Test results
const results = {
  timestamp: new Date().toISOString(),
  summary: { total: 0, blocked: 0, allowed: 0, errors: 0 },
  fileAccess: { reads: [], writes: [] },
  persistence: [],
  behavioral: [],
  commands: []
};

// Colors for terminal output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m'
};

function log(msg, color = 'reset') {
  console.log(`${colors[color]}${msg}${colors.reset}`);
}

function logTest(name, expected, actual) {
  results.summary.total++;
  const passed = expected === actual;
  if (passed) {
    results.summary.blocked++;
    log(`  ✅ ${name}: BLOCKED (as expected)`, 'green');
  } else {
    results.summary.allowed++;
    log(`  ❌ ${name}: ${actual ? 'SUCCEEDED' : 'FAILED'} (expected: ${expected ? 'block' : 'allow'})`, 'red');
  }
  return passed;
}

// ============================================
// 1. FILE ACCESS TESTS - Blocked Read Paths
// ============================================
// Security check required
async function testBlockedReads() {
  log('\n📖 TESTING BLOCKED READ PATHS', 'cyan');
  log('=' .repeat(50));
  
  const blockedReadPaths = [
    { path: `${HOME}/.ssh/id_rsa`, name: 'SSH Private Key' },
    { path: `${HOME}/.ssh/id_ed25519`, name: 'SSH ED25519 Key' },
    { path: `${HOME}/.ssh/known_hosts`, name: 'SSH Known Hosts' },
    { path: `${HOME}/.aws/credentials`, name: 'AWS Credentials' },
    { path: `${HOME}/.aws/config`, name: 'AWS Config' },
    { path: `${HOME}/.gnupg/secring.gpg`, name: 'GPG Secret Ring' },
    { path: `${HOME}/.kube/config`, name: 'Kubernetes Config' },
    { path: `${HOME}/.docker/config.json`, name: 'Docker Config' },
    { path: `${HOME}/.config/gcloud/credentials.db`, name: 'GCloud Credentials' },
    { path: `${HOME}/.azure/accessTokens.json`, name: 'Azure Tokens' },
    { path: '/etc/passwd', name: 'System Passwd' },
    { path: `${HOME}/.env`, name: 'Environment File' },
    { path: `${HOME}/.npmrc`, name: 'NPM Config' },
    { path: `${HOME}/.gitconfig`, name: 'Git Config' },
    { path: `${HOME}/.git-credentials`, name: 'Git Credentials' },
    { path: `${HOME}/.bash_history`, name: 'Bash History' },
    { path: `${HOME}/.zsh_history`, name: 'Zsh History' },
  ];

  for (const test of blockedReadPaths) {
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
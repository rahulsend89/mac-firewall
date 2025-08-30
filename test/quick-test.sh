#!/bin/bash
#
# Quick Firewall Test - Tests core functionality
#

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}🔥 Quick Firewall Test${NC}"
echo "======================"
echo ""

# 1. Test .npmrc read (NPM tokens)
echo -e "${CYAN}Test 1: NPM Token Theft (.npmrc)${NC}"
node -e "
const fs = require('fs');
try {
  const npmrc = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
  console.log('  ❌ .npmrc read succeeded - NOT BLOCKED');
  console.log('  Content:', npmrc.substring(0, 50));
} catch(e) {
  console.log('  ✅ Blocked or killed');
}
" 2>&1 || echo -e "  ${GREEN}✅ Process was killed by firewall${NC}"

sleep 1

# 2. Test SSH key read
echo ""
echo -e "${CYAN}Test 2: SSH Key Theft (.ssh/id_rsa)${NC}"
node -e "
const fs = require('fs');
try {
  const ssh = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
  console.log('  ❌ SSH key read succeeded - NOT BLOCKED');
} catch(e) {
  if (e.code === 'ENOENT') {
    console.log('  ⏭️  File does not exist');
  } else {
    console.log('  ✅ Blocked or killed');
  }
}
" 2>&1 || echo -e "  ${GREEN}✅ Process was killed by firewall${NC}"

sleep 1

# 3. Test GitHub workflow creation
echo ""
echo -e "${CYAN}Test 3: GitHub Workflow Injection${NC}"
mkdir -p .github/workflows 2>/dev/null
node -e "
const fs = require('fs');
try {
  fs.writeFileSync('.github/workflows/test-malicious.yml', 'name: evil');
  console.log('  ❌ Workflow created - NOT BLOCKED');
  fs.unlinkSync('.github/workflows/test-malicious.yml');
} catch(e) {
  console.log('  ✅ Blocked or killed');
}
" 2>&1 || echo -e "  ${GREEN}✅ Process was killed by firewall${NC}"

sleep 1

# 4. Test LaunchAgent creation
echo ""
echo -e "${CYAN}Test 4: Launch Agent Persistence${NC}"
node -e "
const fs = require('fs');
const path = process.env.HOME + '/Library/LaunchAgents/com.test.firewall.plist';
try {
  fs.writeFileSync(path, '<?xml><plist></plist>');
  console.log('  ❌ LaunchAgent created - NOT BLOCKED');
  fs.unlinkSync(path);
} catch(e) {
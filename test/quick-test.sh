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
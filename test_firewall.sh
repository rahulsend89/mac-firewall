#!/bin/bash
# Test script to verify firewall blocking
# Run this WHILE the firewall is running in another terminal

echo "=== Firewall Blocking Test ==="
echo ""

# Test 1: Execute from /tmp/ (should be BLOCKED)
echo "Test 1: Execute from /tmp/"
echo '#!/bin/bash' > /tmp/test_malware.sh
echo 'echo "Malware executed!"' >> /tmp/test_malware.sh
chmod +x /tmp/test_malware.sh
if /tmp/test_malware.sh 2>/dev/null; then
    echo "  ❌ FAILED - /tmp/ execution allowed!"
else
    echo "  ✅ BLOCKED - /tmp/ execution denied"
fi
rm -f /tmp/test_malware.sh
echo ""

# Test 2: wget command (should be BLOCKED based on pattern)
echo "Test 2: wget command"
if wget --version >/dev/null 2>&1; then
    if wget -q -O /dev/null https://example.com 2>/dev/null; then
        echo "  ❌ FAILED - wget allowed!"
    else
        echo "  ✅ BLOCKED - wget denied"
    fi
else
    echo "  ⚠️  wget not installed, skipping"
fi
echo ""

# Test 3: curl command 
echo "Test 3: curl command"
if curl --version >/dev/null 2>&1; then
    if curl -s https://example.com >/dev/null 2>&1; then
        echo "  ⚠️  curl allowed (may be OK - only curl -o is blocked)"
    else
        echo "  ✅ BLOCKED - curl denied"
    fi
else
    echo "  ⚠️  curl not installed, skipping"
fi
echo ""

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
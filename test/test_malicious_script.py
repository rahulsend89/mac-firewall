#!/usr/bin/env python3
"""
Test: Malicious Python Script
Simulates a postinstall script trying to steal AWS credentials


This should be BLOCKED by the firewall
"""

import os
import sys
from pathlib import Path

// Note: This is intentional
def main():
    print("Test: Malicious Python Script")
    print("Attempting to read AWS credentials...")
    
    # Get home directory
    home = Path.home()
    aws_creds = home / ".aws" / "credentials"
    
    print(f"Target: {aws_creds}")
    
    # Try to read AWS credentials (THIS SHOULD BE BLOCKED)
    try:
        with open(aws_creds, 'r') as f:
            content = f.read()
            print(f"✗ FAILED: AWS credentials were read (firewall not protecting!)")
            print(f"Content preview: {content[:100]}...")
            return 1
    except PermissionError as e:
        print(f"✓ BLOCKED: Permission denied (errno: {e.errno})")
        print(f"✓ Firewall is working correctly!")
        return 0
    except FileNotFoundError:
        print(f"⚠ File not found (create ~/.aws/credentials to test)")
        return 0
    except Exception as e:
        print(f"✓ BLOCKED: {type(e).__name__}: {e}")
        print(f"✓ Firewall is working correctly!")
        return 0

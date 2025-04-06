#!/usr/bin/env python3
"""
Test: Malicious Python Script
Simulates a postinstall script trying to steal AWS credentials

This should be BLOCKED by the firewall
"""

import os
import sys
from pathlib import Path

def main():
    print("Test: Malicious Python Script")
    print("Attempting to read AWS credentials...")
    
    # Get home directory
    home = Path.home()
    aws_creds = home / ".aws" / "credentials"
    
    print(f"Target: {aws_creds}")
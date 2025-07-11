#!/usr/bin/env python3
"""
Network Connectivity Test for RDS Database

This script tests basic network connectivity to the RDS instance
before attempting database connections.
"""

import os
import sys
import socket
import subprocess
import time
from pathlib import Path

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ .env file loaded")
except ImportError:
    print("⚠️  python-dotenv not installed, using system environment")

def test_dns_resolution(hostname: str) -> bool:
    """Test if hostname resolves to an IP address."""
    print(f"\n🔍 Testing DNS resolution for {hostname}...")
    try:
        ip_address = socket.gethostbyname(hostname)
        print(f"✅ DNS resolution successful: {hostname} -> {ip_address}")
        return True
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed: {e}")
        return False

def test_port_connectivity(hostname: str, port: int, timeout: int = 10) -> bool:
    """Test if we can connect to the specified port."""
    print(f"\n🔌 Testing port connectivity to {hostname}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        result = sock.connect_ex((hostname, port))
        connect_time = (time.time() - start_time) * 1000
        sock.close()
        
        if result == 0:
            print(f"✅ Port connectivity successful in {connect_time:.2f}ms")
            return True
        else:
            print(f"❌ Port connectivity failed: Connection refused or timeout")
            return False
    except Exception as e:
        print(f"❌ Port connectivity failed: {e}")
        return False

def test_ping(hostname: str) -> bool:
    """Test ping connectivity (may not work with AWS RDS due to ICMP blocking)."""
    print(f"\n🏓 Testing ping to {hostname}...")
    try:
        # Use ping command
        result = subprocess.run(
            ['ping', '-c', '3', hostname],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("✅ Ping successful")
            print(f"   {result.stdout.strip().split('\\n')[-1]}")  # Show summary line
            return True
        else:
            print("❌ Ping failed (this is normal for AWS RDS - ICMP is often blocked)")
            return False
    except Exception as e:
        print(f"❌ Ping failed: {e}")
        return False

def test_traceroute(hostname: str) -> bool:
    """Test traceroute to see the network path."""
    print(f"\n🗺️  Testing traceroute to {hostname}...")
    try:
        # Use traceroute command (or tracert on Windows)
        cmd = ['traceroute', hostname] if sys.platform != 'win32' else ['tracert', hostname]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("✅ Traceroute completed")
            # Show only the first few hops to avoid too much output
            lines = result.stdout.strip().split('\\n')[:10]
            for line in lines:
                print(f"   {line}")
            if len(result.stdout.strip().split('\\n')) > 10:
                print("   ... (truncated)")
            return True
        else:
            print("⚠️  Traceroute had issues, but this doesn't necessarily indicate a problem")
            return False
    except Exception as e:
        print(f"❌ Traceroute failed: {e}")
        return False

def check_local_network() -> bool:
    """Check basic local network connectivity."""
    print(f"\n🌐 Testing local network connectivity...")
    try:
        # Test connectivity to a well-known DNS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('8.8.8.8', 53))
        sock.close()
        
        if result == 0:
            print("✅ Local network connectivity is working")
            return True
        else:
            print("❌ Local network connectivity issues detected")
            return False
    except Exception as e:
        print(f"❌ Network connectivity test failed: {e}")
        return False

def main():
    """Main network connectivity test."""
    print("🔧 Network Connectivity Test for RDS Database")
    print("=" * 60)
    
    # Get RDS connection details from environment
    rds_endpoint = os.getenv('RDS_ENDPOINT', 'voice-biomarker-users-db.cnq0agmieipg.eu-central-1.rds.amazonaws.com')
    rds_port = int(os.getenv('RDS_PORT', '5432'))
    
    print(f"📋 Testing connectivity to: {rds_endpoint}:{rds_port}")
    print(f"🌍 Your public IP can be checked at: https://whatismyipaddress.com/")
    print("-" * 60)
    
    success_count = 0
    total_tests = 0
    
    # Test 1: Basic local network
    total_tests += 1
    if check_local_network():
        success_count += 1
    
    # Test 2: DNS resolution
    total_tests += 1
    if test_dns_resolution(rds_endpoint):
        success_count += 1
    
    # Test 3: Port connectivity
    total_tests += 1
    if test_port_connectivity(rds_endpoint, rds_port, timeout=30):
        success_count += 1
    
    # Test 4: Ping (may fail for AWS RDS)
    total_tests += 1
    if test_ping(rds_endpoint):
        success_count += 1
    
    # Test 5: Traceroute
    total_tests += 1
    if test_traceroute(rds_endpoint):
        success_count += 1
    
    # Summary
    print("\n" + "=" * 60)
    print(f"📊 Network Connectivity Test Summary:")
    print(f"   ✅ Passed: {success_count}")
    print(f"   ❌ Failed: {total_tests - success_count}")
    print(f"   📋 Total: {total_tests}")
    
    if success_count >= 2:  # DNS + Port connectivity are the most important
        print("\n🎉 Basic network connectivity appears to be working!")
        print("If database connection still fails, check:")
        print("  1. RDS Security Groups allow your IP on port 5432")
        print("  2. RDS instance is in 'available' state")
        print("  3. Database credentials are correct")
        print("  4. SSL/TLS configuration matches requirements")
    else:
        print("\n❌ Network connectivity issues detected.")
        print("Common solutions:")
        print("  1. Check your internet connection")
        print("  2. Verify the RDS endpoint URL is correct")
        print("  3. Check if you're behind a corporate firewall")
        print("  4. Ensure RDS Security Groups allow your IP")
    
    return success_count >= 2

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n❌ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1) 
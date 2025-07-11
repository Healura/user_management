#!/usr/bin/env python3
"""
Simple Database Configuration Test

This script tests the database configuration and helps set up the .env file.
"""

import os
import sys
from pathlib import Path

def check_env_file():
    """Check if .env file exists and what's in it."""
    env_file = Path('.env')
    
    print("🔧 Database Configuration Test")
    print("=" * 50)
    
    if not env_file.exists():
        print("❌ .env file not found!")
        print("\nPlease create a .env file with the following content:")
        print_env_template()
        return False
    
    print("✅ .env file found")
    
    # Check for required variables
    required_vars = [
        'RDS_ENDPOINT', 'RDS_PORT', 'RDS_DB_NAME', 
        'RDS_USERNAME', 'RDS_PASSWORD'
    ]
    
    # Load dotenv if available
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ dotenv loaded")
    except ImportError:
        print("⚠️  python-dotenv not installed, reading environment manually")
    
    missing_vars = []
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            missing_vars.append(var)
        else:
            # Don't print the actual password
            display_value = "***PASSWORD***" if var == 'RDS_PASSWORD' else value
            print(f"  ✅ {var}: {display_value}")
    
    if missing_vars:
        print(f"\n❌ Missing required variables: {', '.join(missing_vars)}")
        print("\nPlease add these to your .env file:")
        print_env_template()
        return False
    
    return True

def print_env_template():
    """Print the .env file template."""
    print("""
Create a .env file with this content:

# Database Configuration (Required)
RDS_ENDPOINT=voice-biomarker-users-db.cnq0agmieipg.eu-central-1.rds.amazonaws.com
RDS_PORT=5432
RDS_DB_NAME=voice_biomarker_users
RDS_USERNAME=postgres
RDS_PASSWORD=your_actual_database_password_here

# Database Connection Pool Settings
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600
DB_SSL_MODE=require
DB_ECHO=false

# AWS Configuration
AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY_ID_HERE
AWS_SECRET_ACCESS_KEY=YOUR_AWS_SECRET_ACCESS_KEY_HERE
AWS_REGION=eu-central-1

# Basic Application Settings
ENVIRONMENT=development
SECRET_KEY=your-secret-key-here-generate-with-openssl-rand-hex-32

Note: Replace 'your_actual_database_password_here' with your real RDS password!
Note: Replace AWS credentials with your actual AWS access key and secret!
""")

def test_database_config():
    """Test if the database configuration loads correctly."""
    try:
        from config.database_config import DatabaseConfig, get_database_url
        
        print("\n🔧 Testing Database Configuration...")
        
        # Try to create config
        config = DatabaseConfig()
        print("✅ DatabaseConfig loaded successfully")
        
        # Check individual settings
        print(f"  📊 Endpoint: {config.rds_endpoint}")
        print(f"  📊 Port: {config.rds_port}")
        print(f"  📊 Database: {config.rds_db_name}")
        print(f"  📊 Username: {config.rds_username}")
        print(f"  📊 Password: {'***SET***' if config.rds_password else '***NOT SET***'}")
        
        # Try to generate database URL
        if config.rds_password:
            db_url = get_database_url(config)
            # Don't print the full URL with password
            safe_url = db_url.split('@')[1] if '@' in db_url else "Could not parse"
            print(f"  📊 Database URL: postgresql://***:***@{safe_url}")
            print("✅ Database URL generated successfully")
        else:
            print("❌ Cannot generate database URL without password")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Database configuration error: {e}")
        return False

def test_database_connection():
    """Test actual database connection."""
    try:
        from src.database.database import check_database_connection
        
        print("\n🔗 Testing Database Connection...")
        
        if check_database_connection():
            print("✅ Database connection successful!")
            return True
        else:
            print("❌ Database connection failed")
            return False
            
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        print("\nThis could be due to:")
        print("  1. Incorrect database password")
        print("  2. Network connectivity issues")
        print("  3. RDS instance not accessible")
        print("  4. Security group restrictions")
        return False

def main():
    """Main test function."""
    success = True
    
    # Step 1: Check .env file
    success &= check_env_file()
    
    if not success:
        print("\n❌ Please fix the .env file first, then run this script again.")
        return False
    
    # Step 2: Test configuration loading
    success &= test_database_config()
    
    if not success:
        print("\n❌ Configuration test failed.")
        return False
    
    # Step 3: Test actual connection
    success &= test_database_connection()
    
    if success:
        print("\n🎉 All tests passed! Database configuration is working.")
        print("\nYou can now run the full database test:")
        print("  python test_database_setup.py")
    else:
        print("\n❌ Some tests failed. Please check the configuration.")
    
    return success

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
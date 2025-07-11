#!/usr/bin/env python3
"""
Test script for verifying background task implementation.

This script tests the session cleanup functionality by creating test sessions
and verifying they can be cleaned up properly.
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add the src directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from database.database import get_db
from auth.session_manager import SessionManager
from auth.background_tasks import AuthBackgroundTaskManager
from database.models import User
from utils.password_utils import hash_password
import uuid


async def test_session_cleanup():
    """Test the session cleanup functionality."""
    print("Testing session cleanup functionality...")
    
    # Get database session
    db = next(get_db())
    
    try:
        # Create test user if doesn't exist
        test_email = "test_session_cleanup@example.com"
        test_user = db.query(User).filter_by(email=test_email).first()
        
        if not test_user:
            test_user = User(
                id=uuid.uuid4(),
                email=test_email,
                password_hash=hash_password("test_password_123"),
                first_name="Test",
                last_name="User",
                email_verified=True,
                is_active=True
            )
            db.add(test_user)
            db.commit()
            print(f"Created test user: {test_user.id}")
        
        # Initialize session manager
        session_manager = SessionManager(db)
        
        # Create test sessions with expired times
        print("Creating test sessions...")
        expired_time = datetime.utcnow() - timedelta(hours=2)
        
        # Create expired session
        expired_session = await session_manager.create_session(
            user_id=test_user.id,
            access_token="test_access_token_1",
            refresh_token="test_refresh_token_1",
            device_id="test_device_1"
        )
        
        # Manually set expiration to past
        expired_session.expires_at = expired_time
        expired_session.is_active = True
        db.commit()
        print(f"Created expired session: {expired_session.id}")
        
        # Create valid session
        valid_session = await session_manager.create_session(
            user_id=test_user.id,
            access_token="test_access_token_2",
            refresh_token="test_refresh_token_2",
            device_id="test_device_2"
        )
        print(f"Created valid session: {valid_session.id}")
        
        # Count sessions before cleanup
        sessions_before = len(await session_manager.get_user_sessions(test_user.id))
        print(f"Sessions before cleanup: {sessions_before}")
        
        # Run cleanup
        print("Running session cleanup...")
        cleaned_count = await session_manager.cleanup_expired_sessions()
        print(f"Cleaned up {cleaned_count} expired sessions")
        
        # Count sessions after cleanup
        sessions_after = len(await session_manager.get_user_sessions(test_user.id))
        print(f"Sessions after cleanup: {sessions_after}")
        
        # Verify cleanup worked
        if sessions_after < sessions_before:
            print("✅ Session cleanup test PASSED")
            return True
        else:
            print("❌ Session cleanup test FAILED")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        db.close()


async def test_background_task_manager():
    """Test the background task manager."""
    print("\nTesting background task manager...")
    
    try:
        # Create task manager
        task_manager = AuthBackgroundTaskManager()
        
        # Test start
        print("Starting background task manager...")
        await task_manager.start()
        
        # Check status
        status = task_manager.get_status()
        print(f"Task manager status: {status}")
        
        if status["running"] and len(status["jobs"]) > 0:
            print("✅ Background task manager start test PASSED")
        else:
            print("❌ Background task manager start test FAILED")
            return False
        
        # Test stop
        print("Stopping background task manager...")
        await task_manager.stop()
        
        # Check status after stop
        status = task_manager.get_status()
        print(f"Task manager status after stop: {status}")
        
        if not status["running"]:
            print("✅ Background task manager stop test PASSED")
            return True
        else:
            print("❌ Background task manager stop test FAILED")
            return False
            
    except Exception as e:
        print(f"❌ Background task manager test failed with error: {e}")
        return False


async def main():
    """Run all tests."""
    print("🧪 Testing Background Task Implementation")
    print("=" * 50)
    
    # Test session cleanup
    cleanup_success = await test_session_cleanup()
    
    # Test background task manager
    manager_success = await test_background_task_manager()
    
    # Overall result
    print("\n" + "=" * 50)
    if cleanup_success and manager_success:
        print("🎉 All tests PASSED! Background task implementation is working correctly.")
        return 0
    else:
        print("💥 Some tests FAILED! Please check the implementation.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main()) 
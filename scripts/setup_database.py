#!/usr/bin/env python3
"""
Database Setup and Initialization Script

This script helps set up and initialize the Voice Biomarker database
including running migrations and creating initial roles.

Usage:
    python scripts/setup_database.py [--test-only] [--force]
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = project_root / '.env'
    load_dotenv(env_path)
    print(f"✅ Loaded .env file from: {env_path}")
except ImportError:
    print("⚠️  python-dotenv not installed, using system environment variables")
except Exception as e:
    print(f"⚠️  Could not load .env file: {e}")

try:
    from sqlalchemy import create_engine, text
    from alembic.config import Config
    from alembic import command
    
    from config.database_config import get_database_url, database_config
    from src.database.database import engine, SessionLocal, check_database_connection
    from src.database.models import Base, UserRole
    from src.database.repositories import UserRoleRepository
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root and all dependencies are installed.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_environment():
    """Check if required environment variables are set."""
    logger.info("🔧 Checking environment variables...")
    
    required_vars = ["RDS_PASSWORD"]
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        logger.error("Please create a .env file with the required variables.")
        logger.error("See DATABASE_TESTING_GUIDE.md for details.")
        return False
    
    logger.info("✅ Environment variables check passed")
    return True


def test_connection():
    """Test database connectivity."""
    logger.info("🔗 Testing database connection...")
    
    try:
        if check_database_connection():
            logger.info("✅ Database connection successful")
            
            # Get database info
            with engine.connect() as conn:
                version = conn.execute(text("SELECT version()")).scalar()
                current_db = conn.execute(text("SELECT current_database()")).scalar()
                
            logger.info(f"📊 Connected to database: {current_db}")
            logger.info(f"📊 PostgreSQL version: {version.split(',')[0]}")
            return True
        else:
            logger.error("❌ Database connection failed")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database connection error: {e}")
        return False


def run_migrations():
    """Run database migrations using Alembic."""
    logger.info("📋 Running database migrations...")
    
    try:
        # Configure Alembic
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", get_database_url())
        
        # Run migrations
        command.upgrade(alembic_cfg, "head")
        logger.info("✅ Database migrations completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        logger.error("You may need to initialize migrations first:")
        logger.error("  alembic init alembic")
        logger.error("  alembic revision --autogenerate -m 'Initial migration'")
        return False


def create_initial_roles():
    """Create initial user roles."""
    logger.info("👥 Creating initial user roles...")
    
    try:
        db = SessionLocal()
        role_repo = UserRoleRepository(db)
        
        # Define default roles for healthcare application
        default_roles = [
            {
                "name": "patient",
                "description": "Patient users who can upload voice recordings and view their analysis results"
            },
            {
                "name": "healthcare_provider", 
                "description": "Healthcare providers who can access patient data and analysis results"
            },
            {
                "name": "admin",
                "description": "System administrators with full access to user management and system configuration"
            },
            {
                "name": "analyst",
                "description": "Data analysts who can access aggregated voice analysis data for research"
            },
            {
                "name": "support",
                "description": "Customer support staff with limited access to help users"
            }
        ]
        
        created_roles = []
        
        for role_data in default_roles:
            # Check if role already exists
            existing_role = db.query(UserRole).filter(UserRole.name == role_data["name"]).first()
            
            if not existing_role:
                role = role_repo.create(**role_data)
                created_roles.append(role.name)
                logger.info(f"  ✅ Created role: {role.name}")
            else:
                logger.info(f"  ⏭️  Role already exists: {role_data['name']}")
        
        db.commit()
        db.close()
        
        if created_roles:
            logger.info(f"✅ Created {len(created_roles)} new roles: {', '.join(created_roles)}")
        else:
            logger.info("✅ All default roles already exist")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to create roles: {e}")
        if 'db' in locals():
            db.rollback()
            db.close()
        return False


def verify_schema():
    """Verify that the database schema is correctly set up."""
    logger.info("📊 Verifying database schema...")
    
    try:
        from sqlalchemy import inspect
        
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        expected_tables = [
            "users", "user_roles", "user_role_assignments",
            "audio_files", "voice_analyses", "user_sessions", 
            "notification_preferences", "notification_history", "audit_logs"
        ]
        
        missing_tables = set(expected_tables) - set(existing_tables)
        
        if missing_tables:
            logger.error(f"❌ Missing tables: {', '.join(missing_tables)}")
            logger.error("Run migrations to create missing tables: alembic upgrade head")
            return False
        
        logger.info(f"✅ All {len(expected_tables)} expected tables exist")
        
        # Check for indexes on critical tables
        critical_indexes = {
            "users": ["ix_users_email"],
            "audit_logs": ["ix_audit_logs_timestamp"]
        }
        
        missing_indexes = []
        for table, expected_indexes in critical_indexes.items():
            if table in existing_tables:
                table_indexes = [idx["name"] for idx in inspector.get_indexes(table)]
                table_missing = set(expected_indexes) - set(table_indexes)
                missing_indexes.extend(table_missing)
        
        if missing_indexes:
            logger.warning(f"⚠️  Missing some indexes: {', '.join(missing_indexes)}")
            logger.warning("Consider running migrations to add missing indexes")
        else:
            logger.info("✅ Critical indexes are present")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Schema verification failed: {e}")
        return False


def run_comprehensive_test():
    """Run the comprehensive database test script."""
    logger.info("🧪 Running comprehensive database tests...")
    
    try:
        import subprocess
        result = subprocess.run([sys.executable, "test_database_setup.py"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✅ Comprehensive database tests passed")
            return True
        else:
            logger.error("❌ Some database tests failed")
            logger.error("Check test_database_setup.py output for details")
            if result.stderr:
                logger.error(f"Error output: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to run comprehensive tests: {e}")
        return False


def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description="Database setup and initialization")
    parser.add_argument("--test-only", action="store_true", 
                       help="Only run tests, don't modify database")
    parser.add_argument("--force", action="store_true",
                       help="Force recreation of tables (destructive)")
    
    args = parser.parse_args()
    
    print("🏥 Voice Biomarker Database Setup")
    print("=" * 50)
    
    # Step 1: Check environment
    if not check_environment():
        logger.error("❌ Environment check failed. Setup aborted.")
        sys.exit(1)
    
    # Step 2: Test connection
    if not test_connection():
        logger.error("❌ Database connection failed. Setup aborted.")
        logger.error("Please check your database configuration and network connectivity.")
        sys.exit(1)
    
    if args.test_only:
        logger.info("🧪 Running test-only mode...")
        
        # Run verification and tests
        success = True
        success &= verify_schema()
        success &= run_comprehensive_test()
        
        if success:
            logger.info("🎉 All tests passed! Database is ready for use.")
            sys.exit(0)
        else:
            logger.error("❌ Some tests failed. Check the output above.")
            sys.exit(1)
    
    else:
        logger.info("🔧 Running full database setup...")
        
        # Step 3: Run migrations
        if not run_migrations():
            logger.error("❌ Migration failed. Setup aborted.")
            sys.exit(1)
        
        # Step 4: Create initial roles
        if not create_initial_roles():
            logger.error("❌ Role creation failed. Setup aborted.")
            sys.exit(1)
        
        # Step 5: Verify schema
        if not verify_schema():
            logger.error("❌ Schema verification failed.")
            sys.exit(1)
        
        # Step 6: Run comprehensive tests
        logger.info("🧪 Running final verification tests...")
        if not run_comprehensive_test():
            logger.warning("⚠️  Some tests failed, but setup completed.")
            logger.warning("Check the test results for any issues.")
        
        logger.info("🎉 Database setup completed successfully!")
        logger.info("Your Voice Biomarker database is ready for use.")
        
        # Show next steps
        print("\n📋 Next Steps:")
        print("  1. Start your application: uvicorn src.main:app --reload")
        print("  2. Test API endpoints: curl http://localhost:8000/health")
        print("  3. Review the DATABASE_TESTING_GUIDE.md for more information")


if __name__ == "__main__":
    main()

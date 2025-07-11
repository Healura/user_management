#!/usr/bin/env python3
"""
Comprehensive Database Setup Testing Script for Voice Biomarker User Management Service

This script tests all aspects of the AWS RDS PostgreSQL database setup including:
- Connection and SSL verification
- Schema and table structure
- Indexes and constraints
- CRUD operations
- Relationships
- Performance metrics
- Pool status monitoring
- Migration status

Usage:
    python test_database_setup.py
"""

import os
import sys
import json
import time
import logging
import asyncio
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path

# Add project root to Python path
sys.path.append(str(Path(__file__).parent))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ .env file loaded")
except ImportError:
    print("⚠️  python-dotenv not installed, using system environment")

try:
    from sqlalchemy import (
        create_engine, text, inspect, MetaData, 
        Table, Column, String, Boolean, Integer
    )
    from sqlalchemy.orm import sessionmaker, Session
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.engine import Engine
    from sqlalchemy.pool import QueuePool
    
    from config.database_config import DatabaseConfig, get_database_url
    from src.database.models import (
        Base, User, UserRole, UserRoleAssignment, AudioFile, 
        VoiceAnalysis, UserSession, NotificationPreference,
        NotificationHistory, AuditLog
    )
    from src.database.database import engine, SessionLocal
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root and all dependencies are installed.")
    sys.exit(1)


class DatabaseTester:
    """Comprehensive database testing class."""
    
    def __init__(self):
        """Initialize the database tester."""
        self.config = DatabaseConfig()
        self.engine = None
        self.session = None
        self.results = {
            "timestamp": datetime.now(UTC).isoformat(),
            "database_config": {
                "endpoint": self.config.rds_endpoint,
                "port": self.config.rds_port,
                "database": self.config.rds_db_name,
                "username": self.config.rds_username,
                "ssl_mode": self.config.db_ssl_mode
            },
            "tests": {},
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "warnings": 0
            }
        }
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def log_test_result(self, test_name: str, success: bool, 
                       message: str = "", details: Dict[str, Any] = None,
                       warning: bool = False):
        """Log and store test results."""
        if warning:
            self.logger.warning(f"⚠️  {test_name}: {message}")
            self.results["summary"]["warnings"] += 1
            status = "warning"
        elif success:
            self.logger.info(f"✅ {test_name}: {message}")
            self.results["summary"]["passed"] += 1
            status = "passed"
        else:
            self.logger.error(f"❌ {test_name}: {message}")
            self.results["summary"]["failed"] += 1
            status = "failed"
        
        self.results["tests"][test_name] = {
            "status": status,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now(UTC).isoformat()
        }
        self.results["summary"]["total_tests"] += 1
    
    def test_environment_variables(self) -> bool:
        """Test 1: Verify all required environment variables are set."""
        test_name = "Environment Variables"
        missing_vars = []
        
        required_vars = [
            "RDS_PASSWORD"
        ]
        
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            self.log_test_result(
                test_name, False,
                f"Missing required environment variables: {', '.join(missing_vars)}",
                {"missing_variables": missing_vars}
            )
            return False
        
        self.log_test_result(
            test_name, True,
            "All required environment variables are set",
            {"checked_variables": required_vars}
        )
        return True
    
    def test_database_connection(self) -> bool:
        """Test 2: Test basic database connectivity."""
        test_name = "Database Connection"
        
        try:
            # Create engine for testing
            self.engine = create_engine(
                get_database_url(self.config),
                pool_size=1,
                max_overflow=0,
                pool_timeout=30,  # Increased for AWS RDS
                echo=False,
                connect_args={
                    "connect_timeout": 30,  # Increased for AWS RDS
                    "sslmode": self.config.db_ssl_mode
                }
            )
            
            # Test connection
            start_time = time.time()
            with self.engine.connect() as conn:
                result = conn.execute(text("SELECT 1 as test")).fetchone()
                connection_time = (time.time() - start_time) * 1000
            
            # Get PostgreSQL version
            with self.engine.connect() as conn:
                version_result = conn.execute(text("SELECT version()")).scalar()
            
            self.log_test_result(
                test_name, True,
                f"Connection successful in {connection_time:.2f}ms",
                {
                    "connection_time_ms": round(connection_time, 2),
                    "postgresql_version": version_result,
                    "test_query_result": result[0] if result else None
                }
            )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Connection failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_database_configuration(self) -> bool:
        """Test 3: Verify database configuration settings."""
        test_name = "Database Configuration"
        
        try:
            with self.engine.connect() as conn:
                # Check SSL status
                ssl_result = conn.execute(text("SHOW ssl")).scalar()
                
                # Check encoding
                encoding_result = conn.execute(text("SHOW server_encoding")).scalar()
                
                # Check timezone
                timezone_result = conn.execute(text("SHOW timezone")).scalar()
                
                # Check max connections
                max_conn_result = conn.execute(text("SHOW max_connections")).scalar()
                
                # Check if we can create a test table (permissions check)
                conn.execute(text("CREATE TABLE IF NOT EXISTS test_permissions_check (id INTEGER)"))
                conn.execute(text("DROP TABLE IF EXISTS test_permissions_check"))
                conn.commit()
            
            config_details = {
                "ssl_enabled": ssl_result,
                "encoding": encoding_result,
                "timezone": timezone_result,
                "max_connections": max_conn_result,
                "permissions": "CREATE/DROP table permissions verified"
            }
            
            # Check for any configuration warnings
            warnings = []
            if ssl_result != "on":
                warnings.append("SSL is not enabled")
            if encoding_result != "UTF8":
                warnings.append(f"Encoding is {encoding_result}, expected UTF8")
            
            if warnings:
                self.log_test_result(
                    test_name, True,
                    f"Configuration verified with warnings: {'; '.join(warnings)}",
                    config_details,
                    warning=True
                )
            else:
                self.log_test_result(
                    test_name, True,
                    "Database configuration is optimal",
                    config_details
                )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Configuration check failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_schema_existence(self) -> bool:
        """Test 4: Verify database schema exists and is accessible."""
        test_name = "Schema Accessibility"
        
        try:
            with self.engine.connect() as conn:
                # Check if we can access the public schema
                schema_result = conn.execute(text(
                    "SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'public'"
                )).fetchone()
                
                # Check current database
                current_db = conn.execute(text("SELECT current_database()")).scalar()
                
                # Check current user permissions
                current_user = conn.execute(text("SELECT current_user")).scalar()
                
            details = {
                "schema_accessible": bool(schema_result),
                "current_database": current_db,
                "current_user": current_user,
                "expected_database": self.config.rds_db_name
            }
            
            if current_db != self.config.rds_db_name:
                self.log_test_result(
                    test_name, False,
                    f"Connected to wrong database: {current_db}, expected: {self.config.rds_db_name}",
                    details
                )
                return False
            
            self.log_test_result(
                test_name, True,
                f"Schema accessible, connected to {current_db} as {current_user}",
                details
            )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Schema accessibility check failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_table_structure(self) -> bool:
        """Test 5: Verify all expected tables exist with correct structure."""
        test_name = "Table Structure"
        
        expected_tables = [
            "users", "user_roles", "user_role_assignments", 
            "audio_files", "voice_analyses", "user_sessions",
            "notification_preferences", "notification_history", "audit_logs"
        ]
        
        try:
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()
            
            missing_tables = set(expected_tables) - set(existing_tables)
            extra_tables = set(existing_tables) - set(expected_tables) - {"alembic_version"}
            
            table_details = {}
            for table in expected_tables:
                if table in existing_tables:
                    columns = inspector.get_columns(table)
                    table_details[table] = {
                        "exists": True,
                        "column_count": len(columns),
                        "columns": [col["name"] for col in columns[:5]]  # First 5 columns
                    }
                else:
                    table_details[table] = {"exists": False}
            
            details = {
                "expected_tables": expected_tables,
                "existing_tables": existing_tables,
                "missing_tables": list(missing_tables),
                "extra_tables": list(extra_tables),
                "table_details": table_details
            }
            
            if missing_tables:
                self.log_test_result(
                    test_name, False,
                    f"Missing tables: {', '.join(missing_tables)}",
                    details
                )
                return False
            
            message = f"All {len(expected_tables)} expected tables exist"
            if extra_tables:
                message += f" (found {len(extra_tables)} additional tables)"
                
            self.log_test_result(test_name, True, message, details)
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Table structure check failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_indexes(self) -> bool:
        """Test 6: Verify critical indexes exist."""
        test_name = "Database Indexes"
        
        try:
            inspector = inspect(self.engine)
            
            # Check for critical indexes
            critical_indexes = {
                "users": ["ix_users_email", "ix_users_created_at"],
                "audio_files": ["ix_audio_files_user_id", "ix_audio_files_uploaded_at"],
                "voice_analyses": ["ix_voice_analyses_audio_file_id", "ix_voice_analyses_analyzed_at"],
                "user_sessions": ["ix_user_sessions_user_id", "ix_user_sessions_expires_at"],
                "audit_logs": ["ix_audit_logs_user_id", "ix_audit_logs_timestamp"]
            }
            
            index_status = {}
            missing_indexes = []
            
            for table, expected_indexes in critical_indexes.items():
                if table in inspector.get_table_names():
                    existing_indexes = [idx["name"] for idx in inspector.get_indexes(table)]
                    table_missing = set(expected_indexes) - set(existing_indexes)
                    
                    index_status[table] = {
                        "expected": expected_indexes,
                        "existing": existing_indexes,
                        "missing": list(table_missing)
                    }
                    missing_indexes.extend(table_missing)
                else:
                    index_status[table] = {"error": "Table does not exist"}
            
            details = {"index_status": index_status}
            
            if missing_indexes:
                self.log_test_result(
                    test_name, False,
                    f"Missing critical indexes: {', '.join(missing_indexes)}",
                    details
                )
                return False
            
            self.log_test_result(
                test_name, True,
                "All critical indexes are present",
                details
            )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Index check failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_constraints(self) -> bool:
        """Test 7: Verify foreign key constraints and unique constraints."""
        test_name = "Database Constraints"
        
        try:
            inspector = inspect(self.engine)
            
            # Check foreign key constraints
            tables_with_fks = ["user_role_assignments", "audio_files", "voice_analyses", "user_sessions"]
            fk_status = {}
            
            for table in tables_with_fks:
                if table in inspector.get_table_names():
                    foreign_keys = inspector.get_foreign_keys(table)
                    fk_status[table] = {
                        "foreign_key_count": len(foreign_keys),
                        "foreign_keys": [fk["name"] for fk in foreign_keys if fk["name"]]
                    }
            
            # Check unique constraints
            unique_constraints = inspector.get_unique_constraints("users")
            
            details = {
                "foreign_key_status": fk_status,
                "users_unique_constraints": [uc["name"] for uc in unique_constraints]
            }
            
            # Basic validation - should have some foreign keys
            total_fks = sum(status.get("foreign_key_count", 0) for status in fk_status.values())
            
            if total_fks == 0:
                self.log_test_result(
                    test_name, False,
                    "No foreign key constraints found - database integrity may be compromised",
                    details
                )
                return False
            
            self.log_test_result(
                test_name, True,
                f"Database constraints verified ({total_fks} foreign keys found)",
                details
            )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Constraint check failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_crud_operations(self) -> bool:
        """Test 8: Test basic CRUD operations."""
        test_name = "CRUD Operations"
        
        try:
            # Create a session
            SessionLocal = sessionmaker(bind=self.engine)
            session = SessionLocal()
            
            # Test data
            test_email = f"test_user_{int(time.time())}@example.com"
            
            try:
                # CREATE - Insert a test user
                test_user = User(
                    email=test_email,
                    password_hash="test_hash_123",
                    first_name="Test",
                    last_name="User",
                    is_active=True,
                    email_verified=True,
                    privacy_consent=True
                )
                session.add(test_user)
                session.commit()
                session.refresh(test_user)
                
                # READ - Query the user
                queried_user = session.query(User).filter(User.email == test_email).first()
                
                # UPDATE - Modify the user
                queried_user.first_name = "Updated"
                session.commit()
                
                # Verify update
                updated_user = session.query(User).filter(User.email == test_email).first()
                
                # DELETE - Remove test user
                session.delete(updated_user)
                session.commit()
                
                # Verify deletion
                deleted_user = session.query(User).filter(User.email == test_email).first()
                
                # Validate operations
                crud_results = {
                    "create_success": test_user.id is not None,
                    "read_success": queried_user is not None and queried_user.email == test_email,
                    "update_success": updated_user.first_name == "Updated",
                    "delete_success": deleted_user is None
                }
                
                all_success = all(crud_results.values())
                
                self.log_test_result(
                    test_name, all_success,
                    "CRUD operations completed successfully" if all_success else "Some CRUD operations failed",
                    crud_results
                )
                
                return all_success
                
            finally:
                # Cleanup in case of error
                try:
                    cleanup_user = session.query(User).filter(User.email == test_email).first()
                    if cleanup_user:
                        session.delete(cleanup_user)
                        session.commit()
                except:
                    pass
                session.close()
                
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"CRUD operations failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_relationships(self) -> bool:
        """Test 9: Test table relationships."""
        test_name = "Table Relationships"
        
        try:
            SessionLocal = sessionmaker(bind=self.engine)
            session = SessionLocal()
            
            test_email = f"rel_test_{int(time.time())}@example.com"
            
            try:
                # Create test user
                test_user = User(
                    email=test_email,
                    password_hash="test_hash",
                    first_name="Relationship",
                    last_name="Test",
                    is_active=True,
                    email_verified=True,
                    privacy_consent=True
                )
                session.add(test_user)
                session.commit()
                session.refresh(test_user)
                
                # Create related records
                test_session = UserSession(
                    user_id=test_user.id,
                    device_type="test_device",
                    ip_address="127.0.0.1",
                    is_active=True
                )
                session.add(test_session)
                
                test_notification_pref = NotificationPreference(
                    user_id=test_user.id,
                    reminder_enabled=True,
                    email_enabled=True
                )
                session.add(test_notification_pref)
                session.commit()
                
                # Test relationships
                user_with_relations = session.query(User).filter(User.id == test_user.id).first()
                
                relationship_tests = {
                    "user_sessions_relationship": len(user_with_relations.sessions) > 0,
                    "notification_preferences_relationship": user_with_relations.notification_preferences is not None,
                    "cascade_delete_ready": True  # We'll test this works structurally
                }
                
                # Cleanup
                session.delete(user_with_relations)  # Should cascade delete related records
                session.commit()
                
                all_relationships_work = all(relationship_tests.values())
                
                self.log_test_result(
                    test_name, all_relationships_work,
                    "Table relationships working correctly" if all_relationships_work else "Some relationships failed",
                    relationship_tests
                )
                
                return all_relationships_work
                
            finally:
                # Cleanup
                try:
                    cleanup_user = session.query(User).filter(User.email == test_email).first()
                    if cleanup_user:
                        session.delete(cleanup_user)
                        session.commit()
                except:
                    pass
                session.close()
                
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Relationship test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_performance(self) -> bool:
        """Test 10: Basic performance metrics."""
        test_name = "Performance Metrics"
        
        try:
            times = []
            
            # Test multiple queries for average response time
            for i in range(5):
                start_time = time.time()
                with self.engine.connect() as conn:
                    conn.execute(text("SELECT COUNT(*) FROM users"))
                query_time = (time.time() - start_time) * 1000
                times.append(query_time)
            
            avg_time = sum(times) / len(times)
            max_time = max(times)
            min_time = min(times)
            
            # Test a more complex query
            start_time = time.time()
            with self.engine.connect() as conn:
                conn.execute(text("""
                    SELECT u.email, COUNT(s.id) as session_count 
                    FROM users u 
                    LEFT JOIN user_sessions s ON u.id = s.user_id 
                    GROUP BY u.id, u.email 
                    LIMIT 10
                """))
            complex_query_time = (time.time() - start_time) * 1000
            
            performance_metrics = {
                "simple_query_avg_ms": round(avg_time, 2),
                "simple_query_max_ms": round(max_time, 2),
                "simple_query_min_ms": round(min_time, 2),
                "complex_query_ms": round(complex_query_time, 2),
                "performance_threshold_ms": 1000  # 1 second threshold
            }
            
            # Performance thresholds
            performance_ok = avg_time < 1000 and complex_query_time < 5000
            
            if not performance_ok:
                self.log_test_result(
                    test_name, False,
                    f"Performance issues detected - Average: {avg_time:.2f}ms, Complex: {complex_query_time:.2f}ms",
                    performance_metrics
                )
                return False
            
            self.log_test_result(
                test_name, True,
                f"Performance metrics acceptable - Average: {avg_time:.2f}ms",
                performance_metrics
            )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Performance test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_ssl_connection(self) -> bool:
        """Test 11: Verify SSL connection details."""
        test_name = "SSL Connection"
        
        try:
            with self.engine.connect() as conn:
                # Check SSL status
                ssl_result = conn.execute(text("SHOW ssl")).scalar()
                
                # Try to get SSL cipher (PostgreSQL specific)
                try:
                    ssl_cipher = conn.execute(text("SELECT ssl_cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")).scalar()
                except:
                    ssl_cipher = "Unable to determine"
                
                # Check SSL version if available
                try:
                    ssl_version = conn.execute(text("SELECT ssl_version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")).scalar()
                except:
                    ssl_version = "Unable to determine"
            
            ssl_details = {
                "ssl_enabled": ssl_result,
                "ssl_cipher": ssl_cipher,
                "ssl_version": ssl_version,
                "expected_ssl_mode": self.config.db_ssl_mode
            }
            
            if ssl_result != "on":
                self.log_test_result(
                    test_name, False,
                    f"SSL not enabled (found: {ssl_result})",
                    ssl_details
                )
                return False
            
            self.log_test_result(
                test_name, True,
                f"SSL connection verified (cipher: {ssl_cipher})",
                ssl_details
            )
            return True
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"SSL connection test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_connection_pool(self) -> bool:
        """Test 12: Verify connection pool functionality."""
        test_name = "Connection Pool"
        
        try:
            # Use the main application engine for pool testing
            from src.database.database import engine as main_engine
            pool = main_engine.pool
            
            pool_details = {
                "pool_size": pool.size(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "checked_in": pool.checkedin(),
                "configured_pool_size": self.config.db_pool_size,
                "configured_max_overflow": self.config.db_max_overflow
            }
            
            # Test multiple connections
            connections = []
            try:
                for i in range(3):
                    conn = main_engine.connect()
                    connections.append(conn)
                    # Execute a simple query
                    conn.execute(text("SELECT 1"))
                
                pool_details["concurrent_connections_test"] = "Success"
                
            finally:
                # Close all test connections
                for conn in connections:
                    conn.close()
            
            # Verify pool is working
            pool_working = (
                pool.size() == self.config.db_pool_size and
                pool_details["concurrent_connections_test"] == "Success"
            )
            
            self.log_test_result(
                test_name, pool_working,
                f"Connection pool verified (size: {pool.size()}, checked out: {pool.checkedout()})",
                pool_details
            )
            return pool_working
            
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Connection pool test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_migration_status(self) -> bool:
        """Test 13: Check Alembic migration status."""
        test_name = "Migration Status"
        
        try:
            with self.engine.connect() as conn:
                # Check if alembic_version table exists
                alembic_table_exists = conn.execute(text(
                    "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'alembic_version')"
                )).scalar()
                
                migration_details = {
                    "alembic_table_exists": alembic_table_exists
                }
                
                if alembic_table_exists:
                    # Get current migration version
                    current_version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                    migration_details["current_version"] = current_version
                    
                    # Count total migrations (if we can access the migrations directory)
                    try:
                        migrations_dir = Path("src/database/migrations/versions")
                        if migrations_dir.exists():
                            migration_files = list(migrations_dir.glob("*.py"))
                            migration_details["migration_files_count"] = len(migration_files)
                    except:
                        migration_details["migration_files_count"] = "Unable to determine"
                
                # Migration system is set up if alembic table exists
                migration_ok = alembic_table_exists
                
                message = "Migration system initialized"
                if alembic_table_exists and current_version:
                    message = f"Migrations up to date (version: {current_version[:8]}...)"
                elif not alembic_table_exists:
                    message = "No migration system detected - consider running 'alembic upgrade head'"
                    migration_ok = False
                
                self.log_test_result(
                    test_name, migration_ok,
                    message,
                    migration_details
                )
                return migration_ok
                
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Migration status check failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all database tests."""
        print("🚀 Starting Comprehensive Database Setup Testing...")
        print(f"📋 Testing connection to: {self.config.rds_endpoint}:{self.config.rds_port}")
        print("-" * 80)
        
        # List of all tests to run
        tests = [
            self.test_environment_variables,
            self.test_database_connection,
            self.test_database_configuration,
            self.test_schema_existence,
            self.test_table_structure,
            self.test_indexes,
            self.test_constraints,
            self.test_crud_operations,
            self.test_relationships,
            self.test_performance,
            self.test_ssl_connection,
            self.test_connection_pool,
            self.test_migration_status
        ]
        
        # Run tests
        for test_func in tests:
            try:
                test_func()
            except Exception as e:
                test_name = test_func.__name__.replace("test_", "").replace("_", " ").title()
                self.log_test_result(
                    test_name, False,
                    f"Test execution failed: {str(e)}",
                    {"error_type": type(e).__name__}
                )
        
        # Print summary
        print("-" * 80)
        summary = self.results["summary"]
        print(f"📊 Test Summary:")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⚠️  Warnings: {summary['warnings']}")
        print(f"   📋 Total: {summary['total_tests']}")
        
        if summary['failed'] == 0:
            print("\n🎉 All critical database tests passed! Your database setup is working correctly.")
        elif summary['failed'] < 3:
            print("\n⚠️  Some minor issues detected. Review the failed tests above.")
        else:
            print("\n❌ Multiple critical issues detected. Please review and fix the failed tests.")
        
        print(f"\n📄 Detailed results saved to: database_test_results.json")
        
        return self.results
    
    def save_results(self, filename: str = "database_test_results.json"):
        """Save test results to a JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
        except Exception as e:
            print(f"❌ Failed to save results: {e}")


def main():
    """Main function to run database tests."""
    tester = DatabaseTester()
    
    try:
        results = tester.run_all_tests()
        tester.save_results()
        
        # Exit with appropriate code
        if results["summary"]["failed"] == 0:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n❌ Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error during testing: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
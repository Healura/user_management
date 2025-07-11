#!/usr/bin/env python3
"""
Database Content Inspection Script

This script provides comprehensive tools for inspecting the database content
of the Voice Biomarker User Management Service.

Usage:
    python scripts/inspect_database.py [options]
    
Options:
    --summary           Show table summary (row counts)
    --table TABLE_NAME  Show content of specific table
    --users             Show users table
    --audio-files       Show audio files table
    --roles             Show roles and assignments
    --sessions          Show active sessions
    --notifications     Show notification history
    --audit-logs        Show recent audit logs
    --all-tables        Show all table contents (limited rows)
    --schema            Show database schema info
    --performance       Show performance metrics
    --recent            Show recent activity (last 24h)
    --limit N           Limit number of rows (default: 10)
"""

import os
import sys
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv(project_root / '.env')
except ImportError:
    pass

try:
    from sqlalchemy import text, inspect, func
    from sqlalchemy.orm import Session
    from src.database.database import SessionLocal, engine
    from src.database.models import (
        User, UserRole, UserRoleAssignment, AudioFile, VoiceAnalysis,
        UserSession, NotificationPreference, NotificationHistory, AuditLog
    )
    from config.database_config import database_config
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure you're running this from the project root and all dependencies are installed.")
    sys.exit(1)


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_table_data(data: List[Dict], title: str = "Results"):
    """Print table data in a formatted way."""
    if not data:
        print("  No data found")
        return
    
    print(f"\n{title}:")
    print("-" * 50)
    
    for i, row in enumerate(data, 1):
        print(f"\n[{i}] {row}")


def get_table_summary(db: Session) -> Dict[str, int]:
    """Get row counts for all tables."""
    tables = {
        'users': User,
        'user_roles': UserRole,
        'user_role_assignments': UserRoleAssignment,
        'audio_files': AudioFile,
        'voice_analyses': VoiceAnalysis,
        'user_sessions': UserSession,
        'notification_preferences': NotificationPreference,
        'notification_history': NotificationHistory,
        'audit_logs': AuditLog
    }
    
    summary = {}
    for table_name, model in tables.items():
        try:
            count = db.query(model).count()
            summary[table_name] = count
        except Exception as e:
            summary[table_name] = f"Error: {e}"
    
    return summary


def get_users_info(db: Session, limit: int = 10) -> List[Dict]:
    """Get users information."""
    users = db.query(User).limit(limit).all()
    return [
        {
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active,
            'email_verified': user.email_verified,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        }
        for user in users
    ]


def get_roles_info(db: Session) -> List[Dict]:
    """Get roles and their assignments."""
    roles = db.query(UserRole).all()
    result = []
    
    for role in roles:
        assignments_count = db.query(UserRoleAssignment).filter(
            UserRoleAssignment.role_id == role.id
        ).count()
        
        result.append({
            'id': str(role.id),
            'name': role.name,
            'description': role.description,
            'users_assigned': assignments_count,
            'created_at': role.created_at.isoformat() if role.created_at else None
        })
    
    return result


def get_audio_files_info(db: Session, limit: int = 10) -> List[Dict]:
    """Get audio files information."""
    audio_files = db.query(AudioFile).order_by(AudioFile.uploaded_at.desc()).limit(limit).all()
    return [
        {
            'id': str(af.id),
            'user_id': str(af.user_id),
            'filename': af.filename,
            'file_size': af.file_size,
            'duration_seconds': float(af.duration_seconds) if af.duration_seconds else None,
            'analysis_status': af.analysis_status,
            'uploaded_at': af.uploaded_at.isoformat() if af.uploaded_at else None,
            'is_deleted': af.is_deleted
        }
        for af in audio_files
    ]


def get_active_sessions(db: Session, limit: int = 10) -> List[Dict]:
    """Get active user sessions."""
    sessions = db.query(UserSession).filter(
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    ).order_by(UserSession.last_activity.desc()).limit(limit).all()
    
    return [
        {
            'id': str(session.id),
            'user_id': str(session.user_id),
            'device_type': session.device_type,
            'ip_address': str(session.ip_address) if session.ip_address else None,
            'created_at': session.created_at.isoformat() if session.created_at else None,
            'last_activity': session.last_activity.isoformat() if session.last_activity else None,
            'expires_at': session.expires_at.isoformat() if session.expires_at else None
        }
        for session in sessions
    ]


def get_recent_notifications(db: Session, limit: int = 10) -> List[Dict]:
    """Get recent notification history."""
    notifications = db.query(NotificationHistory).order_by(
        NotificationHistory.sent_at.desc()
    ).limit(limit).all()
    
    return [
        {
            'id': str(notif.id),
            'user_id': str(notif.user_id),
            'notification_type': notif.notification_type,
            'channel': notif.channel,
            'subject': notif.subject,
            'delivery_status': notif.delivery_status,
            'sent_at': notif.sent_at.isoformat() if notif.sent_at else None,
            'error_message': notif.error_message
        }
        for notif in notifications
    ]


def get_recent_audit_logs(db: Session, limit: int = 10) -> List[Dict]:
    """Get recent audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    return [
        {
            'id': str(log.id),
            'user_id': str(log.user_id) if log.user_id else None,
            'action': log.action,
            'resource_type': log.resource_type,
            'resource_id': str(log.resource_id) if log.resource_id else None,
            'ip_address': str(log.ip_address) if log.ip_address else None,
            'timestamp': log.timestamp.isoformat() if log.timestamp else None,
            'details': log.details
        }
        for log in logs
    ]


def get_recent_activity(db: Session, hours: int = 24) -> Dict[str, Any]:
    """Get recent activity across all tables."""
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Recent users
    recent_users = db.query(User).filter(User.created_at > cutoff_time).count()
    
    # Recent audio uploads
    recent_audio = db.query(AudioFile).filter(AudioFile.uploaded_at > cutoff_time).count()
    
    # Recent logins
    recent_logins = db.query(User).filter(User.last_login > cutoff_time).count()
    
    # Recent notifications
    recent_notifications = db.query(NotificationHistory).filter(
        NotificationHistory.sent_at > cutoff_time
    ).count()
    
    # Recent audit logs
    recent_audit = db.query(AuditLog).filter(AuditLog.timestamp > cutoff_time).count()
    
    return {
        'time_period': f'Last {hours} hours',
        'cutoff_time': cutoff_time.isoformat(),
        'new_users': recent_users,
        'audio_uploads': recent_audio,
        'user_logins': recent_logins,
        'notifications_sent': recent_notifications,
        'audit_log_entries': recent_audit
    }


def get_database_schema(db: Session) -> Dict[str, Any]:
    """Get database schema information."""
    inspector = inspect(engine)
    
    schema_info = {
        'database_name': db.execute(text("SELECT current_database()")).scalar(),
        'postgresql_version': db.execute(text("SELECT version()")).scalar().split(',')[0],
        'tables': {},
        'indexes': [],
        'foreign_keys': []
    }
    
    # Get table information
    for table_name in inspector.get_table_names():
        columns = inspector.get_columns(table_name)
        schema_info['tables'][table_name] = {
            'columns': len(columns),
            'column_details': [
                {
                    'name': col['name'],
                    'type': str(col['type']),
                    'nullable': col['nullable'],
                    'default': col['default']
                }
                for col in columns
            ]
        }
        
        # Get indexes for this table
        indexes = inspector.get_indexes(table_name)
        for idx in indexes:
            schema_info['indexes'].append({
                'table': table_name,
                'name': idx['name'],
                'columns': idx['column_names'],
                'unique': idx['unique']
            })
        
        # Get foreign keys for this table
        foreign_keys = inspector.get_foreign_keys(table_name)
        for fk in foreign_keys:
            schema_info['foreign_keys'].append({
                'table': table_name,
                'name': fk['name'],
                'columns': fk['constrained_columns'],
                'referred_table': fk['referred_table'],
                'referred_columns': fk['referred_columns']
            })
    
    return schema_info


def get_performance_metrics(db: Session) -> Dict[str, Any]:
    """Get database performance metrics."""
    metrics = {}
    
    # Connection info
    metrics['connection_info'] = {
        'pool_size': database_config.db_pool_size,
        'max_overflow': database_config.db_max_overflow,
        'pool_timeout': database_config.db_pool_timeout,
        'ssl_mode': database_config.db_ssl_mode
    }
    
    # Database size
    try:
        db_size = db.execute(text("""
            SELECT pg_size_pretty(pg_database_size(current_database())) as size
        """)).scalar()
        metrics['database_size'] = db_size
    except Exception as e:
        metrics['database_size'] = f"Error: {e}"
    
    # Table sizes
    try:
        table_sizes = db.execute(text("""
            SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
            FROM pg_tables WHERE schemaname = 'public'
            ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
        """)).fetchall()
        
        metrics['table_sizes'] = [
            {'schema': row[0], 'table': row[1], 'size': row[2]}
            for row in table_sizes
        ]
    except Exception as e:
        metrics['table_sizes'] = f"Error: {e}"
    
    return metrics


def execute_custom_query(db: Session, query: str) -> List[Dict]:
    """Execute a custom SQL query."""
    try:
        result = db.execute(text(query))
        if result.returns_rows:
            return [dict(row._mapping) for row in result]
        else:
            return [{'message': 'Query executed successfully', 'rowcount': result.rowcount}]
    except Exception as e:
        return [{'error': str(e)}]


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Database Content Inspection Tool')
    parser.add_argument('--summary', action='store_true', help='Show table summary')
    parser.add_argument('--table', type=str, help='Show specific table content')
    parser.add_argument('--users', action='store_true', help='Show users table')
    parser.add_argument('--audio-files', action='store_true', help='Show audio files')
    parser.add_argument('--roles', action='store_true', help='Show roles and assignments')
    parser.add_argument('--sessions', action='store_true', help='Show active sessions')
    parser.add_argument('--notifications', action='store_true', help='Show notification history')
    parser.add_argument('--audit-logs', action='store_true', help='Show recent audit logs')
    parser.add_argument('--all-tables', action='store_true', help='Show all table contents')
    parser.add_argument('--schema', action='store_true', help='Show database schema')
    parser.add_argument('--performance', action='store_true', help='Show performance metrics')
    parser.add_argument('--recent', action='store_true', help='Show recent activity')
    parser.add_argument('--limit', type=int, default=10, help='Limit number of rows')
    parser.add_argument('--query', type=str, help='Execute custom SQL query')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if not any(vars(args).values()):
        parser.print_help()
        return
    
    try:
        db = SessionLocal()
        results = {}
        
        if args.summary:
            print_section("TABLE SUMMARY")
            summary = get_table_summary(db)
            if args.json:
                results['summary'] = summary
            else:
                for table, count in summary.items():
                    print(f"  {table:<25} {count:>10}")
        
        if args.users:
            print_section("USERS")
            users = get_users_info(db, args.limit)
            if args.json:
                results['users'] = users
            else:
                print_table_data(users, "Users")
        
        if args.roles:
            print_section("USER ROLES")
            roles = get_roles_info(db)
            if args.json:
                results['roles'] = roles
            else:
                print_table_data(roles, "Roles")
        
        if args.audio_files:
            print_section("AUDIO FILES")
            audio_files = get_audio_files_info(db, args.limit)
            if args.json:
                results['audio_files'] = audio_files
            else:
                print_table_data(audio_files, "Audio Files")
        
        if args.sessions:
            print_section("ACTIVE SESSIONS")
            sessions = get_active_sessions(db, args.limit)
            if args.json:
                results['sessions'] = sessions
            else:
                print_table_data(sessions, "Active Sessions")
        
        if args.notifications:
            print_section("RECENT NOTIFICATIONS")
            notifications = get_recent_notifications(db, args.limit)
            if args.json:
                results['notifications'] = notifications
            else:
                print_table_data(notifications, "Recent Notifications")
        
        if args.audit_logs:
            print_section("RECENT AUDIT LOGS")
            audit_logs = get_recent_audit_logs(db, args.limit)
            if args.json:
                results['audit_logs'] = audit_logs
            else:
                print_table_data(audit_logs, "Recent Audit Logs")
        
        if args.recent:
            print_section("RECENT ACTIVITY (24H)")
            activity = get_recent_activity(db)
            if args.json:
                results['recent_activity'] = activity
            else:
                print(f"  Time Period: {activity['time_period']}")
                print(f"  New Users: {activity['new_users']}")
                print(f"  Audio Uploads: {activity['audio_uploads']}")
                print(f"  User Logins: {activity['user_logins']}")
                print(f"  Notifications Sent: {activity['notifications_sent']}")
                print(f"  Audit Log Entries: {activity['audit_log_entries']}")
        
        if args.schema:
            print_section("DATABASE SCHEMA")
            schema = get_database_schema(db)
            if args.json:
                results['schema'] = schema
            else:
                print(f"  Database: {schema['database_name']}")
                print(f"  PostgreSQL Version: {schema['postgresql_version']}")
                print(f"  Tables: {len(schema['tables'])}")
                print(f"  Indexes: {len(schema['indexes'])}")
                print(f"  Foreign Keys: {len(schema['foreign_keys'])}")
        
        if args.performance:
            print_section("PERFORMANCE METRICS")
            metrics = get_performance_metrics(db)
            if args.json:
                results['performance'] = metrics
            else:
                print(f"  Database Size: {metrics.get('database_size', 'N/A')}")
                print(f"  Pool Size: {metrics['connection_info']['pool_size']}")
                print(f"  SSL Mode: {metrics['connection_info']['ssl_mode']}")
        
        if args.query:
            print_section("CUSTOM QUERY RESULTS")
            query_results = execute_custom_query(db, args.query)
            if args.json:
                results['query_results'] = query_results
            else:
                print_table_data(query_results, "Query Results")
        
        if args.all_tables:
            print_section("ALL TABLES OVERVIEW")
            all_results = {}
            all_results['summary'] = get_table_summary(db)
            all_results['users'] = get_users_info(db, 5)
            all_results['roles'] = get_roles_info(db)
            all_results['audio_files'] = get_audio_files_info(db, 5)
            all_results['sessions'] = get_active_sessions(db, 5)
            
            if args.json:
                results['all_tables'] = all_results
            else:
                for section, data in all_results.items():
                    print(f"\n{section.upper()}:")
                    print_table_data(data if isinstance(data, list) else [data])
        
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        
        db.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
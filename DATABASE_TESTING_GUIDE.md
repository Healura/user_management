# Voice Biomarker User Management Service - Database Testing Guide

## Overview

This guide provides comprehensive instructions for testing your AWS RDS PostgreSQL database setup for the Voice Biomarker User Management Service. The database is designed to be HIPAA-compliant and supports a healthcare voice analysis platform.

## Database Configuration Summary

**Database Details:**
- **Type:** AWS RDS PostgreSQL 
- **Endpoint:** `voice-biomarker-users-db.cnq0agmieipg.eu-central-1.rds.amazonaws.com`
- **Port:** 5432
- **Database Name:** `voice_biomarker_users`
- **Region:** `eu-central-1`
- **SSL:** Required for security

**Schema Overview:**
- 9 main tables for HIPAA-compliant healthcare data
- Full audit logging for compliance
- Role-based access control (RBAC)
- Voice analysis data with emotional metrics
- Secure session management
- Notification system

## Required Environment Variables

Create a `.env` file in your project root with the following variables:

```bash
# Database Configuration (Required)
RDS_ENDPOINT=voice-biomarker-users-db.cnq0agmieipg.eu-central-1.rds.amazonaws.com
RDS_PORT=5432
RDS_DB_NAME=voice_biomarker_users
RDS_USERNAME=postgres
RDS_PASSWORD=your_secure_database_password_here

# Database Connection Pool Settings
DB_POOL_SIZE=5
DB_MAX_OVERFLOW=10
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600
DB_SSL_MODE=require
DB_ECHO=false

# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_REGION=eu-central-1

# Application Settings
ENVIRONMENT=development
WORKERS=4

# Security
JWT_SECRET_KEY=your_super_secret_jwt_key_here
JWT_ALGORITHM=RS256

# HIPAA Compliance
HIPAA_LOGGING_ENABLED=true
DATA_RETENTION_DAYS=2555  # 7 years
PHI_ENCRYPTION_REQUIRED=true
```

## Running the Comprehensive Database Tests

### 1. Quick Test

Run the comprehensive testing script:

```bash
python test_database_setup.py
```

This script tests 13 critical aspects of your database:

1. **Environment Variables** - Verifies all required env vars are set
2. **Database Connection** - Tests basic connectivity and latency
3. **Database Configuration** - Checks SSL, encoding, timezone settings
4. **Schema Accessibility** - Verifies schema access and permissions
5. **Table Structure** - Confirms all 9 expected tables exist
6. **Database Indexes** - Checks critical performance indexes
7. **Database Constraints** - Verifies foreign keys and unique constraints
8. **CRUD Operations** - Tests create, read, update, delete functionality
9. **Table Relationships** - Validates relationships and cascading deletes
10. **Performance Metrics** - Measures query response times
11. **SSL Connection** - Verifies SSL encryption is active
12. **Connection Pool** - Tests connection pooling functionality
13. **Migration Status** - Checks Alembic migration system

### 2. Individual Component Tests

You can also test individual components using the existing health endpoints:

```bash
# Test basic connectivity
curl http://localhost:8000/health

# Test detailed database status
curl http://localhost:8000/health/database

# Test readiness for production
curl http://localhost:8000/health/ready
```

### 3. Test Results

The script generates detailed JSON results in `database_test_results.json` with:
- Detailed test results for each component
- Performance metrics
- Error details for failed tests
- Summary statistics

## Database Schema Details

### Core Tables

1. **users** - User accounts with healthcare provider associations
   - UUID primary keys for security
   - Email verification and privacy consent tracking
   - Data retention policy compliance

2. **user_roles** - Role definitions for RBAC
   - Standard roles: patient, healthcare_provider, admin, analyst

3. **user_role_assignments** - Many-to-many user-role relationships
   - Audit trail of who assigned roles and when

4. **audio_files** - Voice recordings metadata
   - Encryption key tracking
   - Soft delete with scheduled cleanup
   - HIPAA-compliant storage references

5. **voice_analyses** - Analysis results
   - Emotional metrics (arousal, valence, dominance)
   - Depression/anxiety scores (PHQ-8, GAD-7)
   - Confidence scoring and model versioning

6. **user_sessions** - Session management
   - Device tracking and IP logging
   - Token hash storage for security
   - Session expiration management

7. **notification_preferences** - User notification settings
   - Granular control over notification types
   - HIPAA-compliant communication preferences

8. **notification_history** - Audit trail of sent notifications
   - Delivery status tracking
   - Error logging for failed deliveries

9. **audit_logs** - HIPAA compliance audit trail
   - All data access and modifications logged
   - User action tracking with IP and timestamp

### Key Features

- **PostgreSQL-specific features:** UUID, INET, JSONB columns
- **Comprehensive indexing** for performance
- **Foreign key constraints** for data integrity
- **Cascade deletes** for data cleanup
- **Timezone-aware** timestamps
- **Audit logging** for HIPAA compliance

## Performance Expectations

### Query Performance Thresholds

- **Simple queries:** < 100ms average
- **Complex joins:** < 1000ms
- **Connection latency:** < 50ms to AWS RDS
- **Connection pool:** Should handle 5+ concurrent connections

### AWS RDS Optimizations

The database is configured with:
- Connection pooling (size: 5, max overflow: 10)
- SSL encryption (required mode)
- Connection pre-ping for reliability
- Statement timeout (30 seconds)
- Pool recycling (1 hour)

## Troubleshooting Common Issues

### 1. Connection Issues

**Problem:** Cannot connect to database
```
❌ Database Connection: Connection failed: could not connect to server
```

**Solutions:**
- Verify RDS_PASSWORD environment variable
- Check VPC security groups allow connections on port 5432
- Ensure RDS instance is publicly accessible (if connecting from outside VPC)
- Verify RDS endpoint URL is correct

### 2. SSL Issues

**Problem:** SSL connection fails
```
❌ SSL Connection: SSL not enabled (found: off)
```

**Solutions:**
- Set `DB_SSL_MODE=require` in environment
- Verify RDS instance has SSL enabled
- Check that SSL certificates are valid

### 3. Missing Tables

**Problem:** Expected tables don't exist
```
❌ Table Structure: Missing tables: users, user_roles
```

**Solutions:**
- Run database migrations: `alembic upgrade head`
- Check if you're connected to the correct database
- Verify user has CREATE privileges

### 4. Performance Issues

**Problem:** Slow query performance
```
❌ Performance Metrics: Average: 2000ms, Complex: 8000ms
```

**Solutions:**
- Check if indexes are missing: Look at "Database Indexes" test results
- Review connection pool settings
- Monitor RDS CloudWatch metrics
- Consider upgrading RDS instance class

### 5. Permission Issues

**Problem:** Cannot create test tables
```
❌ Database Configuration: Configuration check failed: permission denied for relation
```

**Solutions:**
- Verify database user has necessary privileges
- Check if user can CREATE and DROP tables
- Review RDS parameter groups for restrictions

## Production Deployment Checklist

### Pre-deployment Database Verification

- [ ] All environment variables configured
- [ ] Database connection test passes
- [ ] SSL connection verified
- [ ] All tables exist with correct structure
- [ ] Indexes are in place for performance
- [ ] Foreign key constraints working
- [ ] Migration system initialized
- [ ] Connection pooling configured
- [ ] Audit logging enabled

### Security Verification

- [ ] SSL mode set to 'require'
- [ ] Database user has minimal necessary privileges
- [ ] RDS security groups properly configured
- [ ] Database password is secure and rotated
- [ ] Audit logging captures all required events
- [ ] Data encryption at rest enabled
- [ ] Network access restricted to application servers

### Performance Verification

- [ ] Query response times within acceptable limits
- [ ] Connection pool size appropriate for load
- [ ] Database monitoring alerts configured
- [ ] CloudWatch metrics enabled
- [ ] Backup strategy implemented
- [ ] Point-in-time recovery tested

## Monitoring and Maintenance

### Key Metrics to Monitor

1. **Connection Metrics**
   - Active connections
   - Connection pool utilization
   - Failed connection attempts

2. **Performance Metrics**
   - Query response times
   - Slow query logs
   - CPU and memory utilization

3. **HIPAA Compliance Metrics**
   - Audit log volume
   - Failed access attempts
   - Data retention compliance

### Regular Maintenance Tasks

- **Weekly:** Review slow query logs
- **Monthly:** Analyze audit logs for compliance
- **Quarterly:** Test backup and recovery procedures
- **Annually:** Review and rotate database credentials

## Advanced Testing

### Load Testing

For production readiness, consider running load tests:

```python
# Example load test script
import asyncio
import aiohttp
import time

async def load_test():
    """Simple load test for database endpoints."""
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(100):  # 100 concurrent requests
            task = session.get('http://localhost:8000/health/database')
            tasks.append(task)
        
        start_time = time.time()
        responses = await asyncio.gather(*tasks)
        end_time = time.time()
        
        print(f"100 requests completed in {end_time - start_time:.2f} seconds")

# Run with: asyncio.run(load_test())
```

### Migration Testing

Test your migration system:

```bash
# Check current migration status
alembic current

# Test upgrading to latest
alembic upgrade head

# Test downgrading (in test environment only)
alembic downgrade -1
alembic upgrade head
```

## Getting Help

If you encounter issues not covered in this guide:

1. Check the application logs for detailed error messages
2. Review the `database_test_results.json` file for detailed test output
3. Monitor CloudWatch logs for RDS-specific issues
4. Verify network connectivity between your application and RDS

## Security Best Practices

1. **Network Security**
   - Use VPC for network isolation
   - Restrict security group access
   - Enable VPC endpoints for enhanced security

2. **Authentication**
   - Use IAM database authentication when possible
   - Rotate database credentials regularly
   - Use least-privilege access principles

3. **Data Protection**
   - Enable encryption at rest
   - Use SSL/TLS for data in transit
   - Implement proper backup encryption

4. **Monitoring**
   - Enable CloudTrail for API logging
   - Set up CloudWatch alarms
   - Regular security assessments

Remember: This is a healthcare application handling PHI data. Always prioritize security and compliance in your database configuration and testing procedures. 
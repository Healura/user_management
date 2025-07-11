# Database Connection Troubleshooting Guide

## 🔍 Issue Identified

**Problem**: Connection timeout when connecting to AWS RDS PostgreSQL database.

**Root Cause**: Your current public IP address (`185.199.104.14`) is not allowed in the RDS Security Groups.

**Error Message**: 
```
Database connection failed: (psycopg2.OperationalError) connection to server at "voice-biomarker-users-db.cnq0agmieipg.eu-central-1.rds.amazonaws.com" (3.120.213.16), port 5432 failed: timeout expired
```

## 🚀 Quick Fix (Automated)

### Option 1: Use the Automated Script
```bash
python fix_rds_security_group.py
```

This script will:
1. Get your current public IP address
2. Check AWS CLI configuration
3. Find the RDS security groups automatically
4. Add your IP to the security groups

### Option 2: Manual AWS Console Fix

1. **Get Your Public IP**: `185.199.104.14` (already identified)

2. **Open AWS Console**:
   - Go to [AWS Console](https://console.aws.amazon.com/)
   - Navigate to **EC2** → **Security Groups**

3. **Find RDS Security Group**:
   - Search for security groups associated with your RDS instance
   - Look for groups with names containing "rds", "database", or "postgres"

4. **Add Inbound Rule**:
   - Click on the security group → **Inbound Rules** → **Edit inbound rules**
   - Click **Add rule**
   - Configure:
     - **Type**: PostgreSQL
     - **Port**: 5432
     - **Source**: My IP (`185.199.104.14/32`)
     - **Description**: Allow local development access
   - Click **Save rules**

## 🔧 Alternative Solutions

### Option 3: Use AWS CLI Manually

```bash
# Get your RDS security group ID
aws rds describe-db-instances --db-instance-identifier voice-biomarker-users-db --region eu-central-1

# Add your IP to the security group (replace SG_ID with actual ID)
aws ec2 authorize-security-group-ingress \
  --group-id SG_ID \
  --protocol tcp \
  --port 5432 \
  --cidr 185.199.104.14/32 \
  --region eu-central-1
```

### Option 4: Update Database Configuration (Temporary)

If you can't modify security groups, you can try adjusting connection timeouts:

```python
# In src/database/database.py, modify connect_args:
connect_args={
    "sslmode": "prefer",  # Try less strict SSL
    "connect_timeout": 60,  # Increase timeout
    "options": "-c statement_timeout=60000"
}
```

## 🧪 Verification Steps

After fixing the security group:

1. **Wait 30-60 seconds** for changes to propagate
2. **Test network connectivity**:
   ```bash
   python test_network_connectivity.py
   ```
3. **Test database connection**:
   ```bash
   python test_database_config.py
   ```

## 📋 Common Issues & Solutions

### Issue: AWS CLI Not Installed
**Solution**: Install AWS CLI
```bash
# macOS
brew install awscli

# Or download from:
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
```

### Issue: AWS Credentials Not Configured
**Solution**: Configure AWS credentials
```bash
aws configure
```
You'll need:
- AWS Access Key ID
- AWS Secret Access Key
- Default region: `eu-central-1`

### Issue: Insufficient Permissions
**Solution**: Ensure your AWS user has these permissions:
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `rds:DescribeDBInstances`

### Issue: Dynamic IP Address
**Solution**: If your IP changes frequently, consider:
1. Using a VPN with static IP
2. Setting up a bastion host
3. Using AWS Systems Manager Session Manager

## 🛡️ Security Considerations

### Best Practices:
1. **Use specific IP ranges**: Always use `/32` for single IP addresses
2. **Remove old IPs**: Clean up security groups when IP changes
3. **Use descriptive names**: Add descriptions to security group rules
4. **Monitor access**: Enable CloudTrail for security group changes

### Production Considerations:
- Use VPC endpoints for private connectivity
- Consider using AWS RDS Proxy
- Implement connection pooling
- Use read replicas for read-heavy workloads

## 🔄 IP Address Management

### If Your IP Changes:
1. **Get new IP**: `curl -s https://httpbin.org/ip | jq -r '.origin'`
2. **Update security group**: Remove old IP, add new IP
3. **Test connection**: Verify connectivity works

### Script for IP Updates:
```bash
# Remove old IP (replace with actual old IP)
aws ec2 revoke-security-group-ingress \
  --group-id SG_ID \
  --protocol tcp \
  --port 5432 \
  --cidr OLD_IP/32 \
  --region eu-central-1

# Add new IP
python fix_rds_security_group.py
```

## 📞 Support

If you continue to have issues:

1. **Check RDS Status**: Ensure RDS instance is in "available" state
2. **Verify Region**: Confirm you're working in `eu-central-1`
3. **Check VPC**: Ensure RDS is in correct VPC and subnets
4. **Review Logs**: Check CloudWatch logs for additional error details

## 🎯 Next Steps

Once database connectivity is fixed:

1. ✅ Test database connection
2. ✅ Run database migrations
3. ✅ Test API endpoints
4. ✅ Set up monitoring and alerts
5. ✅ Configure backup policies

---

**Created**: Database connection troubleshooting guide  
**Last Updated**: Current session  
**Status**: Ready for implementation 
#!/usr/bin/env python3
"""
AWS Connection Test Script for Voice Biomarker Application

This script tests AWS connectivity and permissions for all services
required by the Voice Biomarker application.

Usage:
    python test_aws_connection.py
"""

import os
import sys
import json
import time
from datetime import datetime, UTC
from typing import Dict, Any, Optional

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if it exists
except ImportError:
    # dotenv not available, try loading manually
    env_file = '.env'
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
except ImportError:
    print("❌ boto3 not installed. Install with: pip install boto3")
    sys.exit(1)

class AWSConnectionTester:
    """Test AWS connectivity and permissions."""
    
    def __init__(self):
        """Initialize the AWS connection tester."""
        self.results = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tests": {},
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "warnings": 0
            }
        }
        
        # Check for credentials
        self.aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.aws_region = os.getenv('AWS_REGION', 'eu-central-1')
        
    def log_test_result(self, test_name: str, success: bool, 
                       message: str = "", details: Dict[str, Any] = None,
                       warning: bool = False):
        """Log and store test results."""
        if warning:
            print(f"⚠️  {test_name}: {message}")
            self.results["summary"]["warnings"] += 1
            status = "warning"
        elif success:
            print(f"✅ {test_name}: {message}")
            self.results["summary"]["passed"] += 1
            status = "passed"
        else:
            print(f"❌ {test_name}: {message}")
            self.results["summary"]["failed"] += 1
            status = "failed"
        
        self.results["tests"][test_name] = {
            "status": status,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now(UTC).isoformat()
        }
        self.results["summary"]["total_tests"] += 1
    
    def test_credentials_configured(self) -> bool:
        """Test 1: Check if AWS credentials are configured."""
        test_name = "AWS Credentials Configuration"
        
        missing = []
        if not self.aws_access_key:
            missing.append("AWS_ACCESS_KEY_ID")
        if not self.aws_secret_key:
            missing.append("AWS_SECRET_ACCESS_KEY")
        
        details = {
            "aws_access_key_configured": bool(self.aws_access_key),
            "aws_secret_key_configured": bool(self.aws_secret_key),
            "aws_region": self.aws_region,
            "credentials_source": "environment_variables_or_dotenv",
            "dotenv_file_exists": os.path.exists('.env')
        }
        
        if missing:
            self.log_test_result(
                test_name, False,
                f"Missing environment variables: {', '.join(missing)}",
                details
            )
            return False
        
        # Mask the keys for security
        details["aws_access_key_preview"] = f"{self.aws_access_key[:8]}...{self.aws_access_key[-4:]}"
        
        self.log_test_result(
            test_name, True,
            f"AWS credentials configured for region {self.aws_region}",
            details
        )
        return True
    
    def test_sts_identity(self) -> bool:
        """Test 2: Verify credentials work with AWS STS."""
        test_name = "AWS Identity Verification"
        
        try:
            sts_client = boto3.client('sts', region_name=self.aws_region)
            identity = sts_client.get_caller_identity()
            
            details = {
                "user_id": identity.get('UserId'),
                "account_id": identity.get('Account'),
                "arn": identity.get('Arn'),
                "user_type": "IAM User" if ":user/" in identity.get('Arn', '') else "Role/Other"
            }
            
            self.log_test_result(
                test_name, True,
                f"Authenticated as {details['user_type']}: {identity.get('UserId')}",
                details
            )
            return True
            
        except (NoCredentialsError, PartialCredentialsError) as e:
            self.log_test_result(
                test_name, False,
                f"Invalid credentials: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
        except ClientError as e:
            self.log_test_result(
                test_name, False,
                f"AWS API error: {e.response['Error']['Message']}",
                {"error_code": e.response['Error']['Code']}
            )
            return False
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"Unexpected error: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_rds_permissions(self) -> bool:
        """Test 3: Check RDS permissions."""
        test_name = "RDS Permissions"
        
        try:
            rds_client = boto3.client('rds', region_name=self.aws_region)
            
            # Try to describe DB instances
            response = rds_client.describe_db_instances()
            
            # Look for our specific database
            voice_biomarker_db = None
            for db in response.get('DBInstances', []):
                if 'voice-biomarker' in db.get('DBInstanceIdentifier', '').lower():
                    voice_biomarker_db = db
                    break
            
            details = {
                "total_rds_instances": len(response.get('DBInstances', [])),
                "can_describe_instances": True,
                "voice_biomarker_db_found": voice_biomarker_db is not None
            }
            
            if voice_biomarker_db:
                details.update({
                    "db_identifier": voice_biomarker_db.get('DBInstanceIdentifier'),
                    "db_status": voice_biomarker_db.get('DBInstanceStatus'),
                    "db_endpoint": voice_biomarker_db.get('Endpoint', {}).get('Address'),
                    "db_engine": voice_biomarker_db.get('Engine')
                })
            
            success = details["can_describe_instances"]
            message = f"RDS access verified"
            if voice_biomarker_db:
                message += f" - Found Voice Biomarker DB ({voice_biomarker_db.get('DBInstanceStatus')})"
            else:
                message += " - Voice Biomarker DB not found"
            
            self.log_test_result(test_name, success, message, details)
            return success
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                self.log_test_result(
                    test_name, False,
                    f"RDS access denied: {e.response['Error']['Message']}",
                    {"error_code": error_code}
                )
            else:
                self.log_test_result(
                    test_name, False,
                    f"RDS API error: {e.response['Error']['Message']}",
                    {"error_code": error_code}
                )
            return False
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"RDS test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_s3_permissions(self) -> bool:
        """Test 4: Check S3 permissions."""
        test_name = "S3 Permissions"
        
        try:
            s3_client = boto3.client('s3', region_name=self.aws_region)
            
            # Test basic S3 access
            response = s3_client.list_buckets()
            
            # Look for voice biomarker buckets
            voice_buckets = []
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name', '')
                if 'voice-biomarker' in bucket_name.lower():
                    voice_buckets.append(bucket_name)
            
            details = {
                "total_buckets": len(response.get('Buckets', [])),
                "can_list_buckets": True,
                "voice_biomarker_buckets": voice_buckets
            }
            
            # Test bucket-specific operations if buckets exist
            if voice_buckets:
                test_bucket = voice_buckets[0]
                try:
                    # Test if we can list objects in the bucket
                    s3_client.list_objects_v2(Bucket=test_bucket, MaxKeys=1)
                    details["can_list_objects"] = True
                except ClientError as e:
                    details["can_list_objects"] = False
                    details["list_objects_error"] = e.response['Error']['Code']
            
            success = details["can_list_buckets"]
            message = f"S3 access verified ({len(voice_buckets)} Voice Biomarker buckets found)"
            
            self.log_test_result(test_name, success, message, details)
            return success
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.log_test_result(
                test_name, False,
                f"S3 access denied: {e.response['Error']['Message']}",
                {"error_code": error_code}
            )
            return False
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"S3 test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_kms_permissions(self) -> bool:
        """Test 5: Check KMS permissions."""
        test_name = "KMS Permissions"
        
        try:
            kms_client = boto3.client('kms', region_name=self.aws_region)
            
            # Test basic KMS access by listing keys
            response = kms_client.list_keys(Limit=10)
            
            # Look for voice biomarker keys
            voice_keys = []
            for key in response.get('Keys', []):
                try:
                    key_details = kms_client.describe_key(KeyId=key['KeyId'])
                    key_description = key_details.get('KeyMetadata', {}).get('Description', '')
                    if 'voice-biomarker' in key_description.lower():
                        voice_keys.append({
                            'KeyId': key['KeyId'],
                            'Description': key_description
                        })
                except ClientError:
                    # Can't describe this key, skip it
                    continue
            
            details = {
                "total_keys_found": len(response.get('Keys', [])),
                "can_list_keys": True,
                "voice_biomarker_keys": len(voice_keys),
                "can_describe_keys": True
            }
            
            success = details["can_list_keys"]
            message = f"KMS access verified ({len(voice_keys)} Voice Biomarker keys found)"
            
            self.log_test_result(test_name, success, message, details)
            return success
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                self.log_test_result(
                    test_name, False,
                    f"KMS access denied: {e.response['Error']['Message']}",
                    {"error_code": error_code}
                )
            else:
                self.log_test_result(
                    test_name, False,
                    f"KMS API error: {e.response['Error']['Message']}",
                    {"error_code": error_code}
                )
            return False
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"KMS test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_cloudwatch_permissions(self) -> bool:
        """Test 6: Check CloudWatch Logs permissions."""
        test_name = "CloudWatch Logs Permissions"
        
        try:
            logs_client = boto3.client('logs', region_name=self.aws_region)
            
            # Test basic CloudWatch access
            response = logs_client.describe_log_groups(limit=10)
            
            # Look for voice biomarker log groups
            voice_log_groups = []
            for log_group in response.get('logGroups', []):
                log_group_name = log_group.get('logGroupName', '')
                if 'voice-biomarker' in log_group_name.lower():
                    voice_log_groups.append(log_group_name)
            
            details = {
                "total_log_groups": len(response.get('logGroups', [])),
                "can_describe_log_groups": True,
                "voice_biomarker_log_groups": voice_log_groups
            }
            
            success = details["can_describe_log_groups"]
            message = f"CloudWatch Logs access verified ({len(voice_log_groups)} Voice Biomarker log groups found)"
            
            self.log_test_result(test_name, success, message, details)
            return success
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.log_test_result(
                test_name, False,
                f"CloudWatch access denied: {e.response['Error']['Message']}",
                {"error_code": error_code}
            )
            return False
        except Exception as e:
            self.log_test_result(
                test_name, False,
                f"CloudWatch test failed: {str(e)}",
                {"error_type": type(e).__name__}
            )
            return False
    
    def test_secrets_manager_permissions(self) -> bool:
        """Test 7: Check Secrets Manager permissions (optional)."""
        test_name = "Secrets Manager Permissions"
        
        try:
            secrets_client = boto3.client('secretsmanager', region_name=self.aws_region)
            
            # Test basic Secrets Manager access
            response = secrets_client.list_secrets(MaxResults=10)
            
            # Look for voice biomarker secrets
            voice_secrets = []
            for secret in response.get('SecretList', []):
                secret_name = secret.get('Name', '')
                if 'voice-biomarker' in secret_name.lower():
                    voice_secrets.append(secret_name)
            
            details = {
                "total_secrets": len(response.get('SecretList', [])),
                "can_list_secrets": True,
                "voice_biomarker_secrets": voice_secrets
            }
            
            success = details["can_list_secrets"]
            message = f"Secrets Manager access verified ({len(voice_secrets)} Voice Biomarker secrets found)"
            
            self.log_test_result(test_name, success, message, details)
            return success
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            # Secrets Manager access is optional, so treat as warning
            self.log_test_result(
                test_name, True,
                f"Secrets Manager access limited: {e.response['Error']['Message']}",
                {"error_code": error_code, "optional": True},
                warning=True
            )
            return True
        except Exception as e:
            self.log_test_result(
                test_name, True,
                f"Secrets Manager test failed (optional): {str(e)}",
                {"error_type": type(e).__name__, "optional": True},
                warning=True
            )
            return True
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all AWS connectivity tests."""
        print("🚀 Starting AWS Connection Testing for Voice Biomarker Application...")
        print(f"📋 Testing AWS services in region: {self.aws_region}")
        print("-" * 80)
        
        # List of all tests to run
        tests = [
            self.test_credentials_configured,
            self.test_sts_identity,
            self.test_rds_permissions,
            self.test_s3_permissions,
            self.test_kms_permissions,
            self.test_cloudwatch_permissions,
            self.test_secrets_manager_permissions
        ]
        
        # Run tests
        critical_failure = False
        for test_func in tests:
            try:
                result = test_func()
                # First 4 tests are critical
                if not result and test_func in tests[:4]:
                    critical_failure = True
            except Exception as e:
                test_name = test_func.__name__.replace("test_", "").replace("_", " ").title()
                self.log_test_result(
                    test_name, False,
                    f"Test execution failed: {str(e)}",
                    {"error_type": type(e).__name__}
                )
                critical_failure = True
        
        # Print summary
        print("-" * 80)
        summary = self.results["summary"]
        print(f"📊 AWS Connection Test Summary:")
        print(f"   ✅ Passed: {summary['passed']}")
        print(f"   ❌ Failed: {summary['failed']}")
        print(f"   ⚠️  Warnings: {summary['warnings']}")
        print(f"   📋 Total: {summary['total_tests']}")
        
        if summary['failed'] == 0:
            print("\n🎉 All AWS services are accessible! Your credentials are working correctly.")
            print("You can now run your Voice Biomarker application with confidence.")
        elif critical_failure:
            print("\n❌ Critical AWS connectivity issues detected.")
            print("Please review the failed tests and check your IAM permissions.")
        else:
            print("\n⚠️  Some optional services have limited access, but core functionality should work.")
        
        print(f"\n📄 Detailed results saved to: aws_connection_test_results.json")
        
        return self.results
    
    def save_results(self, filename: str = "aws_connection_test_results.json"):
        """Save test results to a JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
        except Exception as e:
            print(f"❌ Failed to save results: {e}")


def main():
    """Main function to run AWS connection tests."""
    print("🔑 Voice Biomarker AWS Connection Tester")
    print("=" * 50)
    
    tester = AWSConnectionTester()
    
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
"""CloudTrail log parser for healthcare compliance monitoring."""

import json
import gzip
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

import boto3
from botocore.exceptions import ClientError

from config.storage_config import storage_config
from config.aws_config import aws_config

logger = logging.getLogger(__name__)


class CloudTrailEvent:
    """Represents a parsed CloudTrail event."""
    
    def __init__(self, raw_event: Dict[str, Any]):
        self.raw_event = raw_event
        self.event_time = datetime.fromisoformat(
            raw_event.get('eventTime', '').replace('Z', '+00:00')
        )
        self.event_name = raw_event.get('eventName', '')
        self.event_source = raw_event.get('eventSource', '')
        self.user_identity = raw_event.get('userIdentity', {})
        self.source_ip = raw_event.get('sourceIPAddress', '')
        self.user_agent = raw_event.get('userAgent', '')
        self.request_parameters = raw_event.get('requestParameters', {})
        self.response_elements = raw_event.get('responseElements', {})
        self.error_code = raw_event.get('errorCode')
        self.error_message = raw_event.get('errorMessage')
    
    @property
    def is_s3_event(self) -> bool:
        """Check if this is an S3 event."""
        return self.event_source == 's3.amazonaws.com'
    
    @property
    def is_kms_event(self) -> bool:
        """Check if this is a KMS event."""
        return self.event_source == 'kms.amazonaws.com'
    
    @property
    def is_error(self) -> bool:
        """Check if this event represents an error."""
        return self.error_code is not None
    
    @property
    def user_id(self) -> Optional[str]:
        """Extract user ID from event."""
        return self.user_identity.get('principalId', '')
    
    @property
    def bucket_name(self) -> Optional[str]:
        """Extract bucket name for S3 events."""
        if self.is_s3_event:
            return self.request_parameters.get('bucketName')
        return None
    
    @property
    def object_key(self) -> Optional[str]:
        """Extract object key for S3 events."""
        if self.is_s3_event:
            return self.request_parameters.get('key')
        return None


class CloudTrailParser:
    """Parse and analyze CloudTrail logs for healthcare compliance."""
    
    def __init__(self):
        """Initialize CloudTrail parser."""
        if aws_config.aws_access_key_id:
            session = boto3.Session(
                aws_access_key_id=aws_config.aws_access_key_id,
                aws_secret_access_key=aws_config.aws_secret_access_key.get_secret_value() if aws_config.aws_secret_access_key else None,
                region_name=aws_config.aws_region
            )
            self.s3_client = session.client('s3')
            self.cloudtrail_client = session.client('cloudtrail')
        else:
            self.s3_client = None
            self.cloudtrail_client = None
            logger.warning("AWS clients not initialized for CloudTrail parser")
    
    async def parse_log_file(
        self,
        bucket_name: str,
        log_key: str
    ) -> List[CloudTrailEvent]:
        """
        Parse a CloudTrail log file from S3.
        
        Args:
            bucket_name: S3 bucket containing logs
            log_key: S3 key for log file
            
        Returns:
            List of parsed CloudTrail events
        """
        try:
            if not self.s3_client:
                return []
            
            # Download log file
            response = self.s3_client.get_object(
                Bucket=bucket_name,
                Key=log_key
            )
            
            # CloudTrail logs are gzipped JSON
            compressed_content = response['Body'].read()
            
            # Decompress
            decompressed_content = gzip.decompress(compressed_content)
            
            # Parse JSON
            log_data = json.loads(decompressed_content)
            
            # Extract events
            events = []
            for record in log_data.get('Records', []):
                try:
                    event = CloudTrailEvent(record)
                    events.append(event)
                except Exception as e:
                    logger.error(f"Failed to parse event: {e}")
            
            return events
            
        except ClientError as e:
            logger.error(f"Failed to download CloudTrail log: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse CloudTrail log: {e}")
            return []
    
    async def analyze_s3_access_patterns(
        self,
        events: List[CloudTrailEvent],
        time_window: Optional[timedelta] = None
    ) -> Dict[str, Any]:
        """
        Analyze S3 access patterns for anomalies.
        
        Args:
            events: List of CloudTrail events
            time_window: Time window to analyze
            
        Returns:
            Analysis results
        """
        analysis = {
            'total_events': len(events),
            's3_events': 0,
            'unique_users': set(),
            'unique_ips': set(),
            'access_by_user': defaultdict(int),
            'access_by_ip': defaultdict(int),
            'access_by_action': defaultdict(int),
            'errors': [],
            'suspicious_patterns': []
        }
        
        # Filter by time window if specified
        if time_window:
            cutoff = datetime.utcnow() - time_window
            events = [e for e in events if e.event_time > cutoff]
        
        # Analyze S3 events
        for event in events:
            if not event.is_s3_event:
                continue
            
            analysis['s3_events'] += 1
            analysis['unique_users'].add(event.user_id)
            analysis['unique_ips'].add(event.source_ip)
            analysis['access_by_user'][event.user_id] += 1
            analysis['access_by_ip'][event.source_ip] += 1
            analysis['access_by_action'][event.event_name] += 1
            
            # Track errors
            if event.is_error:
                analysis['errors'].append({
                    'time': event.event_time.isoformat(),
                    'user': event.user_id,
                    'action': event.event_name,
                    'error': event.error_code,
                    'message': event.error_message
                })
        
        # Convert sets to counts
        analysis['unique_users'] = len(analysis['unique_users'])
        analysis['unique_ips'] = len(analysis['unique_ips'])
        
        # Detect suspicious patterns
        analysis['suspicious_patterns'] = self._detect_suspicious_patterns(
            analysis['access_by_user'],
            analysis['access_by_ip'],
            analysis['errors']
        )
        
        return analysis
    
    async def find_phi_access_events(
        self,
        events: List[CloudTrailEvent],
        phi_bucket: str = None
    ) -> List[Dict[str, Any]]:
        """
        Find events that accessed PHI data.
        
        Args:
            events: List of CloudTrail events
            phi_bucket: PHI bucket name
            
        Returns:
            List of PHI access events
        """
        if phi_bucket is None:
            phi_bucket = storage_config.aws_s3_bucket
        
        phi_events = []
        
        for event in events:
            if not event.is_s3_event:
                continue
            
            if event.bucket_name == phi_bucket:
                phi_event = {
                    'time': event.event_time.isoformat(),
                    'user': event.user_id,
                    'action': event.event_name,
                    'object_key': event.object_key,
                    'source_ip': event.source_ip,
                    'user_agent': event.user_agent,
                    'success': not event.is_error
                }
                
                # Check for high-risk actions
                high_risk_actions = [
                    'DeleteObject',
                    'DeleteBucket',
                    'PutBucketPolicy',
                    'PutBucketAcl',
                    'PutObjectAcl'
                ]
                
                if event.event_name in high_risk_actions:
                    phi_event['high_risk'] = True
                
                phi_events.append(phi_event)
        
        return phi_events
    
    async def generate_compliance_metrics(
        self,
        events: List[CloudTrailEvent]
    ) -> Dict[str, Any]:
        """
        Generate compliance metrics from CloudTrail events.
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            Compliance metrics
        """
        metrics = {
            'total_events': len(events),
            'time_range': {
                'start': None,
                'end': None
            },
            's3_metrics': {
                'total_operations': 0,
                'successful_operations': 0,
                'failed_operations': 0,
                'unique_files_accessed': set(),
                'data_uploaded_events': 0,
                'data_downloaded_events': 0,
                'data_deleted_events': 0
            },
            'kms_metrics': {
                'total_operations': 0,
                'encryption_operations': 0,
                'decryption_operations': 0,
                'key_rotation_events': 0
            },
            'compliance_violations': []
        }
        
        if not events:
            return metrics
        
        # Set time range
        event_times = [e.event_time for e in events]
        metrics['time_range']['start'] = min(event_times).isoformat()
        metrics['time_range']['end'] = max(event_times).isoformat()
        
        # Analyze events
        for event in events:
            if event.is_s3_event:
                metrics['s3_metrics']['total_operations'] += 1
                
                if event.is_error:
                    metrics['s3_metrics']['failed_operations'] += 1
                else:
                    metrics['s3_metrics']['successful_operations'] += 1
                
                if event.object_key:
                    metrics['s3_metrics']['unique_files_accessed'].add(event.object_key)
                
                # Categorize operations
                if event.event_name in ['PutObject', 'UploadPart']:
                    metrics['s3_metrics']['data_uploaded_events'] += 1
                elif event.event_name in ['GetObject', 'HeadObject']:
                    metrics['s3_metrics']['data_downloaded_events'] += 1
                elif event.event_name == 'DeleteObject':
                    metrics['s3_metrics']['data_deleted_events'] += 1
            
            elif event.is_kms_event:
                metrics['kms_metrics']['total_operations'] += 1
                
                if event.event_name == 'Encrypt':
                    metrics['kms_metrics']['encryption_operations'] += 1
                elif event.event_name == 'Decrypt':
                    metrics['kms_metrics']['decryption_operations'] += 1
                elif event.event_name == 'ScheduleKeyRotation':
                    metrics['kms_metrics']['key_rotation_events'] += 1
            
            # Check for compliance violations
            violations = self._check_compliance_violations(event)
            metrics['compliance_violations'].extend(violations)
        
        # Convert set to count
        metrics['s3_metrics']['unique_files_accessed'] = len(
            metrics['s3_metrics']['unique_files_accessed']
        )
        
        return metrics
    
    def _detect_suspicious_patterns(
        self,
        access_by_user: Dict[str, int],
        access_by_ip: Dict[str, int],
        errors: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect suspicious access patterns."""
        patterns = []
        
        # High volume access from single user
        for user, count in access_by_user.items():
            if count > 100:  # Threshold
                patterns.append({
                    'type': 'high_volume_user',
                    'user': user,
                    'access_count': count,
                    'severity': 'medium'
                })
        
        # High volume access from single IP
        for ip, count in access_by_ip.items():
            if count > 200:  # Threshold
                patterns.append({
                    'type': 'high_volume_ip',
                    'ip': ip,
                    'access_count': count,
                    'severity': 'medium'
                })
        
        # Multiple failed attempts
        failed_by_user = defaultdict(int)
        for error in errors:
            failed_by_user[error['user']] += 1
        
        for user, count in failed_by_user.items():
            if count > 10:  # Threshold
                patterns.append({
                    'type': 'multiple_failures',
                    'user': user,
                    'failure_count': count,
                    'severity': 'high'
                })
        
        return patterns
    
    def _check_compliance_violations(
        self,
        event: CloudTrailEvent
    ) -> List[Dict[str, Any]]:
        """Check event for compliance violations."""
        violations = []
        
        # Check for unencrypted uploads
        if event.event_name == 'PutObject' and event.is_s3_event:
            encryption = event.request_parameters.get('x-amz-server-side-encryption')
            if not encryption:
                violations.append({
                    'type': 'unencrypted_upload',
                    'time': event.event_time.isoformat(),
                    'user': event.user_id,
                    'object': event.object_key,
                    'severity': 'high'
                })
        
        # Check for public access modifications
        if event.event_name in ['PutBucketAcl', 'PutObjectAcl'] and not event.is_error:
            violations.append({
                'type': 'acl_modification',
                'time': event.event_time.isoformat(),
                'user': event.user_id,
                'resource': event.bucket_name or event.object_key,
                'severity': 'critical'
            })
        
        # Check for deletion of objects
        if event.event_name == 'DeleteObject' and not event.is_error:
            violations.append({
                'type': 'object_deletion',
                'time': event.event_time.isoformat(),
                'user': event.user_id,
                'object': event.object_key,
                'severity': 'medium'
            })
        
        return violations


async def analyze_cloudtrail_logs(
    bucket_name: str,
    log_prefix: str,
    time_window: timedelta = timedelta(hours=24)
) -> Dict[str, Any]:
    """
    Analyze CloudTrail logs for a time window.
    
    Args:
        bucket_name: CloudTrail bucket name
        log_prefix: Log file prefix
        time_window: Time window to analyze
        
    Returns:
        Analysis results
    """
    parser = CloudTrailParser()
    
    # List log files in time window
    # This is simplified - in production, filter by date in key
    
    all_events = []
    
    # Parse events from logs
    # ... (implementation would list and parse relevant log files)
    
    # Analyze patterns
    analysis = await parser.analyze_s3_access_patterns(all_events, time_window)
    
    # Find PHI access
    phi_events = await parser.find_phi_access_events(all_events)
    analysis['phi_access_events'] = phi_events
    
    # Generate compliance metrics
    metrics = await parser.generate_compliance_metrics(all_events)
    analysis['compliance_metrics'] = metrics
    
    return analysis
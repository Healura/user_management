#!/usr/bin/env python3
"""
Automated Backup System

Comprehensive backup system for healthcare user management service
with HIPAA-compliant encryption, retention policies, and verification.
"""

import os
import sys
import shutil
import subprocess
import json
import hashlib
import gzip
import tarfile
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from cryptography.fernet import Fernet
import boto3
from botocore.exceptions import NoCredentialsError

# Add the src directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from database.database import check_database_connection


class HealthcareBackupManager:
    """Healthcare-compliant backup management system."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_backup_config(config_file)
        self.backup_log = []
        
        # Backup directories
        self.local_backup_dir = Path(self.config["local_backup_path"])
        self.local_backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Application paths
        self.app_dir = Path(self.config.get("app_directory", "/opt/healthcare-service"))
        self.config_dir = Path(self.config.get("config_directory", "/etc/healthcare-service"))
        self.log_dir = Path(self.config.get("log_directory", "/var/log/healthcare-service"))
        
        # Database configuration
        self.db_config = self.config.get("database", {})
        
        # Encryption setup
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # S3 configuration (optional)
        self.s3_config = self.config.get("s3", {})
        self.s3_client = self._setup_s3_client() if self.s3_config.get("enabled") else None
    
    def create_full_backup(self, backup_id: Optional[str] = None) -> Dict[str, Any]:
        """Create comprehensive system backup."""
        if not backup_id:
            backup_id = f"full_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self._log(f"Starting full backup: {backup_id}")
        
        backup_result = {
            "backup_id": backup_id,
            "backup_type": "full",
            "start_time": datetime.now().isoformat(),
            "components": [],
            "files_backed_up": [],
            "total_size_bytes": 0,
            "encrypted": True,
            "verification_passed": False,
            "remote_backup": False,
            "retention_date": (datetime.now() + timedelta(days=self.config["retention_days"])).isoformat()
        }
        
        try:
            backup_dir = self.local_backup_dir / backup_id
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Backup database
            if self._backup_database(backup_dir, backup_result):
                backup_result["components"].append("database")
            
            # Backup application files
            if self._backup_application(backup_dir, backup_result):
                backup_result["components"].append("application")
            
            # Backup configuration
            if self._backup_configuration(backup_dir, backup_result):
                backup_result["components"].append("configuration")
            
            # Backup logs (selective)
            if self._backup_logs(backup_dir, backup_result):
                backup_result["components"].append("logs")
            
            # Create backup manifest
            self._create_backup_manifest(backup_dir, backup_result)
            
            # Compress and encrypt backup
            compressed_backup = self._compress_backup(backup_dir, backup_id)
            if compressed_backup:
                encrypted_backup = self._encrypt_backup(compressed_backup, backup_id)
                if encrypted_backup:
                    backup_result["encrypted_file"] = str(encrypted_backup)
                    backup_result["total_size_bytes"] = encrypted_backup.stat().st_size
                
                # Clean up unencrypted files
                shutil.rmtree(backup_dir)
                if compressed_backup.exists():
                    compressed_backup.unlink()
            
            # Verify backup integrity
            if self._verify_backup_integrity(backup_result):
                backup_result["verification_passed"] = True
            
            # Upload to remote storage
            if self.s3_client and self.config.get("upload_to_s3", True):
                if self._upload_to_s3(backup_result):
                    backup_result["remote_backup"] = True
            
            # Cleanup old backups
            self._cleanup_old_backups()
            
            backup_result["end_time"] = datetime.now().isoformat()
            backup_result["status"] = "completed"
            
            self._log(f"Full backup completed: {backup_id}")
            return backup_result
            
        except Exception as e:
            backup_result["status"] = "failed"
            backup_result["error"] = str(e)
            backup_result["end_time"] = datetime.now().isoformat()
            self._log(f"Full backup failed: {e}", level="ERROR")
            return backup_result
    
    def create_incremental_backup(self, base_backup_id: str) -> Dict[str, Any]:
        """Create incremental backup based on previous backup."""
        backup_id = f"inc_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self._log(f"Starting incremental backup: {backup_id}")
        
        backup_result = {
            "backup_id": backup_id,
            "backup_type": "incremental",
            "base_backup_id": base_backup_id,
            "start_time": datetime.now().isoformat(),
            "components": [],
            "files_changed": 0,
            "total_size_bytes": 0,
            "encrypted": True
        }
        
        try:
            # Find files changed since base backup
            base_backup_time = self._get_backup_timestamp(base_backup_id)
            if not base_backup_time:
                raise ValueError(f"Base backup not found: {base_backup_id}")
            
            backup_dir = self.local_backup_dir / backup_id
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Incremental database backup
            self._backup_database_incremental(backup_dir, base_backup_time, backup_result)
            
            # Incremental application files backup
            self._backup_application_incremental(backup_dir, base_backup_time, backup_result)
            
            # Always backup current configuration
            if self._backup_configuration(backup_dir, backup_result):
                backup_result["components"].append("configuration")
            
            # Compress and encrypt
            compressed_backup = self._compress_backup(backup_dir, backup_id)
            if compressed_backup:
                encrypted_backup = self._encrypt_backup(compressed_backup, backup_id)
                if encrypted_backup:
                    backup_result["encrypted_file"] = str(encrypted_backup)
                    backup_result["total_size_bytes"] = encrypted_backup.stat().st_size
                
                # Cleanup
                shutil.rmtree(backup_dir)
                compressed_backup.unlink()
            
            backup_result["end_time"] = datetime.now().isoformat()
            backup_result["status"] = "completed"
            
            self._log(f"Incremental backup completed: {backup_id}")
            return backup_result
            
        except Exception as e:
            backup_result["status"] = "failed"
            backup_result["error"] = str(e)
            backup_result["end_time"] = datetime.now().isoformat()
            self._log(f"Incremental backup failed: {e}", level="ERROR")
            return backup_result
    
    def restore_backup(self, backup_id: str, restore_path: Optional[str] = None) -> Dict[str, Any]:
        """Restore system from backup."""
        self._log(f"Starting restore from backup: {backup_id}")
        
        restore_result = {
            "backup_id": backup_id,
            "restore_start": datetime.now().isoformat(),
            "components_restored": [],
            "status": "in_progress"
        }
        
        try:
            # Find backup file
            backup_file = self._find_backup_file(backup_id)
            if not backup_file:
                raise ValueError(f"Backup file not found: {backup_id}")
            
            # Decrypt backup
            decrypted_file = self._decrypt_backup(backup_file)
            
            # Extract backup
            extract_dir = self.local_backup_dir / f"restore_{backup_id}"
            self._extract_backup(decrypted_file, extract_dir)
            
            # Read backup manifest
            manifest_path = extract_dir / "manifest.json"
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            # Restore components
            if restore_path:
                # Restore to specific path
                shutil.copytree(extract_dir, restore_path, dirs_exist_ok=True)
                restore_result["components_restored"] = ["all_files"]
            else:
                # Restore to original locations
                if "database" in manifest.get("components", []):
                    if self._restore_database(extract_dir):
                        restore_result["components_restored"].append("database")
                
                if "application" in manifest.get("components", []):
                    if self._restore_application(extract_dir):
                        restore_result["components_restored"].append("application")
                
                if "configuration" in manifest.get("components", []):
                    if self._restore_configuration(extract_dir):
                        restore_result["components_restored"].append("configuration")
            
            # Cleanup
            shutil.rmtree(extract_dir)
            if decrypted_file.exists():
                decrypted_file.unlink()
            
            restore_result["restore_end"] = datetime.now().isoformat()
            restore_result["status"] = "completed"
            
            self._log(f"Restore completed: {backup_id}")
            return restore_result
            
        except Exception as e:
            restore_result["status"] = "failed"
            restore_result["error"] = str(e)
            restore_result["restore_end"] = datetime.now().isoformat()
            self._log(f"Restore failed: {e}", level="ERROR")
            return restore_result
    
    def verify_all_backups(self) -> Dict[str, Any]:
        """Verify integrity of all backups."""
        self._log("Starting backup verification")
        
        verification_result = {
            "verification_start": datetime.now().isoformat(),
            "backups_checked": 0,
            "backups_valid": 0,
            "backups_invalid": [],
            "total_backup_size": 0
        }
        
        try:
            backup_files = list(self.local_backup_dir.glob("*.enc"))
            
            for backup_file in backup_files:
                backup_id = backup_file.stem.replace(".tar.gz", "")
                
                try:
                    # Basic file integrity check
                    if self._verify_backup_file(backup_file):
                        verification_result["backups_valid"] += 1
                    else:
                        verification_result["backups_invalid"].append(backup_id)
                    
                    verification_result["total_backup_size"] += backup_file.stat().st_size
                    
                except Exception as e:
                    verification_result["backups_invalid"].append({
                        "backup_id": backup_id,
                        "error": str(e)
                    })
                
                verification_result["backups_checked"] += 1
            
            verification_result["verification_end"] = datetime.now().isoformat()
            
            self._log(f"Backup verification completed: {verification_result['backups_valid']}/{verification_result['backups_checked']} valid")
            return verification_result
            
        except Exception as e:
            verification_result["error"] = str(e)
            self._log(f"Backup verification failed: {e}", level="ERROR")
            return verification_result
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups."""
        backups = []
        
        try:
            backup_files = list(self.local_backup_dir.glob("*.enc"))
            
            for backup_file in backup_files:
                backup_id = backup_file.stem.replace(".tar.gz", "")
                
                backup_info = {
                    "backup_id": backup_id,
                    "file_path": str(backup_file),
                    "size_bytes": backup_file.stat().st_size,
                    "created": datetime.fromtimestamp(backup_file.stat().st_ctime).isoformat(),
                    "backup_type": "full" if backup_id.startswith("full_") else "incremental"
                }
                
                # Try to read manifest if backup can be decrypted
                try:
                    manifest = self._read_backup_manifest(backup_id)
                    if manifest:
                        backup_info.update({
                            "components": manifest.get("components", []),
                            "verification_passed": manifest.get("verification_passed", False),
                            "retention_date": manifest.get("retention_date")
                        })
                except:
                    pass
                
                backups.append(backup_info)
            
            # Sort by creation date (newest first)
            backups.sort(key=lambda x: x["created"], reverse=True)
            
        except Exception as e:
            self._log(f"Failed to list backups: {e}", level="ERROR")
        
        return backups
    
    def cleanup_expired_backups(self) -> Dict[str, Any]:
        """Clean up expired backups based on retention policy."""
        self._log("Starting backup cleanup")
        
        cleanup_result = {
            "cleanup_start": datetime.now().isoformat(),
            "backups_removed": [],
            "space_freed_bytes": 0,
            "errors": []
        }
        
        try:
            backups = self.list_backups()
            cutoff_date = datetime.now() - timedelta(days=self.config["retention_days"])
            
            for backup in backups:
                backup_date = datetime.fromisoformat(backup["created"])
                
                if backup_date < cutoff_date:
                    try:
                        backup_file = Path(backup["file_path"])
                        size = backup_file.stat().st_size
                        
                        backup_file.unlink()
                        
                        cleanup_result["backups_removed"].append(backup["backup_id"])
                        cleanup_result["space_freed_bytes"] += size
                        
                        self._log(f"Removed expired backup: {backup['backup_id']}")
                        
                    except Exception as e:
                        cleanup_result["errors"].append({
                            "backup_id": backup["backup_id"],
                            "error": str(e)
                        })
            
            cleanup_result["cleanup_end"] = datetime.now().isoformat()
            
            self._log(f"Backup cleanup completed: {len(cleanup_result['backups_removed'])} backups removed")
            return cleanup_result
            
        except Exception as e:
            cleanup_result["error"] = str(e)
            self._log(f"Backup cleanup failed: {e}", level="ERROR")
            return cleanup_result
    
    # Backup component methods
    
    def _backup_database(self, backup_dir: Path, backup_result: Dict[str, Any]) -> bool:
        """Backup database."""
        self._log("Backing up database")
        
        try:
            db_backup_path = backup_dir / "database.sql"
            
            # PostgreSQL backup
            cmd = [
                "pg_dump",
                "-h", self.db_config.get("host", "localhost"),
                "-p", str(self.db_config.get("port", 5432)),
                "-U", self.db_config.get("username", "healthcare"),
                "-d", self.db_config.get("database", "healthcare_db"),
                "-f", str(db_backup_path),
                "--verbose", "--no-password"
            ]
            
            # Set environment variable for password
            env = os.environ.copy()
            if self.db_config.get("password"):
                env["PGPASSWORD"] = self.db_config["password"]
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                backup_result["files_backed_up"].append(str(db_backup_path))
                self._log("Database backup completed")
                return True
            else:
                self._log(f"Database backup failed: {result.stderr}", level="ERROR")
                return False
                
        except Exception as e:
            self._log(f"Database backup error: {e}", level="ERROR")
            return False
    
    def _backup_application(self, backup_dir: Path, backup_result: Dict[str, Any]) -> bool:
        """Backup application files."""
        self._log("Backing up application files")
        
        try:
            app_backup_path = backup_dir / "application.tar.gz"
            
            with tarfile.open(app_backup_path, "w:gz") as tar:
                # Add application directory
                tar.add(self.app_dir, arcname="application", 
                       exclude=lambda path: "/__pycache__" in path or path.endswith(".pyc"))
            
            backup_result["files_backed_up"].append(str(app_backup_path))
            self._log("Application backup completed")
            return True
            
        except Exception as e:
            self._log(f"Application backup error: {e}", level="ERROR")
            return False
    
    def _backup_configuration(self, backup_dir: Path, backup_result: Dict[str, Any]) -> bool:
        """Backup configuration files."""
        self._log("Backing up configuration")
        
        try:
            config_backup_path = backup_dir / "configuration.tar.gz"
            
            with tarfile.open(config_backup_path, "w:gz") as tar:
                if self.config_dir.exists():
                    tar.add(self.config_dir, arcname="configuration")
            
            backup_result["files_backed_up"].append(str(config_backup_path))
            self._log("Configuration backup completed")
            return True
            
        except Exception as e:
            self._log(f"Configuration backup error: {e}", level="ERROR")
            return False
    
    def _backup_logs(self, backup_dir: Path, backup_result: Dict[str, Any]) -> bool:
        """Backup recent logs."""
        self._log("Backing up logs")
        
        try:
            logs_backup_path = backup_dir / "logs.tar.gz"
            
            # Only backup logs from last 30 days to limit size
            cutoff_date = datetime.now() - timedelta(days=30)
            
            with tarfile.open(logs_backup_path, "w:gz") as tar:
                if self.log_dir.exists():
                    for log_file in self.log_dir.rglob("*.log"):
                        if datetime.fromtimestamp(log_file.stat().st_mtime) > cutoff_date:
                            tar.add(log_file, arcname=f"logs/{log_file.name}")
            
            backup_result["files_backed_up"].append(str(logs_backup_path))
            self._log("Logs backup completed")
            return True
            
        except Exception as e:
            self._log(f"Logs backup error: {e}", level="ERROR")
            return False
    
    # Restore methods
    
    def _restore_database(self, restore_dir: Path) -> bool:
        """Restore database from backup."""
        self._log("Restoring database")
        
        try:
            db_backup_path = restore_dir / "database.sql"
            
            if not db_backup_path.exists():
                self._log("Database backup file not found", level="ERROR")
                return False
            
            cmd = [
                "psql",
                "-h", self.db_config.get("host", "localhost"),
                "-p", str(self.db_config.get("port", 5432)),
                "-U", self.db_config.get("username", "healthcare"),
                "-d", self.db_config.get("database", "healthcare_db"),
                "-f", str(db_backup_path)
            ]
            
            env = os.environ.copy()
            if self.db_config.get("password"):
                env["PGPASSWORD"] = self.db_config["password"]
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                self._log("Database restore completed")
                return True
            else:
                self._log(f"Database restore failed: {result.stderr}", level="ERROR")
                return False
                
        except Exception as e:
            self._log(f"Database restore error: {e}", level="ERROR")
            return False
    
    def _restore_application(self, restore_dir: Path) -> bool:
        """Restore application files."""
        self._log("Restoring application files")
        
        try:
            app_backup_path = restore_dir / "application.tar.gz"
            
            if not app_backup_path.exists():
                self._log("Application backup file not found", level="ERROR")
                return False
            
            # Extract to temporary location first
            temp_dir = restore_dir / "temp_app"
            temp_dir.mkdir(exist_ok=True)
            
            with tarfile.open(app_backup_path, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            # Copy to application directory
            app_source = temp_dir / "application"
            if app_source.exists():
                if self.app_dir.exists():
                    shutil.rmtree(self.app_dir)
                shutil.copytree(app_source, self.app_dir)
            
            shutil.rmtree(temp_dir)
            
            self._log("Application restore completed")
            return True
            
        except Exception as e:
            self._log(f"Application restore error: {e}", level="ERROR")
            return False
    
    def _restore_configuration(self, restore_dir: Path) -> bool:
        """Restore configuration files."""
        self._log("Restoring configuration")
        
        try:
            config_backup_path = restore_dir / "configuration.tar.gz"
            
            if not config_backup_path.exists():
                self._log("Configuration backup file not found", level="ERROR")
                return False
            
            # Extract configuration
            with tarfile.open(config_backup_path, "r:gz") as tar:
                tar.extractall(restore_dir)
            
            # Copy to configuration directory
            config_source = restore_dir / "configuration"
            if config_source.exists():
                self.config_dir.parent.mkdir(parents=True, exist_ok=True)
                if self.config_dir.exists():
                    shutil.rmtree(self.config_dir)
                shutil.copytree(config_source, self.config_dir)
            
            self._log("Configuration restore completed")
            return True
            
        except Exception as e:
            self._log(f"Configuration restore error: {e}", level="ERROR")
            return False
    
    # Utility methods
    
    def _load_backup_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load backup configuration."""
        default_config = {
            "local_backup_path": "/opt/backups",
            "retention_days": 30,
            "encryption_key_file": "/etc/healthcare-service/backup.key",
            "compress_backups": True,
            "upload_to_s3": False,
            "database": {
                "host": "localhost",
                "port": 5432,
                "username": "healthcare",
                "database": "healthcare_db"
            },
            "s3": {
                "enabled": False,
                "bucket": "healthcare-backups",
                "region": "us-east-1"
            }
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key."""
        key_file = Path(self.config["encryption_key_file"])
        
        if key_file.exists():
            with open(key_file, "rb") as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            
            # Save key securely
            key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(key)
            
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
            
            return key
    
    def _setup_s3_client(self):
        """Setup S3 client for remote backups."""
        try:
            return boto3.client(
                's3',
                region_name=self.s3_config.get('region', 'us-east-1')
            )
        except NoCredentialsError:
            self._log("AWS credentials not found", level="WARNING")
            return None
    
    def _compress_backup(self, backup_dir: Path, backup_id: str) -> Optional[Path]:
        """Compress backup directory."""
        if not self.config.get("compress_backups", True):
            return backup_dir
        
        self._log("Compressing backup")
        
        try:
            compressed_path = self.local_backup_dir / f"{backup_id}.tar.gz"
            
            with tarfile.open(compressed_path, "w:gz") as tar:
                tar.add(backup_dir, arcname=backup_id)
            
            return compressed_path
            
        except Exception as e:
            self._log(f"Compression failed: {e}", level="ERROR")
            return None
    
    def _encrypt_backup(self, backup_file: Path, backup_id: str) -> Optional[Path]:
        """Encrypt backup file."""
        self._log("Encrypting backup")
        
        try:
            encrypted_path = backup_file.with_suffix(backup_file.suffix + ".enc")
            
            with open(backup_file, "rb") as infile:
                with open(encrypted_path, "wb") as outfile:
                    data = infile.read()
                    encrypted_data = self.cipher_suite.encrypt(data)
                    outfile.write(encrypted_data)
            
            return encrypted_path
            
        except Exception as e:
            self._log(f"Encryption failed: {e}", level="ERROR")
            return None
    
    def _decrypt_backup(self, encrypted_file: Path) -> Path:
        """Decrypt backup file."""
        self._log("Decrypting backup")
        
        decrypted_path = encrypted_file.with_suffix("")
        
        with open(encrypted_file, "rb") as infile:
            with open(decrypted_path, "wb") as outfile:
                encrypted_data = infile.read()
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                outfile.write(decrypted_data)
        
        return decrypted_path
    
    def _extract_backup(self, backup_file: Path, extract_dir: Path):
        """Extract backup archive."""
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        with tarfile.open(backup_file, "r:gz") as tar:
            tar.extractall(extract_dir)
    
    def _create_backup_manifest(self, backup_dir: Path, backup_result: Dict[str, Any]):
        """Create backup manifest file."""
        manifest = {
            "backup_id": backup_result["backup_id"],
            "backup_type": backup_result["backup_type"],
            "timestamp": backup_result["start_time"],
            "components": backup_result["components"],
            "files": backup_result["files_backed_up"],
            "system_info": {
                "hostname": os.uname().nodename,
                "platform": os.uname().system
            }
        }
        
        manifest_path = backup_dir / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
    
    def _verify_backup_integrity(self, backup_result: Dict[str, Any]) -> bool:
        """Verify backup integrity."""
        try:
            encrypted_file = Path(backup_result.get("encrypted_file", ""))
            if not encrypted_file.exists():
                return False
            
            # Try to decrypt and verify structure
            decrypted_file = self._decrypt_backup(encrypted_file)
            
            # Verify it's a valid tar.gz file
            with tarfile.open(decrypted_file, "r:gz") as tar:
                members = tar.getmembers()
                
                # Check for manifest
                manifest_found = any("manifest.json" in member.name for member in members)
                
            # Cleanup temporary file
            decrypted_file.unlink()
            
            return manifest_found
            
        except Exception as e:
            self._log(f"Backup verification failed: {e}", level="ERROR")
            return False
    
    def _verify_backup_file(self, backup_file: Path) -> bool:
        """Verify individual backup file."""
        try:
            # Check file exists and has reasonable size
            if not backup_file.exists() or backup_file.stat().st_size < 1024:
                return False
            
            # Try to decrypt
            decrypted_file = self._decrypt_backup(backup_file)
            
            # Try to open as tar.gz
            with tarfile.open(decrypted_file, "r:gz") as tar:
                tar.getmembers()
            
            # Cleanup
            decrypted_file.unlink()
            
            return True
            
        except Exception:
            return False
    
    def _upload_to_s3(self, backup_result: Dict[str, Any]) -> bool:
        """Upload backup to S3."""
        if not self.s3_client:
            return False
        
        try:
            encrypted_file = Path(backup_result["encrypted_file"])
            s3_key = f"backups/{backup_result['backup_id']}.tar.gz.enc"
            
            self.s3_client.upload_file(
                str(encrypted_file),
                self.s3_config["bucket"],
                s3_key
            )
            
            self._log(f"Backup uploaded to S3: {s3_key}")
            return True
            
        except Exception as e:
            self._log(f"S3 upload failed: {e}", level="ERROR")
            return False
    
    def _cleanup_old_backups(self):
        """Cleanup old local backups."""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.config["retention_days"])
            
            for backup_file in self.local_backup_dir.glob("*.enc"):
                file_date = datetime.fromtimestamp(backup_file.stat().st_ctime)
                
                if file_date < cutoff_date:
                    backup_file.unlink()
                    self._log(f"Removed old backup: {backup_file.name}")
                    
        except Exception as e:
            self._log(f"Cleanup failed: {e}", level="ERROR")
    
    def _find_backup_file(self, backup_id: str) -> Optional[Path]:
        """Find backup file by ID."""
        backup_file = self.local_backup_dir / f"{backup_id}.tar.gz.enc"
        return backup_file if backup_file.exists() else None
    
    def _read_backup_manifest(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Read backup manifest."""
        try:
            backup_file = self._find_backup_file(backup_id)
            if not backup_file:
                return None
            
            decrypted_file = self._decrypt_backup(backup_file)
            
            temp_dir = self.local_backup_dir / f"temp_{backup_id}"
            temp_dir.mkdir(exist_ok=True)
            
            with tarfile.open(decrypted_file, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            manifest_path = temp_dir / backup_id / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path) as f:
                    manifest = json.load(f)
            else:
                manifest = None
            
            # Cleanup
            shutil.rmtree(temp_dir)
            decrypted_file.unlink()
            
            return manifest
            
        except Exception:
            return None
    
    def _get_backup_timestamp(self, backup_id: str) -> Optional[datetime]:
        """Get backup timestamp."""
        manifest = self._read_backup_manifest(backup_id)
        if manifest and "timestamp" in manifest:
            return datetime.fromisoformat(manifest["timestamp"])
        return None
    
    def _backup_database_incremental(self, backup_dir: Path, since: datetime, backup_result: Dict[str, Any]):
        """Create incremental database backup."""
        # For simplicity, we'll do a full database backup
        # In production, you might use WAL files or specific incremental tools
        if self._backup_database(backup_dir, backup_result):
            backup_result["components"].append("database")
    
    def _backup_application_incremental(self, backup_dir: Path, since: datetime, backup_result: Dict[str, Any]):
        """Create incremental application backup."""
        try:
            changed_files = []
            
            for file_path in self.app_dir.rglob("*"):
                if file_path.is_file():
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_mtime > since:
                        changed_files.append(file_path)
            
            if changed_files:
                app_backup_path = backup_dir / "application_incremental.tar.gz"
                
                with tarfile.open(app_backup_path, "w:gz") as tar:
                    for file_path in changed_files:
                        arcname = str(file_path.relative_to(self.app_dir.parent))
                        tar.add(file_path, arcname=arcname)
                
                backup_result["files_backed_up"].append(str(app_backup_path))
                backup_result["files_changed"] = len(changed_files)
                backup_result["components"].append("application")
                
        except Exception as e:
            self._log(f"Incremental application backup error: {e}", level="ERROR")
    
    def _log(self, message: str, level: str = "INFO"):
        """Log backup message."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}"
        
        print(log_entry)
        self.backup_log.append(log_entry)


def main():
    """Main backup function."""
    parser = argparse.ArgumentParser(description="Healthcare Service Backup Manager")
    parser.add_argument("action", choices=["backup", "restore", "list", "verify", "cleanup"])
    parser.add_argument("--config", help="Backup configuration file")
    parser.add_argument("--backup-id", help="Backup ID for restore operations")
    parser.add_argument("--restore-path", help="Custom restore path")
    parser.add_argument("--incremental", help="Base backup ID for incremental backup")
    parser.add_argument("--force", action="store_true", help="Force operation without confirmation")
    
    args = parser.parse_args()
    
    backup_manager = HealthcareBackupManager(args.config)
    
    try:
        if args.action == "backup":
            if args.incremental:
                result = backup_manager.create_incremental_backup(args.incremental)
            else:
                result = backup_manager.create_full_backup()
            
            print(f"Backup result: {result['status']}")
            if result['status'] == 'completed':
                print(f"Backup ID: {result['backup_id']}")
                print(f"Size: {result['total_size_bytes']} bytes")
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
                
        elif args.action == "restore":
            if not args.backup_id:
                print("ERROR: --backup-id required for restore")
                return False
            
            result = backup_manager.restore_backup(args.backup_id, args.restore_path)
            print(f"Restore result: {result['status']}")
            if result['status'] == 'completed':
                print(f"Components restored: {result['components_restored']}")
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
                
        elif args.action == "list":
            backups = backup_manager.list_backups()
            
            if backups:
                print(f"Found {len(backups)} backups:")
                for backup in backups:
                    print(f"  {backup['backup_id']} - {backup['backup_type']} - {backup['created']} - {backup['size_bytes']} bytes")
            else:
                print("No backups found")
                
        elif args.action == "verify":
            result = backup_manager.verify_all_backups()
            print(f"Verification result: {result['backups_valid']}/{result['backups_checked']} valid")
            if result['backups_invalid']:
                print(f"Invalid backups: {result['backups_invalid']}")
                
        elif args.action == "cleanup":
            result = backup_manager.cleanup_expired_backups()
            print(f"Cleanup result: {len(result['backups_removed'])} backups removed")
            print(f"Space freed: {result['space_freed_bytes']} bytes")
        
        return True
        
    except Exception as e:
        print(f"ERROR: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 
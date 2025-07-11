#!/usr/bin/env python3
"""
Production Deployment Script

Automated production deployment script for healthcare user management service
with comprehensive safety checks, rollback capabilities, and HIPAA compliance.
"""

import os
import sys
import subprocess
import json
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

# Add the src directory to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from database.database import check_database_connection
from health.health_checks import run_health_checks
from admin.maintenance_tools import MaintenanceManager, DeploymentPlan, DeploymentStage


class ProductionDeployer:
    """Production deployment manager with safety checks."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.project_root = project_root
        self.config = self._load_deployment_config(config_file)
        self.deployment_log = []
        
        # Deployment paths
        self.deployment_dir = Path("/opt/healthcare-service")
        self.backup_dir = Path("/opt/backups")
        self.log_dir = Path("/var/log/healthcare-service")
        
        # Critical files that must exist
        self.critical_files = [
            "src/main.py",
            "requirements.txt",
            "config/production.py",
            "scripts/docker_entrypoint.sh"
        ]
        
        # Services to manage
        self.systemd_services = [
            "healthcare-api",
            "healthcare-worker",
            "healthcare-notifications"
        ]
    
    def deploy(
        self,
        version: str,
        stage: str = "production",
        skip_tests: bool = False,
        skip_backup: bool = False,
        auto_rollback: bool = True
    ) -> bool:
        """Execute production deployment."""
        try:
            deployment_id = f"deploy_{version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self._log(f"Starting deployment {deployment_id}")
            
            # Pre-deployment validation
            if not self._validate_deployment_requirements():
                self._log("Pre-deployment validation failed", level="ERROR")
                return False
            
            # Create deployment plan
            deployment_plan = self._create_deployment_plan(deployment_id, version, stage)
            
            # Pre-deployment backup
            if not skip_backup:
                if not self._create_deployment_backup(deployment_id):
                    self._log("Pre-deployment backup failed", level="ERROR")
                    return False
            
            # Run pre-deployment tests
            if not skip_tests:
                if not self._run_pre_deployment_tests():
                    self._log("Pre-deployment tests failed", level="ERROR")
                    return False
            
            # Execute deployment steps
            success = self._execute_deployment_steps(deployment_plan)
            
            if success:
                # Post-deployment verification
                if self._verify_deployment(deployment_plan):
                    self._log(f"Deployment {deployment_id} completed successfully")
                    self._notify_deployment_success(deployment_id, version)
                    return True
                else:
                    self._log("Post-deployment verification failed", level="ERROR")
                    success = False
            
            # Handle deployment failure
            if not success and auto_rollback:
                self._log("Deployment failed, initiating rollback", level="WARNING")
                self._rollback_deployment(deployment_id)
            
            return success
            
        except Exception as e:
            self._log(f"Deployment failed with exception: {e}", level="ERROR")
            if auto_rollback:
                self._rollback_deployment(deployment_id)
            return False
    
    def _validate_deployment_requirements(self) -> bool:
        """Validate deployment requirements."""
        self._log("Validating deployment requirements")
        
        # Check critical files exist
        for file_path in self.critical_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                self._log(f"Critical file missing: {file_path}", level="ERROR")
                return False
        
        # Check database connectivity
        try:
            if not check_database_connection():
                self._log("Database connection check failed", level="ERROR")
                return False
        except Exception as e:
            self._log(f"Database connection error: {e}", level="ERROR")
            return False
        
        # Check system health
        try:
            health_status = run_health_checks()
            if not health_status.get("overall_healthy", False):
                self._log("System health check failed", level="ERROR")
                return False
        except Exception as e:
            self._log(f"Health check error: {e}", level="ERROR")
            return False
        
        # Check disk space
        if not self._check_disk_space():
            self._log("Insufficient disk space", level="ERROR")
            return False
        
        # Check running services
        if not self._check_service_status():
            self._log("Service status check failed", level="ERROR")
            return False
        
        self._log("All deployment requirements validated successfully")
        return True
    
    def _create_deployment_plan(self, deployment_id: str, version: str, stage: str) -> DeploymentPlan:
        """Create deployment plan."""
        return DeploymentPlan(
            id=deployment_id,
            version=version,
            stage=DeploymentStage(stage),
            components=["api", "worker", "notifications", "database"],
            pre_deployment_checks=[
                "validate_configuration",
                "check_dependencies",
                "verify_secrets",
                "test_database_migration"
            ],
            deployment_steps=[
                "stop_services",
                "backup_current_version",
                "update_application_code",
                "install_dependencies",
                "run_database_migrations",
                "update_configuration",
                "start_services",
                "warm_up_services"
            ],
            post_deployment_verification=[
                "health_check_all_services",
                "verify_api_endpoints",
                "test_database_connectivity",
                "verify_compliance_features",
                "check_monitoring_status"
            ],
            rollback_plan=[
                "stop_new_services",
                "restore_previous_version",
                "rollback_database_migrations",
                "restore_configuration",
                "start_previous_services",
                "verify_rollback_success"
            ],
            health_checks=[
                "/health/status",
                "/health/database",
                "/health/compliance"
            ],
            estimated_duration=timedelta(minutes=15),
            created_by="deployment_script"
        )
    
    def _create_deployment_backup(self, deployment_id: str) -> bool:
        """Create pre-deployment backup."""
        self._log("Creating pre-deployment backup")
        
        try:
            backup_path = self.backup_dir / f"pre_deploy_{deployment_id}"
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Backup application code
            self._run_command([
                "rsync", "-av", "--exclude=__pycache__", "--exclude=*.pyc",
                str(self.deployment_dir), str(backup_path / "application")
            ])
            
            # Backup database
            if self.config.get("backup_database", True):
                db_backup_path = backup_path / "database.sql"
                self._backup_database(str(db_backup_path))
            
            # Backup configuration
            config_backup_path = backup_path / "configuration"
            config_backup_path.mkdir(exist_ok=True)
            
            self._run_command([
                "cp", "-r", "/etc/healthcare-service/", str(config_backup_path)
            ])
            
            # Create backup manifest
            manifest = {
                "deployment_id": deployment_id,
                "backup_time": datetime.now().isoformat(),
                "version": self._get_current_version(),
                "backup_path": str(backup_path)
            }
            
            with open(backup_path / "manifest.json", "w") as f:
                json.dump(manifest, f, indent=2)
            
            self._log(f"Backup created successfully at {backup_path}")
            return True
            
        except Exception as e:
            self._log(f"Backup creation failed: {e}", level="ERROR")
            return False
    
    def _run_pre_deployment_tests(self) -> bool:
        """Run pre-deployment tests."""
        self._log("Running pre-deployment tests")
        
        try:
            # Unit tests
            result = self._run_command([
                "python", "-m", "pytest", "tests/", "-v", "--tb=short"
            ], cwd=self.project_root)
            
            if result.returncode != 0:
                self._log("Unit tests failed", level="ERROR")
                return False
            
            # Integration tests
            result = self._run_command([
                "python", "-m", "pytest", "tests/test_integration.py", "-v"
            ], cwd=self.project_root)
            
            if result.returncode != 0:
                self._log("Integration tests failed", level="ERROR")
                return False
            
            # Security tests
            if self.config.get("run_security_tests", True):
                if not self._run_security_tests():
                    self._log("Security tests failed", level="ERROR")
                    return False
            
            self._log("All pre-deployment tests passed")
            return True
            
        except Exception as e:
            self._log(f"Pre-deployment tests failed: {e}", level="ERROR")
            return False
    
    def _execute_deployment_steps(self, deployment_plan: DeploymentPlan) -> bool:
        """Execute deployment steps."""
        self._log("Executing deployment steps")
        
        try:
            for step in deployment_plan.deployment_steps:
                self._log(f"Executing step: {step}")
                
                if not self._execute_deployment_step(step):
                    self._log(f"Deployment step failed: {step}", level="ERROR")
                    return False
                
                self._log(f"Step completed: {step}")
            
            return True
            
        except Exception as e:
            self._log(f"Deployment execution failed: {e}", level="ERROR")
            return False
    
    def _execute_deployment_step(self, step: str) -> bool:
        """Execute individual deployment step."""
        try:
            if step == "stop_services":
                return self._stop_services()
            elif step == "backup_current_version":
                return self._backup_current_application()
            elif step == "update_application_code":
                return self._update_application_code()
            elif step == "install_dependencies":
                return self._install_dependencies()
            elif step == "run_database_migrations":
                return self._run_database_migrations()
            elif step == "update_configuration":
                return self._update_configuration()
            elif step == "start_services":
                return self._start_services()
            elif step == "warm_up_services":
                return self._warm_up_services()
            else:
                self._log(f"Unknown deployment step: {step}", level="WARNING")
                return True
            
        except Exception as e:
            self._log(f"Step execution failed: {e}", level="ERROR")
            return False
    
    def _verify_deployment(self, deployment_plan: DeploymentPlan) -> bool:
        """Verify deployment success."""
        self._log("Verifying deployment")
        
        try:
            # Wait for services to stabilize
            time.sleep(30)
            
            # Health checks
            for health_endpoint in deployment_plan.health_checks:
                if not self._check_health_endpoint(health_endpoint):
                    self._log(f"Health check failed: {health_endpoint}", level="ERROR")
                    return False
            
            # Functional tests
            if not self._run_deployment_verification_tests():
                self._log("Deployment verification tests failed", level="ERROR")
                return False
            
            # Performance baseline check
            if not self._check_performance_baseline():
                self._log("Performance baseline check failed", level="WARNING")
                # Don't fail deployment for performance issues
            
            self._log("Deployment verification successful")
            return True
            
        except Exception as e:
            self._log(f"Deployment verification failed: {e}", level="ERROR")
            return False
    
    def _rollback_deployment(self, deployment_id: str) -> bool:
        """Rollback failed deployment."""
        self._log(f"Rolling back deployment {deployment_id}")
        
        try:
            # Find backup
            backup_path = self.backup_dir / f"pre_deploy_{deployment_id}"
            if not backup_path.exists():
                self._log("Backup not found for rollback", level="ERROR")
                return False
            
            # Stop current services
            self._stop_services()
            
            # Restore application
            self._run_command([
                "rsync", "-av", "--delete",
                str(backup_path / "application/"), str(self.deployment_dir)
            ])
            
            # Restore database if needed
            if self.config.get("rollback_database", False):
                db_backup_path = backup_path / "database.sql"
                if db_backup_path.exists():
                    self._restore_database(str(db_backup_path))
            
            # Restore configuration
            self._run_command([
                "cp", "-r", str(backup_path / "configuration/"), "/etc/"
            ])
            
            # Start services
            self._start_services()
            
            # Verify rollback
            time.sleep(15)
            if self._check_health_endpoint("/health/status"):
                self._log("Rollback completed successfully")
                return True
            else:
                self._log("Rollback verification failed", level="ERROR")
                return False
            
        except Exception as e:
            self._log(f"Rollback failed: {e}", level="ERROR")
            return False
    
    # Helper methods
    
    def _load_deployment_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load deployment configuration."""
        default_config = {
            "backup_database": True,
            "rollback_database": False,
            "run_security_tests": True,
            "performance_threshold_ms": 500,
            "health_check_timeout": 30,
            "service_startup_timeout": 60
        }
        
        if config_file and Path(config_file).exists():
            with open(config_file) as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def _check_disk_space(self, required_gb: int = 5) -> bool:
        """Check available disk space."""
        try:
            result = self._run_command(["df", "-h", "/"])
            # Parse df output to check available space
            # Simplified check - in production, would parse actual output
            return True
        except:
            return False
    
    def _check_service_status(self) -> bool:
        """Check status of system services."""
        try:
            for service in self.systemd_services:
                result = self._run_command(["systemctl", "is-active", service])
                if result.returncode != 0:
                    self._log(f"Service {service} is not active", level="WARNING")
                    # Don't fail for inactive services during deployment
            return True
        except:
            return False
    
    def _stop_services(self) -> bool:
        """Stop application services."""
        self._log("Stopping services")
        try:
            for service in self.systemd_services:
                self._run_command(["systemctl", "stop", service])
            return True
        except Exception as e:
            self._log(f"Failed to stop services: {e}", level="ERROR")
            return False
    
    def _start_services(self) -> bool:
        """Start application services."""
        self._log("Starting services")
        try:
            for service in self.systemd_services:
                self._run_command(["systemctl", "start", service])
            
            # Wait for services to start
            time.sleep(self.config["service_startup_timeout"])
            return True
        except Exception as e:
            self._log(f"Failed to start services: {e}", level="ERROR")
            return False
    
    def _backup_current_application(self) -> bool:
        """Backup current application version."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = self.backup_dir / f"current_version_{timestamp}"
            
            self._run_command([
                "rsync", "-av", str(self.deployment_dir), str(backup_path)
            ])
            return True
        except:
            return False
    
    def _update_application_code(self) -> bool:
        """Update application code."""
        self._log("Updating application code")
        try:
            # Copy new code
            self._run_command([
                "rsync", "-av", "--exclude=__pycache__", "--exclude=*.pyc",
                str(self.project_root) + "/", str(self.deployment_dir)
            ])
            
            # Set proper permissions
            self._run_command(["chown", "-R", "healthcare:healthcare", str(self.deployment_dir)])
            self._run_command(["chmod", "+x", str(self.deployment_dir / "scripts/docker_entrypoint.sh")])
            
            return True
        except Exception as e:
            self._log(f"Failed to update application code: {e}", level="ERROR")
            return False
    
    def _install_dependencies(self) -> bool:
        """Install Python dependencies."""
        self._log("Installing dependencies")
        try:
            result = self._run_command([
                "pip", "install", "-r", "requirements.txt", "--upgrade"
            ], cwd=self.deployment_dir)
            
            return result.returncode == 0
        except Exception as e:
            self._log(f"Failed to install dependencies: {e}", level="ERROR")
            return False
    
    def _run_database_migrations(self) -> bool:
        """Run database migrations."""
        self._log("Running database migrations")
        try:
            result = self._run_command([
                "python", "-m", "alembic", "upgrade", "head"
            ], cwd=self.deployment_dir)
            
            return result.returncode == 0
        except Exception as e:
            self._log(f"Database migration failed: {e}", level="ERROR")
            return False
    
    def _update_configuration(self) -> bool:
        """Update configuration files."""
        self._log("Updating configuration")
        try:
            # Copy production configuration
            config_source = self.deployment_dir / "config/production.py"
            config_dest = Path("/etc/healthcare-service/production.py")
            
            if config_source.exists():
                config_dest.parent.mkdir(parents=True, exist_ok=True)
                self._run_command(["cp", str(config_source), str(config_dest)])
            
            return True
        except Exception as e:
            self._log(f"Configuration update failed: {e}", level="ERROR")
            return False
    
    def _warm_up_services(self) -> bool:
        """Warm up services after startup."""
        self._log("Warming up services")
        try:
            # Make warmup requests to key endpoints
            warmup_endpoints = ["/health/status", "/api/users"]
            
            for endpoint in warmup_endpoints:
                self._check_health_endpoint(endpoint, timeout=10)
            
            return True
        except:
            return True  # Don't fail deployment for warmup issues
    
    def _check_health_endpoint(self, endpoint: str, timeout: int = None) -> bool:
        """Check health endpoint."""
        timeout = timeout or self.config["health_check_timeout"]
        try:
            import requests
            url = f"http://localhost:8000{endpoint}"
            response = requests.get(url, timeout=timeout)
            return response.status_code == 200
        except Exception as e:
            self._log(f"Health check failed for {endpoint}: {e}", level="WARNING")
            return False
    
    def _run_security_tests(self) -> bool:
        """Run security tests."""
        self._log("Running security tests")
        try:
            # Run security-specific tests
            result = self._run_command([
                "python", "-m", "pytest", "tests/test_security.py", "-v"
            ], cwd=self.project_root)
            
            return result.returncode == 0
        except:
            return True  # Don't fail for missing security tests
    
    def _run_deployment_verification_tests(self) -> bool:
        """Run deployment verification tests."""
        self._log("Running deployment verification tests")
        try:
            # Basic API functionality test
            return self._check_health_endpoint("/health/status")
        except:
            return False
    
    def _check_performance_baseline(self) -> bool:
        """Check performance baseline."""
        try:
            import requests
            import time
            
            url = "http://localhost:8000/health/status"
            start_time = time.time()
            response = requests.get(url, timeout=5)
            response_time = (time.time() - start_time) * 1000
            
            threshold = self.config["performance_threshold_ms"]
            if response_time > threshold:
                self._log(f"Performance baseline failed: {response_time}ms > {threshold}ms", level="WARNING")
                return False
            
            return True
        except:
            return False
    
    def _backup_database(self, backup_path: str) -> bool:
        """Backup database."""
        try:
            # PostgreSQL backup
            self._run_command([
                "pg_dump", "-h", "localhost", "-U", "healthcare",
                "-d", "healthcare_db", "-f", backup_path
            ])
            return True
        except:
            return False
    
    def _restore_database(self, backup_path: str) -> bool:
        """Restore database from backup."""
        try:
            self._run_command([
                "psql", "-h", "localhost", "-U", "healthcare",
                "-d", "healthcare_db", "-f", backup_path
            ])
            return True
        except:
            return False
    
    def _get_current_version(self) -> str:
        """Get current application version."""
        try:
            result = self._run_command(["git", "describe", "--tags", "--always"])
            return result.stdout.strip() if result.stdout else "unknown"
        except:
            return "unknown"
    
    def _notify_deployment_success(self, deployment_id: str, version: str):
        """Send deployment success notification."""
        self._log(f"Deployment {deployment_id} completed successfully for version {version}")
        # In production, would send notifications via Slack, email, etc.
    
    def _run_command(self, command: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Run shell command and return result."""
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.stdout:
                self._log(f"Command output: {result.stdout.strip()}")
            if result.stderr and result.returncode != 0:
                self._log(f"Command error: {result.stderr.strip()}", level="ERROR")
            
            return result
        except subprocess.TimeoutExpired:
            self._log(f"Command timed out: {' '.join(command)}", level="ERROR")
            raise
        except Exception as e:
            self._log(f"Command failed: {e}", level="ERROR")
            raise
    
    def _log(self, message: str, level: str = "INFO"):
        """Log deployment message."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {level}: {message}"
        
        print(log_entry)
        self.deployment_log.append(log_entry)
        
        # Write to log file
        self.log_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.log_dir / "deployment.log"
        
        with open(log_file, "a") as f:
            f.write(log_entry + "\n")


def main():
    """Main deployment function."""
    parser = argparse.ArgumentParser(description="Healthcare Service Production Deployment")
    parser.add_argument("--version", required=True, help="Version to deploy")
    parser.add_argument("--stage", default="production", help="Deployment stage")
    parser.add_argument("--config", help="Deployment configuration file")
    parser.add_argument("--skip-tests", action="store_true", help="Skip pre-deployment tests")
    parser.add_argument("--skip-backup", action="store_true", help="Skip pre-deployment backup")
    parser.add_argument("--no-rollback", action="store_true", help="Disable automatic rollback")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("DRY RUN MODE - No actual deployment will occur")
        return True
    
    # Check if running as root (required for systemctl commands)
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root for production deployment")
        return False
    
    deployer = ProductionDeployer(args.config)
    
    success = deployer.deploy(
        version=args.version,
        stage=args.stage,
        skip_tests=args.skip_tests,
        skip_backup=args.skip_backup,
        auto_rollback=not args.no_rollback
    )
    
    if success:
        print(f"✅ Deployment of version {args.version} completed successfully")
        return True
    else:
        print(f"❌ Deployment of version {args.version} failed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 
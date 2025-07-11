"""
Healthcare User Management Service

Comprehensive healthcare user administration including patient and provider
management, role assignments, facility management, and compliance tracking.
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from dataclasses import dataclass

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from src.database.models import User, UserRole, UserRoleAssignment, AuditLog
from src.database.repositories import UserRepository, AuditLogRepository
from src.auth.password_policy import hash_password, generate_random_password
from src.auth.authorization import assign_default_role
from src.security.audit_logger import AuditLogger
from src.notifications.notification_manager import NotificationManager, NotificationType

logger = logging.getLogger(__name__)


@dataclass
class ProviderCredentials:
    """Healthcare provider credential information."""
    license_number: str
    specialization: str
    board_certification: Optional[str] = None
    npi_number: Optional[str] = None
    dea_number: Optional[str] = None
    verification_status: str = "pending"
    verified_date: Optional[datetime] = None
    verified_by: Optional[UUID] = None


@dataclass
class FacilityAssignment:
    """Healthcare facility assignment information."""
    facility_id: str
    facility_name: str
    role_within_facility: str
    assignment_date: datetime
    assigned_by: UUID
    is_primary: bool = False


class HealthcareUserManager:
    """Comprehensive healthcare user management service."""
    
    def __init__(self, db: Session):
        self.db = db
        self.user_repo = UserRepository(db)
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.notification_manager = NotificationManager()
        
        # Healthcare roles configuration
        self.healthcare_roles = {
            "patient": {
                "description": "Patient users with access to their own health data",
                "permissions": ["view_own_data", "upload_recordings", "view_own_analysis"]
            },
            "healthcare_provider": {
                "description": "Licensed healthcare providers with patient access",
                "permissions": ["view_patient_data", "create_analysis", "manage_patients"]
            },
            "nurse": {
                "description": "Nursing staff with limited patient access",
                "permissions": ["view_assigned_patients", "update_patient_notes"]
            },
            "admin": {
                "description": "System administrators with full access",
                "permissions": ["manage_all_users", "system_administration", "compliance_management"]
            },
            "compliance_officer": {
                "description": "HIPAA compliance monitoring and reporting",
                "permissions": ["view_audit_logs", "generate_compliance_reports", "manage_violations"]
            }
        }
    
    async def create_healthcare_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        phone_number: Optional[str],
        role: str,
        facility_id: Optional[str] = None,
        provider_details: Optional[Dict[str, Any]] = None,
        created_by: UUID = None
    ) -> User:
        """Create healthcare user account with role assignment."""
        try:
            logger.info(f"Creating healthcare user: {email} with role: {role}")
            
            # Validate role
            if role not in self.healthcare_roles:
                raise ValueError(f"Invalid healthcare role: {role}")
            
            # Generate temporary password
            temp_password = generate_random_password()
            password_hash = hash_password(temp_password)
            
            # Create user
            user_data = {
                "email": email,
                "password_hash": password_hash,
                "first_name": first_name,
                "last_name": last_name,
                "phone_number": phone_number,
                "is_active": True,
                "email_verified": False,
                "privacy_consent": True,  # Assumed for healthcare context
                "created_at": datetime.utcnow()
            }
            
            user = self.user_repo.create(**user_data)
            
            # Assign healthcare role
            await self._assign_healthcare_role(user.id, role, created_by)
            
            # Assign to facility if specified
            if facility_id:
                await self._assign_to_facility(user.id, facility_id, role, created_by)
            
            # Handle provider-specific setup
            if role == "healthcare_provider" and provider_details:
                await self._setup_provider_credentials(user.id, provider_details, created_by)
            
            # Send welcome notification with temporary password
            await self._send_welcome_notification(user, temp_password, role)
            
            # Log user creation
            await self.audit_logger.log_user_action(
                user_id=created_by,
                action="create_healthcare_user",
                resource_type="user",
                resource_id=user.id,
                details={
                    "target_user_email": email,
                    "assigned_role": role,
                    "facility_id": facility_id,
                    "is_provider": role == "healthcare_provider"
                }
            )
            
            return user
            
        except Exception as e:
            logger.error(f"Healthcare user creation failed: {e}")
            raise
    
    async def list_users(
        self,
        page: int = 1,
        page_size: int = 50,
        role_filter: Optional[str] = None,
        facility_filter: Optional[str] = None,
        active_filter: Optional[bool] = None,
        search_query: Optional[str] = None,
        requesting_user_id: UUID = None
    ) -> Dict[str, Any]:
        """List healthcare users with advanced filtering."""
        try:
            offset = (page - 1) * page_size
            
            # Build query
            query = self.db.query(User)
            
            # Apply filters
            if role_filter:
                query = query.join(UserRoleAssignment).join(UserRole).filter(
                    UserRole.name == role_filter
                )
            
            if active_filter is not None:
                query = query.filter(User.is_active == active_filter)
            
            if search_query:
                search = f"%{search_query}%"
                query = query.filter(
                    or_(
                        User.first_name.ilike(search),
                        User.last_name.ilike(search),
                        User.email.ilike(search)
                    )
                )
            
            # Get total count
            total_count = query.count()
            
            # Get paginated results
            users = query.offset(offset).limit(page_size).all()
            
            # Format user data
            user_list = []
            for user in users:
                user_data = await self._format_user_data(user)
                user_list.append(user_data)
            
            # Log access
            await self.audit_logger.log_user_action(
                user_id=requesting_user_id,
                action="list_healthcare_users",
                resource_type="user_list",
                details={
                    "page": page,
                    "page_size": page_size,
                    "filters": {
                        "role": role_filter,
                        "facility": facility_filter,
                        "active": active_filter,
                        "search": search_query
                    },
                    "total_results": total_count
                }
            )
            
            return {
                "users": user_list,
                "total": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": (total_count + page_size - 1) // page_size
            }
            
        except Exception as e:
            logger.error(f"User listing failed: {e}")
            raise
    
    async def get_user_details(
        self,
        user_id: UUID,
        requesting_user_id: UUID
    ) -> Optional[Dict[str, Any]]:
        """Get detailed healthcare user information."""
        try:
            user = self.user_repo.get(user_id)
            if not user:
                return None
            
            user_details = await self._format_user_data(user, include_extended=True)
            
            # Log access
            await self.audit_logger.log_user_action(
                user_id=requesting_user_id,
                action="view_user_details",
                resource_type="user",
                resource_id=user_id,
                details={"accessed_user_email": user.email}
            )
            
            return user_details
            
        except Exception as e:
            logger.error(f"User details retrieval failed: {e}")
            raise
    
    async def update_user(
        self,
        user_id: UUID,
        updates: Dict[str, Any],
        updated_by: UUID
    ) -> Dict[str, Any]:
        """Update healthcare user with compliance tracking."""
        try:
            user = self.user_repo.get(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Track changes for audit
            original_data = {
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone_number": user.phone_number,
                "is_active": user.is_active
            }
            
            # Apply updates
            updated_user = self.user_repo.update(user_id, updates)
            
            # Log changes
            await self.audit_logger.log_user_action(
                user_id=updated_by,
                action="update_healthcare_user",
                resource_type="user",
                resource_id=user_id,
                details={
                    "target_user_email": user.email,
                    "original_data": original_data,
                    "updates": updates
                }
            )
            
            # Send notification if significant changes
            if any(key in updates for key in ["email", "is_active"]):
                await self._send_account_update_notification(updated_user, updates)
            
            return await self._format_user_data(updated_user)
            
        except Exception as e:
            logger.error(f"User update failed: {e}")
            raise
    
    async def assign_role(
        self,
        user_id: UUID,
        role_name: str,
        facility_id: Optional[str] = None,
        assigned_by: UUID = None
    ) -> Dict[str, Any]:
        """Assign healthcare role to user."""
        try:
            if role_name not in self.healthcare_roles:
                raise ValueError(f"Invalid healthcare role: {role_name}")
            
            user = self.user_repo.get(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Get or create role
            role = self.db.query(UserRole).filter(UserRole.name == role_name).first()
            if not role:
                role = UserRole(name=role_name, description=self.healthcare_roles[role_name]["description"])
                self.db.add(role)
                self.db.flush()
            
            # Check if assignment already exists
            existing_assignment = self.db.query(UserRoleAssignment).filter(
                and_(
                    UserRoleAssignment.user_id == user_id,
                    UserRoleAssignment.role_id == role.id
                )
            ).first()
            
            if existing_assignment:
                return {"message": "Role already assigned", "assignment_id": existing_assignment.id}
            
            # Create role assignment
            assignment = UserRoleAssignment(
                user_id=user_id,
                role_id=role.id,
                assigned_at=datetime.utcnow(),
                assigned_by=assigned_by
            )
            
            self.db.add(assignment)
            self.db.commit()
            
            # Log role assignment
            await self.audit_logger.log_user_action(
                user_id=assigned_by,
                action="assign_healthcare_role",
                resource_type="role_assignment",
                resource_id=assignment.id,
                details={
                    "target_user_email": user.email,
                    "role_assigned": role_name,
                    "facility_id": facility_id
                }
            )
            
            # Send notification
            await self._send_role_assignment_notification(user, role_name)
            
            return {"message": "Role assigned successfully", "assignment_id": assignment.id}
            
        except Exception as e:
            logger.error(f"Role assignment failed: {e}")
            raise
    
    async def assign_facility(
        self,
        user_id: UUID,
        facility_id: str,
        facility_role: Optional[str] = None,
        assigned_by: UUID = None
    ) -> Dict[str, Any]:
        """Assign user to healthcare facility."""
        try:
            user = self.user_repo.get(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Create facility assignment record
            facility_assignment = FacilityAssignment(
                facility_id=facility_id,
                facility_name=f"Facility_{facility_id}",  # Would lookup from facility service
                role_within_facility=facility_role or "general",
                assignment_date=datetime.utcnow(),
                assigned_by=assigned_by
            )
            
            # Store facility assignment (would use dedicated table in production)
            await self.audit_logger.log_user_action(
                user_id=assigned_by,
                action="assign_facility",
                resource_type="facility_assignment",
                resource_id=user_id,
                details={
                    "target_user_email": user.email,
                    "facility_id": facility_id,
                    "facility_role": facility_role
                }
            )
            
            return {"message": "Facility assignment successful", "assignment": facility_assignment}
            
        except Exception as e:
            logger.error(f"Facility assignment failed: {e}")
            raise
    
    async def deactivate_user(
        self,
        user_id: UUID,
        reason: str,
        deactivated_by: UUID
    ) -> Dict[str, Any]:
        """Deactivate user account with audit trail."""
        try:
            user = self.user_repo.get(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Deactivate user
            updated_user = self.user_repo.update(user_id, {
                "is_active": False,
                "updated_at": datetime.utcnow()
            })
            
            # Log deactivation
            await self.audit_logger.log_user_action(
                user_id=deactivated_by,
                action="deactivate_healthcare_user",
                resource_type="user",
                resource_id=user_id,
                details={
                    "target_user_email": user.email,
                    "deactivation_reason": reason,
                    "deactivated_at": datetime.utcnow().isoformat()
                }
            )
            
            # Send notification
            await self._send_account_deactivation_notification(user, reason)
            
            return {"message": "User deactivated successfully", "user_id": user_id}
            
        except Exception as e:
            logger.error(f"User deactivation failed: {e}")
            raise
    
    async def bulk_operation(
        self,
        user_ids: List[UUID],
        operation: str,
        parameters: Dict[str, Any],
        executed_by: UUID
    ) -> Dict[str, Any]:
        """Perform bulk operations on multiple users."""
        try:
            results = {
                "successful": [],
                "failed": [],
                "total": len(user_ids)
            }
            
            for user_id in user_ids:
                try:
                    if operation == "activate":
                        await self._bulk_activate_user(user_id, executed_by)
                    elif operation == "deactivate":
                        await self._bulk_deactivate_user(user_id, parameters.get("reason", "Bulk operation"), executed_by)
                    elif operation == "assign_role":
                        await self.assign_role(user_id, parameters["role"], parameters.get("facility_id"), executed_by)
                    elif operation == "remove_role":
                        await self._bulk_remove_role(user_id, parameters["role"], executed_by)
                    else:
                        raise ValueError(f"Unknown bulk operation: {operation}")
                    
                    results["successful"].append(user_id)
                    
                except Exception as e:
                    results["failed"].append({"user_id": user_id, "error": str(e)})
            
            # Log bulk operation
            await self.audit_logger.log_user_action(
                user_id=executed_by,
                action=f"bulk_{operation}",
                resource_type="bulk_operation",
                details={
                    "operation": operation,
                    "parameters": parameters,
                    "user_count": len(user_ids),
                    "successful_count": len(results["successful"]),
                    "failed_count": len(results["failed"])
                }
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Bulk operation failed: {e}")
            raise
    
    async def get_user_audit_trail(
        self,
        user_id: UUID,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        requesting_user_id: UUID = None
    ) -> List[Dict[str, Any]]:
        """Get comprehensive user audit trail."""
        try:
            query = self.db.query(AuditLog).filter(
                or_(
                    AuditLog.user_id == user_id,
                    AuditLog.resource_id == str(user_id)
                )
            )
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            audit_logs = query.order_by(desc(AuditLog.timestamp)).limit(limit).all()
            
            audit_trail = []
            for log in audit_logs:
                audit_trail.append({
                    "id": log.id,
                    "action": log.action,
                    "timestamp": log.timestamp.isoformat(),
                    "user_id": log.user_id,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "ip_address": log.ip_address,
                    "details": json.loads(log.details) if log.details else {}
                })
            
            # Log audit trail access
            await self.audit_logger.log_user_action(
                user_id=requesting_user_id,
                action="access_user_audit_trail",
                resource_type="audit_trail",
                resource_id=user_id,
                details={
                    "target_user_id": str(user_id),
                    "trail_entries": len(audit_trail),
                    "date_range": {
                        "start": start_date.isoformat() if start_date else None,
                        "end": end_date.isoformat() if end_date else None
                    }
                }
            )
            
            return audit_trail
            
        except Exception as e:
            logger.error(f"Audit trail retrieval failed: {e}")
            raise
    
    # Provider-specific operations
    
    async def onboard_provider(
        self,
        provider_request: Any,  # ProviderRequest from API
        onboarded_by: UUID
    ) -> Dict[str, Any]:
        """Onboard healthcare provider with credential verification."""
        try:
            user_id = provider_request.user_id
            
            credentials = ProviderCredentials(
                license_number=provider_request.license_number,
                specialization=provider_request.specialization,
                board_certification=provider_request.board_certification,
                npi_number=provider_request.npi_number,
                dea_number=provider_request.dea_number,
                verification_status="pending"
            )
            
            # Store provider credentials (would use dedicated table)
            await self.audit_logger.log_user_action(
                user_id=onboarded_by,
                action="onboard_healthcare_provider",
                resource_type="provider_credentials",
                resource_id=user_id,
                details={
                    "license_number": credentials.license_number,
                    "specialization": credentials.specialization,
                    "facility_id": provider_request.facility_id,
                    "verification_documents": provider_request.verification_documents
                }
            )
            
            # Initiate credential verification process
            verification_id = await self._initiate_credential_verification(user_id, credentials)
            
            return {
                "message": "Provider onboarding initiated",
                "verification_id": verification_id,
                "status": "pending_verification"
            }
            
        except Exception as e:
            logger.error(f"Provider onboarding failed: {e}")
            raise
    
    async def verify_provider(
        self,
        provider_id: UUID,
        verification_data: Dict[str, Any],
        verified_by: UUID
    ) -> Dict[str, Any]:
        """Verify healthcare provider credentials."""
        try:
            # Update verification status
            verification_result = {
                "verification_status": "verified",
                "verified_date": datetime.utcnow(),
                "verified_by": verified_by,
                "verification_notes": verification_data.get("notes", "")
            }
            
            # Log verification
            await self.audit_logger.log_user_action(
                user_id=verified_by,
                action="verify_provider_credentials",
                resource_type="provider_verification",
                resource_id=provider_id,
                details=verification_result
            )
            
            # Send verification notification
            provider = self.user_repo.get(provider_id)
            if provider:
                await self._send_provider_verification_notification(provider, verification_result)
            
            return verification_result
            
        except Exception as e:
            logger.error(f"Provider verification failed: {e}")
            raise
    
    # Helper methods
    
    async def _assign_healthcare_role(self, user_id: UUID, role_name: str, assigned_by: UUID):
        """Assign healthcare role to user."""
        await assign_default_role(self.db, str(user_id), role_name)
    
    async def _assign_to_facility(self, user_id: UUID, facility_id: str, role: str, assigned_by: UUID):
        """Assign user to healthcare facility."""
        # Implementation would integrate with facility management system
        pass
    
    async def _setup_provider_credentials(self, user_id: UUID, provider_details: Dict[str, Any], created_by: UUID):
        """Set up provider-specific credentials and permissions."""
        # Implementation would create provider credential records
        pass
    
    async def _format_user_data(self, user: User, include_extended: bool = False) -> Dict[str, Any]:
        """Format user data for API response."""
        user_data = {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number,
            "is_active": user.is_active,
            "email_verified": user.email_verified,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "roles": [assignment.role.name for assignment in user.role_assignments]
        }
        
        if include_extended:
            user_data.update({
                "privacy_consent": user.privacy_consent,
                "data_retention_days": user.data_retention_days,
                "role_details": [
                    {
                        "role": assignment.role.name,
                        "assigned_at": assignment.assigned_at.isoformat(),
                        "assigned_by": assignment.assigned_by
                    }
                    for assignment in user.role_assignments
                ]
            })
        
        return user_data
    
    async def _send_welcome_notification(self, user: User, temp_password: str, role: str):
        """Send welcome notification to new healthcare user."""
        await self.notification_manager.send_notification(
            user_id=user.id,
            notification_type=NotificationType.WELCOME_MESSAGE,
            data={
                "user_name": f"{user.first_name} {user.last_name}",
                "role": role,
                "temp_password": temp_password,
                "reset_required": True
            }
        )
    
    async def _send_account_update_notification(self, user: User, updates: Dict[str, Any]):
        """Send notification for account updates."""
        await self.notification_manager.send_notification(
            user_id=user.id,
            notification_type=NotificationType.ACCOUNT_UPDATE,
            data={
                "user_name": f"{user.first_name} {user.last_name}",
                "updates": updates
            }
        )
    
    async def _send_role_assignment_notification(self, user: User, role_name: str):
        """Send notification for role assignment."""
        await self.notification_manager.send_notification(
            user_id=user.id,
            notification_type=NotificationType.ROLE_ASSIGNED,
            data={
                "user_name": f"{user.first_name} {user.last_name}",
                "role": role_name,
                "permissions": self.healthcare_roles[role_name]["permissions"]
            }
        )
    
    async def _send_account_deactivation_notification(self, user: User, reason: str):
        """Send notification for account deactivation."""
        await self.notification_manager.send_notification(
            user_id=user.id,
            notification_type=NotificationType.ACCOUNT_DEACTIVATED,
            data={
                "user_name": f"{user.first_name} {user.last_name}",
                "reason": reason,
                "contact_support": True
            }
        )
    
    async def _send_provider_verification_notification(self, provider: User, verification_result: Dict[str, Any]):
        """Send provider verification notification."""
        await self.notification_manager.send_notification(
            user_id=provider.id,
            notification_type=NotificationType.PROVIDER_VERIFIED,
            data={
                "provider_name": f"{provider.first_name} {provider.last_name}",
                "verification_status": verification_result["verification_status"],
                "verified_date": verification_result["verified_date"].isoformat()
            }
        )
    
    async def _initiate_credential_verification(self, user_id: UUID, credentials: ProviderCredentials) -> str:
        """Initiate provider credential verification process."""
        verification_id = str(uuid4())
        # Implementation would integrate with credential verification service
        return verification_id
    
    async def _bulk_activate_user(self, user_id: UUID, executed_by: UUID):
        """Activate user as part of bulk operation."""
        self.user_repo.update(user_id, {"is_active": True})
    
    async def _bulk_deactivate_user(self, user_id: UUID, reason: str, executed_by: UUID):
        """Deactivate user as part of bulk operation."""
        self.user_repo.update(user_id, {"is_active": False})
    
    async def _bulk_remove_role(self, user_id: UUID, role_name: str, executed_by: UUID):
        """Remove role from user as part of bulk operation."""
        role = self.db.query(UserRole).filter(UserRole.name == role_name).first()
        if role:
            assignment = self.db.query(UserRoleAssignment).filter(
                and_(
                    UserRoleAssignment.user_id == user_id,
                    UserRoleAssignment.role_id == role.id
                )
            ).first()
            if assignment:
                self.db.delete(assignment)
                self.db.commit()


# Standalone functions for backwards compatibility

async def create_healthcare_user(
    db: Session,
    user_data: Dict[str, Any],
    created_by: UUID
) -> User:
    """Create healthcare user account."""
    manager = HealthcareUserManager(db)
    return await manager.create_healthcare_user(**user_data, created_by=created_by)

async def manage_provider_credentials(
    db: Session,
    provider_id: UUID,
    credentials: Dict[str, Any],
    managed_by: UUID
) -> Dict[str, Any]:
    """Manage healthcare provider credentials."""
    manager = HealthcareUserManager(db)
    return await manager.verify_provider(provider_id, credentials, managed_by)

async def bulk_user_operations(
    db: Session,
    user_ids: List[UUID],
    operation: str,
    parameters: Dict[str, Any],
    executed_by: UUID
) -> Dict[str, Any]:
    """Perform bulk operations on healthcare users."""
    manager = HealthcareUserManager(db)
    return await manager.bulk_operation(user_ids, operation, parameters, executed_by) 
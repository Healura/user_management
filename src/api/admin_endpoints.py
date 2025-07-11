"""
Comprehensive Healthcare Admin API Endpoints

Complete healthcare administration API with user management, system monitoring,
healthcare provider management, and production maintenance capabilities.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Path, status
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_user, require_role
from src.auth.authorization import RoleChecker
from src.database.database import get_db
from src.database.models import User, UserRole, UserRoleAssignment, AudioFile, AuditLog
from src.database.repositories import UserRepository, AuditLogRepository

# Import admin services
from src.admin.user_management import HealthcareUserManager
from src.admin.system_monitoring import SystemMonitor
from src.admin.compliance_dashboard import ComplianceDashboard
from src.admin.maintenance_tools import MaintenanceManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Healthcare Administration"])


# Request/Response Models
class CreateUserRequest(BaseModel):
    """Request model for creating healthcare user accounts"""
    email: EmailStr
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    role: str = Field(..., description="User role: patient, healthcare_provider, admin")
    facility_id: Optional[str] = Field(None, description="Healthcare facility ID")
    provider_license: Optional[str] = Field(None, description="Healthcare provider license number")
    specialization: Optional[str] = Field(None, description="Healthcare provider specialization")
    department: Optional[str] = Field(None, description="Department or unit")

class UserResponse(BaseModel):
    """Response model for user information"""
    id: UUID
    email: str
    first_name: str
    last_name: str
    phone_number: Optional[str]
    roles: List[str]
    is_active: bool
    email_verified: bool
    created_at: datetime
    last_login: Optional[datetime]
    facility_id: Optional[str]
    provider_details: Optional[Dict[str, Any]]

class BulkUserOperation(BaseModel):
    """Request model for bulk user operations"""
    user_ids: List[UUID] = Field(..., description="List of user IDs")
    operation: str = Field(..., description="Operation: activate, deactivate, assign_role, remove_role")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Operation parameters")

class ProviderRequest(BaseModel):
    """Request model for healthcare provider onboarding"""
    user_id: UUID
    license_number: str = Field(..., description="Healthcare provider license number")
    specialization: str = Field(..., description="Medical specialization")
    board_certification: Optional[str] = None
    npi_number: Optional[str] = Field(None, description="National Provider Identifier")
    dea_number: Optional[str] = Field(None, description="DEA registration number")
    facility_id: str = Field(..., description="Primary facility ID")
    verification_documents: List[str] = Field(default_factory=list)

class SystemHealthResponse(BaseModel):
    """Response model for system health status"""
    overall_status: str
    components: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    capacity_status: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    last_updated: datetime

class MaintenanceRequest(BaseModel):
    """Request model for scheduling maintenance"""
    maintenance_type: str = Field(..., description="Type of maintenance")
    scheduled_time: datetime = Field(..., description="Scheduled maintenance time")
    duration_minutes: int = Field(..., description="Expected duration in minutes")
    description: str = Field(..., description="Maintenance description")
    affected_systems: List[str] = Field(default_factory=list)
    requires_downtime: bool = Field(False, description="Whether maintenance requires downtime")


# Healthcare User Administration Endpoints

@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_healthcare_user(
    request: CreateUserRequest,
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Create healthcare user account with role assignment."""
    try:
        logger.info(f"Creating healthcare user account by admin {current_user.id}")
        
        user_manager = HealthcareUserManager(db)
        user = await user_manager.create_healthcare_user(
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            phone_number=request.phone_number,
            role=request.role,
            facility_id=request.facility_id,
            provider_details={
                "license": request.provider_license,
                "specialization": request.specialization,
                "department": request.department
            } if request.provider_license else None,
            created_by=current_user.id
        )
        
        return UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            phone_number=user.phone_number,
            roles=[assignment.role.name for assignment in user.role_assignments],
            is_active=user.is_active,
            email_verified=user.email_verified,
            created_at=user.created_at,
            last_login=user.last_login,
            facility_id=request.facility_id,
            provider_details={
                "license": request.provider_license,
                "specialization": request.specialization,
                "department": request.department
            } if request.provider_license else None
        )
        
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"User creation failed: {str(e)}")

@router.get("/users", response_model=Dict[str, Any])
async def list_healthcare_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Users per page"),
    role: Optional[str] = Query(None, description="Filter by role"),
    facility_id: Optional[str] = Query(None, description="Filter by facility"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search by name or email"),
    current_user: User = Depends(RoleChecker(["admin", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """List healthcare users with advanced filtering."""
    try:
        user_manager = HealthcareUserManager(db)
        
        result = await user_manager.list_users(
            page=page,
            page_size=page_size,
            role_filter=role,
            facility_filter=facility_id,
            active_filter=is_active,
            search_query=search,
            requesting_user_id=current_user.id
        )
        
        return result
        
    except Exception as e:
        logger.error(f"User listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"User listing failed: {str(e)}")

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_healthcare_user(
    user_id: UUID = Path(..., description="User ID"),
    current_user: User = Depends(RoleChecker(["admin", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """Get detailed healthcare user information."""
    try:
        user_manager = HealthcareUserManager(db)
        user_details = await user_manager.get_user_details(
            user_id=user_id,
            requesting_user_id=current_user.id
        )
        
        if not user_details:
            raise HTTPException(status_code=404, detail="User not found")
        
        return user_details
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"User retrieval failed: {str(e)}")

@router.put("/users/{user_id}", response_model=UserResponse)
async def update_healthcare_user(
    user_id: UUID = Path(..., description="User ID"),
    updates: Dict[str, Any] = Body(..., description="User updates"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Update healthcare user with compliance tracking."""
    try:
        logger.info(f"Updating user {user_id} by admin {current_user.id}")
        
        user_manager = HealthcareUserManager(db)
        updated_user = await user_manager.update_user(
            user_id=user_id,
            updates=updates,
            updated_by=current_user.id
        )
        
        return updated_user
        
    except Exception as e:
        logger.error(f"User update failed: {e}")
        raise HTTPException(status_code=500, detail=f"User update failed: {str(e)}")

@router.put("/users/{user_id}/role")
async def assign_user_role(
    user_id: UUID = Path(..., description="User ID"),
    role_name: str = Body(..., description="Role to assign", embed=True),
    facility_id: Optional[str] = Body(None, description="Facility ID for role assignment", embed=True),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Assign healthcare role to user."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.assign_role(
            user_id=user_id,
            role_name=role_name,
            facility_id=facility_id,
            assigned_by=current_user.id
        )
        
        return {"message": f"Role {role_name} assigned successfully", "result": result}
        
    except Exception as e:
        logger.error(f"Role assignment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Role assignment failed: {str(e)}")

@router.put("/users/{user_id}/facility")
async def assign_user_facility(
    user_id: UUID = Path(..., description="User ID"),
    facility_id: str = Body(..., description="Facility ID", embed=True),
    role: Optional[str] = Body(None, description="Role within facility", embed=True),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Assign user to healthcare facility."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.assign_facility(
            user_id=user_id,
            facility_id=facility_id,
            facility_role=role,
            assigned_by=current_user.id
        )
        
        return {"message": "Facility assignment successful", "result": result}
        
    except Exception as e:
        logger.error(f"Facility assignment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Facility assignment failed: {str(e)}")

@router.delete("/users/{user_id}")
async def deactivate_user(
    user_id: UUID = Path(..., description="User ID"),
    reason: str = Body(..., description="Deactivation reason", embed=True),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Deactivate user account (soft delete)."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.deactivate_user(
            user_id=user_id,
            reason=reason,
            deactivated_by=current_user.id
        )
        
        return {"message": "User deactivated successfully", "result": result}
        
    except Exception as e:
        logger.error(f"User deactivation failed: {e}")
        raise HTTPException(status_code=500, detail=f"User deactivation failed: {str(e)}")

@router.post("/users/bulk")
async def bulk_user_operations(
    request: BulkUserOperation,
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Perform bulk operations on multiple users."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.bulk_operation(
            user_ids=request.user_ids,
            operation=request.operation,
            parameters=request.parameters,
            executed_by=current_user.id
        )
        
        return {"message": f"Bulk {request.operation} completed", "result": result}
        
    except Exception as e:
        logger.error(f"Bulk operation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk operation failed: {str(e)}")

@router.get("/users/audit/{user_id}")
async def get_user_audit_trail(
    user_id: UUID = Path(..., description="User ID"),
    start_date: Optional[datetime] = Query(None, description="Audit start date"),
    end_date: Optional[datetime] = Query(None, description="Audit end date"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum audit entries"),
    current_user: User = Depends(RoleChecker(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Get comprehensive user audit trail."""
    try:
        user_manager = HealthcareUserManager(db)
        audit_trail = await user_manager.get_user_audit_trail(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            requesting_user_id=current_user.id
        )
        
        return audit_trail
        
    except Exception as e:
        logger.error(f"Audit trail retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit trail retrieval failed: {str(e)}")


# Healthcare Provider Management Endpoints

@router.post("/providers")
async def onboard_healthcare_provider(
    request: ProviderRequest,
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Onboard healthcare provider with credential verification."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.onboard_provider(
            provider_request=request,
            onboarded_by=current_user.id
        )
        
        return {"message": "Provider onboarding initiated", "result": result}
        
    except Exception as e:
        logger.error(f"Provider onboarding failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider onboarding failed: {str(e)}")

@router.get("/providers")
async def list_healthcare_providers(
    facility_id: Optional[str] = Query(None, description="Filter by facility"),
    specialization: Optional[str] = Query(None, description="Filter by specialization"),
    verification_status: Optional[str] = Query(None, description="Filter by verification status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(RoleChecker(["admin", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """List healthcare providers with filtering."""
    try:
        user_manager = HealthcareUserManager(db)
        providers = await user_manager.list_providers(
            facility_filter=facility_id,
            specialization_filter=specialization,
            verification_filter=verification_status,
            page=page,
            page_size=page_size,
            requesting_user_id=current_user.id
        )
        
        return providers
        
    except Exception as e:
        logger.error(f"Provider listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider listing failed: {str(e)}")

@router.put("/providers/{provider_id}/verify")
async def verify_provider_credentials(
    provider_id: UUID = Path(..., description="Provider ID"),
    verification_data: Dict[str, Any] = Body(..., description="Verification details"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Verify healthcare provider credentials."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.verify_provider(
            provider_id=provider_id,
            verification_data=verification_data,
            verified_by=current_user.id
        )
        
        return {"message": "Provider verification completed", "result": result}
        
    except Exception as e:
        logger.error(f"Provider verification failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider verification failed: {str(e)}")

@router.post("/providers/{provider_id}/suspend")
async def suspend_provider_access(
    provider_id: UUID = Path(..., description="Provider ID"),
    reason: str = Body(..., description="Suspension reason", embed=True),
    duration_days: Optional[int] = Body(None, description="Suspension duration in days", embed=True),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Suspend healthcare provider access."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.suspend_provider(
            provider_id=provider_id,
            reason=reason,
            duration_days=duration_days,
            suspended_by=current_user.id
        )
        
        return {"message": "Provider suspended successfully", "result": result}
        
    except Exception as e:
        logger.error(f"Provider suspension failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider suspension failed: {str(e)}")

@router.get("/providers/{provider_id}/patients")
async def get_provider_patients(
    provider_id: UUID = Path(..., description="Provider ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(RoleChecker(["admin", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """Get provider's patient list."""
    try:
        user_manager = HealthcareUserManager(db)
        patients = await user_manager.get_provider_patients(
            provider_id=provider_id,
            page=page,
            page_size=page_size,
            requesting_user_id=current_user.id
        )
        
        return patients
        
    except Exception as e:
        logger.error(f"Provider patient list retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider patient list retrieval failed: {str(e)}")

@router.put("/providers/{provider_id}/permissions")
async def update_provider_permissions(
    provider_id: UUID = Path(..., description="Provider ID"),
    permissions: Dict[str, Any] = Body(..., description="Permission updates"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Update healthcare provider permissions."""
    try:
        user_manager = HealthcareUserManager(db)
        result = await user_manager.update_provider_permissions(
            provider_id=provider_id,
            permissions=permissions,
            updated_by=current_user.id
        )
        
        return {"message": "Provider permissions updated", "result": result}
        
    except Exception as e:
        logger.error(f"Provider permission update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider permission update failed: {str(e)}")


# System Monitoring and Maintenance Endpoints

@router.get("/system/health", response_model=SystemHealthResponse)
async def get_comprehensive_system_health(
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get comprehensive system health status."""
    try:
        monitor = SystemMonitor(db)
        health_status = await monitor.get_comprehensive_health()
        
        return SystemHealthResponse(**health_status)
        
    except Exception as e:
        logger.error(f"System health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"System health check failed: {str(e)}")

@router.get("/system/metrics")
async def get_real_time_metrics(
    metric_type: Optional[str] = Query(None, description="Filter by metric type"),
    time_range: str = Query("1h", description="Time range for metrics"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get real-time performance metrics."""
    try:
        monitor = SystemMonitor(db)
        metrics = await monitor.get_real_time_metrics(
            metric_type=metric_type,
            time_range=time_range
        )
        
        return metrics
        
    except Exception as e:
        logger.error(f"Metrics retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics retrieval failed: {str(e)}")

@router.get("/system/capacity")
async def get_system_capacity(
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get system capacity and scaling information."""
    try:
        monitor = SystemMonitor(db)
        capacity = await monitor.get_capacity_status()
        
        return capacity
        
    except Exception as e:
        logger.error(f"Capacity check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Capacity check failed: {str(e)}")

@router.post("/system/maintenance")
async def schedule_maintenance_window(
    request: MaintenanceRequest,
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Schedule system maintenance window."""
    try:
        maintenance_manager = MaintenanceManager(db)
        result = await maintenance_manager.schedule_maintenance(
            maintenance_request=request,
            scheduled_by=current_user.id
        )
        
        return {"message": "Maintenance scheduled successfully", "result": result}
        
    except Exception as e:
        logger.error(f"Maintenance scheduling failed: {e}")
        raise HTTPException(status_code=500, detail=f"Maintenance scheduling failed: {str(e)}")

@router.get("/system/logs")
async def get_system_logs(
    log_level: Optional[str] = Query(None, description="Filter by log level"),
    component: Optional[str] = Query(None, description="Filter by component"),
    start_time: Optional[datetime] = Query(None, description="Start time for logs"),
    end_time: Optional[datetime] = Query(None, description="End time for logs"),
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get system log aggregation."""
    try:
        monitor = SystemMonitor(db)
        logs = await monitor.get_system_logs(
            log_level=log_level,
            component=component,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )
        
        return logs
        
    except Exception as e:
        logger.error(f"Log retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Log retrieval failed: {str(e)}")

@router.post("/system/backup")
async def initiate_system_backup(
    backup_type: str = Body(..., description="Type of backup", embed=True),
    include_phi: bool = Body(True, description="Include PHI data", embed=True),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Initiate system backup."""
    try:
        maintenance_manager = MaintenanceManager(db)
        result = await maintenance_manager.initiate_backup(
            backup_type=backup_type,
            include_phi=include_phi,
            initiated_by=current_user.id
        )
        
        return {"message": "Backup initiated successfully", "result": result}
        
    except Exception as e:
        logger.error(f"Backup initiation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Backup initiation failed: {str(e)}")


# Configuration and Deployment Management

@router.get("/config")
async def get_system_configuration(
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get system configuration status."""
    try:
        monitor = SystemMonitor(db)
        config = await monitor.get_configuration_status()
        
        return config
        
    except Exception as e:
        logger.error(f"Configuration retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration retrieval failed: {str(e)}")

@router.put("/config/{component}")
async def update_component_configuration(
    component: str = Path(..., description="Component to configure"),
    configuration: Dict[str, Any] = Body(..., description="Configuration updates"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Update component configuration."""
    try:
        maintenance_manager = MaintenanceManager(db)
        result = await maintenance_manager.update_configuration(
            component=component,
            configuration=configuration,
            updated_by=current_user.id
        )
        
        return {"message": f"{component} configuration updated", "result": result}
        
    except Exception as e:
        logger.error(f"Configuration update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration update failed: {str(e)}")

@router.post("/deploy")
async def deploy_system_update(
    deployment_config: Dict[str, Any] = Body(..., description="Deployment configuration"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Deploy system updates."""
    try:
        maintenance_manager = MaintenanceManager(db)
        result = await maintenance_manager.deploy_update(
            deployment_config=deployment_config,
            deployed_by=current_user.id
        )
        
        return {"message": "Deployment initiated", "result": result}
        
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Deployment failed: {str(e)}")

@router.get("/deploy/status")
async def get_deployment_status(
    deployment_id: Optional[str] = Query(None, description="Specific deployment ID"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get deployment status."""
    try:
        maintenance_manager = MaintenanceManager(db)
        status = await maintenance_manager.get_deployment_status(deployment_id)
        
        return status
        
    except Exception as e:
        logger.error(f"Deployment status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Deployment status check failed: {str(e)}")

@router.post("/config/validate")
async def validate_configuration(
    config_data: Dict[str, Any] = Body(..., description="Configuration to validate"),
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Validate system configuration."""
    try:
        maintenance_manager = MaintenanceManager(db)
        validation_result = await maintenance_manager.validate_configuration(config_data)
        
        return validation_result
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration validation failed: {str(e)}")

@router.get("/features")
async def get_feature_flags(
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Get feature flag management."""
    try:
        maintenance_manager = MaintenanceManager(db)
        features = await maintenance_manager.get_feature_flags()
        
        return features
        
    except Exception as e:
        logger.error(f"Feature flag retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Feature flag retrieval failed: {str(e)}")


# Incident Management

@router.get("/incidents")
async def list_security_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    days: int = Query(30, ge=1, le=365, description="Days to look back"),
    current_user: User = Depends(RoleChecker(["admin", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """List security incidents."""
    try:
        from src.compliance.incident_response import run_incident_response
        
        incidents = await run_incident_response(
            db=db,
            action="list",
            filters={
                "status": status,
                "severity": severity,
                "days": days
            }
        )
        
        return incidents
        
    except Exception as e:
        logger.error(f"Incident listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Incident listing failed: {str(e)}")

@router.put("/incidents/{incident_id}")
async def update_incident_status(
    incident_id: str = Path(..., description="Incident ID"),
    status_update: Dict[str, Any] = Body(..., description="Status update"),
    current_user: User = Depends(RoleChecker(["admin", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """Update security incident status."""
    try:
        from src.compliance.incident_response import IncidentResponseManager
        
        manager = IncidentResponseManager(db)
        result = await manager.update_incident_status(
            incident_id=incident_id,
            status=status_update.get("status"),
            notes=status_update.get("notes")
        )
        
        return {"message": "Incident updated successfully", "result": result}
        
    except Exception as e:
        logger.error(f"Incident update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Incident update failed: {str(e)}") 
"""
Healthcare Administration Module

Comprehensive healthcare administration services including user management,
system monitoring, compliance dashboard, analytics, and maintenance tools.
"""

from .user_management import (
    HealthcareUserManager,
    create_healthcare_user,
    manage_provider_credentials,
    bulk_user_operations
)

from .system_monitoring import (
    SystemMonitor,
    get_system_health,
    get_performance_metrics,
    monitor_capacity
)

from .compliance_dashboard import (
    ComplianceDashboard,
    get_compliance_overview,
    get_risk_dashboard,
    generate_compliance_alerts
)

from .analytics_service import (
    HealthcareAnalyticsService,
    generate_usage_analytics,
    generate_clinical_insights,
    export_analytics_data
)

from .maintenance_tools import (
    MaintenanceManager,
    schedule_maintenance,
    perform_system_backup,
    deploy_updates
)

__all__ = [
    # User Management
    "HealthcareUserManager",
    "create_healthcare_user",
    "manage_provider_credentials", 
    "bulk_user_operations",
    
    # System Monitoring
    "SystemMonitor",
    "get_system_health",
    "get_performance_metrics",
    "monitor_capacity",
    
    # Compliance Dashboard
    "ComplianceDashboard",
    "get_compliance_overview",
    "get_risk_dashboard",
    "generate_compliance_alerts",
    
    # Analytics Service
    "HealthcareAnalyticsService",
    "generate_usage_analytics",
    "generate_clinical_insights",
    "export_analytics_data",
    
    # Maintenance Tools
    "MaintenanceManager",
    "schedule_maintenance",
    "perform_system_backup",
    "deploy_updates"
]

__version__ = "1.0.0" 
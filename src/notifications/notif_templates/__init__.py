#!/usr/bin/env python3
"""
Notification Templates Package

HIPAA-compliant notification templates for healthcare communications.
"""

from typing import Dict, Any

# Import all template functions for easy access
from .patient_templates import *
from .provider_templates import *
from .security_templates import *

__version__ = "1.0.0"
__all__ = [
    # Patient templates
    'get_recording_reminder_template',
    'get_analysis_complete_template', 
    'get_welcome_message_template',
    'get_appointment_reminder_template',
    'get_maintenance_template',
    
    # Provider templates
    'get_file_shared_template',
    'get_patient_alert_template',
    'get_new_patient_template', 
    'get_analysis_review_needed_template',
    'get_system_update_template',
    'get_training_reminder_template',
    
    # Security templates
    'get_login_alert_template',
    'get_password_changed_template',
    'get_suspicious_activity_template',
    'get_account_locked_template',
    'get_mfa_enabled_template',
    'get_data_breach_notification_template'
]
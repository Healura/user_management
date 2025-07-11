"""
Healthcare Provider Notification Templates

Templates for provider-facing notifications including patient alerts,
file sharing, and clinical updates.
"""

from typing import Dict, Any
from datetime import datetime

__all__ = [
    'get_file_shared_template',
    'get_patient_alert_template',
    'get_new_patient_template', 
    'get_analysis_review_needed_template',
    'get_system_update_template',
    'get_training_reminder_template'
]


def get_file_shared_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for file sharing notifications to providers"""
    patient_name = data.get("patient_name", "A patient")
    file_type = data.get("file_type", "voice recording")
    share_id = data.get("share_id", "")
    recording_date = data.get("recording_date", datetime.utcnow().strftime("%B %d, %Y"))
    urgency = data.get("urgency", "normal")
    
    urgency_indicator = "🔴 URGENT: " if urgency == "high" else ""
    
    return {
        "subject": f"{urgency_indicator}Patient File Shared - {file_type.title()}",
        "template": "file_shared",
        "template_data": {
            "provider_name": user.full_name or "Healthcare Provider",
            "patient_name": patient_name,
            "file_type": file_type,
            "share_id": share_id,
            "recording_date": recording_date,
            "urgency": urgency
        },
        "body": f"""
        <h2>Dear {user.full_name or 'Healthcare Provider'},</h2>
        
        <p>{patient_name} has shared a {file_type} with you for review.</p>
        
        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0;">📁 Shared File Details</h3>
            <p><strong>Patient:</strong> {patient_name}</p>
            <p><strong>File Type:</strong> {file_type.title()}</p>
            <p><strong>Recording Date:</strong> {recording_date}</p>
            <p><strong>Priority:</strong> {urgency.title()}</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://provider.voicebiomarker.com/shared/{share_id}" 
               style="background-color: #1976D2; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                View Shared File
            </a>
        </div>
        
        <p><strong>Security Note:</strong> This link will expire in 7 days. Access requires 
        authentication through the provider portal.</p>
        
        <p style="font-size: 12px; color: #666;">
            This message contains protected health information. Do not forward this email.
        </p>
        """,
        "sms_body": f"Voice Biomarker: {patient_name} shared a {file_type}. Log in to provider portal to review.",
        "push_title": "Patient File Shared",
        "push_body": f"{patient_name} shared a {file_type} for your review",
        "push_data": {
            "action": "view_shared_file",
            "share_id": share_id,
            "urgency": urgency
        },
        "action_url": f"voicebiomarker-provider://shared/{share_id}",
        "contains_phi": False,
        "provider_only": True
    }


def get_patient_alert_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for patient health alerts to providers"""
    patient_name = data.get("patient_name", "Patient")
    alert_type = data.get("alert_type", "anomaly_detected")
    alert_severity = data.get("severity", "medium")
    metric_name = data.get("metric_name", "voice pattern")
    deviation = data.get("deviation", "significant change")
    
    severity_colors = {
        "low": "#2196F3",
        "medium": "#FF9800",
        "high": "#F44336"
    }
    
    severity_emoji = {
        "low": "ℹ️",
        "medium": "⚠️",
        "high": "🚨"
    }
    
    return {
        "subject": f"{severity_emoji[alert_severity]} Patient Alert - {patient_name}",
        "template": "patient_alert",
        "template_data": {
            "provider_name": user.full_name or "Healthcare Provider",
            "patient_name": patient_name,
            "alert_type": alert_type,
            "severity": alert_severity,
            "metric_name": metric_name,
            "deviation": deviation,
            "timestamp": datetime.utcnow().isoformat()
        },
        "body": f"""
        <h2>Dear {user.full_name or 'Healthcare Provider'},</h2>
        
        <p>An alert has been generated for your patient based on their recent voice analysis.</p>
        
        <div style="background-color: {severity_colors[alert_severity]}20; padding: 20px; 
                    border-radius: 8px; margin: 20px 0; border-left: 4px solid {severity_colors[alert_severity]};">
            <h3 style="margin-top: 0;">{severity_emoji[alert_severity]} Alert Details</h3>
            <p><strong>Patient:</strong> {patient_name}</p>
            <p><strong>Alert Type:</strong> {alert_type.replace('_', ' ').title()}</p>
            <p><strong>Severity:</strong> {alert_severity.upper()}</p>
            <p><strong>Finding:</strong> {deviation} in {metric_name}</p>
        </div>
        
        <p><strong>Recommended Actions:</strong></p>
        <ul>
            <li>Review the patient's recent voice analysis results</li>
            <li>Compare with baseline measurements</li>
            <li>Consider scheduling a follow-up if warranted</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://provider.voicebiomarker.com/patients/{patient_name}/alerts" 
               style="background-color: {severity_colors[alert_severity]}; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Review Patient Data
            </a>
        </div>
        
        <p style="font-size: 12px; color: #666;">
            This is an automated alert based on AI analysis. Clinical judgment should always be applied.
        </p>
        """,
        "sms_body": f"Voice Biomarker ALERT: {patient_name} - {alert_severity.upper()} severity. Review required.",
        "push_title": f"{severity_emoji[alert_severity]} Patient Alert",
        "push_body": f"{patient_name}: {deviation} detected",
        "push_data": {
            "action": "view_patient_alert",
            "patient_id": data.get("patient_id", ""),
            "severity": alert_severity,
            "alert_type": alert_type
        },
        "action_url": f"voicebiomarker-provider://alerts",
        "contains_phi": False,
        "provider_only": True,
        "priority": "high" if alert_severity == "high" else "normal"
    }


def get_new_patient_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for new patient assignment notifications"""
    patient_name = data.get("patient_name", "New Patient")
    referral_source = data.get("referral_source", "Direct Registration")
    patient_id = data.get("patient_id", "")
    initial_recording = data.get("has_initial_recording", False)
    
    return {
        "subject": f"New Patient Assignment - {patient_name}",
        "template": "new_patient",
        "template_data": {
            "provider_name": user.full_name or "Healthcare Provider",
            "patient_name": patient_name,
            "patient_id": patient_id,
            "referral_source": referral_source,
            "has_initial_recording": initial_recording
        },
        "body": f"""
        <h2>Dear {user.full_name or 'Healthcare Provider'},</h2>
        
        <p>A new patient has been assigned to your care through the Voice Biomarker platform.</p>
        
        <div style="background-color: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0;">👤 New Patient Information</h3>
            <p><strong>Name:</strong> {patient_name}</p>
            <p><strong>Patient ID:</strong> {patient_id}</p>
            <p><strong>Referral Source:</strong> {referral_source}</p>
            <p><strong>Initial Recording:</strong> {'✅ Completed' if initial_recording else '⏳ Pending'}</p>
        </div>
        
        <p><strong>Next Steps:</strong></p>
        <ol>
            <li>Review patient intake information</li>
            <li>{'Review baseline voice recording' if initial_recording else 'Request initial voice recording'}</li>
            <li>Set up monitoring preferences</li>
            <li>Schedule initial consultation if needed</li>
        </ol>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://provider.voicebiomarker.com/patients/{patient_id}" 
               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                View Patient Profile
            </a>
        </div>
        
        <p>The patient has been notified of your assignment and can now share voice recordings 
        with you through the platform.</p>
        """,
        "sms_body": f"Voice Biomarker: New patient {patient_name} assigned to your care. Review profile in provider portal.",
        "push_title": "New Patient Assignment",
        "push_body": f"{patient_name} has been assigned to your care",
        "push_data": {
            "action": "view_new_patient",
            "patient_id": patient_id
        },
        "action_url": f"voicebiomarker-provider://patients/{patient_id}",
        "contains_phi": False,
        "provider_only": True
    }


def get_analysis_review_needed_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for analysis requiring provider review"""
    patient_count = data.get("patient_count", 1)
    oldest_pending = data.get("oldest_pending_days", 0)
    
    return {
        "subject": f"Analysis Review Required - {patient_count} Patient{'s' if patient_count != 1 else ''}",
        "template": "analysis_review_needed",
        "template_data": {
            "provider_name": user.full_name or "Healthcare Provider",
            "patient_count": patient_count,
            "oldest_pending_days": oldest_pending
        },
        "body": f"""
        <h2>Dear {user.full_name or 'Healthcare Provider'},</h2>
        
        <p>You have {patient_count} patient analysis result{'s' if patient_count != 1 else ''} waiting for your review.</p>
        
        <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
            <h3 style="margin-top: 0;">📋 Review Summary</h3>
            <p><strong>Pending Reviews:</strong> {patient_count}</p>
            <p><strong>Oldest Pending:</strong> {oldest_pending} days</p>
            <p><strong>Priority:</strong> {'High' if oldest_pending > 7 else 'Normal'}</p>
        </div>
        
        <p><strong>Why This Matters:</strong></p>
        <ul>
            <li>Timely review ensures continuity of care</li>
            <li>Early intervention opportunities may be identified</li>
            <li>Patient engagement depends on prompt feedback</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://provider.voicebiomarker.com/reviews/pending" 
               style="background-color: #FF9800; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Review Pending Analysis
            </a>
        </div>
        
        <p>Please prioritize reviews that have been pending for more than 7 days to maintain 
        optimal patient care standards.</p>
        
        <p style="font-size: 12px; color: #666;">
            This is an automated reminder to ensure timely patient care. You can adjust reminder 
            frequency in your provider settings.
        </p>
        """,
        "sms_body": f"Voice Biomarker: You have {patient_count} pending analysis review{'s' if patient_count != 1 else ''}. Please log in to the provider portal.",
        "push_title": "Reviews Needed",
        "push_body": f"{patient_count} patient analysis{'es' if patient_count != 1 else ''} awaiting review",
        "push_data": {
            "action": "view_pending_reviews",
            "count": patient_count
        },
        "action_url": "voicebiomarker-provider://reviews/pending",
        "contains_phi": False,
        "provider_only": True
    }


def get_system_update_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for system updates and feature announcements"""
    update_type = data.get("update_type", "feature")
    update_title = data.get("update_title", "Platform Update")
    update_description = data.get("update_description", "")
    effective_date = data.get("effective_date", datetime.utcnow().strftime("%B %d, %Y"))
    
    return {
        "subject": f"Voice Biomarker Update: {update_title}",
        "template": "system_update",
        "template_data": {
            "provider_name": user.full_name or "Healthcare Provider",
            "update_type": update_type,
            "update_title": update_title,
            "update_description": update_description,
            "effective_date": effective_date
        },
        "body": f"""
        <h2>Dear {user.full_name or 'Healthcare Provider'},</h2>
        
        <p>We're excited to inform you about an important update to the Voice Biomarker platform.</p>
        
        <div style="background-color: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0;">🚀 Platform Update</h3>
            <p><strong>Update Type:</strong> {update_type.title()}</p>
            <p><strong>Title:</strong> {update_title}</p>
            <p><strong>Effective Date:</strong> {effective_date}</p>
            {f'<p><strong>Description:</strong> {update_description}</p>' if update_description else ''}
        </div>
        
        <p><strong>What This Means for You:</strong></p>
        <ul>
            <li>Enhanced patient care capabilities</li>
            <li>Improved workflow efficiency</li>
            <li>Better data insights and reporting</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://provider.voicebiomarker.com/updates" 
               style="background-color: #1976D2; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Learn More
            </a>
        </div>
        
        <p>If you have any questions about this update, please contact our support team 
        at provider-support@voicebiomarker.com</p>
        
        <p style="font-size: 12px; color: #666;">
            Visit our documentation portal for detailed information about new features and capabilities.
        </p>
        """,
        "sms_body": f"Voice Biomarker: {update_title} - {update_type} update effective {effective_date}. Check provider portal for details.",
        "push_title": "Platform Update",
        "push_body": f"{update_title} - {update_type} update available",
        "push_data": {
            "action": "view_update",
            "update_type": update_type
        },
        "action_url": "voicebiomarker-provider://updates",
        "contains_phi": False,
        "provider_only": True
    }


def get_training_reminder_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for mandatory training reminders"""
    training_title = data.get("training_title", "HIPAA Compliance Training")
    due_date = data.get("due_date", "")
    completion_url = data.get("completion_url", "https://provider.voicebiomarker.com/training")
    
    return {
        "subject": f"Training Reminder: {training_title}",
        "template": "training_reminder",
        "template_data": {
            "provider_name": user.full_name or "Healthcare Provider",
            "training_title": training_title,
            "due_date": due_date,
            "completion_url": completion_url
        },
        "body": f"""
        <h2>Dear {user.full_name or 'Healthcare Provider'},</h2>
        
        <p>This is a reminder about required training that needs to be completed.</p>
        
        <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
            <h3 style="margin-top: 0;">📚 Required Training</h3>
            <p><strong>Training:</strong> {training_title}</p>
            <p><strong>Due Date:</strong> {due_date}</p>
            <p><strong>Status:</strong> ⏳ Pending Completion</p>
        </div>
        
        <p><strong>Why This Training is Important:</strong></p>
        <ul>
            <li>Ensures compliance with healthcare regulations</li>
            <li>Protects patient privacy and data security</li>
            <li>Maintains platform access privileges</li>
            <li>Keeps you updated on best practices</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{completion_url}" 
               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Complete Training Now
            </a>
        </div>
        
        <p><strong>Important:</strong> Failure to complete required training by the due date 
        may result in temporary suspension of platform access.</p>
        
        <p style="font-size: 12px; color: #666;">
            If you have technical difficulties accessing the training, please contact 
            training-support@voicebiomarker.com
        </p>
        """,
        "sms_body": f"Voice Biomarker: {training_title} due {due_date}. Complete at provider portal to maintain access.",
        "push_title": "Training Due",
        "push_body": f"{training_title} must be completed by {due_date}",
        "push_data": {
            "action": "complete_training",
            "training_title": training_title
        },
        "action_url": "voicebiomarker-provider://training",
        "contains_phi": False,
        "provider_only": True
    }
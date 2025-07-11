"""
Patient-facing Notification Templates

HIPAA-compliant templates for patient communications including
reminders, results, and system messages.
"""

from typing import Dict, Any
from datetime import datetime

__all__ = [
    'get_recording_reminder_template',
    'get_analysis_complete_template', 
    'get_welcome_message_template',
    'get_appointment_reminder_template',
    'get_maintenance_template'
]


def get_recording_reminder_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for voice recording reminders"""
    return {
        "subject": "Voice Recording Reminder - Your Health Matters",
        "template": "recording_reminder",
        "template_data": {
            "user_name": user.full_name or user.username,
            "reminder_type": data.get("reminder_type", "daily"),
            "session_type": data.get("session_type", "regular"),
            "custom_message": data.get("custom_message", "")
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>It's time for your scheduled voice recording session.</p>
        
        <p>Your voice recordings help us monitor your health and provide you with 
        valuable insights. This session should only take a few minutes.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/record" 
               style="background-color: #1976D2; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Start Recording Now
            </a>
        </div>
        
        <p>If you can't record right now, you can complete your session anytime today.</p>
        
        <p style="font-size: 12px; color: #666;">
            Tip: Find a quiet place and speak naturally for the best results.
        </p>
        """,
        "sms_body": "Voice Biomarker: Time for your voice recording. Open the app to start your session.",
        "push_title": "Recording Reminder",
        "push_body": "It's time for your scheduled voice recording",
        "push_data": {
            "action": "open_recorder",
            "session_type": data.get("session_type", "regular")
        },
        "action_url": "voicebiomarker://record",
        "contains_phi": False,
        "legal_disclaimer": True
    }


def get_analysis_complete_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for analysis completion notifications"""
    analysis_id = data.get("analysis_id", "")
    analysis_type = data.get("analysis_type", "standard")
    
    return {
        "subject": "Your Voice Analysis is Ready",
        "template": "analysis_complete",
        "template_data": {
            "user_name": user.full_name or user.username,
            "analysis_id": analysis_id,
            "analysis_type": analysis_type,
            "completion_time": data.get("completion_time", datetime.utcnow().isoformat())
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>Great news! Your voice analysis has been completed and your results are ready to view.</p>
        
        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Analysis Summary</h3>
            <p><strong>Type:</strong> {analysis_type.title()} Analysis</p>
            <p><strong>Completed:</strong> Just now</p>
            <p><strong>Status:</strong> ✅ Ready to view</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/results/{analysis_id}" 
               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                View Your Results
            </a>
        </div>
        
        <p>Your healthcare provider has also been notified and can discuss these results with you.</p>
        
        <p style="font-size: 12px; color: #666;">
            Your results are securely stored and only accessible to you and your authorized healthcare providers.
        </p>
        """,
        "sms_body": "Voice Biomarker: Your voice analysis is complete. Log in to view your results securely.",
        "push_title": "Analysis Complete",
        "push_body": "Your voice analysis results are ready",
        "push_data": {
            "action": "view_results",
            "analysis_id": analysis_id
        },
        "action_url": f"voicebiomarker://results/{analysis_id}",
        "contains_phi": False,
        "secure_link": True
    }


def get_welcome_message_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for new user welcome messages"""
    onboarding_step = data.get("onboarding_step", "welcome")
    
    return {
        "subject": "Welcome to Voice Biomarker - Your Voice, Your Health",
        "template": "welcome_message",
        "template_data": {
            "user_name": user.full_name or user.username,
            "onboarding_step": onboarding_step,
            "provider_name": data.get("provider_name", ""),
            "activation_code": data.get("activation_code", "")
        },
        "body": f"""
        <h2>Welcome {user.full_name or user.username}!</h2>
        
        <p>Thank you for joining Voice Biomarker. We're excited to help you monitor and improve 
        your health through the power of voice analysis.</p>
        
        <div style="background-color: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0;">Getting Started</h3>
            <ol>
                <li><strong>Complete Your Profile:</strong> Add your health information for personalized insights</li>
                <li><strong>Record Your First Sample:</strong> Takes just 30 seconds</li>
                <li><strong>View Your Baseline:</strong> Understand your voice health metrics</li>
            </ol>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/onboarding" 
               style="background-color: #1976D2; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Get Started
            </a>
        </div>
        
        <p><strong>Your Privacy Matters:</strong> All your health data is encrypted and protected 
        according to HIPAA standards. You control who sees your information.</p>
        
        <p>If you have questions, our support team is here to help at support@voicebiomarker.com</p>
        """,
        "sms_body": "Welcome to Voice Biomarker! Complete your profile to start monitoring your health through voice. Get started: https://vbm.link/start",
        "push_title": "Welcome to Voice Biomarker!",
        "push_body": "Complete your profile to get started",
        "push_data": {
            "action": "onboarding",
            "step": onboarding_step
        },
        "action_url": "voicebiomarker://onboarding",
        "contains_phi": False
    }


def get_appointment_reminder_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for appointment reminders"""
    appointment_time = data.get("appointment_time", "")
    provider_name = data.get("provider_name", "Healthcare Provider")
    appointment_type = data.get("appointment_type", "Follow-up")
    hours_before = data.get("hours_before", 24)
    
    # Format time nicely
    if appointment_time:
        try:
            apt_dt = datetime.fromisoformat(appointment_time)
            formatted_time = apt_dt.strftime("%A, %B %d at %I:%M %p")
        except:
            formatted_time = appointment_time
    else:
        formatted_time = "scheduled time"
    
    time_phrase = "tomorrow" if hours_before >= 24 else f"in {hours_before} hours"
    
    return {
        "subject": f"Appointment Reminder - {appointment_type} {time_phrase}",
        "template": "appointment_reminder",
        "template_data": {
            "user_name": user.full_name or user.username,
            "appointment_time": appointment_time,
            "formatted_time": formatted_time,
            "provider_name": provider_name,
            "appointment_type": appointment_type,
            "hours_before": hours_before
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>This is a reminder about your upcoming appointment:</p>
        
        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0;">📅 Appointment Details</h3>
            <p><strong>Type:</strong> {appointment_type}</p>
            <p><strong>Provider:</strong> {provider_name}</p>
            <p><strong>When:</strong> {formatted_time}</p>
        </div>
        
        <p><strong>Prepare for Your Visit:</strong></p>
        <ul>
            <li>Complete a voice recording before your appointment</li>
            <li>Review your recent voice analysis results</li>
            <li>Prepare any questions for your provider</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/appointments" 
               style="background-color: #1976D2; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                View Appointment Details
            </a>
        </div>
        
        <p style="font-size: 12px; color: #666;">
            Need to reschedule? Contact your provider's office or use the app.
        </p>
        """,
        "sms_body": f"Voice Biomarker: Reminder - {appointment_type} with {provider_name} {time_phrase}. Complete a voice recording before your visit.",
        "push_title": "Appointment Reminder",
        "push_body": f"{appointment_type} with {provider_name} {time_phrase}",
        "push_data": {
            "action": "view_appointment",
            "appointment_time": appointment_time
        },
        "action_url": "voicebiomarker://appointments",
        "contains_phi": False
    }


def get_maintenance_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for system maintenance notifications"""
    maintenance_start = data.get("start_time", "")
    maintenance_end = data.get("end_time", "")
    affected_services = data.get("affected_services", ["Voice Recording", "Analysis"])
    
    return {
        "subject": "Scheduled Maintenance - Voice Biomarker Platform",
        "template": "maintenance",
        "template_data": {
            "user_name": user.full_name or user.username,
            "maintenance_start": maintenance_start,
            "maintenance_end": maintenance_end,
            "affected_services": affected_services
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>We're writing to inform you about scheduled maintenance on the Voice Biomarker platform.</p>
        
        <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
            <h3 style="margin-top: 0;">⚠️ Maintenance Window</h3>
            <p><strong>Start:</strong> {maintenance_start}</p>
            <p><strong>End:</strong> {maintenance_end}</p>
            <p><strong>Affected Services:</strong> {', '.join(affected_services)}</p>
        </div>
        
        <p><strong>What This Means:</strong></p>
        <ul>
            <li>You may not be able to record new voice samples during this time</li>
            <li>Analysis processing may be delayed</li>
            <li>Your existing data remains safe and secure</li>
        </ul>
        
        <p>We apologize for any inconvenience and appreciate your patience as we work to improve 
        our platform.</p>
        
        <p style="font-size: 12px; color: #666;">
            For updates, visit our status page or follow us on social media.
        </p>
        """,
        "sms_body": f"Voice Biomarker: Scheduled maintenance {maintenance_start}. Some services may be unavailable. Your data is safe.",
        "push_title": "Scheduled Maintenance",
        "push_body": f"Platform maintenance scheduled for {maintenance_start}",
        "push_data": {
            "action": "view_status",
            "maintenance": True
        },
        "contains_phi": False
    }
# Voice Biomarker Notification System - Phase 4A

## Overview

This document outlines the core notification system implementation for the healthcare user management microservice. The system provides HIPAA-compliant notification delivery across email, SMS, and push notification channels.

## Architecture

### Core Components

1. **NotificationManager** - Central orchestration of all notifications
2. **EmailService** - HIPAA-compliant email notifications with encryption
3. **SMSService** - Healthcare SMS notifications with opt-in/opt-out management
4. **PushNotificationService** - Secure mobile push notifications with PHI filtering
5. **NotificationScheduler** - Healthcare notification scheduling system
6. **Template System** - Healthcare-appropriate message templates

### Database Models

The notification system uses these database models:

- `NotificationPreference` - User notification settings
- `NotificationHistory` - Audit trail of sent notifications
- `UserDevice` - Device tokens for push notifications
- `SMSOptInOut` - SMS consent tracking for compliance
- `ScheduledNotification` - One-time scheduled notifications
- `RecurringNotification` - Recurring notification schedules

## Features

### Healthcare Compliance
- **HIPAA Compliant**: All notifications follow HIPAA guidelines
- **PHI Protection**: No PHI in push notifications, encrypted email for sensitive content
- **Audit Logging**: Complete audit trail for compliance
- **Patient Consent**: Verification before sending notifications
- **Opt-in/Opt-out**: SMS consent management

### Notification Types

#### Patient Notifications
- **Recording Reminders**: Daily voice recording reminders
- **Analysis Complete**: Notification when analysis is ready
- **Welcome Messages**: Onboarding notifications for new users
- **Appointment Reminders**: Healthcare appointment notifications

#### Provider Notifications
- **File Shared**: Patient file sharing alerts
- **Patient Alerts**: Health anomaly notifications
- **New Patient**: Patient assignment notifications
- **Analysis Review**: Pending review reminders

#### Security Notifications
- **Login Alerts**: New device login notifications
- **Password Changes**: Account security notifications
- **Suspicious Activity**: Security threat alerts
- **Account Lockouts**: Account security notifications

## API Endpoints

### User Preferences
```
GET    /notifications/preferences    # Get user notification settings
PUT    /notifications/preferences    # Update notification preferences
```

### Notification Management
```
GET    /notifications/history        # User notification history
POST   /notifications/test           # Test notification delivery
```

### Patient Notifications
```
POST   /notifications/reminder       # Send recording reminder
POST   /notifications/analysis       # Analysis completion notice
POST   /notifications/welcome        # Welcome message for new users
```

### System Notifications (Admin Only)
```
POST   /notifications/security       # Security event notifications
POST   /notifications/maintenance    # System maintenance alerts
POST   /notifications/bulk          # Bulk notifications
POST   /notifications/schedule      # Schedule notifications
```

## Configuration

### Environment Variables

```bash
# Email Configuration (HIPAA-compliant)
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_TLS=true
SMTP_USERNAME=notifications@voicebiomarker.com
SMTP_PASSWORD=your-app-password
EMAIL_ENCRYPTION_REQUIRED=true

# SMS Configuration (HIPAA-compliant provider)
SMS_PROVIDER=twilio
SMS_ACCOUNT_SID=your-twilio-sid
SMS_AUTH_TOKEN=your-twilio-token
SMS_FROM_NUMBER=+1234567890
SMS_ENCRYPTION_REQUIRED=true

# Push Notification Configuration
PUSH_SERVICE=firebase
FIREBASE_PROJECT_ID=voice-biomarker
FIREBASE_PRIVATE_KEY_PATH=./keys/firebase-key.json
PUSH_PHI_FILTERING=true

# Notification Policies
PATIENT_CONSENT_REQUIRED=true
NOTIFICATION_RATE_LIMIT=10
NOTIFICATION_RETRY_ATTEMPTS=3
NOTIFICATION_AUDIT_REQUIRED=true
```

## Usage Examples

### Send Recording Reminder
```python
# Send reminder to current user
POST /notifications/reminder
{
  "custom_message": "Don't forget your daily recording!"
}

# Send reminder to specific patient (provider only)
POST /notifications/reminder
{
  "user_id": "user-uuid",
  "custom_message": "Time for your scheduled recording"
}
```

### Update Notification Preferences
```python
PUT /notifications/preferences
{
  "email_enabled": true,
  "sms_enabled": false,
  "push_enabled": true,
  "reminder_time": "09:00",
  "reminder_frequency": "daily"
}
```

### Test Notifications
```python
POST /notifications/test
{
  "channel": "email",
  "test_type": "basic"
}
```

### Schedule Notification
```python
POST /notifications/schedule
{
  "notification_type": "recording_reminder",
  "user_id": "user-uuid",
  "schedule_type": "daily",
  "scheduled_time": "2024-01-15T09:00:00Z",
  "data": {
    "reminder_type": "scheduled"
  }
}
```

## Healthcare Templates

### Patient Templates
- **Recording Reminder**: "It's time for your scheduled voice recording"
- **Analysis Complete**: "Your voice analysis results are ready"
- **Welcome Message**: "Welcome to Voice Biomarker"
- **Appointment Reminder**: "Upcoming appointment reminder"

### Provider Templates
- **File Shared**: "Patient has shared a voice recording"
- **Patient Alert**: "Health anomaly detected in patient analysis"
- **New Patient**: "New patient assigned to your care"

### Security Templates
- **Login Alert**: "New login detected on your account"
- **Password Changed**: "Your password has been changed"
- **Suspicious Activity**: "Suspicious activity detected"

## Testing

### Manual Testing
1. **Email Delivery**: Send test emails to verify SMTP configuration
2. **SMS Delivery**: Test SMS with opt-in/opt-out keywords
3. **Push Notifications**: Test device registration and message delivery
4. **Template Rendering**: Verify all templates render correctly
5. **Database Integration**: Confirm audit logs are created

### API Testing
```bash
# Test notification preferences
curl -X GET /notifications/preferences \
  -H "Authorization: Bearer YOUR_TOKEN"

# Send test notification
curl -X POST /notifications/test \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel": "email", "test_type": "basic"}'
```

## Security Features

### PHI Protection
- Push notifications contain no PHI (summary only)
- Email encryption for sensitive content
- Secure links for PHI content with expiration
- Audit logging for all notifications

### Compliance
- Patient consent verification
- SMS opt-in/opt-out tracking
- HIPAA-compliant audit trails
- Rate limiting to prevent spam

### Access Control
- Role-based access to notification APIs
- User can only access their own preferences/history
- Admin/provider roles for system notifications

## Integration Points

### Existing Systems
- **Authentication**: Uses existing JWT authentication
- **Database**: Integrates with existing user and audit models
- **Role-Based Access**: Uses existing role system
- **Rate Limiting**: Integrates with existing rate limiting

### Audit Integration
- All notifications logged in `audit_logs` table
- Notification history in `notification_history` table
- SMS consent tracked in `sms_opt_in_out` table

## Next Steps (Phase 4B)

The next phase will add:
- HIPAA compliance automation
- Breach detection and notification
- Advanced analytics and reporting
- Automated compliance monitoring
- Enhanced security features

## Support

For questions about the notification system:
- Technical issues: Check logs in `notification_history` and `audit_logs`
- Configuration: Review environment variables and config files
- Testing: Use the test endpoints to verify functionality 
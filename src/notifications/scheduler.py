"""
Healthcare Notification Scheduler

Handles scheduled notifications for appointments, reminders, and
recurring healthcare tasks with timezone support.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta, time
from enum import Enum
import pytz
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger

from .notification_manager import NotificationManager, NotificationType
from ..database.models import (
    ScheduledNotification,
    RecurringNotification,
    User,
    NotificationPreference
)
from ..database.database import SessionLocal
from config.notification_config import SchedulerConfig

logger = logging.getLogger(__name__)


class ScheduleType(Enum):
    """Types of notification schedules"""
    ONCE = "once"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM_CRON = "custom_cron"
    INTERVAL = "interval"


class NotificationScheduler:
    """Manages scheduled and recurring notifications"""
    
    def __init__(self):
        self.config = SchedulerConfig()
        self.notification_manager = NotificationManager()
        
        # Initialize scheduler
        self.scheduler = AsyncIOScheduler(
            timezone=pytz.UTC,
            job_defaults={
                'coalesce': True,
                'max_instances': 3,
                'misfire_grace_time': 300  # 5 minutes
            }
        )
        
        # Start scheduler
        self.scheduler.start()
        logger.info("Notification scheduler started")
        
        # Load existing schedules
        asyncio.create_task(self._load_existing_schedules())
    
    async def schedule_notification(
        self,
        user_id: int,
        notification_type: Union[str, NotificationType],
        schedule_type: Union[str, ScheduleType],
        scheduled_time: datetime,
        data: Dict[str, Any],
        timezone: str = "UTC",
        recurring_data: Optional[Dict[str, Any]] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Schedule a notification
        
        Args:
            user_id: Target user ID
            notification_type: Type of notification
            schedule_type: Type of schedule
            scheduled_time: When to send (for ONCE) or start time (for recurring)
            data: Notification data
            timezone: User's timezone
            recurring_data: Data for recurring schedules
            end_date: End date for recurring schedules
        
        Returns:
            Schedule creation result
        """
        try:
            # Convert to enum if needed
            if isinstance(schedule_type, str):
                schedule_type = ScheduleType(schedule_type)
            if isinstance(notification_type, str):
                notification_type = NotificationType(notification_type)
            
            # Validate timezone
            try:
                tz = pytz.timezone(timezone)
            except pytz.UnknownTimeZoneError:
                return {
                    "success": False,
                    "message": f"Unknown timezone: {timezone}"
                }
            
            # Convert scheduled time to UTC
            if scheduled_time.tzinfo is None:
                scheduled_time = tz.localize(scheduled_time)
            scheduled_time_utc = scheduled_time.astimezone(pytz.UTC)
            
            # Create database record
            if schedule_type == ScheduleType.ONCE:
                schedule_record = await self._create_one_time_schedule(
                    user_id=user_id,
                    notification_type=notification_type,
                    scheduled_time=scheduled_time_utc,
                    data=data
                )
            else:
                schedule_record = await self._create_recurring_schedule(
                    user_id=user_id,
                    notification_type=notification_type,
                    schedule_type=schedule_type,
                    start_time=scheduled_time_utc,
                    data=data,
                    recurring_data=recurring_data,
                    end_date=end_date,
                    timezone=timezone
                )
            
            # Add job to scheduler
            job = await self._add_scheduler_job(
                schedule_record=schedule_record,
                schedule_type=schedule_type,
                scheduled_time=scheduled_time_utc,
                recurring_data=recurring_data,
                timezone=tz
            )
            
            return {
                "success": True,
                "message": "Notification scheduled successfully",
                "schedule_id": schedule_record.id,
                "job_id": job.id,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None
            }
            
        except Exception as e:
            logger.error(f"Schedule error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to schedule notification: {str(e)}"
            }
    
    async def _create_one_time_schedule(
        self,
        user_id: int,
        notification_type: NotificationType,
        scheduled_time: datetime,
        data: Dict[str, Any]
    ) -> ScheduledNotification:
        """Create one-time schedule record"""
        schedule = ScheduledNotification(
            user_id=user_id,
            notification_type=notification_type.value,
            scheduled_time=scheduled_time,
            status='pending',
            data=json.dumps(data),
            created_at=datetime.utcnow()
        )
        db_session.add(schedule)
        db_session.commit()
        return schedule
    
    async def _create_recurring_schedule(
        self,
        user_id: int,
        notification_type: NotificationType,
        schedule_type: ScheduleType,
        start_time: datetime,
        data: Dict[str, Any],
        recurring_data: Optional[Dict[str, Any]],
        end_date: Optional[datetime],
        timezone: str
    ) -> RecurringNotification:
        """Create recurring schedule record"""
        schedule = RecurringNotification(
            user_id=user_id,
            notification_type=notification_type.value,
            schedule_type=schedule_type.value,
            cron_expression=recurring_data.get('cron') if schedule_type == ScheduleType.CUSTOM_CRON else None,
            interval_seconds=recurring_data.get('interval_seconds') if schedule_type == ScheduleType.INTERVAL else None,
            start_time=start_time,
            end_time=end_date,
            timezone=timezone,
            is_active=True,
            data=json.dumps(data),
            last_run=None,
            next_run=start_time,
            created_at=datetime.utcnow()
        )
        db_session.add(schedule)
        db_session.commit()
        return schedule
    
    async def _add_scheduler_job(
        self,
        schedule_record: Union[ScheduledNotification, RecurringNotification],
        schedule_type: ScheduleType,
        scheduled_time: datetime,
        recurring_data: Optional[Dict[str, Any]],
        timezone: pytz.timezone
    ):
        """Add job to APScheduler"""
        job_id = f"{schedule_type.value}_{schedule_record.id}"
        
        if schedule_type == ScheduleType.ONCE:
            trigger = DateTrigger(
                run_date=scheduled_time,
                timezone=timezone
            )
        elif schedule_type == ScheduleType.DAILY:
            trigger = CronTrigger(
                hour=scheduled_time.hour,
                minute=scheduled_time.minute,
                timezone=timezone
            )
        elif schedule_type == ScheduleType.WEEKLY:
            day_of_week = recurring_data.get('day_of_week', scheduled_time.weekday())
            trigger = CronTrigger(
                day_of_week=day_of_week,
                hour=scheduled_time.hour,
                minute=scheduled_time.minute,
                timezone=timezone
            )
        elif schedule_type == ScheduleType.MONTHLY:
            day = recurring_data.get('day_of_month', scheduled_time.day)
            trigger = CronTrigger(
                day=day,
                hour=scheduled_time.hour,
                minute=scheduled_time.minute,
                timezone=timezone
            )
        elif schedule_type == ScheduleType.CUSTOM_CRON:
            trigger = CronTrigger.from_crontab(
                recurring_data.get('cron', '0 9 * * *'),
                timezone=timezone
            )
        elif schedule_type == ScheduleType.INTERVAL:
            trigger = IntervalTrigger(
                seconds=recurring_data.get('interval_seconds', 3600),
                start_date=scheduled_time,
                timezone=timezone
            )
        else:
            raise ValueError(f"Unknown schedule type: {schedule_type}")
        
        # Add job
        job = self.scheduler.add_job(
            func=self._execute_scheduled_notification,
            trigger=trigger,
            id=job_id,
            args=[schedule_record.id, schedule_type.value],
            replace_existing=True,
            misfire_grace_time=300
        )
        
        return job
    
    async def _execute_scheduled_notification(
        self,
        schedule_id: int,
        schedule_type_str: str
    ):
        """Execute a scheduled notification"""
        try:
            schedule_type = ScheduleType(schedule_type_str)
            
            if schedule_type == ScheduleType.ONCE:
                # Get one-time schedule
                schedule = db_session.query(ScheduledNotification).get(schedule_id)
                if not schedule or schedule.status != 'pending':
                    return
                
                # Send notification
                data = json.loads(schedule.data)
                result = await self.notification_manager.send_notification(
                    user_id=schedule.user_id,
                    notification_type=schedule.notification_type,
                    data=data
                )
                
                # Update status
                schedule.status = 'sent' if result['success'] else 'failed'
                schedule.sent_at = datetime.utcnow()
                schedule.result = json.dumps(result)
                db_session.commit()
                
            else:
                # Get recurring schedule
                schedule = db_session.query(RecurringNotification).get(schedule_id)
                if not schedule or not schedule.is_active:
                    return
                
                # Check end date
                if schedule.end_time and datetime.utcnow() > schedule.end_time:
                    schedule.is_active = False
                    db_session.commit()
                    # Remove job from scheduler
                    self.scheduler.remove_job(f"{schedule_type_str}_{schedule_id}")
                    return
                
                # Send notification
                data = json.loads(schedule.data)
                result = await self.notification_manager.send_notification(
                    user_id=schedule.user_id,
                    notification_type=schedule.notification_type,
                    data=data
                )
                
                # Update last run time
                schedule.last_run = datetime.utcnow()
                schedule.run_count = (schedule.run_count or 0) + 1
                
                # Calculate next run time
                job = self.scheduler.get_job(f"{schedule_type_str}_{schedule_id}")
                if job:
                    schedule.next_run = job.next_run_time
                
                db_session.commit()
                
        except Exception as e:
            logger.error(f"Error executing scheduled notification: {str(e)}")
    
    async def cancel_scheduled_notification(
        self,
        schedule_id: int,
        schedule_type: Union[str, ScheduleType]
    ) -> Dict[str, Any]:
        """Cancel a scheduled notification"""
        try:
            if isinstance(schedule_type, str):
                schedule_type = ScheduleType(schedule_type)
            
            job_id = f"{schedule_type.value}_{schedule_id}"
            
            # Remove from scheduler
            self.scheduler.remove_job(job_id)
            
            # Update database
            if schedule_type == ScheduleType.ONCE:
                schedule = db_session.query(ScheduledNotification).get(schedule_id)
                if schedule:
                    schedule.status = 'cancelled'
                    schedule.cancelled_at = datetime.utcnow()
            else:
                schedule = db_session.query(RecurringNotification).get(schedule_id)
                if schedule:
                    schedule.is_active = False
                    schedule.cancelled_at = datetime.utcnow()
            
            db_session.commit()
            
            return {
                "success": True,
                "message": "Scheduled notification cancelled"
            }
            
        except Exception as e:
            logger.error(f"Error cancelling schedule: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to cancel: {str(e)}"
            }
    
    async def update_scheduled_notification(
        self,
        schedule_id: int,
        schedule_type: Union[str, ScheduleType],
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a scheduled notification"""
        try:
            if isinstance(schedule_type, str):
                schedule_type = ScheduleType(schedule_type)
            
            # Get existing schedule
            if schedule_type == ScheduleType.ONCE:
                schedule = db_session.query(ScheduledNotification).get(schedule_id)
            else:
                schedule = db_session.query(RecurringNotification).get(schedule_id)
            
            if not schedule:
                return {
                    "success": False,
                    "message": "Schedule not found"
                }
            
            # Update fields
            if 'scheduled_time' in updates:
                new_time = updates['scheduled_time']
                if isinstance(new_time, str):
                    new_time = datetime.fromisoformat(new_time)
                
                if schedule_type == ScheduleType.ONCE:
                    schedule.scheduled_time = new_time
                else:
                    schedule.start_time = new_time
            
            if 'data' in updates:
                schedule.data = json.dumps(updates['data'])
            
            if 'is_active' in updates and schedule_type != ScheduleType.ONCE:
                schedule.is_active = updates['is_active']
            
            db_session.commit()
            
            # Reschedule job
            job_id = f"{schedule_type.value}_{schedule_id}"
            self.scheduler.remove_job(job_id)
            
            if schedule_type == ScheduleType.ONCE and schedule.status == 'pending':
                await self._add_scheduler_job(
                    schedule_record=schedule,
                    schedule_type=schedule_type,
                    scheduled_time=schedule.scheduled_time,
                    recurring_data=None,
                    timezone=pytz.timezone('UTC')
                )
            elif schedule_type != ScheduleType.ONCE and schedule.is_active:
                await self._add_scheduler_job(
                    schedule_record=schedule,
                    schedule_type=schedule_type,
                    scheduled_time=schedule.start_time,
                    recurring_data=json.loads(schedule.data) if schedule.data else {},
                    timezone=pytz.timezone(schedule.timezone)
                )
            
            return {
                "success": True,
                "message": "Schedule updated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error updating schedule: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to update: {str(e)}"
            }
    
    async def get_user_schedules(
        self,
        user_id: int,
        include_inactive: bool = False
    ) -> List[Dict[str, Any]]:
        """Get all schedules for a user"""
        schedules = []
        
        # Get one-time schedules
        query = db_session.query(ScheduledNotification).filter_by(user_id=user_id)
        if not include_inactive:
            query = query.filter_by(status='pending')
        
        one_time = query.all()
        for schedule in one_time:
            schedules.append({
                "id": schedule.id,
                "type": "once",
                "notification_type": schedule.notification_type,
                "scheduled_time": schedule.scheduled_time.isoformat(),
                "status": schedule.status,
                "data": json.loads(schedule.data) if schedule.data else {}
            })
        
        # Get recurring schedules
        query = db_session.query(RecurringNotification).filter_by(user_id=user_id)
        if not include_inactive:
            query = query.filter_by(is_active=True)
        
        recurring = query.all()
        for schedule in recurring:
            schedules.append({
                "id": schedule.id,
                "type": schedule.schedule_type,
                "notification_type": schedule.notification_type,
                "start_time": schedule.start_time.isoformat(),
                "end_time": schedule.end_time.isoformat() if schedule.end_time else None,
                "timezone": schedule.timezone,
                "is_active": schedule.is_active,
                "last_run": schedule.last_run.isoformat() if schedule.last_run else None,
                "next_run": schedule.next_run.isoformat() if schedule.next_run else None,
                "run_count": schedule.run_count,
                "data": json.loads(schedule.data) if schedule.data else {}
            })
        
        return schedules
    
    async def _load_existing_schedules(self):
        """Load existing schedules from database on startup"""
        try:
            # Load pending one-time schedules
            one_time_schedules = db_session.query(ScheduledNotification).filter_by(
                status='pending'
            ).filter(
                ScheduledNotification.scheduled_time > datetime.utcnow()
            ).all()
            
            for schedule in one_time_schedules:
                await self._add_scheduler_job(
                    schedule_record=schedule,
                    schedule_type=ScheduleType.ONCE,
                    scheduled_time=schedule.scheduled_time,
                    recurring_data=None,
                    timezone=pytz.UTC
                )
            
            # Load active recurring schedules
            recurring_schedules = db_session.query(RecurringNotification).filter_by(
                is_active=True
            ).all()
            
            for schedule in recurring_schedules:
                schedule_type = ScheduleType(schedule.schedule_type)
                recurring_data = json.loads(schedule.data) if schedule.data else {}
                
                await self._add_scheduler_job(
                    schedule_record=schedule,
                    schedule_type=schedule_type,
                    scheduled_time=schedule.start_time,
                    recurring_data=recurring_data,
                    timezone=pytz.timezone(schedule.timezone)
                )
            
            logger.info(f"Loaded {len(one_time_schedules)} one-time and {len(recurring_schedules)} recurring schedules")
            
        except Exception as e:
            logger.error(f"Error loading existing schedules: {str(e)}")
    
    async def schedule_recording_reminders(
        self,
        user_id: int,
        reminder_times: List[time],
        timezone: str = "UTC"
    ) -> Dict[str, Any]:
        """Schedule daily recording reminders for a user"""
        try:
            results = []
            
            for reminder_time in reminder_times:
                # Create datetime for today at the specified time
                today = datetime.now(pytz.timezone(timezone)).date()
                reminder_datetime = datetime.combine(today, reminder_time)
                
                result = await self.schedule_notification(
                    user_id=user_id,
                    notification_type=NotificationType.RECORDING_REMINDER,
                    schedule_type=ScheduleType.DAILY,
                    scheduled_time=reminder_datetime,
                    data={
                        "reminder_type": "daily_recording",
                        "message": "Time for your daily voice recording"
                    },
                    timezone=timezone
                )
                
                results.append(result)
            
            return {
                "success": all(r["success"] for r in results),
                "message": f"Scheduled {len(results)} daily reminders",
                "reminders": results
            }
            
        except Exception as e:
            logger.error(f"Error scheduling recording reminders: {str(e)}")
            return {
                "success": False,
                "message": str(e)
            }
    
    async def schedule_appointment_reminder(
        self,
        user_id: int,
        appointment_time: datetime,
        provider_name: str,
        appointment_type: str,
        reminder_intervals: List[int] = [24, 2]  # Hours before appointment
    ) -> Dict[str, Any]:
        """Schedule appointment reminders"""
        try:
            results = []
            
            for hours_before in reminder_intervals:
                reminder_time = appointment_time - timedelta(hours=hours_before)
                
                # Skip if reminder time is in the past
                if reminder_time < datetime.utcnow():
                    continue
                
                result = await self.schedule_notification(
                    user_id=user_id,
                    notification_type=NotificationType.APPOINTMENT_REMINDER,
                    schedule_type=ScheduleType.ONCE,
                    scheduled_time=reminder_time,
                    data={
                        "appointment_time": appointment_time.isoformat(),
                        "provider_name": provider_name,
                        "appointment_type": appointment_type,
                        "hours_before": hours_before
                    }
                )
                
                results.append(result)
            
            return {
                "success": all(r["success"] for r in results),
                "message": f"Scheduled {len(results)} appointment reminders",
                "reminders": results
            }
            
        except Exception as e:
            logger.error(f"Error scheduling appointment reminders: {str(e)}")
            return {
                "success": False,
                "message": str(e)
            }
    
    def get_scheduler_status(self) -> Dict[str, Any]:
        """Get scheduler status and statistics"""
        jobs = self.scheduler.get_jobs()
        
        return {
            "scheduler_running": self.scheduler.running,
            "total_jobs": len(jobs),
            "jobs": [
                {
                    "id": job.id,
                    "name": job.name,
                    "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                    "trigger": str(job.trigger)
                }
                for job in jobs
            ]
        }
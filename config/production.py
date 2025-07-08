"""Production configuration overrides."""

import os
from typing import List

# Security settings for production
SECURE_COOKIES = True
SAMESITE_COOKIES = "strict"
CORS_ORIGINS: List[str] = [
    "https://app.voicebiomarker.com",
    "https://www.voicebiomarker.com"
]

# Stricter rate limiting in production
RATE_LIMIT_REQUESTS_PER_MINUTE = 60
MAX_LOGIN_ATTEMPTS = 3

# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "json": {
            "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "json",
            "stream": "ext://sys.stdout"
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "json",
            "filename": "/var/log/voice-biomarker/error.log",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5
        }
    },
    "loggers": {
        "": {
            "level": "INFO",
            "handlers": ["console", "error_file"]
        },
        "uvicorn.access": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False
        },
        "sqlalchemy.engine": {
            "level": "WARNING"
        }
    }
}

# Performance settings
DB_POOL_SIZE = 20
DB_MAX_OVERFLOW = 30
DB_POOL_TIMEOUT = 30
DB_POOL_RECYCLE = 1800  # 30 minutes

# Security headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://api.voicebiomarker.com; "
        "frame-ancestors 'none';"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "geolocation=(), microphone=(), camera=(), "
        "payment=(), usb=(), magnetometer=(), "
        "accelerometer=(), gyroscope=()"
    )
}

# AWS settings
USE_SECRETS_MANAGER = True
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")

# Monitoring
ENABLE_PROMETHEUS = True
ENABLE_CLOUDWATCH = True
CLOUDWATCH_LOG_GROUP = "/aws/ecs/voice-biomarker/user-management"
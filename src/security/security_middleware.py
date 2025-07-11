"""Security middleware for request validation and protection."""

import logging
import uuid
import time
from typing import Optional, Callable

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config.security_config import security_config
from config.auth_settings import auth_settings

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for all requests."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process each request with security checks."""
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Start timing
        start_time = time.time()
        
        # Add security headers to request processing
        request.state.start_time = start_time
        
        try:
            # Validate request
            await self._validate_request(request)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            response = self._add_security_headers(response, request_id)
            
            # Log request
            process_time = time.time() - start_time
            await self._log_request(request, response, process_time)
            
            return response
            
        except HTTPException as e:
            # Re-raise HTTP exceptions
            raise e
        except Exception as e:
            # Log unexpected errors
            logger.error(f"Request {request_id} failed: {e}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
                headers={"X-Request-ID": request_id}
            )
    
    async def _validate_request(self, request: Request) -> None:
        """Validate incoming request for security issues."""
        # Check IP whitelist if enabled
        if security_config.enable_ip_whitelist and security_config.ip_whitelist:
            client_ip = request.client.host if request.client else None
            if client_ip and client_ip not in security_config.ip_whitelist:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied"
                )
        
        # Validate content type for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if not content_type:
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Content-Type header required"
                )
        
        # Check for suspicious patterns in URL
        if self._has_suspicious_pattern(str(request.url)):
            logger.warning(f"Suspicious URL pattern detected: {request.url}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid request"
            )
    
    def _has_suspicious_pattern(self, url: str) -> bool:
        """Check for suspicious patterns in URL."""
        suspicious_patterns = [
            "../",  # Path traversal
            "..\\",  # Path traversal (Windows)
            "<script",  # XSS attempt
            "javascript:",  # XSS attempt
            "data:text/html",  # Data URL XSS
            "vbscript:",  # VBScript injection
            "onload=",  # Event handler injection
            "onerror=",  # Event handler injection
            "%00",  # Null byte injection
            "%0d%0a",  # CRLF injection
            "union select",  # SQL injection
            "' or '1'='1",  # SQL injection
        ]
        
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in suspicious_patterns)
    
    def _add_security_headers(self, response: Response, request_id: str) -> Response:
        """Add security headers to response."""
        # Request ID for tracking
        response.headers["X-Request-ID"] = request_id
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # Strict Transport Security (if HTTPS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), "
            "accelerometer=(), gyroscope=()"
        )
        
        return response
    
    async def _log_request(
        self,
        request: Request,
        response: Response,
        process_time: float
    ) -> None:
        """Log request details for monitoring."""
        # Skip logging for health checks
        if request.url.path in ["/health", "/health/live", "/health/ready"]:
            return
        
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        log_data = {
            "request_id": request.state.request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "process_time": round(process_time * 1000, 2),  # milliseconds
        }
        
        # Log at appropriate level
        if response.status_code >= 500:
            logger.error(f"Request failed: {log_data}")
        elif response.status_code >= 400:
            logger.warning(f"Request error: {log_data}")
        else:
            logger.info(f"Request completed: {log_data}")


def add_security_headers(response: Response) -> Response:
    """
    Add security headers to a response.
    
    Args:
        response: FastAPI response object
        
    Returns:
        Response with security headers
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response


async def validate_request_origin(
    request: Request,
    allowed_origins: Optional[list[str]] = None
) -> bool:
    """
    Validate request origin for CORS security.
    
    Args:
        request: FastAPI request
        allowed_origins: List of allowed origins
        
    Returns:
        True if origin is valid
    """
    if allowed_origins is None:
        allowed_origins = auth_settings.cors_origins
    
    origin = request.headers.get("origin")
    if not origin:
        # No origin header, could be same-origin request
        return True
    
    return origin in allowed_origins


class SQLInjectionProtection:
    """SQL injection protection utilities."""
    
    @staticmethod
    def validate_identifier(identifier: str) -> bool:
        """
        Validate database identifier (table/column name).
        
        Args:
            identifier: Identifier to validate
            
        Returns:
            True if valid
        """
        # Only allow alphanumeric and underscore
        import re
        return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', identifier))
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """
        Sanitize string for database queries.
        
        Args:
            value: String to sanitize
            
        Returns:
            Sanitized string
        """
        # This is a basic implementation
        # In practice, use parameterized queries instead
        return value.replace("'", "''").replace("\\", "\\\\")


class XSSProtection:
    """XSS protection utilities."""
    
    @staticmethod
    def sanitize_html(html: str) -> str:
        """
        Sanitize HTML content.
        
        Args:
            html: HTML to sanitize
            
        Returns:
            Sanitized HTML
        """
        import html
        return html.escape(html)
    
    @staticmethod
    def validate_json_input(data: dict) -> dict:
        """
        Validate and sanitize JSON input.
        
        Args:
            data: JSON data to validate
            
        Returns:
            Sanitized data
        """
        import html
        
        def sanitize_value(value):
            if isinstance(value, str):
                return html.escape(value)
            elif isinstance(value, dict):
                return {k: sanitize_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value(item) for item in value]
            else:
                return value
        
        return sanitize_value(data)
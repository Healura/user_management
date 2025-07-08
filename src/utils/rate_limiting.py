import logging
import time
from typing import Optional, Dict, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

import redis
from fastapi import HTTPException, Request, status

from config.auth_settings import auth_settings

logger = logging.getLogger(__name__)


class RateLimitExceeded(HTTPException):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(self, retry_after: int):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)}
        )


class RateLimiter:
    """Rate limiter with Redis support and in-memory fallback."""
    
    def __init__(self):
        self.redis_client = self._init_redis()
        # In-memory fallback storage
        self.memory_store: Dict[str, list[float]] = defaultdict(list)
        self.memory_lock = asyncio.Lock()
    
    def _init_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis client if available."""
        if auth_settings.redis_url:
            try:
                client = redis.from_url(
                    auth_settings.redis_url,
                    decode_responses=True
                )
                client.ping()
                logger.info("Redis connection established for rate limiting")
                return client
            except Exception as e:
                logger.warning(f"Redis connection failed, using memory store: {e}")
        return None
    
    async def check_user_rate_limit(
    user_id: str,
    max_requests: Optional[int] = None,
    window_seconds: Optional[int] = None
) -> None:
    """
    Check rate limit for a specific user.
    
    Args:
        user_id: User ID
        max_requests: Maximum requests
        window_seconds: Time window
        
    Raises:
        RateLimitExceeded: If rate limit exceeded
    """
    if max_requests is None:
        max_requests = auth_settings.rate_limit_requests_per_minute
    if window_seconds is None:
        window_seconds = 60
    
    key = f"user_rate_limit:{user_id}"
    is_allowed, retry_after = await _rate_limiter.check_rate_limit(
        key, max_requests, window_seconds
    )
    
    if not is_allowed:
        raise RateLimitExceeded(retry_after) check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, int]:
        """
        Check if rate limit is exceeded.
        
        Args:
            key: Rate limit key (e.g., user_id or IP)
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        if self.redis_client:
            return self._check_redis(key, max_requests, window_seconds)
        else:
            return await self._check_memory(key, max_requests, window_seconds)
    
    def _check_redis(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, int]:
        """Check rate limit using Redis."""
        try:
            pipeline = self.redis_client.pipeline()
            now = time.time()
            window_start = now - window_seconds
            
            # Remove old entries
            pipeline.zremrangebyscore(key, 0, window_start)
            # Count requests in window
            pipeline.zcard(key)
            # Add current request
            pipeline.zadd(key, {str(now): now})
            # Set expiry
            pipeline.expire(key, window_seconds + 1)
            
            results = pipeline.execute()
            request_count = results[1]
            
            if request_count >= max_requests:
                # Get oldest request time to calculate retry_after
                oldest = self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest:
                    oldest_time = oldest[0][1]
                    retry_after = int(oldest_time + window_seconds - now) + 1
                    return False, retry_after
            
            return True, 0
            
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fallback to allowing request on Redis error
            return True, 0
    
    async def _check_memory(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, int]:
        """Check rate limit using in-memory storage."""
        async with self.memory_lock:
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old entries
            self.memory_store[key] = [
                req_time for req_time in self.memory_store[key]
                if req_time > window_start
            ]
            
            # Check limit
            if len(self.memory_store[key]) >= max_requests:
                oldest_time = min(self.memory_store[key])
                retry_after = int(oldest_time + window_seconds - now) + 1
                return False, retry_after
            
            # Add current request
            self.memory_store[key].append(now)
            return True, 0
    
    async def reset_limit(self, key: str) -> None:
        """Reset rate limit for a key."""
        if self.redis_client:
            self.redis_client.delete(key)
        else:
            async with self.memory_lock:
                self.memory_store.pop(key, None)


# Global rate limiter instance
_rate_limiter = RateLimiter()


async def check_rate_limit(
    request: Request,
    max_requests: Optional[int] = None,
    window_seconds: Optional[int] = None,
    key_prefix: str = "rate_limit"
) -> None:
    """
    Check rate limit for the current request.
    
    Args:
        request: FastAPI request object
        max_requests: Maximum requests (default from settings)
        window_seconds: Time window in seconds
        key_prefix: Prefix for rate limit key
        
    Raises:
        RateLimitExceeded: If rate limit is exceeded
    """
    if max_requests is None:
        max_requests = auth_settings.rate_limit_requests_per_minute
    if window_seconds is None:
        window_seconds = 60  # 1 minute default
    
    # Use IP address as key
    client_ip = request.client.host if request.client else "unknown"
    key = f"{key_prefix}:{client_ip}"
    
    is_allowed, retry_after = await _rate_limiter.check_rate_limit(
        key, max_requests, window_seconds
    )
    
    if not is_allowed:
        raise RateLimitExceeded(retry_after)


def rate_limit(
    max_requests: Optional[int] = None,
    window_seconds: Optional[int] = None,
    key_prefix: str = "rate_limit"
):
    """
    Decorator for rate limiting endpoints.
    
    Args:
        max_requests: Maximum requests allowed
        window_seconds: Time window in seconds
        key_prefix: Prefix for rate limit key
        
    Usage:
        @router.get("/")
        @rate_limit(max_requests=10, window_seconds=60)
        async def my_endpoint():
            ...
    """
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            await check_rate_limit(
                request,
                max_requests=max_requests,
                window_seconds=window_seconds,
                key_prefix=key_prefix
            )
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator


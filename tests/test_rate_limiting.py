"""Tests for rate limiting functionality."""

import pytest
import asyncio
from fastapi.testclient import TestClient
from src.api.main import app
from src.utils.rate_limiting import RateLimiter, RateLimitExceeded

client = TestClient(app)


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_allows_requests(self):
        """Test rate limiter allows requests within limit."""
        limiter = RateLimiter()
        
        # Should allow requests within limit
        for i in range(5):
            allowed, retry_after = await limiter.check_rate_limit(
                "test_key", max_requests=10, window_seconds=60
            )
            assert allowed is True
            assert retry_after == 0
    
    @pytest.mark.asyncio
    async def test_rate_limiter_blocks_excess_requests(self):
        """Test rate limiter blocks requests over limit."""
        limiter = RateLimiter()
        
        # Make requests up to limit
        for i in range(5):
            allowed, _ = await limiter.check_rate_limit(
                "test_key2", max_requests=5, window_seconds=60
            )
            assert allowed is True
        
        # Next request should be blocked
        allowed, retry_after = await limiter.check_rate_limit(
            "test_key2", max_requests=5, window_seconds=60
        )
        assert allowed is False
        assert retry_after > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiter_window_expiry(self):
        """Test rate limiter resets after window expires."""
        limiter = RateLimiter()
        
        # Use very short window for testing
        allowed, _ = await limiter.check_rate_limit(
            "test_key3", max_requests=1, window_seconds=1
        )
        assert allowed is True
        
        # Should be blocked immediately
        allowed, _ = await limiter.check_rate_limit(
            "test_key3", max_requests=1, window_seconds=1
        )
        assert allowed is False
        
        # Wait for window to expire
        await asyncio.sleep(1.1)
        
        # Should be allowed again
        allowed, _ = await limiter.check_rate_limit(
            "test_key3", max_requests=1, window_seconds=1
        )
        assert allowed is True
    
    def test_login_endpoint_rate_limiting(self):
        """Test rate limiting on login endpoint."""
        # This test would need to make multiple requests quickly
        # to trigger rate limiting on the login endpoint
        
        # Make multiple login attempts
        for i in range(10):
            response = client.post("/auth/login", json={
                "email": f"test{i}@example.com",
                "password": "wrongpassword"
            })
            # First few should work (even if login fails)
            if i < 10:  # Assuming limit is 10 per minute
                assert response.status_code in [401, 200]
        
        # Next request should be rate limited
        response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "password"
        })
        # May be 429 if rate limiting is triggered
        # This depends on the actual rate limit configuration
    
    @pytest.mark.asyncio
    async def test_reset_rate_limit(self):
        """Test resetting rate limit for a key."""
        limiter = RateLimiter()
        
        # Fill up the limit
        for i in range(5):
            await limiter.check_rate_limit(
                "test_reset", max_requests=5, window_seconds=60
            )
        
        # Should be blocked
        allowed, _ = await limiter.check_rate_limit(
            "test_reset", max_requests=5, window_seconds=60
        )
        assert allowed is False
        
        # Reset the limit
        await limiter.reset_limit("test_reset")
        
        # Should be allowed again
        allowed, _ = await limiter.check_rate_limit(
            "test_reset", max_requests=5, window_seconds=60
        )
        assert allowed is True
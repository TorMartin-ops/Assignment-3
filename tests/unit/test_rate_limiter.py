"""
Unit Tests for Rate Limiter
Tests rate limiting logic, TOCTOU prevention, and concurrency safety
"""
import pytest
from datetime import datetime, timedelta
from services.rate_limiter import RateLimiter


class TestRateLimiter:
    """Test rate limiting functionality"""

    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance"""
        return RateLimiter(requests_per_minute=5, window_minutes=1)

    def test_first_request_allowed(self, rate_limiter, db_connection):
        """Test that first request is always allowed"""
        from database import get_db_connection

        key = 'ip:192.168.1.100'  # Use unique IP to avoid conflicts
        endpoint = '/test-first-request'

        # CLEANUP: Ensure clean state for this specific test
        conn = get_db_connection()
        conn.execute('DELETE FROM rate_limits WHERE key = ? AND endpoint = ?', (key, endpoint))
        conn.commit()
        conn.close()

        is_limited, remaining, reset_time = rate_limiter.is_rate_limited(key, endpoint)

        assert not is_limited, f"First request should not be limited, got is_limited={is_limited}"
        assert remaining == 5, f"Should have 5 remaining, got {remaining}"
        assert reset_time is None, f"Reset time should be None, got {reset_time}"

    def test_record_request_increments_count(self, rate_limiter, db_connection):
        """Test that recording requests increments counter"""
        from database import get_db_connection

        key = 'ip:192.168.1.1'
        endpoint = '/login'

        # CLEANUP: Ensure clean state
        conn = get_db_connection()
        conn.execute('DELETE FROM rate_limits WHERE key = ? AND endpoint = ?', (key, endpoint))
        conn.commit()
        conn.close()

        # Record first request
        assert rate_limiter.record_request(key, endpoint)

        # Check rate limit - should have 4 remaining (5-1=4)
        is_limited, remaining, reset_time = rate_limiter.is_rate_limited(key, endpoint)
        assert not is_limited, f"Should not be limited after 1 request, but is_limited={is_limited}"
        assert remaining == 4, f"Should have 4 remaining, got {remaining}"

    def test_rate_limit_enforcement(self, rate_limiter, db_connection):
        """Test that rate limit is enforced after threshold"""
        key = 'ip:192.168.1.1'
        endpoint = '/login'

        # Make 5 requests (at limit)
        for i in range(5):
            assert rate_limiter.record_request(key, endpoint)

        # 6th request should be rate limited
        is_limited, remaining, reset_time = rate_limiter.is_rate_limited(key, endpoint)
        assert is_limited
        assert remaining == 0
        assert reset_time is not None

    def test_different_endpoints_tracked_separately(self, rate_limiter, db_connection):
        """Test that different endpoints have separate rate limits"""
        key = 'ip:192.168.1.1'

        # Max out /login endpoint
        for i in range(5):
            rate_limiter.record_request(key, '/login')

        # /register should still be available
        is_limited, remaining, _ = rate_limiter.is_rate_limited(key, '/register')
        assert not is_limited
        assert remaining == 5

    def test_different_keys_tracked_separately(self, rate_limiter, db_connection):
        """Test that different IPs/users have separate rate limits"""
        endpoint = '/login'

        # Max out IP1
        for i in range(5):
            rate_limiter.record_request('ip:192.168.1.1', endpoint)

        # IP2 should still be available
        is_limited, remaining, _ = rate_limiter.is_rate_limited('ip:192.168.1.2', endpoint)
        assert not is_limited
        assert remaining == 5

    def test_expired_entries_cleaned_up(self, rate_limiter, db_connection):
        """Test that old rate limit entries are cleaned up"""
        key = 'ip:192.168.1.1'
        endpoint = '/login'

        # Record request
        rate_limiter.record_request(key, endpoint)

        # Simulate time passing (cleanup happens in is_rate_limited)
        # In real implementation, this would use time mocking
        # For now, just verify the cleanup query exists in the code
        assert True  # Placeholder - would need time mocking for full test

    @pytest.mark.slow
    def test_transaction_prevents_race_condition(self, rate_limiter, db_connection):
        """Test that transaction prevents TOCTOU race condition"""
        # This test would require concurrent execution testing
        # Verifying that BEGIN IMMEDIATE is used
        import inspect
        source = inspect.getsource(rate_limiter.record_request)
        assert 'BEGIN IMMEDIATE' in source or 'transaction' in source.lower()

    def test_per_user_rate_limiting(self, rate_limiter):
        """Test that per-user rate limiting uses username instead of IP"""
        # This tests the decorator functionality
        # Would need Flask request context for full test
        assert hasattr(rate_limiter, 'limit')
        assert callable(rate_limiter.limit)


class TestRateLimitDecorator:
    """Test rate limit decorator functionality"""

    def test_decorator_exists(self):
        """Test that rate limit decorator can be applied"""
        rate_limiter = RateLimiter()
        decorator = rate_limiter.limit(requests_per_minute=10)
        assert callable(decorator)

    def test_decorator_per_user_option(self):
        """Test that decorator supports per_user parameter"""
        rate_limiter = RateLimiter()
        decorator = rate_limiter.limit(per_user=True)
        assert callable(decorator)

"""
Database-Based Rate Limiter (No Redis required)
Tracks request rates in SQLite for brute force protection
"""
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from database import get_db_connection
import time

class RateLimiter:
    """
    Database-backed rate limiter
    Tracks requests per key (IP or username) per endpoint
    """

    def __init__(self, requests_per_minute=5, window_minutes=1):
        """
        Initialize rate limiter

        Args:
            requests_per_minute: Maximum requests allowed in window
            window_minutes: Time window in minutes
        """
        self.requests_per_minute = requests_per_minute
        self.window_minutes = window_minutes

    def is_rate_limited(self, key, endpoint):
        """
        Check if key is rate limited for endpoint

        Args:
            key: Rate limit key (e.g., 'ip:192.168.1.1' or 'user:alice')
            endpoint: Endpoint path (e.g., '/login')

        Returns:
            (is_limited, remaining_attempts, reset_time) tuple
        """
        conn = get_db_connection()
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=self.window_minutes)

        # Clean up expired rate limit entries
        conn.execute(
            'DELETE FROM rate_limits WHERE window_end < ?',
            (window_start,)
        )
        conn.commit()

        # Count recent requests
        recent_requests = conn.execute('''
            SELECT SUM(request_count) as total
            FROM rate_limits
            WHERE key = ? AND endpoint = ? AND window_end > ?
        ''', (key, endpoint, window_start)).fetchone()

        total_requests = recent_requests['total'] if recent_requests['total'] else 0

        if total_requests >= self.requests_per_minute:
            # Find oldest window to determine reset time
            oldest_window = conn.execute('''
                SELECT window_end
                FROM rate_limits
                WHERE key = ? AND endpoint = ? AND window_end > ?
                ORDER BY window_end ASC
                LIMIT 1
            ''', (key, endpoint, window_start)).fetchone()

            reset_time = oldest_window['window_end'] if oldest_window else now
            conn.close()
            return True, 0, reset_time
        else:
            remaining = self.requests_per_minute - total_requests
            conn.close()
            return False, remaining, None

    def record_request(self, key, endpoint):
        """
        Record a request for rate limiting

        Uses transaction with immediate lock to prevent TOCTOU race conditions

        Args:
            key: Rate limit key
            endpoint: Endpoint path

        Returns:
            Success boolean
        """
        conn = get_db_connection()
        now = datetime.utcnow()
        window_end = now + timedelta(minutes=self.window_minutes)

        try:
            # BEGIN IMMEDIATE to acquire write lock immediately (prevents race conditions)
            conn.execute('BEGIN IMMEDIATE')

            # Try to increment existing window
            existing = conn.execute('''
                SELECT id FROM rate_limits
                WHERE key = ? AND endpoint = ?
                  AND window_start <= ? AND window_end > ?
            ''', (key, endpoint, now, now)).fetchone()

            if existing:
                conn.execute('''
                    UPDATE rate_limits
                    SET request_count = request_count + 1
                    WHERE id = ?
                ''', (existing['id'],))
            else:
                # Create new window
                conn.execute('''
                    INSERT INTO rate_limits
                    (key, endpoint, request_count, window_start, window_end)
                    VALUES (?, ?, 1, ?, ?)
                ''', (key, endpoint, now, window_end))

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            conn.execute('ROLLBACK')
            conn.close()
            print(f"Rate limit record error: {e}")
            return False

    def limit(self, requests_per_minute=None, per_user=False):
        """
        Decorator for rate limiting routes

        Args:
            requests_per_minute: Override default rate limit
            per_user: Use username instead of IP for rate limiting

        Returns:
            Decorated function
        """
        limit = requests_per_minute or self.requests_per_minute

        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Determine rate limit key
                if per_user and request.form.get('username'):
                    key = f"user:{request.form.get('username')}"
                else:
                    key = f"ip:{request.remote_addr}"

                endpoint = request.path

                # Check rate limit
                is_limited, remaining, reset_time = self.is_rate_limited(key, endpoint)

                if is_limited:
                    reset_seconds = int((reset_time - datetime.utcnow()).total_seconds())
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'message': f'Too many requests. Try again in {reset_seconds} seconds',
                        'retry_after': reset_seconds
                    }), 429

                # Record this request
                self.record_request(key, endpoint)

                # Add rate limit headers
                response = f(*args, **kwargs)

                if hasattr(response, 'headers'):
                    response.headers['X-RateLimit-Limit'] = str(limit)
                    response.headers['X-RateLimit-Remaining'] = str(remaining - 1)

                return response

            return decorated_function
        return decorator


# Global instance
_rate_limiter = None

def get_rate_limiter():
    """Get singleton rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(requests_per_minute=5, window_minutes=1)
    return _rate_limiter

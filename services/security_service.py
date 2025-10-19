"""
Security Service
Handles security logging, brute force protection, account lockouts
"""
from datetime import datetime, timedelta
import json
from database import get_db_connection

class SecurityService:
    """
    Security monitoring and enforcement service
    Handles login attempts tracking, account lockouts, security logging
    """

    # Configuration
    LOCKOUT_THRESHOLD = 3  # Failed attempts before lockout
    LOCKOUT_DURATION = timedelta(minutes=15)  # Lockout duration
    CAPTCHA_THRESHOLD = 3  # Show CAPTCHA after N failures

    def __init__(self):
        """Initialize security service"""
        pass

    def log_security_event(self, event_type, username=None, ip_address=None,
                          user_agent=None, endpoint=None, metadata=None,
                          severity='info'):
        """
        Log security event

        Args:
            event_type: Type of event (login_success, login_failed, etc.)
            username: Username involved
            ip_address: Client IP address
            user_agent: Client user agent
            endpoint: API endpoint
            metadata: Additional metadata dict
            severity: Event severity (info, warning, critical)

        Returns:
            Event ID
        """
        conn = get_db_connection()

        metadata_json = json.dumps(metadata) if metadata else None

        cursor = conn.execute('''
            INSERT INTO security_events
            (event_type, severity, username, ip_address, user_agent,
             endpoint, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (event_type, severity, username, ip_address, user_agent,
              endpoint, metadata_json, datetime.utcnow()))

        event_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Log critical events (already logged to database above)
        # Additional logging could be added here if needed (syslog, monitoring system, etc.)

        return event_id

    def log_login_attempt(self, username, ip_address, user_agent,
                         success, failure_reason=None):
        """
        Log login attempt

        Args:
            username: Username attempted
            ip_address: Client IP
            user_agent: Client user agent
            success: Whether login succeeded
            failure_reason: Reason for failure

        Returns:
            Attempt ID
        """
        conn = get_db_connection()

        cursor = conn.execute('''
            INSERT INTO login_attempts
            (username, ip_address, user_agent, success, failure_reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, ip_address, user_agent, success, failure_reason,
              datetime.utcnow()))

        attempt_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Also log as security event
        event_type = 'login_success' if success else 'login_failed'
        severity = 'info' if success else 'warning'

        self.log_security_event(
            event_type, username, ip_address, user_agent,
            '/login',
            {'reason': failure_reason} if failure_reason else None,
            severity
        )

        return attempt_id

    def check_account_lockout(self, username):
        """
        Check if account is currently locked

        Args:
            username: Username to check

        Returns:
            (is_locked, message, remaining_seconds) tuple
        """
        conn = get_db_connection()

        lockout = conn.execute('''
            SELECT * FROM account_lockouts
            WHERE username = ? AND locked_until > ?
        ''', (username, datetime.utcnow())).fetchone()

        if lockout:
            # Convert string to datetime (SQLite stores as string)
            locked_until = datetime.fromisoformat(lockout['locked_until']) if isinstance(lockout['locked_until'], str) else lockout['locked_until']
            remaining = (locked_until - datetime.utcnow()).total_seconds()
            remaining_minutes = int(remaining / 60)
            remaining_seconds = int(remaining % 60)

            message = f"Account locked. Try again in {remaining_minutes}m {remaining_seconds}s"
            conn.close()
            return True, message, int(remaining)

        conn.close()
        return False, None, 0

    def get_recent_failures(self, username, window=None):
        """
        Get count of recent failed login attempts

        Args:
            username: Username to check
            window: Time window (defaults to lockout duration)

        Returns:
            Count of failures
        """
        window = window or self.LOCKOUT_DURATION
        cutoff = datetime.utcnow() - window

        conn = get_db_connection()

        count = conn.execute('''
            SELECT COUNT(*) as count FROM login_attempts
            WHERE username = ? AND success = 0 AND timestamp >= ?
        ''', (username, cutoff)).fetchone()['count']

        conn.close()
        return count

    def apply_account_lockout(self, username, failed_count):
        """
        Apply account lockout

        Uses transaction to prevent race conditions

        Args:
            username: Username to lock
            failed_count: Number of failed attempts

        Returns:
            Success boolean
        """
        locked_until = datetime.utcnow() + self.LOCKOUT_DURATION

        conn = get_db_connection()

        try:
            # BEGIN IMMEDIATE for write lock (prevents concurrent lockout attempts)
            conn.execute('BEGIN IMMEDIATE')

            # Check if lockout already exists
            existing = conn.execute(
                'SELECT id FROM account_lockouts WHERE username = ?',
                (username,)
            ).fetchone()

            if existing:
                conn.execute('''
                    UPDATE account_lockouts
                    SET locked_until = ?, failed_attempts = ?, locked_at = ?
                    WHERE username = ?
                ''', (locked_until, failed_count, datetime.utcnow(), username))
            else:
                conn.execute('''
                    INSERT INTO account_lockouts
                    (username, locked_until, failed_attempts, lockout_reason)
                    VALUES (?, ?, ?, 'too_many_failures')
                ''', (username, locked_until, failed_count))

            conn.commit()
            conn.close()

            # Log critical event
            self.log_security_event(
                'account_locked',
                username=username,
                metadata={'failed_attempts': failed_count},
                severity='critical'
            )

            # Account locked event already logged to security_events table
            return True

        except Exception as e:
            conn.execute('ROLLBACK')
            conn.close()
            print(f"Account lockout error: {e}")
            return False

    def clear_account_lockout(self, username):
        """
        Clear account lockout after successful login

        Args:
            username: Username to unlock

        Returns:
            Success boolean
        """
        conn = get_db_connection()

        deleted = conn.execute('''
            DELETE FROM account_lockouts WHERE username = ?
        ''', (username,)).rowcount

        conn.commit()
        conn.close()

        if deleted > 0:
            self.log_security_event(
                'lockout_cleared',
                username=username,
                severity='info'
            )

        return True

    def requires_captcha(self, username):
        """
        Check if CAPTCHA is required for user

        Args:
            username: Username to check

        Returns:
            Boolean indicating if CAPTCHA is required
        """
        failures = self.get_recent_failures(username)
        return failures >= self.CAPTCHA_THRESHOLD

    def get_login_statistics(self, username=None, hours=24):
        """
        Get login statistics

        Args:
            username: Username filter (optional)
            hours: Time window in hours

        Returns:
            Statistics dict
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        conn = get_db_connection()

        if username:
            total = conn.execute('''
                SELECT COUNT(*) as count FROM login_attempts
                WHERE username = ? AND timestamp >= ?
            ''', (username, cutoff)).fetchone()['count']

            successful = conn.execute('''
                SELECT COUNT(*) as count FROM login_attempts
                WHERE username = ? AND success = 1 AND timestamp >= ?
            ''', (username, cutoff)).fetchone()['count']

            failed = conn.execute('''
                SELECT COUNT(*) as count FROM login_attempts
                WHERE username = ? AND success = 0 AND timestamp >= ?
            ''', (username, cutoff)).fetchone()['count']
        else:
            total = conn.execute('''
                SELECT COUNT(*) as count FROM login_attempts
                WHERE timestamp >= ?
            ''', (cutoff,)).fetchone()['count']

            successful = conn.execute('''
                SELECT COUNT(*) as count FROM login_attempts
                WHERE success = 1 AND timestamp >= ?
            ''', (cutoff,)).fetchone()['count']

            failed = conn.execute('''
                SELECT COUNT(*) as count FROM login_attempts
                WHERE success = 0 AND timestamp >= ?
            ''', (cutoff,)).fetchone()['count']

        conn.close()

        return {
            'total_attempts': total,
            'successful': successful,
            'failed': failed,
            'success_rate': (successful / total * 100) if total > 0 else 0
        }


# Singleton instance
_security_service = None

def get_security_service():
    """Get singleton security service instance"""
    global _security_service
    if _security_service is None:
        _security_service = SecurityService()
    return _security_service

"""
Authentication Routes
Handles user registration, login, logout
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from services.auth_service import get_auth_service
from services.security_service import get_security_service
from services.rate_limiter import get_rate_limiter
from utils.recaptcha import get_recaptcha_service

auth_bp = Blueprint('auth', __name__)

# Get services
auth_service = get_auth_service()
security_service = get_security_service()
rate_limiter = get_rate_limiter()
recaptcha_service = get_recaptcha_service()

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('auth/register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html')

        # Register user
        success, result = auth_service.register_user(username, email, password)

        if success:
            # Log security event
            security_service.log_security_event(
                'user_registered',
                username=username,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                severity='info'
            )

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {result}', 'danger')
            return render_template('auth/register.html')

    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limiter.limit(requests_per_minute=5, per_user=True)
def login():
    """User login with brute force protection"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('auth/login.html')

        # Check account lockout
        is_locked, message, remaining = security_service.check_account_lockout(username)
        if is_locked:
            flash(message, 'danger')
            return render_template('auth/login.html', locked=True)

        # Check if CAPTCHA is required
        requires_captcha = security_service.requires_captcha(username)

        # Validate CAPTCHA if required
        if requires_captcha and recaptcha_service.is_enabled():
            is_valid, error = recaptcha_service.verify_response()
            if not is_valid:
                flash(f'CAPTCHA verification failed: {error}', 'danger')
                security_service.log_security_event(
                    'captcha_failed',
                    username=username,
                    ip_address=request.remote_addr,
                    metadata={'error': error},
                    severity='warning'
                )
                return render_template('auth/login.html',
                                     requires_captcha=True,
                                     username=username)

        # Authenticate
        success, result = auth_service.authenticate(username, password)

        # Log attempt
        security_service.log_login_attempt(
            username,
            request.remote_addr,
            request.headers.get('User-Agent'),
            success,
            None if success else 'invalid_credentials'
        )

        if success:
            user = result

            # Clear lockout
            security_service.clear_account_lockout(username)

            # Check if 2FA is enabled
            if user.get('totp_enabled'):
                # Store pending login in session
                session['pending_2fa_user_id'] = user['id']
                session['pending_2fa_username'] = user['username']
                return redirect(url_for('twofa.verify_2fa'))
            else:
                # Complete login
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('home'))
        else:
            # Failed login
            failures = security_service.get_recent_failures(username)

            if failures >= security_service.LOCKOUT_THRESHOLD:
                # Apply lockout
                security_service.apply_account_lockout(username, failures)
                flash(f'Account locked for {security_service.LOCKOUT_DURATION.total_seconds()//60} minutes', 'danger')
            else:
                remaining = security_service.LOCKOUT_THRESHOLD - failures
                flash(f'Invalid credentials. {remaining} attempts remaining.', 'danger')

            return render_template('auth/login.html',
                                 requires_captcha=requires_captcha,
                                 username=username)

    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    """User logout"""
    username = session.get('username')

    if username:
        security_service.log_security_event(
            'user_logout',
            username=username,
            ip_address=request.remote_addr,
            severity='info'
        )

    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@auth_bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Change user password"""
    if 'user_id' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return render_template('security/change_password.html')

        # Change password
        success, error = auth_service.change_password(
            session['user_id'],
            old_password,
            new_password
        )

        if success:
            security_service.log_security_event(
                'password_changed',
                username=session['username'],
                ip_address=request.remote_addr,
                severity='warning'
            )

            flash('Password changed successfully', 'success')
            return redirect(url_for('auth.security_settings'))
        else:
            flash(f'Password change failed: {error}', 'danger')
            return render_template('security/change_password.html')

    return render_template('security/change_password.html')

@auth_bp.route('/security-settings')
def security_settings():
    """Security settings dashboard"""
    if 'user_id' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('auth.login'))

    user = auth_service.get_user_by_id(session['user_id'])

    # Get login statistics
    stats = security_service.get_login_statistics(username=user['username'])

    return render_template('security/security_settings.html',
                         user=user,
                         stats=stats)

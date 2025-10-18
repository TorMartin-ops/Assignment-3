"""
Two-Factor Authentication Routes
Handles 2FA setup, verification, backup codes
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from services.totp_service import get_totp_service
from services.security_service import get_security_service
from services.auth_service import get_auth_service
from services.rate_limiter import get_rate_limiter

twofa_bp = Blueprint('twofa', __name__)

# Get services
totp_service = get_totp_service()
security_service = get_security_service()
auth_service = get_auth_service()
rate_limiter = get_rate_limiter()

@twofa_bp.route('/setup-2fa', methods=['GET', 'POST'])
@rate_limiter.limit(requests_per_minute=5, per_user=True)
def setup_2fa():
    """Setup 2FA for user account (rate limited to prevent code brute force during setup)"""
    if 'user_id' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('auth.login'))

    user = auth_service.get_user_by_id(session['user_id'])

    if user['totp_enabled']:
        flash('2FA is already enabled', 'info')
        return redirect(url_for('auth.security_settings'))

    if request.method == 'POST':
        # User confirmed setup, enable 2FA
        secret = session.get('temp_totp_secret')
        code = request.form.get('code', '').strip()

        if not secret or not code:
            flash('Invalid request', 'danger')
            return redirect(url_for('twofa.setup_2fa'))

        # Verify the code with temporary secret
        import pyotp
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            # Enable 2FA and generate backup codes
            success, backup_codes = totp_service.enable_2fa(session['user_id'], secret)

            if success:
                # Clear temp secret
                session.pop('temp_totp_secret', None)

                # Store backup codes in session for one-time display
                session['new_backup_codes'] = backup_codes

                security_service.log_security_event(
                    '2fa_enabled',
                    username=session['username'],
                    ip_address=request.remote_addr,
                    severity='warning'
                )

                flash('2FA enabled successfully!', 'success')
                return redirect(url_for('twofa.show_backup_codes'))
            else:
                flash('Failed to enable 2FA', 'danger')
        else:
            flash('Invalid code. Please try again.', 'danger')

        return render_template('2fa/setup.html', secret=secret)

    # GET: Generate new secret and show QR code
    secret = totp_service.generate_secret()
    session['temp_totp_secret'] = secret

    # Generate QR code
    qr_code = totp_service.generate_qr_code(secret, session['username'])

    return render_template('2fa/setup.html', secret=secret, qr_code=qr_code)

@twofa_bp.route('/verify-2fa', methods=['GET', 'POST'])
@rate_limiter.limit(requests_per_minute=5, per_user=False)
def verify_2fa():
    """Verify 2FA code during login (rate limited per IP to prevent brute force)"""
    if 'pending_2fa_user_id' not in session:
        flash('Invalid request', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        use_backup = request.form.get('use_backup') == 'true'

        user_id = session['pending_2fa_user_id']
        username = session['pending_2fa_username']

        if use_backup:
            # Verify backup code
            is_valid, remaining = totp_service.verify_backup_code(user_id, code)

            if is_valid:
                # Complete login
                session.pop('pending_2fa_user_id')
                session.pop('pending_2fa_username')
                session['user_id'] = user_id
                session['username'] = username

                security_service.log_security_event(
                    '2fa_backup_used',
                    username=username,
                    ip_address=request.remote_addr,
                    metadata={'remaining_codes': remaining},
                    severity='warning'
                )

                flash(f'Login successful. {remaining} backup codes remaining.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid backup code', 'danger')
        else:
            # Verify TOTP code
            is_valid, error = totp_service.verify_totp(user_id, code)

            if is_valid:
                # Complete login
                session.pop('pending_2fa_user_id')
                session.pop('pending_2fa_username')
                session['user_id'] = user_id
                session['username'] = username

                security_service.log_security_event(
                    '2fa_verified',
                    username=username,
                    ip_address=request.remote_addr,
                    severity='info'
                )

                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('home'))
            else:
                flash(f'Verification failed: {error}', 'danger')

        return render_template('2fa/verify.html')

    return render_template('2fa/verify.html')

@twofa_bp.route('/backup-codes')
def show_backup_codes():
    """Show backup codes (one-time only after setup)"""
    if 'user_id' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('auth.login'))

    backup_codes = session.pop('new_backup_codes', None)

    if not backup_codes:
        flash('Backup codes already viewed', 'warning')
        return redirect(url_for('auth.security_settings'))

    return render_template('2fa/backup_codes.html', backup_codes=backup_codes)

@twofa_bp.route('/disable-2fa', methods=['GET', 'POST'])
@rate_limiter.limit(requests_per_minute=3, per_user=True)
def disable_2fa():
    """Disable 2FA (requires password confirmation, rate limited to prevent password brute force)"""
    if 'user_id' not in session:
        flash('Please log in', 'warning')
        return redirect(url_for('auth.login'))

    user = auth_service.get_user_by_id(session['user_id'])

    if not user['totp_enabled']:
        flash('2FA is not enabled', 'info')
        return redirect(url_for('auth.security_settings'))

    if request.method == 'POST':
        password = request.form.get('password', '')

        # Verify password
        success, _ = auth_service.authenticate(user['username'], password)

        if success:
            # Disable 2FA
            totp_service.disable_2fa(session['user_id'])

            security_service.log_security_event(
                '2fa_disabled',
                username=session['username'],
                ip_address=request.remote_addr,
                severity='critical'
            )

            flash('2FA has been disabled', 'warning')
            return redirect(url_for('auth.security_settings'))
        else:
            flash('Invalid password', 'danger')

    return render_template('2fa/disable.html')

"""
Google reCAPTCHA Integration
Validates reCAPTCHA responses from users
"""
import os
import requests
from flask import request


class ReCaptchaService:
    """
    Service for validating Google reCAPTCHA responses

    Uses reCAPTCHA v2 (checkbox) for brute force protection
    """

    def __init__(self):
        """Initialize reCAPTCHA service with Google API credentials"""
        self.secret_key = os.getenv('RECAPTCHA_SECRET_KEY', '')
        self.site_key = os.getenv('RECAPTCHA_SITE_KEY', '')
        self.verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        self.enabled = bool(self.secret_key and self.site_key)

    def get_site_key(self):
        """
        Get reCAPTCHA site key for frontend

        Returns:
            Site key string for HTML integration
        """
        return self.site_key

    def is_enabled(self):
        """
        Check if reCAPTCHA is configured and enabled

        Returns:
            Boolean indicating if reCAPTCHA is available
        """
        return self.enabled

    def verify_response(self, recaptcha_response=None):
        """
        Verify reCAPTCHA response from user

        Args:
            recaptcha_response: Optional reCAPTCHA response token
                                If None, reads from request.form

        Returns:
            (is_valid, error_message) tuple
            - is_valid: Boolean indicating if verification passed
            - error_message: Error description if failed, None if succeeded

        Examples:
            >>> is_valid, error = recaptcha.verify_response(token)
            >>> if not is_valid:
            ...     flash(f'CAPTCHA failed: {error}')
        """
        # If reCAPTCHA not configured, pass validation (development mode)
        if not self.enabled:
            return True, None

        # Get response token from form if not provided
        if recaptcha_response is None:
            recaptcha_response = request.form.get('g-recaptcha-response', '')

        if not recaptcha_response:
            return False, "CAPTCHA response missing"

        # Verify with Google's API
        try:
            payload = {
                'secret': self.secret_key,
                'response': recaptcha_response,
                'remoteip': request.remote_addr
            }

            response = requests.post(
                self.verify_url,
                data=payload,
                timeout=5
            )

            result = response.json()

            if result.get('success'):
                return True, None
            else:
                error_codes = result.get('error-codes', [])
                error_msg = self._translate_error_codes(error_codes)
                return False, error_msg

        except requests.RequestException as e:
            # Network error - fail gracefully
            return False, f"CAPTCHA verification failed: {str(e)}"

    def _translate_error_codes(self, error_codes):
        """
        Translate Google error codes to user-friendly messages

        Args:
            error_codes: List of error code strings from Google

        Returns:
            Human-readable error message
        """
        translations = {
            'missing-input-secret': 'CAPTCHA configuration error',
            'invalid-input-secret': 'CAPTCHA configuration error',
            'missing-input-response': 'Please complete the CAPTCHA',
            'invalid-input-response': 'CAPTCHA verification failed',
            'bad-request': 'CAPTCHA request error',
            'timeout-or-duplicate': 'CAPTCHA expired, please try again'
        }

        if not error_codes:
            return "CAPTCHA verification failed"

        # Return first translated error
        for code in error_codes:
            if code in translations:
                return translations[code]

        return f"CAPTCHA error: {error_codes[0]}"


# Singleton instance
_recaptcha_service = None


def get_recaptcha_service():
    """
    Get singleton reCAPTCHA service instance

    Returns:
        ReCaptchaService instance
    """
    global _recaptcha_service
    if _recaptcha_service is None:
        _recaptcha_service = ReCaptchaService()
    return _recaptcha_service

"""
Security Headers Configuration
Provides consistent security headers across the application
"""


def set_security_headers(response):
    """
    Add security headers to Flask response

    Headers include:
    - Content Security Policy (CSP)
    - X-Content-Type-Options
    - X-Frame-Options
    - X-XSS-Protection
    - Strict-Transport-Security (HSTS)

    Args:
        response: Flask response object

    Returns:
        Modified response with security headers
    """
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://www.google.com https://www.gstatic.com; "
        "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "img-src 'self' https: data:; "
        "connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "frame-src https://www.google.com;"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

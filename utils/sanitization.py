"""
Input Sanitization Utilities
XSS and injection prevention
"""
import bleach


def sanitize_html_input(content, allowed_tags=None, strip=True):
    """
    Sanitize user input to prevent XSS attacks

    Args:
        content: Raw user input string
        allowed_tags: List of allowed HTML tags (default: none)
        strip: Strip tags or escape them (default: strip)

    Returns:
        Sanitized string safe for display

    Examples:
        >>> sanitize_html_input("<script>alert('xss')</script>Hello")
        'Hello'
        >>> sanitize_html_input("<b>Bold</b> text", allowed_tags=['b'])
        '<b>Bold</b> text'
    """
    if allowed_tags is None:
        allowed_tags = []

    return bleach.clean(content, tags=allowed_tags, strip=strip)


def sanitize_comment(content):
    """
    Sanitize user comment - strips all HTML tags

    Args:
        content: User comment text

    Returns:
        Plain text comment with all HTML removed
    """
    return sanitize_html_input(content, allowed_tags=[], strip=True)

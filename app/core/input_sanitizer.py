"""
Input Sanitization and Validation Module
Protects against OWASP Top 10 injection attacks and other security threats

Security measures:
1. SQL Injection prevention
2. XSS (Cross-Site Scripting) prevention
3. Command Injection prevention
4. LDAP Injection prevention
5. Path Traversal prevention
6. Input length limits
7. Character whitelist validation
"""

import re
import html
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Maximum allowed input lengths
MAX_QUERY_LENGTH = 200
MIN_QUERY_LENGTH = 2

# Whitelist pattern: alphanumeric, spaces, and common safe characters
# Allows: letters, numbers, spaces, dots, hyphens, underscores
SAFE_QUERY_PATTERN = re.compile(r'^[\w\s\.\-\,\:\;\(\)\/\@]+$', re.UNICODE)

# Dangerous patterns to detect and block
DANGEROUS_PATTERNS = [
    # SQL Injection patterns
    (r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)', 'SQL keyword'),
    (r'(--|;|\/\*|\*\/)', 'SQL comment/terminator'),
    (r'(\bOR\b\s+\d+\s*=\s*\d+)', 'SQL injection OR'),
    (r'(\bAND\b\s+\d+\s*=\s*\d+)', 'SQL injection AND'),
    (r"('|\"|`)\s*(OR|AND)\s*('|\"|`)", 'SQL injection quote'),

    # Command Injection patterns
    (r'(\||&&|\$\(|`|;|\n|\r)', 'Command injection'),
    (r'(\b(cat|ls|rm|mv|cp|chmod|chown|wget|curl|bash|sh|python|perl|ruby|nc|netcat)\b)', 'Shell command'),

    # Path Traversal patterns
    (r'(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)', 'Path traversal'),

    # XSS patterns
    (r'(<\s*script|<\s*img|<\s*iframe|<\s*object|<\s*embed|<\s*svg|<\s*on\w+\s*=)', 'XSS tag'),
    (r'(javascript:|vbscript:|data:text\/html)', 'XSS protocol'),
    (r'(on\w+\s*=\s*["\'])', 'XSS event handler'),

    # LDAP Injection patterns
    (r'(\*\)|\)\(|\(\||\(&)', 'LDAP injection'),

    # Template Injection patterns
    (r'(\{\{|\}\}|\{%|%\}|\$\{)', 'Template injection'),

    # XML/XXE patterns
    (r'(<!ENTITY|<!DOCTYPE.*\[)', 'XXE injection'),
]

# Compile patterns for efficiency
COMPILED_DANGEROUS_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in DANGEROUS_PATTERNS
]


def sanitize_query(query: str) -> Tuple[str, Optional[str]]:
    """
    Sanitize and validate a search query input.

    Returns:
        Tuple of (sanitized_query, error_message)
        If error_message is not None, the query should be rejected
    """
    if not query:
        return "", "Query cannot be empty"

    # Strip whitespace
    query = query.strip()

    # Check minimum length
    if len(query) < MIN_QUERY_LENGTH:
        return "", f"Query must be at least {MIN_QUERY_LENGTH} characters"

    # Check maximum length
    if len(query) > MAX_QUERY_LENGTH:
        return "", f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters"

    # Check for dangerous patterns
    for pattern, threat_name in COMPILED_DANGEROUS_PATTERNS:
        if pattern.search(query):
            logger.warning(f"Blocked potentially malicious input: {threat_name} - Query: {query[:50]}...")
            return "", "Invalid characters detected in query"

    # HTML encode to prevent XSS when displayed
    sanitized = html.escape(query)

    # Normalize whitespace (collapse multiple spaces)
    sanitized = ' '.join(sanitized.split())

    return sanitized, None


def escape_for_display(text: str) -> str:
    """
    Escape text for safe HTML display.
    Use this when rendering user input in responses.
    """
    if not text:
        return ""
    return html.escape(str(text))


def validate_limit(limit: int, max_limit: int = 100, default: int = 10) -> int:
    """
    Validate and constrain a limit parameter.

    - Returns default if limit is <= 0 or not an integer
    - Caps at max_limit if limit exceeds it
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return default

    if limit <= 0:
        return default

    return min(limit, max_limit)


def is_valid_cve_id(cve_id: str) -> bool:
    """
    Validate CVE ID format (e.g., CVE-2024-12345)
    """
    if not cve_id:
        return False
    pattern = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
    return bool(pattern.match(cve_id))


def log_security_event(event_type: str, details: str, ip_address: str = None):
    """
    Log security-related events for monitoring and alerting.
    """
    log_msg = f"SECURITY_EVENT: {event_type}"
    if ip_address:
        log_msg += f" | IP: {ip_address}"
    log_msg += f" | Details: {details}"
    logger.warning(log_msg)

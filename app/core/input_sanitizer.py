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
MAX_FILENAME_LENGTH = 255
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


def sanitize_filename(filename: str) -> Tuple[str, Optional[str]]:
    """
    Sanitize and validate a filename input.

    Returns:
        Tuple of (sanitized_filename, error_message)
    """
    if not filename:
        return "", "Filename cannot be empty"

    # Strip whitespace
    filename = filename.strip()

    # Check length
    if len(filename) > MAX_FILENAME_LENGTH:
        return "", f"Filename exceeds maximum length of {MAX_FILENAME_LENGTH} characters"

    # Check for path traversal
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        logger.warning(f"Blocked path traversal attempt: {filename}")
        return "", "Invalid filename"

    # Check for null bytes
    if '\x00' in filename:
        logger.warning("Blocked null byte injection attempt")
        return "", "Invalid filename"

    # Only allow safe filename characters
    safe_filename_pattern = re.compile(r'^[\w\s\.\-]+$', re.UNICODE)
    if not safe_filename_pattern.match(filename):
        return "", "Filename contains invalid characters"

    return filename, None


def sanitize_email_content(content: str, max_length: int = 50000) -> Tuple[str, Optional[str]]:
    """
    Sanitize email content for phishing analysis.

    Returns:
        Tuple of (sanitized_content, error_message)
    """
    if not content:
        return "", "Email content cannot be empty"

    # Check length
    if len(content) > max_length:
        return "", f"Email content exceeds maximum length of {max_length} characters"

    # For email analysis, we want to preserve the content for analysis
    # but still check for obvious exploit attempts

    # Check for null bytes
    if '\x00' in content:
        logger.warning("Blocked null byte in email content")
        return "", "Invalid email content"

    return content, None


# Dangerous file signatures (magic bytes) to block
DANGEROUS_FILE_SIGNATURES = {
    b'MZ': 'Windows Executable (EXE/DLL)',
    b'\x7fELF': 'Linux Executable (ELF)',
    b'PK\x03\x04': 'ZIP Archive (may contain malware)',
    b'Rar!': 'RAR Archive',
    b'\x1f\x8b': 'GZIP Archive',
    b'%PDF': 'PDF Document',
    b'\xd0\xcf\x11\xe0': 'Microsoft Office Document (OLE)',
    b'\x00\x00\x00\x18ftypmp4': 'MP4 Video',
    b'\x00\x00\x00\x1cftypmp4': 'MP4 Video',
    b'GIF8': 'GIF Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'\x89PNG': 'PNG Image',
    b'#!/': 'Shell Script',
    b'<?php': 'PHP Script',
    b'<script': 'JavaScript/HTML',
}

# Allowed file extensions for email files
ALLOWED_EMAIL_EXTENSIONS = {'.eml', '.msg', '.txt'}

# Dangerous extensions that should never be accepted
DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.com', '.msi', '.scr',  # Windows executables
    '.sh', '.bash', '.zsh', '.csh',  # Shell scripts
    '.py', '.pyw', '.pyc', '.pyo',  # Python
    '.js', '.jsx', '.ts', '.tsx',  # JavaScript
    '.php', '.phtml', '.php5',  # PHP
    '.rb', '.pl', '.cgi',  # Ruby, Perl, CGI
    '.jar', '.class', '.war',  # Java
    '.ps1', '.psm1', '.psd1',  # PowerShell
    '.vbs', '.vbe', '.wsf', '.wsh',  # VBScript
    '.app', '.dmg', '.pkg',  # macOS
    '.deb', '.rpm', '.AppImage',  # Linux packages
    '.iso', '.img',  # Disk images
    '.lnk', '.url', '.desktop',  # Shortcuts
    '.reg', '.inf',  # Windows registry/config
    '.hta', '.htm', '.html', '.svg',  # HTML (can contain scripts)
}


def validate_uploaded_file(content: bytes, filename: str, max_size: int = 10 * 1024 * 1024) -> Tuple[bool, Optional[str]]:
    """
    Comprehensive validation for uploaded files.

    Security checks:
    1. File size limit
    2. Extension whitelist
    3. Magic bytes detection (file type verification)
    4. Null byte injection prevention
    5. Double extension attacks

    Args:
        content: File content as bytes
        filename: Original filename
        max_size: Maximum allowed file size in bytes

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check file size
    if len(content) > max_size:
        log_security_event("FILE_TOO_LARGE", f"Size: {len(content)} bytes, Max: {max_size}")
        return False, f"File size exceeds {max_size // (1024*1024)}MB limit"

    # Sanitize and validate filename
    filename_lower = filename.lower().strip()

    # Check for null bytes in filename (path traversal attack)
    if '\x00' in filename:
        log_security_event("NULL_BYTE_ATTACK", f"Filename: {filename[:50]}")
        return False, "Invalid filename detected"

    # Check for double extensions (e.g., file.txt.exe)
    parts = filename_lower.split('.')
    if len(parts) > 2:
        for part in parts[1:]:
            ext = f'.{part}'
            if ext in DANGEROUS_EXTENSIONS:
                log_security_event("DOUBLE_EXTENSION_ATTACK", f"Filename: {filename}")
                return False, "Potentially dangerous file type detected"

    # Check file extension
    ext = '.' + filename_lower.split('.')[-1] if '.' in filename_lower else ''
    if ext in DANGEROUS_EXTENSIONS:
        log_security_event("DANGEROUS_EXTENSION", f"Extension: {ext}, Filename: {filename}")
        return False, f"File type '{ext}' is not allowed for security reasons"

    if ext not in ALLOWED_EMAIL_EXTENSIONS:
        log_security_event("DISALLOWED_EXTENSION", f"Extension: {ext}")
        return False, f"Only {', '.join(ALLOWED_EMAIL_EXTENSIONS)} files are allowed"

    # Check magic bytes (file signature)
    for signature, file_type in DANGEROUS_FILE_SIGNATURES.items():
        if content.startswith(signature):
            log_security_event("DANGEROUS_FILE_SIGNATURE", f"Type: {file_type}, Filename: {filename}")
            return False, f"File appears to be a {file_type}, not an email file"

    # For .eml files, verify it looks like an email (text-based)
    if ext == '.eml':
        try:
            # Try to decode as text
            text_content = content.decode('utf-8', errors='ignore')

            # Check for email headers (basic validation)
            email_indicators = ['From:', 'To:', 'Subject:', 'Date:', 'MIME-Version:', 'Content-Type:']
            has_email_header = any(indicator in text_content[:2000] for indicator in email_indicators)

            if not has_email_header:
                # Might be a disguised file
                log_security_event("INVALID_EML_FORMAT", f"Filename: {filename}")
                return False, "File does not appear to be a valid email file"

        except Exception as e:
            logger.warning(f"Error validating email file: {e}")
            return False, "Unable to validate file format"

    return True, None


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

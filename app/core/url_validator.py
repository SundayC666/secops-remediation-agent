"""
URL Validator - SSRF Protection
Validates URLs to prevent Server-Side Request Forgery attacks
"""

import ipaddress
import socket
import logging
from urllib.parse import urlparse
from typing import Tuple

logger = logging.getLogger(__name__)

# Allowed URL schemes
ALLOWED_SCHEMES = {'http', 'https'}

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    'localhost',
    'localhost.localdomain',
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '[::1]',
}

# Blocked domain suffixes (internal/cloud metadata)
BLOCKED_SUFFIXES = (
    '.local',
    '.internal',
    '.localhost',
    '.corp',
    '.lan',
)

# Cloud metadata endpoints
CLOUD_METADATA_IPS = {
    '169.254.169.254',  # AWS, GCP, Azure metadata
    '100.100.100.200',  # Alibaba Cloud
    'fd00:ec2::254',    # AWS IPv6 metadata
}


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_reserved or
            ip.is_link_local or
            ip.is_multicast or
            str(ip) in CLOUD_METADATA_IPS
        )
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> str:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate a URL for SSRF protection

    Returns:
        Tuple of (is_safe, error_message)
        is_safe: True if URL is safe to fetch
        error_message: Description if URL is blocked
    """
    if not url:
        return False, "Empty URL"

    try:
        parsed = urlparse(url)
    except Exception as e:
        logger.warning(f"URL parse error: {e}")
        return False, f"Invalid URL format: {e}"

    # Check scheme
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        logger.warning(f"Blocked URL scheme: {parsed.scheme}")
        return False, f"Blocked URL scheme: {parsed.scheme}. Only http/https allowed."

    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    # Check blocked hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        logger.warning(f"Blocked hostname: {hostname}")
        return False, f"Blocked hostname: {hostname}"

    # Check blocked suffixes
    for suffix in BLOCKED_SUFFIXES:
        if hostname_lower.endswith(suffix):
            logger.warning(f"Blocked internal domain: {hostname}")
            return False, f"Blocked internal domain: {hostname}"

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if is_private_ip(str(ip)):
            logger.warning(f"Blocked private IP: {ip}")
            return False, f"Blocked private/reserved IP: {ip}"
    except ValueError:
        # Not an IP, resolve hostname
        resolved_ip = resolve_hostname(hostname)
        if resolved_ip and is_private_ip(resolved_ip):
            logger.warning(f"Hostname {hostname} resolves to private IP: {resolved_ip}")
            return False, f"Hostname resolves to private IP: {resolved_ip}"

    # Check cloud metadata IPs
    if hostname in CLOUD_METADATA_IPS:
        logger.warning(f"Blocked cloud metadata endpoint: {hostname}")
        return False, f"Blocked cloud metadata endpoint: {hostname}"

    return True, ""


def sanitize_url_for_logging(url: str) -> str:
    """Remove sensitive parts from URL for safe logging"""
    try:
        parsed = urlparse(url)
        # Remove password from URL
        if parsed.password:
            return url.replace(parsed.password, "***")
        return url
    except Exception:
        return "[invalid url]"

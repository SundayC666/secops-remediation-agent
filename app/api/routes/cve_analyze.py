"""
CVE Analysis API Endpoint
Handles vulnerability queries and returns grouped results
Supports direct NVD API queries for OS-specific vulnerabilities

Security: Input sanitization against OWASP Top 10 attacks
"""

import re
import logging
from typing import Optional, List

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, field_validator

from app.core.os_detector import detect_os_from_user_agent
from app.core.input_sanitizer import (
    sanitize_query,
    validate_limit,
    log_security_event,
    escape_for_display
)
from app.utils.startup import ensure_rag_initialized
from app.services.cve_collector import CVEDataCollector

router = APIRouter()
logger = logging.getLogger(__name__)

# OS to CPE mapping for accurate NVD queries
OS_CPE_MAPPING = {
    "macos": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
    "mac os x": "cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*",
    "windows": "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*",
    "windows_10": "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
    "windows_11": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
    "linux": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
    "ubuntu": "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*",
    "debian": "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*",
    "android": "cpe:2.3:o:google:android:*:*:*:*:*:*:*:*",
    "ios": "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*",
}

# OS keyword to search mapping (more specific keywords first)
# Includes common variations and typos
OS_KEYWORD_MAPPING = {
    # macOS variations
    "macos 15": "apple macos sequoia",
    "macos15": "apple macos sequoia",
    "mac os 15": "apple macos sequoia",
    "macos 14": "apple macos sonoma",
    "macos14": "apple macos sonoma",
    "mac os 14": "apple macos sonoma",
    "macos 13": "apple macos ventura",
    "macos13": "apple macos ventura",
    "mac os 13": "apple macos ventura",
    "mac os x": "apple mac os x",
    "macos": "apple macos",
    "mac os": "apple macos",
    # Windows variations
    "windows 11": "microsoft windows 11",
    "windows11": "microsoft windows 11",
    "win 11": "microsoft windows 11",
    "win11": "microsoft windows 11",
    "windows 10": "microsoft windows 10",
    "windows10": "microsoft windows 10",
    "win 10": "microsoft windows 10",
    "win10": "microsoft windows 10",
    "windows server": "microsoft windows server",
    "windows": "microsoft windows",
    # Ubuntu variations
    "ubuntu 24": "ubuntu 24.04",
    "ubuntu24": "ubuntu 24.04",
    "ubuntu 22": "ubuntu 22.04",
    "ubuntu22": "ubuntu 22.04",
    "ubuntu 20": "ubuntu 20.04",
    "ubuntu20": "ubuntu 20.04",
    "ubuntu": "ubuntu linux",
    # Linux
    "linux": "linux kernel",
    "debian": "debian linux",
    # Android variations
    "android 15": "google android 15",
    "android15": "google android 15",
    "android 14": "google android 14",
    "android14": "google android 14",
    "android": "google android",
    # iOS variations
    "ios 26": "apple ios 26",
    "ios26": "apple ios 26",
    "ios 18": "apple ios 18",
    "ios18": "apple ios 18",
    "ios 17": "apple ios 17",
    "ios17": "apple ios 17",
    "ios": "apple ios iphone",
    # Browsers
    "chrome": "google chrome",
    "firefox": "mozilla firefox",
    "safari": "apple safari",
}


class CVEAnalyzeRequest(BaseModel):
    """Request model for CVE analysis with input validation"""
    query: str
    limit: int = 10

    @field_validator('query')
    @classmethod
    def validate_query(cls, v):
        """Validate and sanitize query input"""
        sanitized, error = sanitize_query(v)
        if error:
            raise ValueError(error)
        return sanitized

    @field_validator('limit')
    @classmethod
    def validate_limit_field(cls, v):
        """Validate limit parameter"""
        return validate_limit(v, max_limit=50, default=10)


class CVEFinding(BaseModel):
    """Individual CVE finding"""
    cve: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    published_date: str
    is_exploited: bool
    patch_link: Optional[str]
    nvd_link: Optional[str] = None  # Link to NVD database
    os_tags: List[str]
    note: Optional[str] = None
    remediation_summary: Optional[str] = None  # Short summary for collapsed view
    source_type: Optional[str] = None  # "os", "browser", or None for general


class CVEResultGroup(BaseModel):
    """Group of CVE findings"""
    findings: List[CVEFinding]
    action_plan: List[str] = []


class CVEAnalyzeResponse(BaseModel):
    """Response model for CVE analysis"""
    detected_os: dict
    your_system: CVEResultGroup
    other_systems: CVEResultGroup
    query: str
    search_description: str  # Human-readable search description
    total_results: int


@router.get("/cve/latest", response_model=CVEAnalyzeResponse)
async def get_latest_cves(request: Request, limit: int = 5) -> CVEAnalyzeResponse:
    """
    Get latest CVEs affecting the user's detected OS and browser

    Auto-detects OS and browser from User-Agent and fetches CVEs from CIRCL API
    sorted by severity then by date (newest first)
    """
    # Validate and constrain limit parameter
    limit = validate_limit(limit, max_limit=50, default=5)

    # Detect user's OS
    user_agent = request.headers.get("User-Agent", "")
    os_info = detect_os_from_user_agent(user_agent)

    your_system_findings = []
    other_system_findings = []
    search_description = "Latest vulnerabilities"

    # If we detected a system, fetch CVEs from CIRCL API
    if os_info.normalized != "Unknown":
        collector = CVEDataCollector()

        # Build search keywords based on detected system
        search_keywords = []

        # Add OS keyword
        os_family_lower = os_info.family.lower() if os_info.family else ""
        if "mac" in os_family_lower or "darwin" in os_family_lower:
            search_keywords.append("apple macos")
        elif "windows" in os_family_lower:
            search_keywords.append("microsoft windows")
        elif "linux" in os_family_lower:
            search_keywords.append("linux kernel")
        elif "android" in os_family_lower:
            search_keywords.append("google android")
        elif "ios" in os_family_lower:
            search_keywords.append("apple ios")

        # Add browser keyword if detected (from browser info, not just tags)
        browser_name = os_info.browser.name.lower() if os_info.browser else ""
        if "chrome" in browser_name:
            search_keywords.append("google chrome")
        elif "firefox" in browser_name:
            search_keywords.append("mozilla firefox")
        elif "safari" in browser_name:
            search_keywords.append("apple safari")
        elif "edge" in browser_name:
            search_keywords.append("microsoft edge")

        # Fetch CVEs for each keyword and tag with source type
        # Ensure we get a mix of OS and browser CVEs
        os_cves = []
        browser_cves = []

        for i, keyword in enumerate(search_keywords[:2]):  # Limit to 2 searches
            cves = await collector.fetch_by_keyword(keyword, limit=limit)
            # Tag CVEs with source type (first keyword is OS, second is browser)
            source_type = "os" if i == 0 else "browser"
            for cve in cves:
                cve["_source_type"] = source_type

            if source_type == "os":
                os_cves.extend(cves)
            else:
                browser_cves.extend(cves)

        # Combine CVEs - take half from each source if both exist
        all_cves = []
        if os_cves and browser_cves:
            half_limit = limit // 2
            all_cves = os_cves[:half_limit] + browser_cves[:half_limit]
            # Add more if we have room
            remaining = limit - len(all_cves)
            if remaining > 0:
                all_cves.extend(os_cves[half_limit:half_limit + remaining // 2])
                all_cves.extend(browser_cves[half_limit:half_limit + remaining // 2])
        else:
            all_cves = os_cves + browser_cves

        if all_cves:
            your_system_findings = _filter_and_sort_findings([
                _cve_to_finding(cve, source_type=cve.get("_source_type")) for cve in all_cves
            ])[:limit]
            # Build search description with OS and browser info
            if os_info.browser:
                browser_str = f"{os_info.browser.name} {os_info.browser.version}" if os_info.browser.version else os_info.browser.name
                search_description = f"Latest vulnerabilities for {os_info.normalized} + {browser_str}"
            else:
                search_description = f"Latest vulnerabilities for {os_info.normalized}"

    # Fallback to RAG if no CIRCL results
    if not your_system_findings:
        if not await ensure_rag_initialized(request.app):
            raise HTTPException(
                status_code=503,
                detail="System is initializing. Please try again in a moment."
            )

        rag_engine = request.app.state.rag_engine

        if os_info.normalized == "Unknown":
            search_description = "Latest vulnerabilities (all systems)"
            query = "security vulnerabilities"
        else:
            search_description = f"Latest vulnerabilities for {os_info.normalized}"
            query = f"{os_info.normalized} vulnerabilities security"

        # Only get CVEs for user's system - no "other" category needed
        results = await rag_engine.search(
            query=query,
            os_tags=os_info.tags if os_info.normalized != "Unknown" else None,
            limit=limit * 2,
            include_other_os=False  # Don't include other OS CVEs
        )

        # Combine all results - they're all relevant to user's search
        all_rag_results = results.get("your_system", []) + results.get("other_systems", [])
        your_system_findings = _filter_and_sort_findings([
            _cve_to_finding(cve) for cve in all_rag_results
        ])[:limit]

    # Generate customized action plan
    action_plan = _generate_customized_action_plan(your_system_findings)

    return CVEAnalyzeResponse(
        detected_os={
            "family": os_info.family,
            "version": os_info.version,
            "normalized": os_info.normalized,
            "tags": os_info.tags
        },
        your_system=CVEResultGroup(
            findings=your_system_findings,
            action_plan=action_plan
        ),
        other_systems=CVEResultGroup(
            findings=[]  # No "other" category - all results are for user's system
        ),
        query="(auto-detected)",
        search_description=search_description,
        total_results=len(your_system_findings)
    )


@router.post("/cve/analyze", response_model=CVEAnalyzeResponse)
async def analyze_cves(request: Request, body: CVEAnalyzeRequest) -> CVEAnalyzeResponse:
    """
    Analyze CVEs based on user query and detected OS

    The endpoint:
    1. Validates and sanitizes user input (OWASP protection)
    2. Detects user's OS from User-Agent header
    3. Checks if query mentions specific OS/product
    4. If OS-specific, queries NVD directly for accurate results
    5. Otherwise, searches local RAG index
    6. Returns findings with remediation suggestions
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    # Query is already validated by Pydantic validator
    # Additional check for empty query after sanitization
    if not body.query or len(body.query.strip()) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters")

    # Detect user's OS
    user_agent = request.headers.get("User-Agent", "")
    os_info = detect_os_from_user_agent(user_agent)

    # Normalize query: lowercase, collapse multiple spaces, strip
    query_normalized = ' '.join(body.query.lower().split())

    # Check if query mentions a specific OS - if so, query NVD directly
    # Sort by length (longest first) to match more specific keywords first
    # e.g., "windows 10" before "windows"
    detected_os_keyword = None
    sorted_os_keys = sorted(OS_KEYWORD_MAPPING.keys(), key=len, reverse=True)
    for os_key in sorted_os_keys:
        # Normalize the key too for consistent matching
        if os_key in query_normalized:
            detected_os_keyword = os_key
            break

    your_system_findings = []
    other_system_findings = []
    search_description = f"Search results for: {body.query}"

    # If query mentions specific OS, fetch directly from NVD
    if detected_os_keyword:
        logger.info(f"OS-specific query detected: {detected_os_keyword}")
        collector = CVEDataCollector()

        # Use keyword search for NVD
        search_keyword = OS_KEYWORD_MAPPING.get(detected_os_keyword, detected_os_keyword)
        nvd_cves = await collector.fetch_by_keyword(search_keyword, limit=body.limit * 2)

        if nvd_cves:
            your_system_findings = _filter_and_sort_findings([
                _cve_to_finding(cve) for cve in nvd_cves
            ])[:body.limit]
            # Keep simple search description for manual queries
            search_description = f"Search results for: {body.query}"
            logger.info(f"Found {len(your_system_findings)} CVEs from NVD for {detected_os_keyword}")

    # If no OS-specific results, try CIRCL keyword search first
    # For manual searches, we want results directly related to the search term
    # NOT unrelated CVEs categorized by OS
    if not your_system_findings:
        logger.info(f"Trying CIRCL keyword search for: {body.query}")
        collector = CVEDataCollector()

        # Search CIRCL directly with user's query
        # CIRCL API uses vendor/product search, so results are already relevant
        circl_cves = await collector.fetch_by_keyword(body.query, limit=body.limit * 2)

        if circl_cves:
            # For vendor searches (like "adobe"), trust CIRCL results as they use vendor/product API
            # No additional keyword filtering needed - the API already filtered by vendor
            your_system_findings = _filter_and_sort_findings([
                _cve_to_finding(cve) for cve in circl_cves
            ])[:body.limit]
            logger.info(f"Found {len(your_system_findings)} CVEs from CIRCL for: {body.query}")

        # Only fall back to RAG if CIRCL returns nothing
        if not your_system_findings:
            # Ensure RAG engine is initialized
            if not await ensure_rag_initialized(request.app):
                raise HTTPException(
                    status_code=503,
                    detail="System is initializing. Please try again in a moment."
                )

            rag_engine = request.app.state.rag_engine

            # Search RAG index - but for manual searches, don't split by OS
            # All results should be related to the search query
            results = await rag_engine.search(
                query=body.query,
                os_tags=None,  # Don't filter by OS for manual searches
                limit=body.limit * 4,
                include_other_os=False  # Don't include unrelated OS CVEs
            )

            # Combine all results into your_system for manual search
            all_rag_results = results.get("your_system", []) + results.get("other_systems", [])

            # For RAG results, filter to ensure some relevance to search term
            # This prevents semantic search from returning completely unrelated results
            search_terms = body.query.lower().split()
            relevant_results = []
            for cve in all_rag_results:
                desc = cve.get("description", "").lower()
                title = cve.get("title", "").lower()
                cve_id = cve.get("cve_id", "").lower()
                # Check if any search term appears in description, title, or CVE ID
                if any(term in desc or term in title or term in cve_id for term in search_terms):
                    relevant_results.append(cve)

            # If no relevant results, return empty (don't show unrelated CVEs)
            your_system_findings = _filter_and_sort_findings([
                _cve_to_finding(cve) for cve in relevant_results
            ])[:body.limit]

            # No "other_systems" for manual searches - all results are search-relevant
            other_system_findings = []

    # Generate customized action plan for ALL CVEs found (not just your_system)
    all_findings = your_system_findings + other_system_findings
    action_plan = _generate_customized_action_plan(all_findings)

    return CVEAnalyzeResponse(
        detected_os={
            "family": os_info.family,
            "version": os_info.version,
            "normalized": os_info.normalized,
            "tags": os_info.tags
        },
        your_system=CVEResultGroup(
            findings=your_system_findings,
            action_plan=action_plan  # Action plan is now for all CVEs
        ),
        other_systems=CVEResultGroup(
            findings=other_system_findings
        ),
        query=body.query,
        search_description=search_description,
        total_results=len(your_system_findings) + len(other_system_findings)
    )


def _cve_to_finding(cve: dict, include_os_note: bool = False, source_type: Optional[str] = None) -> CVEFinding:
    """Convert CVE dict to CVEFinding model"""
    patch_links = cve.get("patch_links", [])
    os_tags = cve.get("os_tags", [])
    cve_id = cve.get("cve_id", "")

    note = None
    if include_os_note and os_tags:
        note = f"This vulnerability affects: {', '.join(os_tags)}"

    # Generate NVD link
    nvd_link = None
    if cve_id and cve_id.startswith("CVE-"):
        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # Generate short remediation summary
    remediation_summary = _generate_remediation_summary(cve)

    # Infer source_type from description if not provided
    if not source_type:
        desc_lower = cve.get("description", "").lower()
        if any(x in desc_lower for x in ["chrome", "firefox", "safari", "edge", "browser"]):
            source_type = "browser"
        elif any(x in desc_lower for x in ["macos", "windows", "linux", "android", "ios", "kernel"]):
            source_type = "os"

    return CVEFinding(
        cve=cve_id,
        title=cve.get("title", ""),
        description=cve.get("description", "")[:500],  # Truncate long descriptions
        severity=cve.get("severity", "UNKNOWN"),
        cvss_score=cve.get("cvss_score"),
        published_date=cve.get("published_date", ""),
        is_exploited=cve.get("is_exploited", False),
        patch_link=patch_links[0] if patch_links else None,
        nvd_link=nvd_link,
        os_tags=os_tags,
        note=note,
        remediation_summary=remediation_summary,
        source_type=source_type
    )


def _generate_remediation_summary(cve: dict) -> str:
    """Generate a short remediation summary for the collapsed view"""
    severity = cve.get("severity", "").upper()
    is_exploited = cve.get("is_exploited", False)
    patch_links = cve.get("patch_links", [])

    if is_exploited:
        if patch_links:
            return "Actively exploited - Apply patch immediately"
        return "Actively exploited - Check vendor for updates"

    if severity == "CRITICAL":
        if patch_links:
            return "Critical - Apply available patch urgently"
        return "Critical - Monitor vendor for patch release"

    if severity == "HIGH":
        if patch_links:
            return "High priority - Schedule patching soon"
        return "High priority - Review vendor advisories"

    if patch_links:
        return "Patch available - Plan to update"
    return "Monitor for vendor updates"


def _is_valid_cve(finding: CVEFinding) -> bool:
    """Check if a CVE is valid and not rejected/reserved"""
    invalid_patterns = [
        "rejected",
        "not used",
        "reserved",
        "** reserved **",
        "this candidate has been reserved",
        "this cve id has been rejected"
    ]

    desc_lower = finding.description.lower()
    title_lower = finding.title.lower()

    for pattern in invalid_patterns:
        if pattern in desc_lower or pattern in title_lower:
            return False

    # Also filter out CVEs with empty or very short descriptions
    if len(finding.description.strip()) < 20:
        return False

    # Don't filter UNKNOWN severity - we'll infer it from description later
    # Many valid CVEs from CIRCL API don't have CVSS scores yet

    return True


def _infer_severity_from_description(finding: CVEFinding) -> CVEFinding:
    """Infer severity from description if UNKNOWN"""
    if finding.severity != "UNKNOWN":
        return finding

    desc_lower = finding.description.lower()

    # Chromium severity mapping
    if "(chromium security severity: critical)" in desc_lower:
        finding.severity = "CRITICAL"
    elif "(chromium security severity: high)" in desc_lower:
        finding.severity = "HIGH"
    elif "(chromium security severity: medium)" in desc_lower:
        finding.severity = "MEDIUM"
    elif "(chromium security severity: low)" in desc_lower:
        finding.severity = "LOW"
    # General severity keywords
    elif any(x in desc_lower for x in ["remote code execution", "rce", "arbitrary code"]):
        finding.severity = "CRITICAL"
    elif any(x in desc_lower for x in ["heap overflow", "buffer overflow", "use after free", "out of bounds write"]):
        finding.severity = "HIGH"
    elif any(x in desc_lower for x in ["out of bounds read", "information disclosure"]):
        finding.severity = "MEDIUM"
    elif any(x in desc_lower for x in ["denial of service", "dos"]):
        finding.severity = "MEDIUM"

    return finding


def _filter_and_sort_findings(findings: List[CVEFinding]) -> List[CVEFinding]:
    """Filter invalid CVEs and sort by severity then by date (newest first)"""
    # Filter out invalid/rejected CVEs
    valid_findings = [f for f in findings if _is_valid_cve(f)]

    # Infer severity from description for CVEs without CVSS scores
    valid_findings = [_infer_severity_from_description(f) for f in valid_findings]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    # Sort: exploited first, then severity, then date (newest first)
    # For date, we negate by using reverse string comparison (YYYY-MM-DD format works alphabetically)
    return sorted(
        valid_findings,
        key=lambda f: (
            0 if f.is_exploited else 1,  # Exploited first
            severity_order.get(f.severity, 4),  # Then by severity
            # Invert date string for descending order (newest first)
            "" if not f.published_date else "".join(chr(255 - ord(c)) for c in f.published_date),
        )
    )


def _generate_customized_action_plan(findings: List[CVEFinding]) -> List[str]:
    """
    Generate customized action plan for specific CVEs.
    Each action item is specific to a CVE with concrete remediation steps.
    """
    if not findings:
        return []  # Return empty - no "no vulnerabilities" message here

    plan = []

    # Process each CVE individually with specific recommendations
    for cve in findings[:8]:  # Limit to top 8 CVEs for action plan
        action = _generate_cve_specific_action(cve)
        if action:
            plan.append(action)

    return plan


def _generate_cve_specific_action(cve: CVEFinding) -> str:
    """Generate a specific action item for a single CVE"""
    desc_lower = cve.description.lower()
    severity = cve.severity
    cve_id = cve.cve

    # Determine urgency prefix
    if cve.is_exploited:
        prefix = f"🚨 {cve_id}"
        urgency = "URGENT"
    elif severity == "CRITICAL":
        prefix = f"🔴 {cve_id}"
        urgency = "CRITICAL"
    elif severity == "HIGH":
        prefix = f"🟠 {cve_id}"
        urgency = "HIGH"
    elif severity == "MEDIUM":
        prefix = f"🟡 {cve_id}"
        urgency = "MEDIUM"
    else:
        prefix = f"🔵 {cve_id}"
        urgency = "LOW"

    # Analyze vulnerability type and generate specific action
    action_detail = ""

    # Remote Code Execution
    if "remote code execution" in desc_lower or "rce" in desc_lower or "arbitrary code" in desc_lower:
        if cve.patch_link:
            action_detail = "RCE vulnerability - Apply patch and review network exposure"
        else:
            action_detail = "RCE vulnerability - Restrict network access until patch available"

    # Privilege Escalation
    elif "privilege escalation" in desc_lower or "elevated privileges" in desc_lower:
        if cve.patch_link:
            action_detail = "Privilege escalation - Apply patch and audit user permissions"
        else:
            action_detail = "Privilege escalation - Review least-privilege policies"

    # Buffer Overflow
    elif "buffer overflow" in desc_lower or "heap overflow" in desc_lower or "stack overflow" in desc_lower:
        if cve.patch_link:
            action_detail = "Memory corruption - Apply patch immediately"
        else:
            action_detail = "Memory corruption - Enable exploit mitigations (ASLR, DEP)"

    # SQL Injection
    elif "sql injection" in desc_lower:
        action_detail = "SQL injection - Review parameterized queries and input validation"

    # XSS
    elif "cross-site scripting" in desc_lower or "xss" in desc_lower:
        action_detail = "XSS vulnerability - Review output encoding and CSP headers"

    # Authentication/Authorization bypass
    elif "authentication bypass" in desc_lower or "authorization bypass" in desc_lower or "auth bypass" in desc_lower:
        if cve.patch_link:
            action_detail = "Auth bypass - Apply patch and review access logs"
        else:
            action_detail = "Auth bypass - Implement additional access controls"

    # Denial of Service
    elif "denial of service" in desc_lower or "dos" in desc_lower:
        if cve.patch_link:
            action_detail = "DoS vulnerability - Apply patch, consider rate limiting"
        else:
            action_detail = "DoS vulnerability - Implement rate limiting and monitoring"

    # Information Disclosure
    elif "information disclosure" in desc_lower or "sensitive information" in desc_lower or "data exposure" in desc_lower:
        action_detail = "Data exposure risk - Review data access controls and logging"

    # Use After Free
    elif "use after free" in desc_lower or "use-after-free" in desc_lower:
        if cve.patch_link:
            action_detail = "Memory safety issue - Apply patch immediately"
        else:
            action_detail = "Memory safety issue - Consider sandboxing affected component"

    # Path Traversal
    elif "path traversal" in desc_lower or "directory traversal" in desc_lower:
        action_detail = "Path traversal - Review file access controls and input sanitization"

    # Default based on patch availability
    else:
        if cve.patch_link:
            action_detail = f"Apply security update"
        else:
            action_detail = f"Monitor vendor for patch release"

    # Add exploited warning
    if cve.is_exploited:
        action_detail = f"ACTIVELY EXPLOITED - {action_detail}"

    return f"{prefix}: {action_detail}"

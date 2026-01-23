"""
CVE Analysis API Endpoint
Handles vulnerability queries and returns grouped results
Supports direct NVD API queries for OS-specific vulnerabilities

Security: Input sanitization against OWASP Top 10 attacks
Rate limiting: 30 requests/minute per IP
"""

import re
import logging
from typing import Optional, List

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

from app.core.os_detector import detect_os_from_user_agent
from app.core.input_sanitizer import (
    sanitize_query,
    validate_limit,
    log_security_event,
    escape_for_display
)
from app.utils.startup import ensure_rag_initialized
from app.services.cve_collector import CVEDataCollector
from app.services.llm_service import get_llm_service, check_llm_status
from app.core.sla_tracker import get_sla_tracker, SLAStatus

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
        return validate_limit(v, max_limit=50, default=20)


class CVEReference(BaseModel):
    """CVE Reference link"""
    url: str
    source: str  # "official" (from CVE/NVD), "vendor" (from vendor security page)
    tags: List[str] = []  # e.g., ["Patch", "Vendor Advisory"]


class SLAInfoResponse(BaseModel):
    """SLA information for a CVE"""
    sla_days: int
    deadline: Optional[str] = None
    days_remaining: Optional[int] = None
    hours_remaining: Optional[int] = None
    status: str  # "on_track", "due_soon", "overdue", "unknown"
    status_label: str
    priority_rank: int
    priority_label: str
    policy_reference: str
    is_kev: bool
    recommended_action: Optional[str] = None


class CVEFinding(BaseModel):
    """Individual CVE finding"""
    cve: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    published_date: str
    last_modified_date: Optional[str] = None
    is_exploited: bool
    patch_link: Optional[str]
    nvd_link: Optional[str] = None  # Link to NVD database
    references: List[CVEReference] = []  # Official references from CVE
    affected_versions: List[str] = []  # Detailed affected version info from CPE
    os_tags: List[str]
    note: Optional[str] = None
    remediation_summary: Optional[str] = None  # Short summary for collapsed view
    source_type: Optional[str] = None  # "os", "browser", or None for general
    sla_info: Optional[SLAInfoResponse] = None  # SLA tracking information


class LLMAnalysis(BaseModel):
    """LLM-powered analysis result"""
    affects_user: Optional[bool] = None
    confidence: str = "low"
    explanation: str = ""
    recommended_action: str = ""
    priority: str = "medium"


class CVEResultGroup(BaseModel):
    """Group of CVE findings"""
    findings: List[CVEFinding]
    action_plan: List[str] = []


class SLASummary(BaseModel):
    """SLA compliance summary"""
    total: int = 0
    on_track: int = 0
    due_soon: int = 0
    overdue: int = 0
    unknown: int = 0
    kev_count: int = 0
    compliance_rate: float = 0.0


class CVEAnalyzeResponse(BaseModel):
    """Response model for CVE analysis"""
    detected_os: dict
    your_system: CVEResultGroup
    other_systems: CVEResultGroup
    query: str
    search_description: str  # Human-readable search description
    total_results: int
    llm_available: bool = False  # Whether LLM analysis is available
    sla_summary: Optional[SLASummary] = None  # SLA compliance summary


class LLMStatusResponse(BaseModel):
    """LLM service status"""
    available: bool
    model: str
    base_url: str


@router.get("/llm/status", response_model=LLMStatusResponse)
@limiter.limit("60/minute")
async def get_llm_status(request: Request) -> LLMStatusResponse:
    """Check if LLM service (Ollama) is available"""
    status = await check_llm_status()
    return LLMStatusResponse(**status)


class CVEDeepAnalysisRequest(BaseModel):
    """Request for LLM-powered deep CVE analysis"""
    cve_id: str
    description: str
    severity: str
    user_system: str  # e.g., "Windows 11 22H2"
    affected_versions: List[str] = []


class CVEDeepAnalysisResponse(BaseModel):
    """LLM-powered deep analysis result"""
    cve_id: str
    affects_user: Optional[bool]
    confidence: str
    explanation: str
    recommended_action: str
    priority: str
    llm_used: bool


@router.post("/cve/deep-analyze", response_model=CVEDeepAnalysisResponse)
@limiter.limit("10/minute")
async def deep_analyze_cve(request: Request, body: CVEDeepAnalysisRequest) -> CVEDeepAnalysisResponse:
    """
    Use LLM to perform deep analysis of a specific CVE.

    Analyzes whether the CVE affects the user's specific system
    and provides customized recommendations.

    Requires Ollama to be running with llama3.2:3b model.
    """
    llm_service = get_llm_service()

    result = await llm_service.analyze_cve_impact(
        cve_id=body.cve_id,
        description=body.description,
        severity=body.severity,
        user_system=body.user_system,
        affected_versions=body.affected_versions
    )

    return CVEDeepAnalysisResponse(
        cve_id=body.cve_id,
        affects_user=result.get("affects_user"),
        confidence=result.get("confidence", "low"),
        explanation=result.get("explanation", ""),
        recommended_action=result.get("recommended_action", ""),
        priority=result.get("priority", "medium"),
        llm_used=await llm_service.is_available()
    )


@router.get("/cve/latest", response_model=CVEAnalyzeResponse)
@limiter.limit("30/minute")
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

        # Fetch CVEs for each keyword with OVER-FETCH strategy
        # Fetch 3x the limit to ensure we have enough after deduplication and filtering
        over_fetch_ratio = 3
        fetch_limit = limit * over_fetch_ratio

        os_cves = []
        browser_cves = []

        for i, keyword in enumerate(search_keywords[:2]):  # Limit to 2 searches
            cves = await collector.fetch_by_keyword(keyword, limit=fetch_limit)
            # Tag CVEs with source type (first keyword is OS, second is browser)
            source_type = "os" if i == 0 else "browser"
            for cve in cves:
                cve["_source_type"] = source_type

            if source_type == "os":
                os_cves.extend(cves)
            else:
                browser_cves.extend(cves)

        # Combine all CVEs - deduplication and sorting will happen in _filter_and_sort_findings
        # This ensures we pick the best CVEs across both sources
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

    # Calculate SLA summary
    sla_summary = _calculate_sla_summary(your_system_findings)

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
        total_results=len(your_system_findings),
        sla_summary=sla_summary
    )


@router.post("/cve/analyze", response_model=CVEAnalyzeResponse)
@limiter.limit("30/minute")
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
    search_source = "none"

    # =================================================================
    # STEP 1: Try NVD CPE-based search (Primary - Most Precise)
    # =================================================================
    collector = CVEDataCollector()

    # Use the keyword directly - CVEDataCollector handles CPE mapping internally
    search_keyword = OS_KEYWORD_MAPPING.get(detected_os_keyword, body.query) if detected_os_keyword else body.query
    logger.info(f"Searching NVD with CPE for: {search_keyword}")

    nvd_cves = await collector.fetch_by_keyword(search_keyword, limit=body.limit * 2, years=3)

    if nvd_cves:
        your_system_findings = _filter_and_sort_findings([
            _cve_to_finding(cve) for cve in nvd_cves
        ])[:body.limit]
        search_source = "nvd_cpe"
        logger.info(f"Found {len(your_system_findings)} CVEs from NVD CPE search for: {search_keyword}")

    # =================================================================
    # STEP 2: Fallback to RAG semantic search if NVD returns nothing
    # =================================================================
    if not your_system_findings:
        logger.info(f"NVD CPE search returned no results, falling back to RAG for: {body.query}")

        # Ensure RAG engine is initialized
        if not await ensure_rag_initialized(request.app):
            raise HTTPException(
                status_code=503,
                detail="System is initializing. Please try again in a moment."
            )

        rag_engine = request.app.state.rag_engine

        # Perform semantic search with RAG
        results = await rag_engine.search(
            query=body.query,
            os_tags=None,  # Don't filter by OS for manual searches
            limit=body.limit * 2,
            include_other_os=False
        )

        # Get RAG results
        rag_results = results.get("your_system", [])

        if rag_results:
            your_system_findings = _filter_and_sort_findings([
                _cve_to_finding(cve) for cve in rag_results
            ])[:body.limit]
            search_source = "rag_semantic"
            logger.info(f"Found {len(your_system_findings)} CVEs from RAG semantic search")

    # Log search source for debugging
    logger.info(f"Search completed. Source: {search_source}, Results: {len(your_system_findings)}")

    # Generate customized action plan for ALL CVEs found (not just your_system)
    all_findings = your_system_findings + other_system_findings
    action_plan = _generate_customized_action_plan(all_findings)

    # Calculate SLA summary
    sla_summary = _calculate_sla_summary(all_findings)

    # Check LLM availability
    llm_status = await check_llm_status()

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
        total_results=len(your_system_findings) + len(other_system_findings),
        llm_available=llm_status.get("available", False),
        sla_summary=sla_summary
    )


def _cve_to_finding(cve: dict, include_os_note: bool = False, source_type: Optional[str] = None) -> CVEFinding:
    """Convert CVE dict to CVEFinding model with SLA information"""
    patch_links = cve.get("patch_links", [])
    os_tags = cve.get("os_tags", [])
    cve_id = cve.get("cve_id", "")
    severity = cve.get("severity", "UNKNOWN")
    is_exploited = cve.get("is_exploited", False)
    published_date = cve.get("published_date", "")
    last_modified_date = cve.get("last_modified_date", "")

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

    # Build references list from CVE data
    references = []
    raw_refs = cve.get("references", [])

    # Process references - could be list of dicts or list of strings
    for ref in raw_refs[:5]:  # Limit to 5 references
        if isinstance(ref, dict):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
        elif isinstance(ref, str):
            url = ref
            tags = []
        else:
            continue

        if url:
            # Determine if this is a patch/advisory link
            is_patch = any(t in ["Patch", "Vendor Advisory", "Mitigation"] for t in tags)
            if not is_patch:
                # Check URL for common patch indicators
                url_lower = url.lower()
                if any(x in url_lower for x in ["patch", "advisory", "security", "update", "bulletin"]):
                    is_patch = True

            references.append(CVEReference(
                url=url,
                source="official",  # From CVE/NVD database
                tags=tags if tags else (["Vendor Advisory"] if is_patch else [])
            ))

    # Get affected versions
    affected_versions = cve.get("affected_versions", [])

    # Calculate SLA information
    sla_tracker = get_sla_tracker()
    sla_info = sla_tracker.calculate_sla(
        cve_id=cve_id,
        severity=severity,
        is_kev=is_exploited,  # KEV status from CISA
        published_date=published_date
    )
    sla_response = SLAInfoResponse(
        sla_days=sla_info.sla_days,
        deadline=sla_info.deadline.isoformat() if sla_info.deadline else None,
        days_remaining=sla_info.days_remaining,
        hours_remaining=sla_info.hours_remaining,
        status=sla_info.status.value,
        status_label=sla_info.status_label,
        priority_rank=sla_info.priority_rank,
        priority_label=sla_info.priority_label,
        policy_reference=sla_info.policy_reference,
        is_kev=sla_info.is_kev,
        recommended_action=sla_info.recommended_action
    )

    return CVEFinding(
        cve=cve_id,
        title=cve.get("title", ""),
        description=cve.get("description", "")[:500],  # Truncate long descriptions
        severity=severity,
        cvss_score=cve.get("cvss_score"),
        published_date=published_date,
        last_modified_date=last_modified_date,
        is_exploited=is_exploited,
        patch_link=patch_links[0] if patch_links else None,
        nvd_link=nvd_link,
        references=references,
        affected_versions=affected_versions,
        os_tags=os_tags,
        note=note,
        remediation_summary=remediation_summary,
        source_type=source_type,
        sla_info=sla_response
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
    """
    Filter invalid CVEs, deduplicate, and sort by priority (KEV first, then severity, then date).

    Priority order (per CISA BOD 22-01):
    1. KEV + Critical
    2. KEV + High
    3. KEV + Medium
    4. KEV + Low
    5. Critical (non-KEV)
    6. High (non-KEV)
    7. Medium (non-KEV)
    8. Low (non-KEV)

    Within same priority: newest CVEs first (by published_date)
    """
    # Filter out invalid/rejected CVEs
    valid_findings = [f for f in findings if _is_valid_cve(f)]

    # Deduplicate by CVE ID (keep the first occurrence which has more complete data)
    seen_cve_ids = set()
    unique_findings = []
    for f in valid_findings:
        if f.cve and f.cve not in seen_cve_ids:
            seen_cve_ids.add(f.cve)
            unique_findings.append(f)
    valid_findings = unique_findings

    # Infer severity from description for CVEs without CVSS scores
    valid_findings = [_infer_severity_from_description(f) for f in valid_findings]

    # Sort by SLA priority rank (which implements KEV > CVSS logic)
    # Fallback to old logic if sla_info not present
    def sort_key(f: CVEFinding):
        # Use SLA priority rank if available (lower = higher priority)
        if f.sla_info:
            priority = f.sla_info.priority_rank
        else:
            # Fallback: KEV first, then severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            kev_offset = 0 if f.is_exploited else 4
            priority = kev_offset + severity_order.get(f.severity.upper(), 4)

        # Secondary sort: SLA status (overdue first, then due_soon)
        sla_status_order = {"overdue": 0, "due_soon": 1, "on_track": 2, "unknown": 3}
        sla_status = f.sla_info.status if f.sla_info else "unknown"
        status_priority = sla_status_order.get(sla_status, 3)

        # Tertiary sort: date (newest first)
        date_key = "" if not f.published_date else "".join(chr(255 - ord(c)) for c in f.published_date)

        return (priority, status_priority, date_key)

    return sorted(valid_findings, key=sort_key)


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


def _calculate_sla_summary(findings: List[CVEFinding]) -> SLASummary:
    """Calculate SLA compliance summary from findings"""
    summary = SLASummary(
        total=len(findings),
        on_track=0,
        due_soon=0,
        overdue=0,
        unknown=0,
        kev_count=0,
        compliance_rate=0.0
    )

    for finding in findings:
        if finding.sla_info:
            status = finding.sla_info.status
            if status == "on_track":
                summary.on_track += 1
            elif status == "due_soon":
                summary.due_soon += 1
            elif status == "overdue":
                summary.overdue += 1
            else:
                summary.unknown += 1

            if finding.sla_info.is_kev:
                summary.kev_count += 1
        else:
            summary.unknown += 1

    # Calculate compliance rate (non-overdue / total with known status)
    known_count = summary.total - summary.unknown
    if known_count > 0:
        compliant = summary.on_track + summary.due_soon
        summary.compliance_rate = round((compliant / known_count) * 100, 1)

    return summary

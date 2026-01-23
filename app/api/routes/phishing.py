"""
Phishing Analysis API Endpoint
Analyzes uploaded emails for phishing indicators with detailed breakdown
Integrates with external APIs (Google Safe Browsing, VirusTotal) for enhanced detection

Security: Input sanitization against OWASP Top 10 attacks
Rate limiting: 10 requests/minute per IP for file uploads
"""

from typing import Optional, List, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request
from pydantic import BaseModel
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.utils.email_parser import get_email_parser
from app.core.phishing_analyzer import analyze_email
from app.core.url_reputation import check_url_reputation, check_urls_batch, get_checker
from app.core.domain_checker import get_domain_checker
from app.core.input_sanitizer import (
    sanitize_filename,
    sanitize_email_content,
    validate_uploaded_file,
    log_security_event
)
from app.services.llm_service import get_llm_service

logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)
router = APIRouter()


class CheckResult(BaseModel):
    """Individual check result"""
    category: str
    name: str
    status: str
    score: int
    description: str
    details: Optional[str] = None
    reference_url: Optional[str] = None


class DomainAnalysisResult(BaseModel):
    """Domain analysis result"""
    domain: str
    is_suspicious: bool
    risk_level: str
    checks: List[dict] = []


class AttachmentAnalysisResult(BaseModel):
    """Attachment analysis result"""
    filename: str
    extension: str
    risk_level: str
    description: str
    reference_url: Optional[str] = None


class ScoringCriteria(BaseModel):
    """Scoring criteria info"""
    category: str
    description: str
    max_points: Optional[int] = None
    url: Optional[str] = None


class URLReputationCheck(BaseModel):
    """URL reputation check result from external APIs"""
    source: str
    is_malicious: bool
    threat_type: Optional[str] = None
    confidence: float
    details: Optional[str] = None
    reference_url: Optional[str] = None


class URLReputationResult(BaseModel):
    """Full URL reputation report"""
    url: str
    domain: str
    is_malicious: bool
    risk_score: int
    threat_types: List[str]
    recommendation: str
    checks: List[URLReputationCheck]
    api_status: dict


class LLMAnalysisResult(BaseModel):
    """LLM analysis result for phishing detection"""
    is_phishing: Optional[bool] = None
    confidence: str = "low"
    risk_score_adjustment: int = 0
    explanation: str = ""
    key_indicators: List[str] = []


class PhishingAnalysisResponse(BaseModel):
    """Response model for phishing analysis"""
    is_phishing: bool
    confidence: str
    risk_level: str
    risk_score: int
    max_score: int
    recommendation: str
    explanation: str
    checks: List[CheckResult]
    domain_analyses: List[DomainAnalysisResult]
    attachment_analyses: List[AttachmentAnalysisResult]
    scoring_criteria: List[dict]
    email_metadata: dict
    url_reputation: Optional[List[URLReputationResult]] = None
    api_status: Optional[dict] = None
    llm_analysis: Optional[LLMAnalysisResult] = None  # LLM-powered analysis


@router.post("/phishing/analyze", response_model=PhishingAnalysisResponse)
@limiter.limit("10/minute")
async def analyze_phishing(
    request: Request,
    file: Optional[UploadFile] = File(None),
    email_text: Optional[str] = Form(None)
) -> PhishingAnalysisResponse:
    """
    Analyze an email for phishing indicators with detailed breakdown

    Accepts either:
    - file: An uploaded .eml file
    - email_text: Plain text email content

    Security:
    - Input validation against OWASP Top 10
    - File type validation
    - Content length limits

    Returns detailed analysis including:
    - Risk score with breakdown by category
    - Domain analysis for all URLs
    - Attachment risk assessment
    - Scoring criteria with reference URLs
    """
    # Get client IP for security logging
    client_ip = request.client.host if request.client else "unknown"

    if not file and not email_text:
        raise HTTPException(
            status_code=400,
            detail="Please provide either a .eml file or email text"
        )

    parser = get_email_parser()
    email_data = {}

    # Parse the email
    if file:
        # Read file content first
        content = await file.read()
        filename = file.filename or "unknown.eml"

        # Comprehensive file validation (checks magic bytes, extension, size, etc.)
        is_valid, error_msg = validate_uploaded_file(content, filename)
        if not is_valid:
            log_security_event("FILE_REJECTED", f"{error_msg} - Filename: {filename}", client_ip)
            raise HTTPException(status_code=400, detail=error_msg)

        email_data = parser.parse_eml(content)
    else:
        # Validate email text content
        sanitized_content, content_error = sanitize_email_content(email_text)
        if content_error:
            log_security_event("INVALID_EMAIL_CONTENT", content_error, client_ip)
            raise HTTPException(status_code=400, detail=content_error)

        email_data = parser.parse_text(email_text)

    # Check for parsing errors
    if "error" in email_data:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse email: {email_data['error']}"
        )

    # Prepare email content for analysis
    analysis_input = {
        "from": email_data.get("from", "Unknown"),
        "to": email_data.get("to", "Unknown"),
        "subject": email_data.get("subject", "No subject"),
        "date": email_data.get("date", "Unknown"),
        "body": email_data.get("body", "")[:5000],
        "urls": email_data.get("urls", []),
        "attachments": email_data.get("attachments", []),
        "headers": email_data.get("headers", {})
    }

    # Perform analysis
    analysis = analyze_email(analysis_input)

    # Check URL reputation using external APIs
    urls = email_data.get("urls", [])[:5]  # Limit to 5 URLs for API rate limits
    url_reputation = []
    api_status = get_checker().get_api_status()

    if urls:
        try:
            url_reputation = await check_urls_batch(urls)
            logger.info(f"URL reputation check completed for {len(urls)} URLs")

            # Enhance analysis with external API results
            for url_report in url_reputation:
                if url_report.get("is_malicious"):
                    # Add external API findings to analysis
                    analysis["risk_score"] = min(100, analysis["risk_score"] + url_report.get("risk_score", 0) // 2)

                    # Add check for external API detection
                    for check in url_report.get("checks", []):
                        if check.get("is_malicious"):
                            analysis["checks"].append({
                                "category": "external_api",
                                "name": f"{check.get('source')} Detection",
                                "status": "critical",
                                "score": 30,
                                "description": check.get("details", "Malicious URL detected"),
                                "details": f"Threat: {check.get('threat_type', 'Unknown')}",
                                "reference_url": check.get("reference_url")
                            })

                    # Update domain analysis
                    for domain_analysis in analysis.get("domain_analyses", []):
                        if domain_analysis.get("domain") == url_report.get("domain"):
                            domain_analysis["is_suspicious"] = True
                            domain_analysis["risk_level"] = "critical"

            # Recalculate is_phishing based on enhanced score
            if analysis["risk_score"] >= 50:
                analysis["is_phishing"] = True
                analysis["risk_level"] = "high" if analysis["risk_score"] >= 50 else "medium"
            if analysis["risk_score"] >= 70:
                analysis["risk_level"] = "critical"
                analysis["confidence"] = "high"

        except Exception as e:
            logger.error(f"URL reputation check failed: {e}")

    # Add domain trust information to domain analyses
    domain_checker = get_domain_checker()
    for domain_analysis in analysis.get("domain_analyses", []):
        domain = domain_analysis.get("domain", "")
        if domain:
            trust_info = domain_checker.get_domain_trust_score(domain)
            domain_analysis["trust_score"] = trust_info.get("trust_score", 50)
            domain_analysis["trust_level"] = trust_info.get("trust_level", "medium")
            domain_analysis["trust_indicators"] = trust_info.get("trust_indicators", [])
            domain_analysis["risk_indicators"] = trust_info.get("risk_indicators", [])
            domain_analysis["is_known_trusted"] = trust_info.get("is_known_trusted", False)

            # Add trust checks to domain
            for indicator in trust_info.get("trust_indicators", []):
                domain_analysis["checks"].append({
                    "description": indicator,
                    "is_trust": True
                })
            for indicator in trust_info.get("risk_indicators", []):
                domain_analysis["checks"].append({
                    "description": indicator,
                    "is_risk": True
                })

    # LLM-powered analysis for additional insights
    llm_analysis_result = None
    try:
        llm_service = get_llm_service()
        if await llm_service.is_available():
            llm_result = await llm_service.analyze_phishing_email(
                from_addr=analysis_input.get("from", ""),
                subject=analysis_input.get("subject", ""),
                body=analysis_input.get("body", "")[:500],
                urls=analysis_input.get("urls", [])[:5],
                rule_based_score=analysis["risk_score"]
            )

            llm_analysis_result = LLMAnalysisResult(
                is_phishing=llm_result.get("is_phishing"),
                confidence=llm_result.get("confidence", "low"),
                risk_score_adjustment=llm_result.get("risk_score_adjustment", 0),
                explanation=llm_result.get("explanation", ""),
                key_indicators=llm_result.get("key_indicators", [])
            )

            # Apply LLM score adjustment (limited to ±20 points)
            adjustment = llm_result.get("risk_score_adjustment", 0)
            if adjustment != 0:
                original_score = analysis["risk_score"]
                analysis["risk_score"] = max(0, min(100, original_score + adjustment))
                logger.info(f"LLM adjusted phishing score: {original_score} -> {analysis['risk_score']}")

                # Update is_phishing and risk_level based on adjusted score
                if analysis["risk_score"] >= 70:
                    analysis["is_phishing"] = True
                    analysis["risk_level"] = "critical"
                elif analysis["risk_score"] >= 50:
                    analysis["is_phishing"] = True
                    analysis["risk_level"] = "high"
                elif analysis["risk_score"] >= 30:
                    analysis["is_phishing"] = True
                    analysis["risk_level"] = "medium"
                elif analysis["risk_score"] >= 15:
                    analysis["is_phishing"] = False
                    analysis["risk_level"] = "low"
                else:
                    analysis["is_phishing"] = False
                    analysis["risk_level"] = "safe"
    except Exception as e:
        logger.warning(f"LLM phishing analysis failed: {e}")

    # Extract metadata for response
    email_metadata = {
        "from": email_data.get("from", "Unknown"),
        "to": email_data.get("to", "Unknown"),
        "subject": email_data.get("subject", "No subject"),
        "date": email_data.get("date", "Unknown"),
        "urls_count": len(email_data.get("urls", [])),
        "attachments_count": len(email_data.get("attachments", [])),
        "attachments": email_data.get("attachments", []),
        "urls": email_data.get("urls", [])[:10],  # First 10 URLs
        "has_html": bool(email_data.get("body_html"))
    }

    return PhishingAnalysisResponse(
        is_phishing=analysis["is_phishing"],
        confidence=analysis["confidence"],
        risk_level=analysis["risk_level"],
        risk_score=analysis["risk_score"],
        max_score=analysis["max_score"],
        recommendation=analysis["recommendation"],
        explanation=analysis["explanation"],
        checks=analysis["checks"],
        domain_analyses=analysis["domain_analyses"],
        attachment_analyses=analysis["attachment_analyses"],
        scoring_criteria=analysis["scoring_criteria"],
        email_metadata=email_metadata,
        url_reputation=url_reputation,
        api_status=api_status,
        llm_analysis=llm_analysis_result
    )


@router.post("/phishing/analyze-text")
@limiter.limit("20/minute")
async def analyze_phishing_text(
    request: Request,
    subject: str = Form(""),
    sender: str = Form(""),
    body: str = Form("")
) -> PhishingAnalysisResponse:
    """
    Analyze email content provided as form fields
    Useful for quick analysis without file upload
    """
    if not body and not subject:
        raise HTTPException(
            status_code=400,
            detail="Please provide at least subject or body content"
        )

    parser = get_email_parser()

    # Extract URLs from body
    urls = parser._extract_urls(body)

    # Prepare analysis input
    analysis_input = {
        "from": sender or "Unknown",
        "to": "Unknown",
        "subject": subject,
        "date": "Unknown",
        "body": body[:5000],
        "urls": urls,
        "attachments": [],
        "headers": {}
    }

    # Perform analysis
    analysis = analyze_email(analysis_input)

    # Check URL reputation using external APIs
    url_reputation = []
    api_status = get_checker().get_api_status()

    if urls:
        try:
            url_reputation = await check_urls_batch(urls[:5])
            logger.info(f"URL reputation check completed for {len(urls[:5])} URLs")

            # Enhance analysis with external API results
            for url_report in url_reputation:
                if url_report.get("is_malicious"):
                    analysis["risk_score"] = min(100, analysis["risk_score"] + url_report.get("risk_score", 0) // 2)

                    for check in url_report.get("checks", []):
                        if check.get("is_malicious"):
                            analysis["checks"].append({
                                "category": "external_api",
                                "name": f"{check.get('source')} Detection",
                                "status": "critical",
                                "score": 30,
                                "description": check.get("details", "Malicious URL detected"),
                                "details": f"Threat: {check.get('threat_type', 'Unknown')}",
                                "reference_url": check.get("reference_url")
                            })

                    for domain_analysis in analysis.get("domain_analyses", []):
                        if domain_analysis.get("domain") == url_report.get("domain"):
                            domain_analysis["is_suspicious"] = True
                            domain_analysis["risk_level"] = "critical"

            if analysis["risk_score"] >= 50:
                analysis["is_phishing"] = True
                analysis["risk_level"] = "high"
            if analysis["risk_score"] >= 70:
                analysis["risk_level"] = "critical"
                analysis["confidence"] = "high"

        except Exception as e:
            logger.error(f"URL reputation check failed: {e}")

    email_metadata = {
        "from": sender or "Unknown",
        "to": "Unknown",
        "subject": subject,
        "date": "Unknown",
        "urls_count": len(urls),
        "attachments_count": 0,
        "attachments": [],
        "urls": urls[:10],
        "has_html": False
    }

    return PhishingAnalysisResponse(
        is_phishing=analysis["is_phishing"],
        confidence=analysis["confidence"],
        risk_level=analysis["risk_level"],
        risk_score=analysis["risk_score"],
        max_score=analysis["max_score"],
        recommendation=analysis["recommendation"],
        explanation=analysis["explanation"],
        checks=analysis["checks"],
        domain_analyses=analysis["domain_analyses"],
        attachment_analyses=analysis["attachment_analyses"],
        scoring_criteria=analysis["scoring_criteria"],
        email_metadata=email_metadata,
        url_reputation=url_reputation,
        api_status=api_status
    )

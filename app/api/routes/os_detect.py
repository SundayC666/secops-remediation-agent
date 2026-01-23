"""
OS Detection API Endpoint
Detects client operating system and browser from HTTP User-Agent header
"""

from typing import Optional, List

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.core.os_detector import detect_os_from_user_agent, detect_browser, OSInfo


router = APIRouter()


class BrowserDetectResponse(BaseModel):
    """Response model for browser detection"""
    name: Optional[str]
    version: Optional[str]
    engine: Optional[str]


class OSDetectResponse(BaseModel):
    """Response model for OS detection"""
    family: str
    version: Optional[str]
    normalized: str
    tags: List[str]
    browser: Optional[BrowserDetectResponse] = None


@router.get("/os/detect", response_model=OSDetectResponse)
async def detect_os(request: Request) -> OSDetectResponse:
    """
    Detect the client's operating system and browser from User-Agent header

    This endpoint reads the User-Agent HTTP header and parses it
    to identify the client's operating system and browser.
    The detected OS is used to filter CVE results to show relevant vulnerabilities.

    Returns:
        OSDetectResponse with family, version, normalized name, tags, and browser info
    """
    user_agent = request.headers.get("User-Agent", "")

    os_info: OSInfo = detect_os_from_user_agent(user_agent)
    browser_info = detect_browser(user_agent)

    browser_response = None
    if browser_info:
        browser_response = BrowserDetectResponse(
            name=browser_info.name,
            version=browser_info.version,
            engine=browser_info.engine
        )

    return OSDetectResponse(
        family=os_info.family,
        version=os_info.version,
        normalized=os_info.normalized,
        tags=os_info.tags,
        browser=browser_response
    )

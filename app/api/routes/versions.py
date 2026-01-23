"""
Version Tracking API Endpoint
Returns latest OS/software versions for quick search buttons
Rate limiting: 60/minute for reads, 5/minute for refresh
"""

import logging
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.services.version_tracker import get_version_tracker

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)
router = APIRouter()


class QuickButton(BaseModel):
    """Quick search button data"""
    label: str
    query: str
    icon: str
    css_class: str


class VersionInfo(BaseModel):
    """Version information for a product"""
    version: str
    query: str
    display: str
    codename: str = None


class ProductVersions(BaseModel):
    """Product with its versions"""
    name: str
    icon: str
    css_class: str
    versions: List[VersionInfo]


class QuickButtonsResponse(BaseModel):
    """Response for quick buttons endpoint"""
    buttons: List[QuickButton]
    cache_status: Dict[str, Any]


class AllVersionsResponse(BaseModel):
    """Response for all versions endpoint"""
    products: Dict[str, ProductVersions]
    cache_status: Dict[str, Any]


@router.get("/versions/buttons", response_model=QuickButtonsResponse)
@limiter.limit("60/minute")
async def get_quick_buttons(request: Request) -> QuickButtonsResponse:
    """
    Get quick search buttons with latest OS/software versions

    Returns formatted button data that can be directly rendered in the UI.
    Versions are automatically updated from NVD and cached for 24 hours.
    """
    try:
        tracker = get_version_tracker()
        buttons = await tracker.get_quick_buttons()
        cache_status = tracker.get_status()

        return QuickButtonsResponse(
            buttons=buttons,
            cache_status=cache_status
        )
    except Exception as e:
        logger.error(f"Failed to get quick buttons: {e}")
        raise HTTPException(status_code=500, detail="Failed to load version data")


@router.get("/versions/all", response_model=AllVersionsResponse)
@limiter.limit("30/minute")
async def get_all_versions(request: Request) -> AllVersionsResponse:
    """
    Get all tracked product versions

    Returns complete version information for all tracked products.
    """
    try:
        tracker = get_version_tracker()
        versions = await tracker.update_versions()
        cache_status = tracker.get_status()

        return AllVersionsResponse(
            products=versions,
            cache_status=cache_status
        )
    except Exception as e:
        logger.error(f"Failed to get versions: {e}")
        raise HTTPException(status_code=500, detail="Failed to load version data")


@router.post("/versions/refresh")
@limiter.limit("5/minute")
async def refresh_versions(request: Request) -> Dict[str, Any]:
    """
    Force refresh version cache

    Manually triggers a refresh of version data from NVD.
    Use sparingly to avoid hitting API rate limits.
    """
    try:
        tracker = get_version_tracker()
        await tracker.update_versions(force=True)
        cache_status = tracker.get_status()

        return {
            "status": "success",
            "message": "Version cache refreshed",
            "cache_status": cache_status
        }
    except Exception as e:
        logger.error(f"Failed to refresh versions: {e}")
        raise HTTPException(status_code=500, detail="Failed to refresh version data")

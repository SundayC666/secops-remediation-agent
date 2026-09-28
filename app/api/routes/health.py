"""
Health check endpoint
Provides system status information
"""

from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
import time

router = APIRouter()

# Track startup time
_startup_time = time.time()


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    version: str
    uptime_seconds: float
    timestamp: str


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint

    Returns:
        HealthResponse: System health status
    """
    uptime = time.time() - _startup_time

    return HealthResponse(
        status="healthy",
        version="2.0.0",
        uptime_seconds=round(uptime, 2),
        timestamp=datetime.utcnow().isoformat()
    )

"""
Health check endpoint
Provides system status information
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from datetime import datetime
import time

from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Track startup time
_startup_time = time.time()


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    version: str
    uptime_seconds: float
    timestamp: str


@router.get("/health", response_model=HealthResponse)
@limiter.limit("60/minute")
async def health_check(request: Request):
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

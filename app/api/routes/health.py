"""
Health check endpoint
Provides system status information
"""

from typing import Optional
from fastapi import APIRouter, Request
from pydantic import BaseModel
from datetime import datetime
import time

from app.utils.startup import get_init_status

router = APIRouter()

# Track startup time
_startup_time = time.time()


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    version: str
    uptime_seconds: float
    timestamp: str


class StatusResponse(BaseModel):
    """System status response model"""
    rag_ready: bool
    rag_initializing: bool
    cve_count: int
    error: Optional[str]


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


@router.get("/status", response_model=StatusResponse)
async def system_status(request: Request):
    """
    System status endpoint - check RAG initialization progress

    Returns:
        StatusResponse: RAG engine and CVE indexing status
    """
    status = get_init_status(request.app)

    return StatusResponse(
        rag_ready=status["initialized"],
        rag_initializing=status["initializing"],
        cve_count=status["cve_count"],
        error=status["error"]
    )

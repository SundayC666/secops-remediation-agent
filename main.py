"""
SecOps Remediation Agent v2.0
FastAPI-based security vulnerability analysis system with local LLM support

Entry point: python main.py
"""

import asyncio
import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.api.routes import health, os_detect, cve_analyze, phishing, versions
from app.utils.startup import initialize_system

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI application
app = FastAPI(
    title="SecOps Remediation Agent",
    description="Local-first security vulnerability analysis with OS detection and phishing analysis",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware - restrict origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://security-automation-platform.onrender.com",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not settings.DEBUG:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.on_event("startup")
async def startup_event():
    """Initialize system components on startup"""
    print("=" * 70)
    print("SecOps Remediation Agent v2.0")
    print("=" * 70)

    await initialize_system(app)

    print("=" * 70)
    print(f"System ready! Server running on {settings.SERVER_URL}")
    print(f"API Docs: {settings.SERVER_URL}/api/docs")
    print("=" * 70)


# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


# Include API routes
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(os_detect.router, prefix="/api", tags=["OS Detection"])
app.include_router(cve_analyze.router, prefix="/api", tags=["CVE Analysis"])
app.include_router(phishing.router, prefix="/api", tags=["Phishing Analysis"])
app.include_router(versions.router, prefix="/api", tags=["Version Tracking"])


@app.get("/")
async def serve_index():
    """Serve the main HTML page"""
    return FileResponse("static/index.html")


if __name__ == "__main__":
    # Run the server (PORT env var for Render deployment)
    port = int(os.environ.get("PORT", settings.PORT))
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=port,
        reload=settings.DEBUG,
        log_level="info"
    )

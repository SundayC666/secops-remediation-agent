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
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.api.routes import health, os_detect, cve_analyze, phishing, versions
from app.utils.startup import initialize_system


# Create FastAPI application
app = FastAPI(
    title="SecOps Remediation Agent",
    description="Local-first security vulnerability analysis with OS detection and phishing analysis",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)


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

"""
Startup initialization logic
Handles system component initialization on server startup
"""

import logging
import asyncio
from pathlib import Path
from fastapi import FastAPI

logger = logging.getLogger(__name__)

# Global initialization lock to prevent multiple concurrent initializations
_init_lock = asyncio.Lock()
_init_task = None


async def initialize_system(app: FastAPI):
    """
    Initialize system components on startup

    Starts background initialization of RAG engine while server
    becomes immediately available for basic requests.

    Args:
        app: FastAPI application instance
    """
    global _init_task

    try:
        logger.info("[1/2] Creating directories...")
        Path("data").mkdir(exist_ok=True)
        Path("lancedb").mkdir(exist_ok=True)

        # Set initial state
        app.state.initialized = False
        app.state.initializing = False
        app.state.cve_count = 0
        app.state.rag_engine = None
        app.state.init_error = None

        logger.info("[2/2] Starting background RAG initialization...")

        # Start background initialization
        _init_task = asyncio.create_task(_background_init(app))

        logger.info("Server ready - RAG initializing in background")

    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise


async def _background_init(app: FastAPI):
    """Background task to initialize RAG engine"""
    try:
        app.state.initializing = True

        # Import here to avoid loading at startup
        from app.core.rag_engine import rag_engine
        from app.services.cve_collector import CVEDataCollector

        logger.info("Background init: Loading embedding model...")
        await rag_engine.initialize()
        logger.info("Background init: Model loaded")

        logger.info("Background init: Fetching CVE data...")
        collector = CVEDataCollector()
        cves = await collector.fetch_all()
        logger.info(f"Background init: Fetched {len(cves)} CVEs")

        if cves:
            logger.info("Background init: Building vector index...")
            indexed_count = await rag_engine.index_cves(cves)
            app.state.cve_count = indexed_count
            logger.info(f"Background init: Indexed {indexed_count} CVEs")

        app.state.rag_engine = rag_engine
        app.state.initialized = True
        app.state.initializing = False

        exploited = sum(1 for c in cves if c.get("is_exploited"))
        logger.info(f"RAG ready: {len(cves)} CVEs, {exploited} actively exploited")

    except Exception as e:
        logger.error(f"Background init failed: {e}")
        import traceback
        traceback.print_exc()
        app.state.init_error = str(e)
        app.state.initializing = False


async def ensure_rag_initialized(app: FastAPI) -> bool:
    """
    Check if RAG engine is initialized

    Returns:
        True if ready, False if still initializing or failed
    """
    return getattr(app.state, "initialized", False)


def get_init_status(app: FastAPI) -> dict:
    """Get current initialization status"""
    return {
        "initialized": getattr(app.state, "initialized", False),
        "initializing": getattr(app.state, "initializing", False),
        "cve_count": getattr(app.state, "cve_count", 0),
        "error": getattr(app.state, "init_error", None)
    }

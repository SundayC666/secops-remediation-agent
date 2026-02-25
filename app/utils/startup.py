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


def _load_model_sync():
    """Load sentence transformer model synchronously (for thread pool)"""
    try:
        from sentence_transformers import SentenceTransformer
        # Pre-load the model to trigger any mutex locks in thread pool
        _ = SentenceTransformer('all-MiniLM-L6-v2')
        logger.info("Sentence Transformer model pre-loaded in thread pool")
    except Exception as e:
        logger.warning(f"Model pre-load failed (will retry on use): {e}")


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

        # Set initial state
        app.state.initialized = False
        app.state.initializing = False
        app.state.cve_count = 0
        app.state.rag_engine = None
        app.state.init_error = None

        logger.info("[2/2] RAG engine will initialize on first use (lazy loading)")

        # Don't start background init - let RAG initialize on first use
        # This prevents mutex lock from blocking the event loop at startup
        logger.info("Server ready - RAG will initialize on first search request")

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

        logger.info("Background init: Loading embedding model in thread pool...")
        # Run model loading in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _load_model_sync)

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
    Ensure RAG engine is initialized (lazy initialization).

    Returns:
        True if ready, False if initialization failed
    """
    global _init_task

    # Already initialized
    if getattr(app.state, "initialized", False):
        return True

    # Currently initializing - wait for it
    if getattr(app.state, "initializing", False):
        # Wait up to 60 seconds for initialization
        for _ in range(60):
            await asyncio.sleep(1)
            if getattr(app.state, "initialized", False):
                return True
            if getattr(app.state, "init_error", None):
                return False
        return False

    # Not yet started - trigger lazy initialization in thread pool
    async with _init_lock:
        # Double-check after acquiring lock
        if getattr(app.state, "initialized", False):
            return True

        if not getattr(app.state, "initializing", False):
            logger.info("Triggering lazy RAG initialization...")
            _init_task = asyncio.create_task(_background_init(app))

    # Wait for initialization to complete
    for _ in range(60):
        await asyncio.sleep(1)
        if getattr(app.state, "initialized", False):
            return True
        if getattr(app.state, "init_error", None):
            return False

    return False


def get_init_status(app: FastAPI) -> dict:
    """Get current initialization status"""
    return {
        "initialized": getattr(app.state, "initialized", False),
        "initializing": getattr(app.state, "initializing", False),
        "cve_count": getattr(app.state, "cve_count", 0),
        "error": getattr(app.state, "init_error", None)
    }

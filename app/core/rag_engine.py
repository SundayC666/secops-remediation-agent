"""
RAG Engine with Sentence Transformers + ChromaDB
Provides semantic search capability for CVE data as a fallback when CPE search returns no results.
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Lazy imports to avoid startup delay
_sentence_transformer = None
_chromadb = None


def _get_sentence_transformer():
    """Lazy load sentence transformer model"""
    global _sentence_transformer
    if _sentence_transformer is None:
        from sentence_transformers import SentenceTransformer
        # all-MiniLM-L6-v2: lightweight (80MB), fast, good quality
        _sentence_transformer = SentenceTransformer('all-MiniLM-L6-v2')
        logger.info("Loaded Sentence Transformer model: all-MiniLM-L6-v2")
    return _sentence_transformer


def _get_chromadb():
    """Lazy load chromadb"""
    global _chromadb
    if _chromadb is None:
        import chromadb
        _chromadb = chromadb
    return _chromadb


class RAGEngine:
    """
    RAG (Retrieval-Augmented Generation) Engine for CVE semantic search.

    Uses:
    - Sentence Transformers for text embeddings (all-MiniLM-L6-v2)
    - ChromaDB for vector storage and similarity search

    This provides semantic search capability when exact CPE-based search
    fails to find results.
    """

    COLLECTION_NAME = "cve_embeddings"
    DB_PATH = "data/chromadb"

    def __init__(self):
        self._client = None
        self._collection = None
        self._model = None
        self._initialized = False
        self._last_index_time: Optional[datetime] = None
        self._cve_count = 0

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def cve_count(self) -> int:
        return self._cve_count

    async def initialize(self, cves: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        Initialize the RAG engine.

        Args:
            cves: Optional list of CVE data to index. If None, loads existing index.

        Returns:
            True if initialization successful, False otherwise
        """
        if self._initialized:
            return True

        try:
            # Ensure data directory exists
            Path(self.DB_PATH).mkdir(parents=True, exist_ok=True)

            # Initialize ChromaDB
            chromadb = _get_chromadb()
            self._client = chromadb.PersistentClient(path=self.DB_PATH)

            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"description": "CVE embeddings for semantic search"}
            )

            # Check existing data
            existing_count = self._collection.count()

            if cves and len(cves) > 0:
                # Index provided CVEs
                await self.index_cves(cves)
                logger.info(f"Indexed {len(cves)} CVEs into RAG engine")
            elif existing_count > 0:
                logger.info(f"Using existing RAG index with {existing_count} CVEs")
                self._cve_count = existing_count
            else:
                logger.warning("RAG engine initialized with empty index")

            self._initialized = True
            return True

        except Exception as e:
            logger.error(f"Failed to initialize RAG engine: {e}")
            return False

    async def index_cves(self, cves: List[Dict[str, Any]]) -> int:
        """
        Index CVEs into ChromaDB with embeddings.

        Args:
            cves: List of CVE data dictionaries

        Returns:
            Number of CVEs indexed
        """
        if not cves:
            return 0

        # Ensure initialized
        if not self._client:
            chromadb = _get_chromadb()
            Path(self.DB_PATH).mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self.DB_PATH)

        # Load model (lazy)
        model = _get_sentence_transformer()

        # Prepare documents for embedding
        documents = []
        metadatas = []
        ids = []

        for cve in cves:
            cve_id = cve.get("cve_id", "")
            if not cve_id:
                continue

            # Create searchable text combining key fields
            description = cve.get("description", "")
            affected = " ".join(cve.get("affected_versions", []))
            tags = " ".join(cve.get("tags", []))

            # Combine into single searchable document
            doc_text = f"{cve_id} {description} {affected} {tags}"

            documents.append(doc_text)
            ids.append(cve_id)

            # Store metadata for retrieval
            metadatas.append({
                "cve_id": cve_id,
                "severity": cve.get("severity", "UNKNOWN"),
                "cvss_score": str(cve.get("cvss_score", "")),
                "published_date": cve.get("published_date", ""),
                "is_exploited": str(cve.get("is_exploited", False)),
                "description": description[:500],  # Truncate for storage
            })

        if not documents:
            return 0

        # Generate embeddings
        logger.info(f"Generating embeddings for {len(documents)} CVEs...")
        embeddings = model.encode(documents, show_progress_bar=False)

        # Clear existing data and add new
        try:
            # Delete existing collection and recreate
            self._client.delete_collection(self.COLLECTION_NAME)
        except Exception:
            pass  # Collection might not exist

        self._collection = self._client.create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "CVE embeddings for semantic search"}
        )

        # Add to ChromaDB
        self._collection.add(
            documents=documents,
            embeddings=embeddings.tolist(),
            metadatas=metadatas,
            ids=ids
        )

        self._cve_count = len(documents)
        self._last_index_time = datetime.now()
        self._initialized = True
        logger.info(f"Successfully indexed {self._cve_count} CVEs")
        return self._cve_count

    async def search(
        self,
        query: str,
        limit: int = 10,
        os_tags: Optional[List[str]] = None,
        min_severity: Optional[str] = None,
        include_other_os: bool = False
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Perform semantic search for CVEs.

        Args:
            query: Search query (natural language)
            limit: Maximum number of results
            os_tags: Optional OS tags to filter results (e.g., ['windows', 'macos'])
            min_severity: Optional minimum severity filter
            include_other_os: Whether to include CVEs from other OS

        Returns:
            Dictionary with 'your_system' and 'other_systems' CVE lists
        """
        if not self._initialized or not self._collection:
            logger.warning("RAG engine not initialized, returning empty results")
            return {"your_system": [], "other_systems": []}

        if self._collection.count() == 0:
            logger.warning("RAG index is empty, returning empty results")
            return {"your_system": [], "other_systems": []}

        try:
            # Load model and generate query embedding
            model = _get_sentence_transformer()
            query_embedding = model.encode(query)

            # Build where filter if needed
            where_filter = None
            if min_severity:
                severity_values = self._get_severity_values(min_severity)
                if severity_values:
                    where_filter = {"severity": {"$in": severity_values}}

            # Perform similarity search
            results = self._collection.query(
                query_embeddings=[query_embedding.tolist()],
                n_results=min(limit * 2, 50),  # Fetch more to filter
                where=where_filter,
                include=["documents", "metadatas", "distances"]
            )

            # Process results
            your_system = []
            other_systems = []

            if results and results['metadatas'] and len(results['metadatas']) > 0:
                for i, metadata in enumerate(results['metadatas'][0]):
                    distance = results['distances'][0][i] if results['distances'] else 1.0

                    # Convert distance to similarity score (0-1)
                    # ChromaDB uses L2 distance, smaller = more similar
                    similarity = max(0, 1 - (distance / 2))

                    cve_result = {
                        "cve_id": metadata.get("cve_id", ""),
                        "title": f"{metadata.get('cve_id', '')}: {metadata.get('description', '')[:80]}...",
                        "description": metadata.get("description", ""),
                        "severity": metadata.get("severity", "UNKNOWN"),
                        "cvss_score": self._safe_float(metadata.get("cvss_score")),
                        "published_date": metadata.get("published_date", ""),
                        "is_exploited": metadata.get("is_exploited") == "True",
                        "similarity_score": round(similarity, 3),
                        "source": "rag"
                    }

                    # Categorize by OS if tags provided
                    if os_tags:
                        doc_text = results['documents'][0][i].lower() if results['documents'] else ""
                        is_matching_os = any(tag.lower() in doc_text for tag in os_tags)

                        if is_matching_os:
                            your_system.append(cve_result)
                        elif include_other_os:
                            other_systems.append(cve_result)
                    else:
                        your_system.append(cve_result)

            # Sort by similarity score
            your_system.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
            other_systems.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)

            # Limit results
            your_system = your_system[:limit]
            other_systems = other_systems[:limit]

            logger.info(f"RAG search for '{query}': {len(your_system)} matching, {len(other_systems)} other")
            return {"your_system": your_system, "other_systems": other_systems}

        except Exception as e:
            logger.error(f"RAG search failed: {e}")
            return {"your_system": [], "other_systems": []}

    async def add_cves(self, cves: List[Dict[str, Any]]) -> int:
        """
        Add new CVEs to the existing index (incremental update).

        Args:
            cves: List of CVE data to add

        Returns:
            Number of CVEs added
        """
        if not self._initialized:
            return await self.index_cves(cves)

        if not cves:
            return 0

        model = _get_sentence_transformer()

        added = 0
        for cve in cves:
            cve_id = cve.get("cve_id", "")
            if not cve_id:
                continue

            # Check if already exists
            try:
                existing = self._collection.get(ids=[cve_id])
                if existing and existing['ids']:
                    continue
            except Exception:
                pass

            # Create document
            description = cve.get("description", "")
            affected = " ".join(cve.get("affected_versions", []))
            tags = " ".join(cve.get("tags", []))
            doc_text = f"{cve_id} {description} {affected} {tags}"

            # Generate embedding
            embedding = model.encode(doc_text)

            # Add to collection
            self._collection.add(
                documents=[doc_text],
                embeddings=[embedding.tolist()],
                metadatas=[{
                    "cve_id": cve_id,
                    "severity": cve.get("severity", "UNKNOWN"),
                    "cvss_score": str(cve.get("cvss_score", "")),
                    "published_date": cve.get("published_date", ""),
                    "is_exploited": str(cve.get("is_exploited", False)),
                    "description": description[:500],
                }],
                ids=[cve_id]
            )
            added += 1

        self._cve_count = self._collection.count()
        logger.info(f"Added {added} new CVEs to RAG index (total: {self._cve_count})")
        return added

    async def clear_index(self) -> None:
        """Clear all data from the index."""
        if self._client:
            try:
                self._client.delete_collection(self.COLLECTION_NAME)
                self._collection = self._client.create_collection(
                    name=self.COLLECTION_NAME,
                    metadata={"description": "CVE embeddings for semantic search"}
                )
                self._cve_count = 0
                logger.info("Cleared RAG index")
            except Exception as e:
                logger.error(f"Failed to clear index: {e}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get RAG engine statistics."""
        return {
            "initialized": self._initialized,
            "cve_count": self._cve_count,
            "last_index_time": self._last_index_time.isoformat() if self._last_index_time else None,
            "model": "all-MiniLM-L6-v2",
            "vector_db": "ChromaDB"
        }

    def _get_severity_values(self, min_severity: str) -> List[str]:
        """Get severity values at or above the minimum."""
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            idx = severity_order.index(min_severity.upper())
            return severity_order[idx:]
        except ValueError:
            return severity_order

    def _safe_float(self, value) -> Optional[float]:
        """Safely convert value to float."""
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None


# Global RAG engine instance
rag_engine = RAGEngine()

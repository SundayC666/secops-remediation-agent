"""
RAG Engine with TF-IDF Search
Uses TF-IDF vectorization for CVE similarity matching (no PyTorch required)
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from collections import Counter
import math

from app.core.config import settings

logger = logging.getLogger(__name__)


class TFIDFVectorizer:
    """Simple TF-IDF vectorizer without external dependencies"""

    def __init__(self):
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.doc_count = 0

    def fit(self, documents: List[str]) -> None:
        """Build vocabulary and IDF scores from documents"""
        self.doc_count = len(documents)
        word_doc_count: Counter = Counter()

        for doc in documents:
            words = set(self._tokenize(doc))
            for word in words:
                word_doc_count[word] += 1

        # Build vocabulary from most common words
        for idx, (word, _) in enumerate(word_doc_count.most_common(5000)):
            self.vocab[word] = idx

        # Calculate IDF
        for word, count in word_doc_count.items():
            if word in self.vocab:
                self.idf[word] = math.log((self.doc_count + 1) / (count + 1)) + 1

    def transform(self, documents: List[str]) -> List[List[float]]:
        """Transform documents to TF-IDF vectors"""
        vectors = []
        for doc in documents:
            vector = [0.0] * len(self.vocab)
            words = self._tokenize(doc)
            word_counts = Counter(words)
            total_words = len(words) or 1

            for word, count in word_counts.items():
                if word in self.vocab:
                    tf = count / total_words
                    idf = self.idf.get(word, 1.0)
                    vector[self.vocab[word]] = tf * idf

            # Normalize
            norm = math.sqrt(sum(v * v for v in vector)) or 1
            vector = [v / norm for v in vector]
            vectors.append(vector)

        return vectors

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words"""
        text = text.lower()
        words = re.findall(r'\b[a-z0-9]+\b', text)
        return words


class RAGEngine:
    """
    RAG (Retrieval-Augmented Generation) engine using TF-IDF search.
    Lightweight implementation without PyTorch dependency.
    """

    def __init__(self):
        self.index_file = Path("data/cve_index.json")
        self.vectorizer: Optional[TFIDFVectorizer] = None
        self.cves: List[Dict[str, Any]] = []
        self.vectors: List[List[float]] = []
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the RAG engine"""
        if self._initialized:
            return

        logger.info("Initializing TF-IDF vectorizer")
        self.vectorizer = TFIDFVectorizer()

        # Try to load existing index
        if self.index_file.exists():
            try:
                self._load_index()
                logger.info(f"Loaded existing index with {len(self.cves)} CVEs")
            except Exception as e:
                logger.warning(f"Could not load index: {e}")

        self._initialized = True
        logger.info("RAG engine initialized")

    async def index_cves(self, cves: List[Dict[str, Any]]) -> int:
        """
        Index CVE records for search

        Args:
            cves: List of CVE records to index

        Returns:
            Number of records indexed
        """
        if not self._initialized:
            await self.initialize()

        if not cves:
            logger.warning("No CVEs to index")
            return 0

        logger.info(f"Indexing {len(cves)} CVEs...")

        self.cves = cves
        texts = [self._create_searchable_text(cve) for cve in cves]

        # Build TF-IDF vectors
        self.vectorizer.fit(texts)
        self.vectors = self.vectorizer.transform(texts)

        # Save index
        self._save_index()

        logger.info(f"Indexed {len(cves)} CVE records")
        return len(cves)

    async def search(
        self,
        query: str,
        os_tags: Optional[List[str]] = None,
        limit: int = 10,
        include_other_os: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Search for relevant CVEs based on query and OS tags

        Args:
            query: Search query text
            os_tags: OS tags to filter by (from detected user OS)
            limit: Maximum number of results per category
            include_other_os: Whether to include results for other OSes

        Returns:
            Dict with 'your_system' and 'other_systems' CVE lists
        """
        if not self._initialized:
            await self.initialize()

        if not self.vectors or len(self.cves) == 0:
            logger.warning("No CVE data indexed yet")
            return {"your_system": [], "other_systems": []}

        # Extract product/OS keywords from query for strict matching
        query_lower = query.lower()
        query_keywords = self._extract_product_keywords(query_lower)

        # Transform query
        query_vector = self.vectorizer.transform([query])[0]

        # Calculate cosine similarities
        similarities = []
        for vec in self.vectors:
            sim = sum(a * b for a, b in zip(query_vector, vec))
            similarities.append(sim)

        # Get top results
        indexed_sims = list(enumerate(similarities))
        indexed_sims.sort(key=lambda x: x[1], reverse=True)
        top_indices = [idx for idx, _ in indexed_sims[:limit * 5]]  # Get more candidates

        your_system = []
        other_systems = []

        for idx in top_indices:
            cve = self.cves[idx].copy()
            cve["similarity"] = similarities[idx]

            # Get OS tags and description for this CVE
            cve_os_tags = set(cve.get("os_tags", []))
            cve_description = cve.get("description", "").lower()

            # Check if CVE matches the query keywords (product/OS specific)
            matches_query_product = self._matches_product_keywords(
                query_keywords, cve_os_tags, cve_description
            )

            if os_tags:
                user_os_set = set(os_tags)
                # CVE matches user's OS ONLY if tags explicitly overlap
                # Don't auto-match CVEs with no OS tags to user's OS anymore
                matches_user_os = bool(cve_os_tags & user_os_set)

                # For "your_system": must match OS tags AND be relevant to query
                if matches_user_os and matches_query_product:
                    if len(your_system) < limit:
                        your_system.append(cve)
                # For "other_systems": CVEs that don't match user OS but match query
                elif include_other_os and matches_query_product and len(other_systems) < limit:
                    if not cve_os_tags:
                        cve["os_tags"] = ["generic"]
                    other_systems.append(cve)
            else:
                # No OS tags provided - only return CVEs matching query keywords
                if matches_query_product:
                    if len(your_system) < limit:
                        your_system.append(cve)

        return {
            "your_system": your_system,
            "other_systems": other_systems
        }

    def _extract_product_keywords(self, query: str) -> set:
        """Extract product/OS keywords from query for filtering"""
        keywords = set()

        # OS keywords mapping
        os_mappings = {
            "macos": {"macos", "mac os", "apple", "darwin", "osx"},
            "windows": {"windows", "microsoft", "win10", "win11"},
            "linux": {"linux", "ubuntu", "debian", "rhel", "centos", "fedora"},
            "android": {"android", "google android"},
            "ios": {"ios", "iphone", "ipad"},
            "chrome": {"chrome", "chromium", "google chrome"},
            "firefox": {"firefox", "mozilla"},
            "safari": {"safari"},
        }

        for os_key, os_variants in os_mappings.items():
            for variant in os_variants:
                if variant in query:
                    keywords.add(os_key)
                    break

        # Also extract version patterns like "10.15", "windows 11"
        version_patterns = [
            r'macos\s*(\d+\.?\d*)',
            r'windows\s*(\d+)',
            r'ios\s*(\d+)',
            r'android\s*(\d+)',
        ]
        for pattern in version_patterns:
            match = re.search(pattern, query)
            if match:
                # Already captured OS above, version is bonus context
                pass

        return keywords

    def _matches_product_keywords(
        self,
        query_keywords: set,
        cve_os_tags: set,
        cve_description: str
    ) -> bool:
        """Check if CVE matches the product keywords from query"""
        # If no specific product keywords in query, match all
        if not query_keywords:
            return True

        # Check if CVE os_tags overlap with query keywords
        if query_keywords & cve_os_tags:
            return True

        # Check if description mentions the queried product
        for keyword in query_keywords:
            if keyword in cve_description:
                return True

        return False

    def _create_searchable_text(self, cve: Dict[str, Any]) -> str:
        """Create a searchable text representation of a CVE"""
        parts = [
            cve.get("cve_id", ""),
            cve.get("title", ""),
            cve.get("description", ""),
            cve.get("severity", ""),
        ]

        # Add OS tags as text
        os_tags = cve.get("os_tags", [])
        if os_tags:
            parts.append(" ".join(os_tags))

        # Add exploited status
        if cve.get("is_exploited"):
            parts.append("actively exploited known exploited vulnerability KEV")

        return " ".join(filter(None, parts))

    def _save_index(self) -> None:
        """Save index to file"""
        try:
            data = {
                "cves": self.cves,
                "vectors": self.vectors,
                "vocab": self.vectorizer.vocab,
                "idf": self.vectorizer.idf,
                "doc_count": self.vectorizer.doc_count
            }
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump(data, f)
            logger.info(f"Saved index to {self.index_file}")
        except Exception as e:
            logger.error(f"Error saving index: {e}")

    def _load_index(self) -> None:
        """Load index from file"""
        with open(self.index_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.cves = data.get("cves", [])
        self.vectors = data.get("vectors", [])
        self.vectorizer.vocab = data.get("vocab", {})
        self.vectorizer.idf = data.get("idf", {})
        self.vectorizer.doc_count = data.get("doc_count", 0)

    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the indexed data"""
        return {
            "total_cves": len(self.cves),
            "indexed": len(self.vectors) > 0 and len(self.cves) > 0
        }


# Global RAG engine instance
rag_engine = RAGEngine()

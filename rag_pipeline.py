"""
RAG (Retrieval-Augmented Generation) Pipeline
Handles vector embeddings, storage, and retrieval
"""

import os
import json
import pickle
from typing import List, Dict, Optional
import logging
import numpy as np

# Vector store and embeddings
import faiss
from sentence_transformers import SentenceTransformer

# LangChain components
try:
    from langchain.text_splitter import RecursiveCharacterTextSplitter
except ImportError:
    # For newer versions of langchain
    from langchain_text_splitters import RecursiveCharacterTextSplitter

try:
    from langchain.docstore.document import Document
except ImportError:
    # For newer versions of langchain
    from langchain_core.documents import Document

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityRAGPipeline:
    """RAG Pipeline for security chatbot"""
    
    def __init__(self, embedding_model: str = "all-MiniLM-L6-v2"):
        """
        Initialize RAG pipeline
        
        Args:
            embedding_model: HuggingFace model name for embeddings
        """
        logger.info(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        self.dimension = self.embedding_model.get_sentence_embedding_dimension()
        
        # FAISS index
        self.index = None
        self.documents = []
        self.metadata = []
        
        # Text splitter for chunking
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=100,
            length_function=len,
        )
    
    def build_knowledge_base(self, cve_data: List[Dict], 
                           infrastructure_data: Optional[List[Dict]] = None):
        """
        Build vector store from CVE and infrastructure data
        
        Args:
            cve_data: List of CVE dictionaries
            infrastructure_data: Optional infrastructure descriptions
        """
        logger.info("Building knowledge base...")
        
        documents = []
        
        # Process CVE data
        for cve in cve_data:
            # Create document from full text
            doc = Document(
                page_content=cve['full_text'],
                metadata={
                    'source': 'cve',
                    'cve_id': cve['cve_id'],
                    'severity': cve['severity'],
                    'cvss_score': cve['cvss_score'],
                    'published_date': cve['published_date']
                }
            )
            documents.append(doc)
        
        # Process infrastructure data if provided
        if infrastructure_data:
            for infra in infrastructure_data:
                doc = Document(
                    page_content=infra['description'],
                    metadata={
                        'source': 'infrastructure',
                        'asset_name': infra.get('name', 'Unknown'),
                        'asset_type': infra.get('type', 'Unknown')
                    }
                )
                documents.append(doc)
        
        logger.info(f"Processing {len(documents)} documents...")
        
        # Split documents into chunks
        split_docs = self.text_splitter.split_documents(documents)
        logger.info(f"Split into {len(split_docs)} chunks")
        
        # Create embeddings
        texts = [doc.page_content for doc in split_docs]
        logger.info("Generating embeddings...")
        embeddings = self.embedding_model.encode(
            texts, 
            show_progress_bar=True,
            convert_to_numpy=True
        )
        
        # Build FAISS index
        logger.info("Building FAISS index...")
        self.index = faiss.IndexFlatL2(self.dimension)
        self.index.add(embeddings.astype('float32'))
        
        # Store documents and metadata
        self.documents = split_docs
        self.metadata = [doc.metadata for doc in split_docs]
        
        logger.info(f"Knowledge base built with {len(self.documents)} chunks")
    
    def retrieve(self, query: str, top_k: int = 5) -> List[Dict]:
        """
        Retrieve relevant documents for a query
        
        Args:
            query: User query
            top_k: Number of documents to retrieve
            
        Returns:
            List of relevant documents with metadata
        """
        if self.index is None:
            logger.warning("Knowledge base not built yet")
            return []
        
        # Encode query
        query_embedding = self.embedding_model.encode(
            [query],
            convert_to_numpy=True
        )
        
        # Search FAISS index
        distances, indices = self.index.search(
            query_embedding.astype('float32'), 
            top_k
        )
        
        # Collect results
        results = []
        for idx, distance in zip(indices[0], distances[0]):
            if idx < len(self.documents):
                results.append({
                    'content': self.documents[idx].page_content,
                    'metadata': self.metadata[idx],
                    'relevance_score': float(1 / (1 + distance))  # Convert distance to similarity
                })
        
        return results
    
    def save_index(self, directory: str = 'vector_store'):
        """Save FAISS index and metadata to disk"""
        os.makedirs(directory, exist_ok=True)
        
        # Save FAISS index
        index_path = os.path.join(directory, 'faiss_index.bin')
        faiss.write_index(self.index, index_path)
        
        # Save documents and metadata
        docs_path = os.path.join(directory, 'documents.pkl')
        with open(docs_path, 'wb') as f:
            pickle.dump({
                'documents': self.documents,
                'metadata': self.metadata
            }, f)
        
        logger.info(f"Index saved to {directory}")
    
    def load_index(self, directory: str = 'vector_store'):
        """Load FAISS index and metadata from disk"""
        index_path = os.path.join(directory, 'faiss_index.bin')
        docs_path = os.path.join(directory, 'documents.pkl')
        
        if not os.path.exists(index_path) or not os.path.exists(docs_path):
            logger.warning(f"Index not found in {directory}")
            return False
        
        # Load FAISS index
        self.index = faiss.read_index(index_path)
        
        # Load documents and metadata
        with open(docs_path, 'rb') as f:
            data = pickle.load(f)
            self.documents = data['documents']
            self.metadata = data['metadata']
        
        logger.info(f"Index loaded from {directory}")
        return True
    
    def add_custom_document(self, text: str, metadata: Dict):
        """
        Add a custom document to the knowledge base
        
        Args:
            text: Document text
            metadata: Document metadata
        """
        if self.index is None:
            logger.warning("Knowledge base not built yet")
            return
        
        # Create document
        doc = Document(page_content=text, metadata=metadata)
        
        # Split if needed
        split_docs = self.text_splitter.split_documents([doc])
        
        # Generate embeddings
        texts = [d.page_content for d in split_docs]
        embeddings = self.embedding_model.encode(
            texts,
            convert_to_numpy=True
        )
        
        # Add to index
        self.index.add(embeddings.astype('float32'))
        
        # Update documents and metadata
        self.documents.extend(split_docs)
        self.metadata.extend([d.metadata for d in split_docs])
        
        logger.info(f"Added {len(split_docs)} chunks to knowledge base")


def create_sample_infrastructure() -> List[Dict]:
    """Create sample infrastructure data for testing"""
    infrastructure = [
        {
            'name': 'Web Server Cluster',
            'type': 'servers',
            'description': """
            Web Server Cluster Infrastructure:
            - Operating System: Ubuntu 22.04 LTS
            - Web Server: Apache 2.4.52
            - Application: WordPress 6.4
            - PHP Version: 8.1.2
            - Database: MySQL 8.0.32
            - SSL/TLS: OpenSSL 3.0.2
            - Location: Primary Data Center
            - Critical Asset: Handles public-facing website
            - Exposed Services: HTTP (80), HTTPS (443)
            """
        },
        {
            'name': 'Database Server',
            'type': 'database',
            'description': """
            Database Server Infrastructure:
            - Operating System: Red Hat Enterprise Linux 9
            - Database: PostgreSQL 15.2
            - Backup System: Automated daily backups
            - Location: Secure Data Center
            - Critical Asset: Stores customer data and financial records
            - Network: Internal network only, no external exposure
            - Security: Encrypted at rest and in transit
            """
        },
        {
            'name': 'Application Server',
            'type': 'application',
            'description': """
            Application Server Infrastructure:
            - Operating System: Windows Server 2022
            - Runtime: .NET Framework 4.8, .NET 7.0
            - Application Server: IIS 10.0
            - Message Queue: RabbitMQ 3.12
            - Cache: Redis 7.0
            - Critical Asset: Runs core business applications
            - Exposed Services: API Gateway (Port 8080)
            """
        },
        {
            'name': 'Network Infrastructure',
            'type': 'network',
            'description': """
            Network Infrastructure:
            - Firewall: Cisco ASA 5516-X (Software version 9.16)
            - VPN: OpenVPN 2.6.0
            - Router: Cisco ISR 4000 Series
            - Switch: Cisco Catalyst 9300
            - IDS/IPS: Snort 3.1.50
            - Network Segmentation: DMZ, Internal, Management VLANs
            - Remote Access: VPN required for all external access
            """
        }
    ]
    return infrastructure


if __name__ == "__main__":
    # Test the RAG pipeline
    from cve_collector import CVEDataCollector
    
    print("Testing RAG Pipeline...")
    
    # Load or fetch CVE data
    collector = CVEDataCollector()
    if os.path.exists('data/cve_data.json'):
        cves = collector.load_from_file()
    else:
        print("Fetching CVE data...")
        # UPDATED: Match the 90-day window
        cves = collector.fetch_recent_cves(days=90, max_results=200)
        collector.save_to_file(cves)
    
    # Create infrastructure data
    infrastructure = create_sample_infrastructure()
    
    # Build RAG pipeline
    print("\nBuilding RAG pipeline...")
    rag = SecurityRAGPipeline()
    rag.build_knowledge_base(cves, infrastructure)
    
    # Test retrieval
    test_queries = [
        "What vulnerabilities affect Apache web servers?",
        "Tell me about high severity CVEs",
        "What are the risks to our Windows servers?"
    ]
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        results = rag.retrieve(query, top_k=3)
        for i, result in enumerate(results, 1):
            print(f"\nResult {i} (Score: {result['relevance_score']:.3f}):")
            print(f"Source: {result['metadata'].get('source')}")
            print(f"Content preview: {result['content'][:200]}...")
    
    # Save index
    rag.save_index()
    print("\nRAG pipeline test completed!")
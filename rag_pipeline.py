"""
RAG Pipeline Module
Handles document ingestion, embedding generation, and vector store management (FAISS).
Supports dynamic infrastructure context loading.
"""

import os
import json
import logging
from typing import List, Dict
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityRAGPipeline:
    """
    RAG Pipeline for ingesting CVE data and Infrastructure Context.
    """
    
    def __init__(self, vector_store_path: str = "vector_store"):
        self.vector_store_path = vector_store_path
        self.embeddings = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
        self.index = None
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )

    def load_infrastructure_context(self) -> List[Dict]:
        """
        Load infrastructure context from a JSON file.
        This allows the user to define their own tech stack in the UI.
        """
        file_path = "data/infrastructure.json"
        
        # Default sample if file doesn't exist (First run experience)
        default_infra = [
            {"id": "asset_01", "name": "Production Web Server", "details": "OS: Ubuntu 22.04 LTS, Software: Apache 2.4.52, Python 3.10"},
            {"id": "asset_02", "name": "Corporate Database", "details": "OS: Windows Server 2019, Software: PostgreSQL 14.2"},
            {"id": "asset_03", "name": "Employee Workstations", "details": "OS: Windows 11 Enterprise 22H2, Software: Office 365, Adobe Reader"}
        ]
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if data:
                        logger.info(f"Loaded {len(data)} infrastructure assets from {file_path}")
                        return data
            except Exception as e:
                logger.error(f"Error loading infrastructure file: {e}")
        
        # If no file or error, return default and save it
        logger.info("Using default sample infrastructure context.")
        self.save_infrastructure_context(default_infra)
        return default_infra

    def save_infrastructure_context(self, data: List[Dict]):
        """Save infrastructure context to file"""
        os.makedirs("data", exist_ok=True)
        with open("data/infrastructure.json", 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def build_knowledge_base(self, cve_data: List[Dict], infrastructure_data: List[Dict]):
        """
        Build FAISS index from CVE data and Infrastructure context.
        """
        documents = []
        
        # 1. Process CVEs
        for cve in cve_data:
            # We include the CISA warning in the indexed text so it's searchable
            content = f"{cve['cisa_warning']} CVE: {cve['id']}\nSeverity: {cve['severity']}\nDescription: {cve['description']}"
            meta = {
                "source": "cve", 
                "cve_id": cve['id'], 
                "severity": cve['severity'],
                "is_exploited": cve.get('is_exploited', False)
            }
            documents.append(Document(page_content=content, metadata=meta))
            
        # 2. Process Infrastructure Context
        for infra in infrastructure_data:
            content = f"Asset: {infra['name']}\nDetails: {infra['details']}"
            meta = {"source": "infrastructure", "asset_id": infra['id']}
            documents.append(Document(page_content=content, metadata=meta))
            
        # 3. Split and Index
        logger.info(f"Processing {len(documents)} documents...")
        chunks = self.text_splitter.split_documents(documents)
        
        logger.info("Generating embeddings and building index...")
        self.index = FAISS.from_documents(chunks, self.embeddings)
        logger.info("Knowledge base built successfully.")

    def save_index(self):
        """Save FAISS index to disk"""
        if self.index:
            self.index.save_local(self.vector_store_path)
            logger.info(f"Index saved to {self.vector_store_path}")

    def load_index(self) -> bool:
        """Load FAISS index from disk"""
        if os.path.exists(self.vector_store_path):
            try:
                self.index = FAISS.load_local(
                    self.vector_store_path, 
                    self.embeddings,
                    allow_dangerous_deserialization=True
                )
                logger.info("Index loaded from vector_store")
                return True
            except Exception as e:
                logger.error(f"Failed to load index: {e}")
                return False
        return False

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict]:
        """Retrieve relevant documents"""
        if not self.index:
            return []
            
        docs_and_scores = self.index.similarity_search_with_score(query, k=top_k)
        results = []
        for doc, score in docs_and_scores:
            results.append({
                "content": doc.page_content,
                "metadata": doc.metadata,
                "score": float(score)
            })
        return results
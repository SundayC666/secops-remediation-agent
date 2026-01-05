"""
LLM Integration Module
Supports OpenAI API and Ollama (local LLM)
"""

import os
import logging
import requests
from typing import List, Dict, Optional, Union
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Check available libraries
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("openai library not found. OpenAI features will be disabled.")

try:
    import requests
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    logger.warning("requests library not found. Ollama features will be disabled.")


class LLMInterface:
    """Interface for interacting with LLMs"""
    
    def __init__(self, use_ollama: bool = False, model: str = "gpt-4o-mini"):
        """
        Initialize LLM interface
        
        Args:
            use_ollama: If True, use Ollama local LLM instead of OpenAI
            model: Model name (gpt-4o-mini for OpenAI, llama2 for Ollama)
        """
        self.use_ollama = use_ollama
        self.model = model
        
        if use_ollama:
            if not OLLAMA_AVAILABLE:
                raise ImportError("requests library required for Ollama")
            self.ollama_url = "http://localhost:11434/api/generate"
            logger.info(f"Using Ollama with model: {model}")
            logger.info("Warming up model (first load may take time)...")
            self._warmup_model()
        else:
            if not OPENAI_AVAILABLE:
                raise ImportError("openai library required for OpenAI API")
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OPENAI_API_KEY not found in environment")
            self.client = OpenAI(api_key=api_key)
            logger.info(f"Using OpenAI with model: {model}")
    
    def _warmup_model(self):
        """Warm up the Ollama model by making a simple request"""
        if not self.use_ollama:
            return
        
        try:
            payload = {
                "model": self.model,
                "prompt": "Hello",
                "stream": False,
                "options": {
                    "num_predict": 10  # Generate only 10 tokens
                }
            }
            
            logger.info("Loading model into memory...")
            response = requests.post(
                self.ollama_url,
                json=payload,
                timeout=300
            )
            logger.info("Model warmed up and ready!")
        except Exception as e:
            logger.warning(f"Model warmup failed: {e}")

    def generate_response(self, prompt: str, max_tokens: int = 1000) -> str:
        """
        Generate response from LLM
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens in response
            
        Returns:
            Generated response text
        """
        if self.use_ollama:
            return self._generate_ollama(prompt)
        else:
            return self._generate_openai(prompt, max_tokens)
    
    def _generate_openai(self, prompt: str, max_tokens: int) -> str:
        """Generate response using OpenAI API"""
        try:
            # IMPORTANT: System prompt engineered to reduce hallucinations
            system_instruction = (
                "You are a SecOps Remediation Agent. "
                "You must answer the user's question BASED ONLY on the provided Context (Retrieved CVE Data). "
                "If the answer is not in the context, state that you don't know. "
                "DO NOT fabricate information."
            )

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.3,  # Lower temperature for more factual responses
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return f"Error generating response: {str(e)}"
    
    def _generate_ollama(self, prompt: str) -> str:
        """Generate response using Ollama local API"""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3
                }
            }
            
            response = requests.post(
                self.ollama_url,
                json=payload,
                timeout=600
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get('response', '').strip()
            
        except requests.exceptions.ConnectionError:
            return "Error: Cannot connect to Ollama. Make sure Ollama is running (ollama serve)."
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return f"Error generating response: {str(e)}"


class SecurityChatbot:
    """Security chatbot with RAG capabilities"""
    
    def __init__(self, rag_pipeline, llm_interface: LLMInterface):
        """
        Initialize security chatbot
        
        Args:
            rag_pipeline: RAG pipeline instance
            llm_interface: LLM interface instance
        """
        self.rag = rag_pipeline
        self.llm = llm_interface
        self.conversation_history = []
    
    def chat(self, user_query: str, include_context: bool = True) -> Dict:
        """
        Process user query and generate response
        
        Args:
            user_query: User's question
            include_context: Whether to use RAG retrieval
            
        Returns:
            Dictionary with response and metadata
        """
        # Retrieve relevant context if requested
        context_docs = []
        if include_context and self.rag.index is not None:
            context_docs = self.rag.retrieve(user_query, top_k=5)
        
        # Build prompt
        prompt = self._build_prompt(user_query, context_docs)
        
        # Generate response
        response = self.llm.generate_response(prompt)
        
        # Store in history
        self.conversation_history.append({
            'query': user_query,
            'response': response,
            'context_used': len(context_docs) > 0
        })
        
        return {
            'response': response,
            'context_documents': context_docs,
            'sources': self._extract_sources(context_docs)
        }
    
    def _build_prompt(self, query: str, context_docs: List[Dict]) -> str:
        """Build prompt for LLM with retrieved context"""
        
        if not context_docs:
            # No context available
            prompt = f"""You are a cybersecurity expert assistant. Answer the following security question:

Question: {query}

Provide a clear, actionable response based on cybersecurity best practices."""
            return prompt
        
        # Build context from retrieved documents
        context_text = ""
        for i, doc in enumerate(context_docs, 1):
            metadata = doc['metadata']
            source_type = metadata.get('source', 'unknown')
            
            if source_type == 'cve':
                context_text += f"\n--- CVE Information {i} ---\n"
                context_text += f"CVE ID: {metadata.get('cve_id', 'Unknown')}\n"
                context_text += f"Severity: {metadata.get('severity', 'Unknown')}\n"
                context_text += f"Content:\n{doc['content']}\n"
            else:
                context_text += f"\n--- Infrastructure Information {i} ---\n"
                context_text += f"{doc['content']}\n"
        
        # Build full prompt with ANTI-HALLUCINATION instructions
        prompt = f"""You are a SecOps Remediation Agent. Use the following context information to answer the security question.

Context Information:
{context_text}

Question: {query}

Instructions:
- Base your answer ONLY on the provided context.
- If the context doesn't contain the answer, explicitly state that you lack sufficient information.
- DO NOT fabricate CVE IDs or severity scores.
- Provide specific, actionable recommendations (e.g., 'Upgrade Apache to version 2.4.58').
- If mentioning CVEs, include the CVE ID and severity.

Answer:"""
        
        return prompt
    
    def _extract_sources(self, context_docs: List[Dict]) -> List[str]:
        """Extract source references from context documents"""
        sources = []
        seen_cves = set()
        
        for doc in context_docs:
            metadata = doc['metadata']
            if metadata.get('source') == 'cve':
                cve_id = metadata.get('cve_id')
                if cve_id and cve_id not in seen_cves:
                    severity = metadata.get('severity', 'Unknown')
                    sources.append(f"{cve_id} ({severity})")
                    seen_cves.add(cve_id)
        
        return sources
    
    def get_conversation_history(self) -> List[Dict]:
        """Get conversation history"""
        return self.conversation_history
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []


def create_chatbot(use_ollama: bool = False) -> Optional[SecurityChatbot]:
    """
    Create and initialize security chatbot
    
    Args:
        use_ollama: Use Ollama instead of OpenAI
        
    Returns:
        SecurityChatbot instance or None if setup fails
    """
    from rag_pipeline import SecurityRAGPipeline, create_sample_infrastructure
    from cve_collector import CVEDataCollector
    
    try:
        # Initialize RAG pipeline
        logger.info("Initializing RAG pipeline...")
        rag = SecurityRAGPipeline()
        
        # Load or build knowledge base
        if rag.load_index():
            logger.info("Loaded existing knowledge base")
        else:
            logger.info("Building new knowledge base...")
            
            # Load CVE data
            collector = CVEDataCollector()
            if os.path.exists('data/cve_data.json'):
                cves = collector.load_from_file()
            else:
                cves = collector.fetch_recent_cves(days=90, max_results=200)
                collector.save_to_file(cves)
            
            # Create infrastructure data
            infrastructure = create_sample_infrastructure()
            
            # Build knowledge base
            rag.build_knowledge_base(cves, infrastructure)
            rag.save_index()
        
        # Initialize LLM
        logger.info("Initializing LLM...")
        if use_ollama:
            ollama_model = os.getenv('OLLAMA_MODEL', 'llama2:latest')
            llm = LLMInterface(use_ollama=True, model=ollama_model)
        else:
            # Read from env, defaulting to gpt-4o-mini
            openai_model = os.getenv('OPENAI_MODEL_NAME', 'gpt-4o-mini')
            llm = LLMInterface(use_ollama=False, model=openai_model)
        
        # Create chatbot
        chatbot = SecurityChatbot(rag, llm)
        logger.info("Chatbot initialized successfully!")
        
        return chatbot
        
    except Exception as e:
        logger.error(f"Failed to create chatbot: {e}")
        return None


if __name__ == "__main__":
    # Test the chatbot
    print("Initializing Security Chatbot...")
    
    # Try to use Ollama first (free), fall back to OpenAI
    use_ollama = os.getenv('USE_OLLAMA', 'false').lower() == 'true'
    
    chatbot = create_chatbot(use_ollama=use_ollama)
    
    if chatbot:
        print("\n=== Security Chatbot Ready ===\n")
        
        # Test queries
        test_queries = [
            "What are the most critical vulnerabilities in our infrastructure?",
            "How should we protect our Apache web servers?",
            "What is the risk level of our Windows servers?"
        ]
        
        for query in test_queries:
            print(f"User: {query}")
            result = chatbot.chat(query)
            print(f"\nChatbot: {result['response']}")
            if result['sources']:
                print(f"Sources: {', '.join(result['sources'])}")
            print("\n" + "="*50 + "\n")
    else:
        print("Failed to initialize chatbot. Check logs for details.")
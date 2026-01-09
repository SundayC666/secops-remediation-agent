"""
LLM Integration Module
Supports OpenAI API and Ollama with Structured JSON Output for UI Rendering.
"""

import os
import logging
import requests
import json
from typing import List, Dict, Optional
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Check available libraries
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import requests
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


class LLMInterface:
    def __init__(self, use_ollama: bool = False, model: str = "gpt-4o-mini"):
        self.use_ollama = use_ollama
        self.model = model
        
        if use_ollama:
            if not OLLAMA_AVAILABLE: raise ImportError("requests library required for Ollama")
            self.ollama_url = "http://localhost:11434/api/generate"
            self._warmup_model()
        else:
            if not OPENAI_AVAILABLE: raise ImportError("openai library required for OpenAI API")
            api_key = os.getenv('OPENAI_API_KEY')
            if not api_key: raise ValueError("OPENAI_API_KEY not found")
            self.client = OpenAI(api_key=api_key)
    
    def _warmup_model(self):
        if not self.use_ollama: return
        try: requests.post(self.ollama_url, json={"model": self.model, "prompt": "Hi", "stream": False, "options": {"num_predict": 1}}, timeout=5)
        except: pass

    def generate_response(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        if self.use_ollama: return self._generate_ollama(prompt, system_instruction)
        else: return self._generate_openai(prompt, system_instruction)
    
    def _generate_openai(self, prompt: str, system_instruction: Optional[str]) -> str:
        try:
            # Force JSON mode for OpenAI
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system_instruction}, {"role": "user", "content": prompt}],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            return response.choices[0].message.content.strip()
        except Exception as e: return json.dumps({"error": str(e)})
    
    def _generate_ollama(self, prompt: str, system_instruction: Optional[str]) -> str:
        try:
            final_prompt = prompt
            if system_instruction: final_prompt = f"System: {system_instruction}\n\nUser: {prompt}"
            res = requests.post(self.ollama_url, json={"model": self.model, "prompt": final_prompt, "stream": False, "format": "json"}, timeout=120)
            res.raise_for_status()
            return res.json().get('response', '')
        except Exception as e: return json.dumps({"error": str(e)})


class SecurityChatbot:
    def __init__(self, rag_pipeline, llm_interface: LLMInterface):
        self.rag = rag_pipeline
        self.llm = llm_interface
        self.conversation_history = []
    
    def chat(self, user_query: str, include_context: bool = True, custom_system_prompt: str = None) -> Dict:
        context_docs = []
        mode = "RAG"
        
        # 1. Retrieval
        if include_context and self.rag.index is not None:
            context_docs = self.rag.retrieve(user_query, top_k=5)

        # 2. Logic Selection
        if custom_system_prompt:
            # For Phishing or custom tasks
            response = self.llm.generate_response(user_query, system_instruction=custom_system_prompt)
            mode = "Custom"
        else:
            # RAG Mode with JSON Output
            prompt = self._build_prompt(user_query, context_docs)
            
            system_instruction = """
            You are a SecOps Remediation Agent. 
            You MUST return your response in valid JSON format.
            Do not include markdown formatting.
            """
            
            response = self.llm.generate_response(prompt, system_instruction=system_instruction)
            
            # Retry Logic
            # If the output is basically empty or "I don't know", fallback to General Knowledge
            if "I don't know" in response or "null" in response or len(response) < 50:
                mode = "General Knowledge"
                context_docs = [] # Clear irrelevent context
                
                # --- UPDATED GENERAL PROMPT TO MATCH DASHBOARD STRUCTURE ---
                general_prompt = f"""
                User Query: "{user_query}"
                Internal DB: No specific CVE records found.
                
                Task: Provide general security advice using the SAME JSON structure.
                Treat "Best Practices" as "findings".
                
                JSON Structure:
                {{
                    "summary": "Brief executive summary of general risks...",
                    "highest_severity": "INFO",
                    "findings": [
                        {{
                            "cve": "N/A",
                            "title": "General Best Practice (e.g., Enable MFA)",
                            "description": "Explanation of why this is important...",
                            "affected_assets": "General Systems",
                            "remediation": "Actionable steps...",
                            "patch_link": null,
                            "kev": false
                        }}
                    ],
                    "action_plan": ["Step 1...", "Step 2..."]
                }}
                """
                response = self.llm.generate_response(general_prompt, system_instruction="You are a Cybersecurity Mentor. Output JSON.")

        self.conversation_history.append({'query': user_query, 'response': response, 'mode': mode})
        
        return {
            'response': response,
            'context_documents': context_docs,
            'sources': self._extract_sources(context_docs),
            'mode': mode
        }
    
    def _build_prompt(self, query: str, context_docs: List[Dict]) -> str:
        if not context_docs: return query
        
        context_text = ""
        for i, doc in enumerate(context_docs, 1):
            meta = doc['metadata']
            context_text += f"\n--- Source {i} ---\n"
            if meta.get('is_exploited'): context_text += "🚨 STATUS: ACTIVELY EXPLOITED (CISA KEV)\n"
            context_text += f"{doc['content']}\n"
            
        prompt = f"""
        CONTEXT DATA:
        {context_text}

        USER QUESTION: {query}

        INSTRUCTIONS:
        1. Analyze the Context Data.
        2. Output a JSON object.
        3. **CRITICAL**: If the context contains CVEs, YOU MUST LIST THEM in the "findings" array. Do not summarize them away.
        4. If a CVE is mentioned, extract its ID, Description, and Remediation.

        JSON Structure:
        {{
            "summary": "High-level summary (e.g., 'Found 2 High Severity CVEs').",
            "highest_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE",
            "findings": [
                {{
                    "cve": "CVE-XXXX-XXXX (Required)",
                    "title": "Short descriptive title",
                    "description": "Detailed explanation.",
                    "affected_assets": "Assets from context or 'Unknown'",
                    "remediation": "Specific fix.",
                    "patch_link": "URL or null",
                    "kev": true/false
                }}
            ],
            "action_plan": [
                "Step 1...",
                "Step 2..."
            ]
        }}
        """
        return prompt
    
    def _extract_sources(self, context_docs: List[Dict]) -> List[str]:
        sources = []
        seen = set()
        for doc in context_docs:
            meta = doc['metadata']
            if meta.get('source') == 'cve':
                cve_id = meta.get('cve_id')
                if cve_id not in seen:
                    sev = meta.get('severity', 'UNK')
                    kev_badge = "🔥 **KEV**" if meta.get('is_exploited') else ""
                    link = f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id}) ({sev}) {kev_badge}"
                    sources.append(link)
                    seen.add(cve_id)
        return sources

    def clear_history(self):
        self.conversation_history = []

def create_chatbot(use_ollama: bool = False):
    from rag_pipeline import SecurityRAGPipeline
    from cve_collector import CVEDataCollector
    try:
        rag = SecurityRAGPipeline()
        if not rag.load_index():
            collector = CVEDataCollector(api_key=os.getenv('NVD_API_KEY'))
            cves = collector.fetch_recent_cves(days=90, max_results=200)
            collector.save_to_file(cves)
            infra = rag.load_infrastructure_context()
            rag.build_knowledge_base(cves, infra)
            rag.save_index()
        else:
            rag.load_infrastructure_context()
        llm = LLMInterface(use_ollama=use_ollama, model=os.getenv('OLLAMA_MODEL', 'llama2:latest') if use_ollama else os.getenv('OPENAI_MODEL_NAME', 'gpt-4o-mini'))
        return SecurityChatbot(rag, llm)
    except Exception as e:
        print(f"Error: {e}")
        return None
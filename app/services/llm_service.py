"""
LLM Service - Ollama Integration with LangChain
Provides AI-powered analysis for CVE and Phishing detection

Uses llama3.2:3b for fast, stable responses
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from functools import lru_cache

from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

logger = logging.getLogger(__name__)


class LLMService:
    """
    LLM Service using Ollama for local inference.

    Features:
    - Fast response (< 2 seconds with llama3.2:3b)
    - Graceful fallback if Ollama unavailable
    - Caching for repeated queries
    """

    # Default model - fast and stable
    DEFAULT_MODEL = "llama3.2:3b"

    # Ollama server URL
    OLLAMA_BASE_URL = "http://localhost:11434"

    # Timeout settings
    REQUEST_TIMEOUT = 30  # seconds

    def __init__(self, model: str = None):
        self.model = model or self.DEFAULT_MODEL
        self._llm: Optional[OllamaLLM] = None
        self._available: Optional[bool] = None

    @property
    def llm(self) -> Optional[OllamaLLM]:
        """Lazy initialization of LLM"""
        if self._llm is None:
            try:
                self._llm = OllamaLLM(
                    model=self.model,
                    base_url=self.OLLAMA_BASE_URL,
                    temperature=0.1,  # Low temperature for consistent outputs
                    num_predict=512,  # Limit response length for speed
                )
                logger.info(f"LLM initialized with model: {self.model}")
            except Exception as e:
                logger.error(f"Failed to initialize LLM: {e}")
                self._llm = None
        return self._llm

    async def is_available(self) -> bool:
        """Check if Ollama is running and model is available"""
        if self._available is not None:
            return self._available

        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.OLLAMA_BASE_URL}/api/tags")
                if response.status_code == 200:
                    models = response.json().get("models", [])
                    model_names = [m.get("name", "").split(":")[0] for m in models]
                    self._available = self.model.split(":")[0] in model_names
                    if not self._available:
                        logger.warning(f"Model {self.model} not found. Available: {model_names}")
                else:
                    self._available = False
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            self._available = False

        return self._available

    async def analyze_cve_impact(
        self,
        cve_id: str,
        description: str,
        severity: str,
        user_system: str,
        affected_versions: List[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze CVE impact on user's specific system.

        Returns:
            {
                "affects_user": bool,
                "confidence": "high" | "medium" | "low",
                "explanation": str,
                "recommended_action": str,
                "priority": "critical" | "high" | "medium" | "low"
            }
        """
        if not await self.is_available():
            return self._fallback_cve_analysis(severity, affected_versions, user_system)

        prompt = PromptTemplate.from_template("""Analyze this CVE for the user's system. Be concise.

CVE: {cve_id}
Severity: {severity}
Description: {description}
Affected Versions: {affected_versions}
User's System: {user_system}

Respond in this exact format:
AFFECTS_USER: [YES/NO/UNCERTAIN]
CONFIDENCE: [HIGH/MEDIUM/LOW]
EXPLANATION: [One sentence explaining why]
ACTION: [One specific action to take]
PRIORITY: [CRITICAL/HIGH/MEDIUM/LOW]""")

        try:
            chain = prompt | self.llm | StrOutputParser()
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    chain.invoke,
                    {
                        "cve_id": cve_id,
                        "severity": severity,
                        "description": description[:500],
                        "affected_versions": ", ".join(affected_versions[:5]) if affected_versions else "Not specified",
                        "user_system": user_system
                    }
                ),
                timeout=self.REQUEST_TIMEOUT
            )
            return self._parse_cve_response(result, severity)
        except asyncio.TimeoutError:
            logger.warning(f"LLM timeout for CVE {cve_id}")
            return self._fallback_cve_analysis(severity, affected_versions, user_system)
        except Exception as e:
            logger.error(f"LLM error for CVE {cve_id}: {e}")
            return self._fallback_cve_analysis(severity, affected_versions, user_system)

    async def analyze_phishing_email(
        self,
        from_addr: str,
        subject: str,
        body: str,
        urls: List[str] = None,
        rule_based_score: int = 0
    ) -> Dict[str, Any]:
        """
        Deep analysis of potential phishing email.

        Returns:
            {
                "is_phishing": bool,
                "confidence": "high" | "medium" | "low",
                "risk_score_adjustment": int,  # -20 to +20
                "explanation": str,
                "key_indicators": List[str]
            }
        """
        if not await self.is_available():
            return self._fallback_phishing_analysis(rule_based_score)

        prompt = PromptTemplate.from_template("""Analyze this email for phishing indicators. Be concise.

From: {from_addr}
Subject: {subject}
Body (first 500 chars): {body}
URLs found: {urls}
Rule-based score: {rule_score}/100

Consider:
1. Sender legitimacy
2. Urgency/pressure tactics
3. Suspicious URLs
4. Request for sensitive info
5. Grammar/spelling issues

Respond in this exact format:
IS_PHISHING: [YES/NO/UNCERTAIN]
CONFIDENCE: [HIGH/MEDIUM/LOW]
SCORE_ADJUST: [number from -20 to +20]
EXPLANATION: [One sentence]
INDICATORS: [comma-separated list of 2-3 key indicators]""")

        try:
            chain = prompt | self.llm | StrOutputParser()
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    chain.invoke,
                    {
                        "from_addr": from_addr,
                        "subject": subject,
                        "body": body[:500],
                        "urls": ", ".join(urls[:5]) if urls else "None",
                        "rule_score": rule_based_score
                    }
                ),
                timeout=self.REQUEST_TIMEOUT
            )
            return self._parse_phishing_response(result, rule_based_score)
        except asyncio.TimeoutError:
            logger.warning("LLM timeout for phishing analysis")
            return self._fallback_phishing_analysis(rule_based_score)
        except Exception as e:
            logger.error(f"LLM error for phishing analysis: {e}")
            return self._fallback_phishing_analysis(rule_based_score)

    def _parse_cve_response(self, response: str, severity: str) -> Dict[str, Any]:
        """Parse LLM response for CVE analysis"""
        result = {
            "affects_user": None,
            "confidence": "low",
            "explanation": "",
            "recommended_action": "",
            "priority": severity.lower() if severity else "medium"
        }

        try:
            lines = response.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("AFFECTS_USER:"):
                    value = line.split(":", 1)[1].strip().upper()
                    result["affects_user"] = value == "YES"
                elif line.startswith("CONFIDENCE:"):
                    result["confidence"] = line.split(":", 1)[1].strip().lower()
                elif line.startswith("EXPLANATION:"):
                    result["explanation"] = line.split(":", 1)[1].strip()
                elif line.startswith("ACTION:"):
                    result["recommended_action"] = line.split(":", 1)[1].strip()
                elif line.startswith("PRIORITY:"):
                    result["priority"] = line.split(":", 1)[1].strip().lower()
        except Exception as e:
            logger.warning(f"Failed to parse CVE response: {e}")

        return result

    def _parse_phishing_response(self, response: str, rule_score: int) -> Dict[str, Any]:
        """Parse LLM response for phishing analysis"""
        result = {
            "is_phishing": None,
            "confidence": "low",
            "risk_score_adjustment": 0,
            "explanation": "",
            "key_indicators": []
        }

        try:
            lines = response.strip().split("\n")
            for line in lines:
                line = line.strip()
                if line.startswith("IS_PHISHING:"):
                    value = line.split(":", 1)[1].strip().upper()
                    result["is_phishing"] = value == "YES"
                elif line.startswith("CONFIDENCE:"):
                    result["confidence"] = line.split(":", 1)[1].strip().lower()
                elif line.startswith("SCORE_ADJUST:"):
                    try:
                        adj = int(line.split(":", 1)[1].strip())
                        result["risk_score_adjustment"] = max(-20, min(20, adj))
                    except ValueError:
                        pass
                elif line.startswith("EXPLANATION:"):
                    result["explanation"] = line.split(":", 1)[1].strip()
                elif line.startswith("INDICATORS:"):
                    indicators = line.split(":", 1)[1].strip()
                    result["key_indicators"] = [i.strip() for i in indicators.split(",") if i.strip()]
        except Exception as e:
            logger.warning(f"Failed to parse phishing response: {e}")

        return result

    def _fallback_cve_analysis(
        self,
        severity: str,
        affected_versions: List[str],
        user_system: str
    ) -> Dict[str, Any]:
        """Fallback when LLM is unavailable"""
        # Simple rule-based fallback
        affects_user = None
        if affected_versions:
            user_system_lower = user_system.lower()
            for version in affected_versions:
                if any(x in version.lower() for x in user_system_lower.split()):
                    affects_user = True
                    break

        priority_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        return {
            "affects_user": affects_user,
            "confidence": "low",
            "explanation": "LLM unavailable - based on version matching only",
            "recommended_action": "Check NVD for detailed impact information",
            "priority": priority_map.get(severity.upper(), "medium")
        }

    def _fallback_phishing_analysis(self, rule_score: int) -> Dict[str, Any]:
        """Fallback when LLM is unavailable"""
        return {
            "is_phishing": None,
            "confidence": "low",
            "risk_score_adjustment": 0,
            "explanation": "LLM unavailable - using rule-based analysis only",
            "key_indicators": []
        }


# Global instance
_llm_service: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    """Get or create the global LLM service instance"""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service


async def check_llm_status() -> Dict[str, Any]:
    """Check LLM service status"""
    service = get_llm_service()
    available = await service.is_available()
    return {
        "available": available,
        "model": service.model,
        "base_url": service.OLLAMA_BASE_URL
    }

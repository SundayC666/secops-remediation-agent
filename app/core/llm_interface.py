"""
LLM Interface for Ollama
Provides local LLM capabilities for security analysis
"""

import httpx
import json
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class LLMInterface:
    """Interface for local LLM via Ollama"""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2:3b",
        timeout: float = 60.0
    ):
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self._available = None

    async def check_availability(self) -> bool:
        """Check if Ollama is running and model is available"""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                if response.status_code == 200:
                    data = response.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    # Check if our model or a variant is available
                    model_base = self.model.split(":")[0]
                    self._available = any(model_base in m for m in models)
                    if not self._available:
                        logger.warning(f"Model {self.model} not found. Available: {models}")
                    return self._available
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            self._available = False
        return False

    @property
    def is_available(self) -> bool:
        """Return cached availability status"""
        return self._available if self._available is not None else False

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 1024
    ) -> Optional[str]:
        """Generate text using the LLM"""
        if not self._available:
            await self.check_availability()
            if not self._available:
                return None

        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json=payload
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("message", {}).get("content", "")
                else:
                    logger.error(f"LLM error: {response.status_code} - {response.text}")
                    return None

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return None

    async def analyze_cve(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Analyze a CVE and generate specific remediation advice"""
        system_prompt = """You are a cybersecurity expert. Analyze the given CVE and provide:
1. A brief risk assessment (1-2 sentences)
2. Specific remediation steps (2-3 actionable items)
3. Temporary mitigations if no patch is available

Be concise and actionable. Format your response as JSON with keys: risk_assessment, remediation_steps (array), mitigations (array)."""

        prompt = f"""Analyze this vulnerability:
CVE ID: {cve_data.get('cve_id', 'Unknown')}
Severity: {cve_data.get('severity', 'Unknown')}
CVSS Score: {cve_data.get('cvss_score', 'N/A')}
Description: {cve_data.get('description', 'No description')}
Actively Exploited: {cve_data.get('is_exploited', False)}
Patch Available: {'Yes' if cve_data.get('patch_links') else 'No'}

Provide your analysis in JSON format."""

        response = await self.generate(prompt, system_prompt, temperature=0.2)

        if response:
            try:
                # Try to parse JSON from response
                # Handle cases where LLM wraps JSON in markdown
                clean_response = response.strip()
                if clean_response.startswith("```"):
                    lines = clean_response.split("\n")
                    clean_response = "\n".join(lines[1:-1])
                return json.loads(clean_response)
            except json.JSONDecodeError:
                # Return raw text if not valid JSON
                return {"raw_analysis": response}

        return None

    async def analyze_phishing_email(
        self,
        email_content: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Analyze an email for phishing indicators"""
        system_prompt = """You are an email security expert specializing in phishing detection.
Analyze the provided email and identify phishing indicators.

Respond in JSON format with:
- is_phishing: boolean (true/false)
- confidence: string ("high", "medium", "low")
- indicators: array of specific suspicious elements found
- risk_level: string ("critical", "high", "medium", "low")
- recommendation: string (what the user should do)
- explanation: string (brief explanation of your assessment)"""

        prompt = f"""Analyze this email for phishing:

From: {email_content.get('from', 'Unknown')}
To: {email_content.get('to', 'Unknown')}
Subject: {email_content.get('subject', 'No subject')}
Date: {email_content.get('date', 'Unknown')}

Body:
{email_content.get('body', 'No content')[:2000]}

URLs found in email:
{json.dumps(email_content.get('urls', []), indent=2)}

Attachments:
{json.dumps(email_content.get('attachments', []), indent=2)}

Analyze for phishing indicators and respond in JSON format."""

        response = await self.generate(prompt, system_prompt, temperature=0.1, max_tokens=1500)

        if response:
            try:
                clean_response = response.strip()
                if clean_response.startswith("```"):
                    lines = clean_response.split("\n")
                    clean_response = "\n".join(lines[1:-1])
                return json.loads(clean_response)
            except json.JSONDecodeError:
                # Fallback analysis without LLM
                return self._fallback_phishing_analysis(email_content)

        return self._fallback_phishing_analysis(email_content)

    def _fallback_phishing_analysis(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback phishing analysis when LLM is unavailable"""
        indicators = []
        risk_score = 0

        subject = email_content.get('subject', '').lower()
        body = email_content.get('body', '').lower()
        from_addr = email_content.get('from', '').lower()
        urls = email_content.get('urls', [])

        # Check for urgency keywords
        urgency_keywords = ['urgent', 'immediately', 'action required', 'suspended',
                          'verify', 'confirm', 'expire', 'limited time', 'act now']
        for keyword in urgency_keywords:
            if keyword in subject or keyword in body:
                indicators.append(f"Urgency keyword detected: '{keyword}'")
                risk_score += 15

        # Check for suspicious phrases
        suspicious_phrases = ['click here', 'verify your account', 'update your information',
                            'confirm your identity', 'unusual activity', 'security alert',
                            'password reset', 'suspended account']
        for phrase in suspicious_phrases:
            if phrase in body:
                indicators.append(f"Suspicious phrase: '{phrase}'")
                risk_score += 10

        # Check URLs
        for url in urls:
            url_lower = url.lower()
            # Check for IP addresses in URLs
            if any(c.isdigit() for c in url.split('/')[2] if '/' in url):
                indicators.append(f"Suspicious URL with IP address: {url[:50]}...")
                risk_score += 25
            # Check for common phishing domains
            phishing_patterns = ['login', 'secure', 'account', 'verify', 'update']
            if any(p in url_lower for p in phishing_patterns):
                indicators.append(f"URL contains suspicious keyword: {url[:50]}...")
                risk_score += 15
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
            if any(s in url_lower for s in shorteners):
                indicators.append(f"URL shortener detected: {url[:50]}...")
                risk_score += 20

        # Check sender
        free_email = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
        corporate_keywords = ['bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google']
        for keyword in corporate_keywords:
            if keyword in body or keyword in subject:
                if any(f in from_addr for f in free_email):
                    indicators.append(f"Corporate reference but sent from free email: {from_addr}")
                    risk_score += 30

        # Check for attachments
        attachments = email_content.get('attachments', [])
        risky_extensions = ['.exe', '.zip', '.rar', '.js', '.vbs', '.bat', '.scr']
        for att in attachments:
            if any(att.lower().endswith(ext) for ext in risky_extensions):
                indicators.append(f"Risky attachment type: {att}")
                risk_score += 35

        # Determine risk level
        if risk_score >= 50:
            risk_level = "critical"
            is_phishing = True
            confidence = "high"
        elif risk_score >= 30:
            risk_level = "high"
            is_phishing = True
            confidence = "medium"
        elif risk_score >= 15:
            risk_level = "medium"
            is_phishing = False
            confidence = "low"
        else:
            risk_level = "low"
            is_phishing = False
            confidence = "high"

        # Generate recommendation
        if is_phishing:
            recommendation = "Do not click any links or download attachments. Report this email to your IT security team and delete it."
        elif risk_level == "medium":
            recommendation = "Exercise caution. Verify the sender through official channels before taking any action."
        else:
            recommendation = "This email appears safe, but always verify unexpected requests through official channels."

        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "indicators": indicators if indicators else ["No obvious phishing indicators detected"],
            "risk_level": risk_level,
            "risk_score": risk_score,
            "recommendation": recommendation,
            "explanation": f"Analysis based on {len(indicators)} indicators found. Risk score: {risk_score}/100",
            "llm_used": False
        }


# Global LLM instance
_llm_instance: Optional[LLMInterface] = None


def get_llm() -> LLMInterface:
    """Get or create LLM instance"""
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = LLMInterface()
    return _llm_instance


async def initialize_llm() -> bool:
    """Initialize and check LLM availability"""
    llm = get_llm()
    available = await llm.check_availability()
    if available:
        logger.info(f"LLM initialized: {llm.model}")
    else:
        logger.warning("LLM not available - using fallback analysis")
    return available

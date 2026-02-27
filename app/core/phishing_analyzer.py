"""
Advanced Phishing Email Analyzer
Provides detailed analysis with scoring breakdown and reference URLs
"""

import re
import math
import json
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field
from pathlib import Path
import logging
from collections import Counter

logger = logging.getLogger(__name__)

# Import Tranco service for domain reputation
try:
    from app.services.tranco_service import get_tranco_service
    TRANCO_AVAILABLE = True
except ImportError:
    TRANCO_AVAILABLE = False
    logger.warning("Tranco service not available")

# Path to whitelist configuration file
WHITELIST_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "whitelist.json"


def load_whitelist_config() -> Dict[str, List[str]]:
    """
    Load whitelist configuration from JSON file.
    Returns default empty dict if file doesn't exist or is invalid.
    """
    try:
        if WHITELIST_CONFIG_PATH.exists():
            with open(WHITELIST_CONFIG_PATH, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"Loaded whitelist config from {WHITELIST_CONFIG_PATH}")
                return config
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load whitelist config: {e}")
    return {}


@dataclass
class AnalysisCheck:
    """Individual analysis check result"""
    category: str
    name: str
    status: str  # "safe", "warning", "danger", "critical"
    score: int  # Points added to risk score
    description: str
    details: Optional[str] = None
    reference_url: Optional[str] = None


@dataclass
class DomainAnalysis:
    """Domain analysis result"""
    domain: str
    is_suspicious: bool
    risk_level: str
    checks: List[AnalysisCheck] = field(default_factory=list)


@dataclass
class AttachmentAnalysis:
    """Attachment analysis result"""
    filename: str
    extension: str
    risk_level: str
    description: str
    reference_url: Optional[str] = None


@dataclass
class PhishingAnalysisResult:
    """Complete phishing analysis result"""
    is_phishing: bool
    confidence: str
    risk_level: str
    risk_score: int
    max_score: int
    recommendation: str
    explanation: str
    checks: List[AnalysisCheck]
    domain_analyses: List[DomainAnalysis]
    attachment_analyses: List[AttachmentAnalysis]
    scoring_criteria: List[Dict[str, Any]]
    data_source: Optional[Dict[str, str]] = None  # Tranco or offline fallback info


class PhishingAnalyzer:
    """Advanced phishing email analyzer with detailed scoring"""

    # Scoring weights and thresholds
    SCORE_THRESHOLDS = {
        "critical": 70,
        "high": 50,
        "medium": 30,
        "low": 0
    }

    # Known suspicious TLDs (expanded list based on phishing research)
    SUSPICIOUS_TLDS = [
        # Common phishing TLDs
        '.xyz', '.top', '.click', '.link', '.work', '.date', '.download',
        '.win', '.bid', '.stream', '.racing', '.review', '.cricket',
        '.science', '.party', '.gq', '.cf', '.ga', '.ml', '.tk',
        # Additional high-risk TLDs
        '.vip', '.icu', '.buzz', '.monster', '.loan', '.online', '.site',
        '.club', '.wang', '.men', '.cam', '.rest', '.life', '.live',
        '.space', '.tech', '.store', '.ooo', '.fun', '.zone', '.kim',
        '.pro', '.fit', '.tokyo', '.mobi', '.info', '.biz', '.pw',
        '.cc', '.su', '.cn', '.ru', '.ua', '.in', '.br'  # Country codes often abused
    ]

    # Known ISP/consumer email domains (used for combination analysis)
    ISP_EMAIL_DOMAINS = [
        'windstream.net', 'comcast.net', 'verizon.net', 'att.net', 'cox.net',
        'charter.net', 'spectrum.net', 'frontier.com', 'centurylink.net',
        'earthlink.net', 'sbcglobal.net', 'bellsouth.net', 'optonline.net',
        'optimum.net', 'roadrunner.com', 'twc.com', 'rcn.com', 'suddenlink.net'
    ]

    # Known legitimate domains that are often spoofed
    COMMONLY_SPOOFED = [
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'bank', 'chase', 'wellsfargo', 'citibank', 'usps',
        'fedex', 'dhl', 'ups', 'irs', 'dropbox', 'linkedin', 'twitter',
        'instagram', 'whatsapp', 'telegram', 'coinbase', 'binance'
    ]

    # Government and postal services (high-value impersonation targets)
    GOVERNMENT_POSTAL_KEYWORDS = {
        # Taiwan postal and government
        'chunghwa': 'post.gov.tw',
        'post.gov': 'post.gov.tw',
        # International postal
        'usps': 'usps.com',
        'royal mail': 'royalmail.com',
        'canada post': 'canadapost.ca',
        'australia post': 'auspost.com.au',
        'japan post': 'post.japanpost.jp',
        # Government tax agencies
        'irs': 'irs.gov',
        'hmrc': 'gov.uk',
        'ato': 'ato.gov.au',
    }

    # Email tracking/marketing services (often used to mask phishing URLs)
    EMAIL_TRACKING_SERVICES = [
        'mg.', 'email.mg.', 'mailgun', 'sendgrid', 'mailchimp',
        'constantcontact', 'campaign-archive', 'list-manage',
        'click.', 'track.', 'links.', 'go.', 'redirect.',
        'r.', 't.', 'l.', 'e.', 'trk.', 'open.',
        'cloudwick.com', 'emltrk.com', 'hubspot', 'marketo'
    ]

    # Legitimate enterprise security/email protection services (NOT phishing indicators)
    LEGITIMATE_EMAIL_SECURITY_SERVICES = [
        'safelinks.protection.outlook.com',  # Microsoft 365 SafeLinks
        'protection.outlook.com',  # Microsoft 365 protection
        'urldefense.proofpoint.com',  # Proofpoint URL Defense
        'urldefense.com',  # Proofpoint
        'click.pstmrk.it',  # Postmark (legitimate email service)
        'mimecast.com',  # Mimecast email security
        'barracuda.com',  # Barracuda email security
        'fireeyecloud.com',  # FireEye email security
        'fireeye.com',
    ]

    # Legitimate tech companies / recruiting platforms (whitelist)
    LEGITIMATE_TECH_COMPANIES = [
        # Major tech companies
        'tiktok.com', 'bytedance.com',
        'meta.com', 'facebook.com', 'instagram.com',
        'google.com', 'youtube.com',
        'amazon.com', 'aws.amazon.com',
        'microsoft.com', 'linkedin.com',
        'apple.com',
        'netflix.com',
        'uber.com', 'lyft.com',
        'airbnb.com',
        'twitter.com', 'x.com',
        'snap.com', 'snapchat.com',
        'spotify.com',
        'salesforce.com',
        'adobe.com',
        'oracle.com',
        'ibm.com',
        'intel.com',
        'nvidia.com',
        'tesla.com',
        'stripe.com',
        'coinbase.com',
        # Major banks and financial institutions
        'bankofamerica.com',
        'chase.com', 'jpmorganchase.com',
        'wellsfargo.com',
        'citi.com', 'citibank.com',
        'usbank.com',
        'capitalone.com',
        'discover.com',
        'americanexpress.com', 'amex.com',
        'schwab.com',
        'fidelity.com',
        'vanguard.com',
        'paypal.com',
        # Recruiting / Assessment platforms
        'codesignal.com',
        'hackerrank.com',
        'leetcode.com',
        'codility.com',
        'greenhouse.io',
        'lever.co',
        'workday.com',
        'icims.com',
        'taleo.net',
        'smartrecruiters.com',
        'jobvite.com',
        # Universities
        'edu',
    ]

    # Legitimate email tracking patterns from known companies
    LEGITIMATE_TRACKING_PATTERNS = [
        r'url\d*\..*\.(tiktok|bytedance|meta|facebook|google|amazon|microsoft|apple)\.com',  # url3572.careers.tiktok.com
        r'click\..*\.(tiktok|bytedance|meta|facebook|google|amazon|microsoft|apple)\.com',
        r'links\..*\.(tiktok|bytedance|meta|facebook|google|amazon|microsoft|apple)\.com',
        r'email\..*\.(tiktok|bytedance|meta|facebook|google|amazon|microsoft|apple)\.com',
        r't\..*\.(tiktok|bytedance|meta|facebook|google|amazon|microsoft|apple)\.com',
    ]

    # Trusted sender domains (educational institutions, large enterprises, etc.)
    TRUSTED_SENDER_DOMAINS = [
        '.edu',  # Educational institutions
        '.gov',  # Government
        '.mil',  # Military
        'microsoft.com',
        'google.com',
        'apple.com',
        'amazon.com',
    ]

    # Risky file extensions
    DANGEROUS_EXTENSIONS = {
        'critical': ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
                    '.js', '.jse', '.ws', '.wsf', '.msc', '.msi', '.msp', '.hta'],
        'high': ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'],
        'medium': ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.pdf'],
        'low': ['.docx', '.xlsx', '.pptx', '.txt', '.csv']
    }

    # Reference URLs for security education (verified working as of 2026-01)
    # All URLs are from official government or major tech company sources
    REFERENCES = {
        "phishing_general": "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing",
        "email_headers": "https://support.google.com/mail/answer/29436",
        "url_safety": "https://transparencyreport.google.com/safe-browsing/search",
        "attachment_safety": "https://www.cisa.gov/news-events/news/using-caution-email-attachments",
        "spf_dkim": "https://support.google.com/a/answer/33786",
        "domain_spoofing": "https://www.ic3.gov/PSA/2020/PSA200406",
        "social_engineering": "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks",
        "url_shorteners": "https://us-cert.cisa.gov/ncas/tips/ST04-014"
    }

    def __init__(self):
        self.checks: List[AnalysisCheck] = []
        self.domain_analyses: List[DomainAnalysis] = []
        self.attachment_analyses: List[AttachmentAnalysis] = []
        self.risk_score = 0
        self.data_source_info: Optional[Dict[str, str]] = None

        # Load whitelist from config file and merge with hardcoded lists
        self._load_whitelist_config()

        # Initialize Tranco service for domain reputation
        self.tranco_service = None
        if TRANCO_AVAILABLE:
            try:
                self.tranco_service = get_tranco_service()
                self.data_source_info = self.tranco_service.get_data_source_display()
                logger.info(f"Tranco service initialized: {self.data_source_info['source']}")
            except Exception as e:
                logger.warning(f"Failed to initialize Tranco service: {e}")

    def _load_whitelist_config(self):
        """
        Load and merge whitelist configuration from config/whitelist.json.
        User-defined whitelist entries are merged with hardcoded defaults.
        """
        config = load_whitelist_config()

        # Merge legitimate tech companies from config
        if "legitimate_tech_companies" in config:
            for domain in config["legitimate_tech_companies"]:
                if domain not in self.LEGITIMATE_TECH_COMPANIES:
                    self.LEGITIMATE_TECH_COMPANIES.append(domain)

        # Merge recruiting platforms (add to tech companies list)
        if "recruiting_platforms" in config:
            for domain in config["recruiting_platforms"]:
                if domain not in self.LEGITIMATE_TECH_COMPANIES:
                    self.LEGITIMATE_TECH_COMPANIES.append(domain)

        # Merge email security services from config
        if "email_security_services" in config:
            for domain in config["email_security_services"]:
                if domain not in self.LEGITIMATE_EMAIL_SECURITY_SERVICES:
                    self.LEGITIMATE_EMAIL_SECURITY_SERVICES.append(domain)

        # Merge trusted TLDs from config
        if "trusted_tlds" in config:
            for tld in config["trusted_tlds"]:
                if tld not in self.TRUSTED_SENDER_DOMAINS:
                    self.TRUSTED_SENDER_DOMAINS.append(tld)

        # Add user custom additions (filter out comments)
        if "user_additions" in config:
            for entry in config["user_additions"]:
                if not entry.startswith("_") and entry not in self.LEGITIMATE_TECH_COMPANIES:
                    self.LEGITIMATE_TECH_COMPANIES.append(entry)

        logger.debug(f"Whitelist loaded: {len(self.LEGITIMATE_TECH_COMPANIES)} tech companies, "
                    f"{len(self.LEGITIMATE_EMAIL_SECURITY_SERVICES)} email security services")

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string (higher = more random)"""
        if not text:
            return 0.0
        counter = Counter(text.lower())
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
        return entropy

    @staticmethod
    def _is_gibberish_domain(domain: str) -> Tuple[bool, float]:
        """
        Detect if a domain name looks like random gibberish.
        Returns (is_gibberish, entropy_score)

        Normal English words have entropy around 2.5-3.5
        Random strings have entropy around 4.0-5.0
        """
        # Extract just the main domain name (not TLD or subdomain)
        parts = domain.split('.')
        if len(parts) >= 2:
            main_part = parts[-2]  # e.g., "twetcqs" from "twetcqs.vip"
        else:
            main_part = parts[0]

        # Skip very short domains
        if len(main_part) <= 3:
            return False, 0.0

        entropy = PhishingAnalyzer._calculate_entropy(main_part)

        # Check consonant-to-vowel ratio (gibberish often has unusual ratios)
        vowels = set('aeiou')
        vowel_count = sum(1 for c in main_part.lower() if c in vowels)
        consonant_count = len(main_part) - vowel_count

        # Normal English: roughly 40% vowels
        vowel_ratio = vowel_count / len(main_part) if main_part else 0

        # High entropy + unusual vowel ratio = likely gibberish
        is_gibberish = False

        # "twetcqs" has entropy ~2.52 and vowel ratio of 0.14 (very low)
        if entropy > 2.3 and vowel_ratio < 0.25:
            is_gibberish = True
        # Very high entropy alone is suspicious
        elif entropy > 3.8:
            is_gibberish = True
        # Check for unlikely consonant clusters
        elif re.search(r'[bcdfghjklmnpqrstvwxz]{4,}', main_part.lower()):
            is_gibberish = True
        # Check for no vowels at all in longer strings
        elif len(main_part) > 4 and vowel_count == 0:
            is_gibberish = True

        return is_gibberish, entropy

    # Known company domain patterns for smart trust inference
    # Maps root company to their known associated domains/patterns
    COMPANY_DOMAIN_FAMILIES = {
        'amazon': ['amazon.com', 'amazon.co', 'aws.amazon.com', 'aws.training', 'awstrack.me', 'amazonses.com', 'a]mazon.'],
        'google': ['google.com', 'gmail.com', 'youtube.com', 'goo.gl', 'g.co', 'googlemail.com'],
        'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'office365.com', 'microsoftonline.com'],
        'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
        'meta': ['meta.com', 'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'fbcdn.net'],
        'linkedin': ['linkedin.com', 'licdn.com'],
        'github': ['github.com', 'github.io', 'githubusercontent.com'],
        'salesforce': ['salesforce.com', 'force.com', 'exacttarget.com', 'pardot.com'],
        'hubspot': ['hubspot.com', 'hubspotlinks.com', 'hs-analytics.net'],
        'mailchimp': ['mailchimp.com', 'list-manage.com', 'mailchi.mp'],
        'sendgrid': ['sendgrid.com', 'sendgrid.net'],
    }

    def _get_sender_trust_context(self, sender_domain: str) -> Optional[str]:
        """
        Determine if sender belongs to a known legitimate company family.
        Returns the company name if trusted, None otherwise.

        This enables smart trust propagation:
        - If sender is aws.training, URLs from awstrack.me are trusted
        - If sender is salesforce.com, URLs from pardot.com are trusted
        """
        if not sender_domain:
            return None

        sender_lower = sender_domain.lower()

        # Check against known company domain families
        for company, domains in self.COMPANY_DOMAIN_FAMILIES.items():
            for domain_pattern in domains:
                if sender_lower.endswith(domain_pattern) or sender_lower == domain_pattern:
                    return company

        # Also check LEGITIMATE_TECH_COMPANIES list
        for company_domain in self.LEGITIMATE_TECH_COMPANIES:
            if sender_lower.endswith(company_domain):
                # Extract company name from domain
                return company_domain.split('.')[0]

        return None

    def _is_url_trusted_by_sender(self, url_domain: str, sender_trust_context: Optional[str]) -> bool:
        """
        Check if a URL domain should be trusted based on sender context.

        If sender is from aws.training (amazon family), then awstrack.me is trusted.
        """
        if not sender_trust_context or not url_domain:
            return False

        url_lower = url_domain.lower()

        # Check if URL belongs to same company family as sender
        if sender_trust_context in self.COMPANY_DOMAIN_FAMILIES:
            for domain_pattern in self.COMPANY_DOMAIN_FAMILIES[sender_trust_context]:
                if url_lower.endswith(domain_pattern) or domain_pattern in url_lower:
                    return True

        return False

    def _check_domain_with_tranco(self, domain: str) -> Tuple[bool, str, int]:
        """
        Check domain trust using Tranco list.

        Returns:
            (is_trusted, trust_level, rank)
            is_trusted: True if domain is in Tranco top domains
            trust_level: "high", "medium", "low", "unknown"
            rank: Domain rank (0 if not found)
        """
        if not self.tranco_service:
            return False, "unknown", 0

        rank = self.tranco_service.get_domain_rank(domain)
        if rank:
            trust_level, _ = self.tranco_service.get_trust_score(domain)
            return True, trust_level, rank
        return False, "unknown", 0

    def analyze(self, email_content: Dict[str, Any]) -> PhishingAnalysisResult:
        """Perform comprehensive phishing analysis"""
        # Reset state
        self.checks = []
        self.domain_analyses = []
        self.attachment_analyses = []
        self.risk_score = 0

        # Extract email components
        from_addr = email_content.get('from', '')
        to_addr = email_content.get('to', '')
        subject = email_content.get('subject', '')
        body = email_content.get('body', '')
        urls = email_content.get('urls', [])
        attachments = email_content.get('attachments', [])
        headers = email_content.get('headers', {})

        # Extract sender domain and determine trust context
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_addr)
        sender_domain = domain_match.group(1).lower() if domain_match else ""
        self.sender_trust_context = self._get_sender_trust_context(sender_domain)

        if self.sender_trust_context:
            logger.info(f"Sender trust context: {sender_domain} belongs to '{self.sender_trust_context}' family")

        # Run all checks
        self._check_sender(from_addr, body, subject)
        self._check_subject(subject)
        self._check_body_content(body)
        self._check_urls(urls)
        self._check_attachments(attachments)
        self._check_headers(headers)
        self._check_urgency_tactics(subject, body)
        self._check_impersonation(from_addr, body, subject)
        self._check_isp_sender_with_suspicious_urls(from_addr, urls)
        self._check_government_postal_impersonation(from_addr, subject, body, urls)
        self._check_email_tracking_urls(urls)

        # Calculate final result
        return self._build_result()

    def _add_check(self, category: str, name: str, status: str, score: int,
                   description: str, details: str = None, ref_key: str = None):
        """Add an analysis check result"""
        self.risk_score += score
        self.checks.append(AnalysisCheck(
            category=category,
            name=name,
            status=status,
            score=score,
            description=description,
            details=details,
            reference_url=self.REFERENCES.get(ref_key) if ref_key else None
        ))

    def _check_sender(self, from_addr: str, body: str, subject: str):
        """Analyze sender address"""
        from_lower = from_addr.lower()

        # Extract domain from email
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_addr)
        sender_domain = domain_match.group(1) if domain_match else ""

        # Check for display name spoofing
        display_name_match = re.search(r'^([^<]+)<', from_addr)
        if display_name_match:
            display_name = display_name_match.group(1).strip().lower()
            # Check if display name contains company but domain doesn't match
            for company in self.COMMONLY_SPOOFED:
                if company in display_name and company not in sender_domain:
                    self._add_check(
                        "sender", "Display Name Spoofing",
                        "critical", 30,
                        f"Display name contains '{company}' but sender domain is '{sender_domain}'",
                        f"Legitimate {company} emails come from official domains",
                        "domain_spoofing"
                    )
                    break

        # Check for free email providers impersonating companies
        free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                         'aol.com', 'mail.com', 'protonmail.com']
        if any(p in sender_domain for p in free_providers):
            for company in self.COMMONLY_SPOOFED:
                if company in body.lower() or company in subject.lower():
                    self._add_check(
                        "sender", "Free Email Provider",
                        "danger", 25,
                        f"Email mentions '{company}' but sent from free email provider",
                        f"Sender: {from_addr}",
                        "phishing_general"
                    )
                    break
            else:
                self._add_check(
                    "sender", "Free Email Provider",
                    "warning", 5,
                    "Email sent from free email provider",
                    f"Domain: {sender_domain}",
                    None
                )

        # Check for suspicious TLD
        for tld in self.SUSPICIOUS_TLDS:
            if sender_domain.endswith(tld):
                self._add_check(
                    "sender", "Suspicious TLD",
                    "danger", 20,
                    f"Sender domain uses suspicious TLD: {tld}",
                    f"Domain: {sender_domain}",
                    "domain_spoofing"
                )
                break

        # Check for lookalike domains (typosquatting)
        typosquat_patterns = [
            (r'paypa[l1]', 'paypal'), (r'amaz[o0]n', 'amazon'),
            (r'app[l1]e', 'apple'), (r'g[o0]{2}g[l1]e', 'google'),
            (r'micr[o0]s[o0]ft', 'microsoft'), (r'netf[l1]ix', 'netflix'),
            (r'faceb[o0]{2}k', 'facebook')
        ]
        for pattern, company in typosquat_patterns:
            if re.search(pattern, sender_domain) and company not in sender_domain:
                self._add_check(
                    "sender", "Typosquatting Domain",
                    "critical", 35,
                    f"Domain appears to impersonate {company}",
                    f"Suspicious domain: {sender_domain}",
                    "domain_spoofing"
                )
                break

    def _check_subject(self, subject: str):
        """Analyze email subject"""
        subject_lower = subject.lower()

        # Check for RE:/FW: tricks
        if re.match(r'^(re|fw|fwd):\s*', subject_lower):
            # Check if it's a fake reply/forward (no real conversation)
            self._add_check(
                "subject", "Reply/Forward Prefix",
                "warning", 5,
                "Subject starts with RE:/FW: which may be used to appear legitimate",
                None,
                "social_engineering"
            )

        # Check for all caps
        caps_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
        if caps_ratio > 0.5 and len(subject) > 10:
            self._add_check(
                "subject", "Excessive Capitalization",
                "warning", 10,
                "Subject uses excessive capital letters to create urgency",
                f"Subject: {subject[:50]}...",
                "social_engineering"
            )

        # Check for common phishing subject patterns
        phishing_subjects = [
            (r'account.*(suspend|lock|limit|verify|confirm)', "Account threat"),
            (r'(password|credential).*(expire|reset|change)', "Credential urgency"),
            (r'(invoice|payment|receipt).*\d+', "Fake invoice/payment"),
            (r'(prize|winner|won|lottery|inheritance)', "Prize/lottery scam"),
            (r'(urgent|immediate|action required)', "Urgency pressure"),
            (r'security.*(alert|warning|notice)', "Fake security alert")
        ]
        for pattern, description in phishing_subjects:
            if re.search(pattern, subject_lower):
                self._add_check(
                    "subject", "Phishing Subject Pattern",
                    "danger", 15,
                    f"Subject matches known phishing pattern: {description}",
                    f"Subject: {subject[:50]}",
                    "phishing_general"
                )
                break

    def _check_body_content(self, body: str):
        """Analyze email body content"""
        body_lower = body.lower()

        # Check for generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear member',
                           'dear client', 'dear valued', 'dear account holder']
        for greeting in generic_greetings:
            if greeting in body_lower:
                self._add_check(
                    "content", "Generic Greeting",
                    "warning", 10,
                    "Email uses generic greeting instead of your name",
                    f"Found: '{greeting}'",
                    "phishing_general"
                )
                break

        # Check for threats/consequences
        threat_patterns = [
            (r'(account|access).*(suspend|terminat|cancel|block|close)', "Account threat"),
            (r'(legal|law enforcement|police|fbi|court)', "Legal threat"),
            (r'(within|in)\s*\d+\s*(hour|day|minute)', "Time pressure"),
            (r'fail(ure)?\s*to\s*(respond|verify|confirm)', "Failure consequence")
        ]
        for pattern, threat_type in threat_patterns:
            if re.search(pattern, body_lower):
                self._add_check(
                    "content", "Threat/Pressure Tactic",
                    "danger", 15,
                    f"Email uses {threat_type} to pressure action",
                    None,
                    "social_engineering"
                )
                break

        # Check for credential requests (actual sensitive info, not login links)
        credential_requests = [
            r'(enter|provide|confirm|verify).*(password|pin|ssn|social security)',
            r'(credit card|card number|cvv|expir(ation|y)?\s*(date)?)',  # More specific: expiration date, not just "expir"
            r'(bank account|routing number|account number)',
            r'(type|send|reply).*(password|credential)',  # Asking to send password
        ]

        # Exclude legitimate contexts (OA, job applications, etc.)
        legitimate_contexts = [
            'assessment', 'online assessment', 'coding challenge', 'interview',
            'application', 'job application', 'position', 'role', 'intern',
            'codesignal', 'hackerrank', 'leetcode', 'codility'
        ]
        is_legitimate_context = any(ctx in body_lower for ctx in legitimate_contexts)

        if not is_legitimate_context:
            for pattern in credential_requests:
                if re.search(pattern, body_lower):
                    self._add_check(
                        "content", "Credential Request",
                        "critical", 30,
                        "Email requests sensitive personal/financial information",
                        "Legitimate companies never ask for passwords or full card numbers via email",
                        "phishing_general"
                    )
                    break

        # Check for grammar/spelling issues (simplified check)
        grammar_issues = [
            r'\bi\s+am\b', r'\bwe\s+is\b', r'\byou\s+is\b',
            r'kindly\s+(do|click|verify)', r'dear\s+sir/madam'
        ]
        issue_count = sum(1 for p in grammar_issues if re.search(p, body_lower))
        if issue_count >= 2:
            self._add_check(
                "content", "Grammar/Spelling Issues",
                "warning", 10,
                "Email contains grammar or spelling issues common in phishing",
                None,
                "phishing_general"
            )

    def _check_urls(self, urls: List[str]):
        """Analyze URLs in the email"""
        if not urls:
            return

        # Track domains we've already scored to avoid double-counting
        scored_domains = set()

        for url in urls[:10]:  # Limit to first 10 URLs
            domain_analysis = self._analyze_url(url)
            self.domain_analyses.append(domain_analysis)

            # Add check based on domain analysis - but only score each domain ONCE
            if domain_analysis.is_suspicious:
                domain = domain_analysis.domain
                for check in domain_analysis.checks:
                    # Create a unique key for this type of check on this domain
                    check_key = f"{domain}:{check.name}"
                    if check_key not in scored_domains:
                        scored_domains.add(check_key)
                        self.risk_score += check.score
                        self.checks.append(check)
                    # Still show the check in domain analysis, but don't add duplicate score

    def _analyze_url(self, url: str) -> DomainAnalysis:
        """Analyze a single URL"""
        checks = []
        is_suspicious = False
        risk_level = "safe"

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()

            # Check for IP address instead of domain
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, domain):
                checks.append(AnalysisCheck(
                    category="url", name="IP Address URL",
                    status="critical", score=30,
                    description="URL uses IP address instead of domain name",
                    details=f"URL: {url[:60]}...",
                    reference_url=self.REFERENCES["url_safety"]
                ))
                is_suspicious = True
                risk_level = "critical"

            # Check for URL shorteners (must match exactly, not substring)
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                         'is.gd', 'buff.ly', 'short.link', 'cutt.ly', 'rb.gy',
                         'shorturl.at', 'tiny.cc', 'v.gd', 'clck.ru']
            # Must be exact domain match (not substring like "support.codesignal.com")
            is_shortener = domain in shorteners or any(domain.endswith('.' + s) for s in shorteners)
            if is_shortener:
                checks.append(AnalysisCheck(
                    category="url", name="URL Shortener",
                    status="danger", score=20,
                    description="URL uses shortening service to hide actual destination",
                    details=f"Shortener: {domain}",
                    reference_url=self.REFERENCES["url_shorteners"]
                ))
                is_suspicious = True
                risk_level = "high" if risk_level == "safe" else risk_level

            # Check for suspicious TLDs
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    checks.append(AnalysisCheck(
                        category="url", name="Suspicious TLD",
                        status="danger", score=20,
                        description=f"URL uses suspicious top-level domain: {tld}",
                        details=f"Domain: {domain}",
                        reference_url=self.REFERENCES["domain_spoofing"]
                    ))
                    is_suspicious = True
                    risk_level = "high" if risk_level == "safe" else risk_level
                    break

            # Check for gibberish/random domain names (DGA-like patterns)
            # SMART TRUST: Skip if URL belongs to same company family as trusted sender
            is_trusted_by_sender = hasattr(self, 'sender_trust_context') and self._is_url_trusted_by_sender(domain, self.sender_trust_context)

            # Also check Tranco list for domain reputation
            is_tranco_trusted, tranco_trust_level, tranco_rank = self._check_domain_with_tranco(domain)

            is_gibberish, entropy = self._is_gibberish_domain(domain)
            if is_gibberish and not is_trusted_by_sender and not is_tranco_trusted:
                checks.append(AnalysisCheck(
                    category="url", name="Random/Gibberish Domain",
                    status="danger", score=25,
                    description="Domain name appears to be randomly generated (potential DGA)",
                    details=f"Domain: {domain}, Entropy: {entropy:.2f}",
                    reference_url=self.REFERENCES["domain_spoofing"]
                ))
                is_suspicious = True
                risk_level = "high" if risk_level == "safe" else risk_level
            elif is_gibberish and is_trusted_by_sender:
                # Log but don't flag - domain looks random but is trusted via sender context
                logger.debug(f"Skipping gibberish check for {domain} - trusted by sender context")
            elif is_gibberish and is_tranco_trusted:
                # Log but don't flag - domain looks random but is in Tranco top domains
                logger.debug(f"Skipping gibberish check for {domain} - in Tranco top {tranco_rank}")

            # Check for typosquatting - only flag if domain looks like it's impersonating
            # but ISN'T the real domain
            # IMPORTANT: Skip this check if domain is trusted by Tranco (high-ranking domains are legit)
            # This handles banks worldwide without needing to manually whitelist each one
            if is_tranco_trusted and tranco_rank and tranco_rank <= 10000:
                logger.debug(f"Skipping typosquatting check for {domain} - Tranco rank {tranco_rank}")
            else:
                for company in self.COMMONLY_SPOOFED:
                    # Check if domain contains company name variation but isn't official
                    if company in domain:
                        # Skip generic terms that would cause false positives
                        if company in ['bank', 'irs', 'twitter', 'instagram', 'whatsapp', 'telegram']:
                            continue

                        # Check if domain matches sender context (trusted sender's own links)
                        if is_trusted_by_sender:
                            logger.debug(f"Skipping impersonation check for {domain} - trusted by sender")
                            continue

                        # For known companies, check against their official domains
                        official_domains = {
                            'paypal': ['paypal.com'],
                            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.co.jp'],
                            'apple': ['apple.com', 'icloud.com'],
                            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'hotmail.com', 'office.com'],
                            'google': ['google.com', 'gmail.com', 'youtube.com'],
                            'facebook': ['facebook.com', 'fb.com', 'meta.com'],
                            'netflix': ['netflix.com'],
                            'chase': ['chase.com', 'jpmorganchase.com'],
                            'wellsfargo': ['wellsfargo.com'],
                            'citibank': ['citi.com', 'citibank.com', 'citigroup.com'],
                            'usps': ['usps.com'],
                            'fedex': ['fedex.com'],
                            'dhl': ['dhl.com'],
                            'ups': ['ups.com'],
                            'dropbox': ['dropbox.com'],
                            'linkedin': ['linkedin.com'],
                            'coinbase': ['coinbase.com'],
                            'binance': ['binance.com'],
                        }
                        if company in official_domains:
                            # Check if this is the official domain or a subdomain of it
                            is_official = any(
                                domain == official or domain.endswith('.' + official)
                                for official in official_domains[company]
                            )
                            if not is_official:
                                checks.append(AnalysisCheck(
                                    category="url", name="Domain Impersonation",
                                    status="critical", score=35,
                                    description=f"URL may be impersonating {company}",
                                    details=f"Suspicious domain: {domain}",
                                    reference_url=self.REFERENCES["domain_spoofing"]
                                ))
                                is_suspicious = True
                                risk_level = "critical"
                                break

            # Check for suspicious path patterns
            suspicious_paths = ['/login', '/signin', '/verify', '/secure', '/account',
                              '/update', '/confirm', '/password', '/credential']
            if any(p in path for p in suspicious_paths):
                if is_suspicious:  # Only flag if domain is already suspicious
                    checks.append(AnalysisCheck(
                        category="url", name="Suspicious URL Path",
                        status="warning", score=10,
                        description="URL path suggests credential harvesting page",
                        details=f"Path contains sensitive keywords",
                        reference_url=self.REFERENCES["phishing_general"]
                    ))

            # Check for data: or javascript: URLs
            if url.lower().startswith(('data:', 'javascript:')):
                checks.append(AnalysisCheck(
                    category="url", name="Dangerous URL Scheme",
                    status="critical", score=40,
                    description="URL uses dangerous scheme that can execute code",
                    details=f"Scheme: {url[:20]}...",
                    reference_url=self.REFERENCES["url_safety"]
                ))
                is_suspicious = True
                risk_level = "critical"

        except Exception as e:
            logger.warning(f"URL parsing error: {e}")

        return DomainAnalysis(
            domain=domain if 'domain' in dir() else url[:50],
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            checks=checks
        )

    def _check_attachments(self, attachments: List[str]):
        """Analyze email attachments"""
        for filename in attachments:
            ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''

            # Determine risk level
            if ext in self.DANGEROUS_EXTENSIONS['critical']:
                risk_level = "critical"
                description = "Executable file - can run malicious code"
                score = 40
            elif ext in self.DANGEROUS_EXTENSIONS['high']:
                risk_level = "high"
                description = "Archive file - may contain hidden malware"
                score = 25
            elif ext in self.DANGEROUS_EXTENSIONS['medium']:
                risk_level = "medium"
                description = "Document with macros - may contain malicious scripts"
                score = 15
            else:
                risk_level = "low"
                description = "Standard file type"
                score = 0

            self.attachment_analyses.append(AttachmentAnalysis(
                filename=filename,
                extension=ext,
                risk_level=risk_level,
                description=description,
                reference_url=self.REFERENCES["attachment_safety"]
            ))

            if risk_level in ["critical", "high"]:
                self._add_check(
                    "attachment", f"Risky Attachment: {ext}",
                    "critical" if risk_level == "critical" else "danger",
                    score,
                    description,
                    f"Filename: {filename}",
                    "attachment_safety"
                )

    def _check_headers(self, headers: Dict[str, Any]):
        """Analyze email headers for authentication"""
        # Check SPF
        spf = headers.get('spf', '').lower()
        if spf:
            if 'fail' in spf or 'softfail' in spf:
                self._add_check(
                    "authentication", "SPF Failed",
                    "danger", 25,
                    "Email failed SPF authentication - sender may be spoofed",
                    f"SPF result: {spf[:50]}",
                    "spf_dkim"
                )
            elif 'pass' in spf:
                self._add_check(
                    "authentication", "SPF Passed",
                    "safe", 0,
                    "Email passed SPF authentication",
                    None,
                    "spf_dkim"
                )

        # Check DKIM
        dkim = headers.get('dkim', '').lower()
        if dkim:
            if 'fail' in dkim:
                self._add_check(
                    "authentication", "DKIM Failed",
                    "danger", 25,
                    "Email failed DKIM signature verification",
                    None,
                    "spf_dkim"
                )
            elif 'pass' in dkim:
                self._add_check(
                    "authentication", "DKIM Passed",
                    "safe", 0,
                    "Email passed DKIM authentication",
                    None,
                    "spf_dkim"
                )

    def _check_urgency_tactics(self, subject: str, body: str):
        """Check for social engineering urgency tactics"""
        combined = (subject + ' ' + body).lower()

        urgency_patterns = [
            (r'(act|respond|reply)\s*(now|immediately|urgently)', "Immediate action pressure"),
            (r'(expire|expiring|expired)\s*(today|soon|in \d+)', "Expiration pressure"),
            (r'(last|final)\s*(chance|warning|notice)', "Final notice pressure"),
            (r'(limited|only)\s*\d+\s*(left|remaining|available)', "Scarcity tactic"),
            (r'don\'?t\s*(miss|lose|ignore)', "Fear of loss")
        ]

        found_tactics = []
        for pattern, tactic in urgency_patterns:
            if re.search(pattern, combined):
                found_tactics.append(tactic)

        if len(found_tactics) >= 2:
            self._add_check(
                "tactics", "Multiple Urgency Tactics",
                "danger", 20,
                "Email uses multiple pressure tactics common in phishing",
                f"Tactics found: {', '.join(found_tactics[:3])}",
                "social_engineering"
            )
        elif found_tactics:
            self._add_check(
                "tactics", "Urgency Tactic",
                "warning", 10,
                f"Email uses urgency tactic: {found_tactics[0]}",
                None,
                "social_engineering"
            )

    def _check_impersonation(self, from_addr: str, body: str, subject: str):
        """Check for brand/company impersonation"""
        # Check for brand mentions without proper sender domain
        brand_domains = {
            'paypal': ['paypal.com'],
            'amazon': ['amazon.com', 'amazon.co'],
            'apple': ['apple.com', 'icloud.com'],
            'microsoft': ['microsoft.com', 'office.com'],
            'google': ['google.com', 'gmail.com'],
            'netflix': ['netflix.com'],
            'facebook': ['facebook.com', 'meta.com'],
            'instagram': ['instagram.com'],
            'linkedin': ['linkedin.com'],
            'twitter': ['twitter.com', 'x.com'],
            'chase': ['chase.com'],
            'wellsfargo': ['wellsfargo.com'],
            'bankofamerica': ['bankofamerica.com']
        }

        from_domain = re.search(r'@([a-zA-Z0-9.-]+)', from_addr)
        sender_domain = from_domain.group(1).lower() if from_domain else ""

        # If sender is from a legitimate tech company, skip impersonation check
        # (e.g., TikTok emails mentioning LinkedIn profile are NOT impersonation)
        if self._is_legitimate_company_sender(sender_domain):
            return

        # If we can't determine the sender domain, skip impersonation check
        # (avoids false positives when email parser only captures display name)
        if not sender_domain:
            return

        # Only check subject line for impersonation (not body content)
        # Body may legitimately mention brands (e.g., "view my LinkedIn profile")
        combined = (from_addr + ' ' + subject).lower()

        for brand, official_domains in brand_domains.items():
            if brand in combined:
                if not any(d in sender_domain for d in official_domains):
                    self._add_check(
                        "impersonation", f"{brand.title()} Impersonation",
                        "danger", 20,
                        f"Email mentions {brand.title()} but isn't from official domain",
                        f"Sender domain: {sender_domain}, Expected: {', '.join(official_domains)}",
                        "domain_spoofing"
                    )
                    break

    def _is_legitimate_company_sender(self, sender_domain: str) -> bool:
        """Check if sender is from a known legitimate company"""
        if not sender_domain:
            return False

        for company in self.LEGITIMATE_TECH_COMPANIES:
            if sender_domain.endswith(company) or sender_domain.endswith('.' + company):
                return True
        return False

    def _check_isp_sender_with_suspicious_urls(self, from_addr: str, urls: List[str]):
        """
        Check for ISP/consumer email sender combined with suspicious URLs.
        This is a common pattern in compromised account phishing.
        """
        # Extract sender domain
        domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_addr)
        sender_domain = domain_match.group(1).lower() if domain_match else ""

        # Check if sender is from an ISP/consumer email domain
        is_isp_sender = any(isp in sender_domain for isp in self.ISP_EMAIL_DOMAINS)

        if not is_isp_sender:
            return

        # Check if any URLs are suspicious
        suspicious_url_found = False
        suspicious_details = []

        for url in urls[:10]:
            try:
                parsed = urlparse(url)
                url_domain = parsed.netloc.lower()

                # SMART TRUST: Skip if URL belongs to same company family as trusted sender
                if hasattr(self, 'sender_trust_context') and self._is_url_trusted_by_sender(url_domain, self.sender_trust_context):
                    continue

                # Check for suspicious TLD
                has_suspicious_tld = any(url_domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS)

                # Check for gibberish domain
                is_gibberish, entropy = self._is_gibberish_domain(url_domain)

                if has_suspicious_tld or is_gibberish:
                    suspicious_url_found = True
                    suspicious_details.append(url_domain)

            except Exception:
                pass

        if suspicious_url_found:
            self._add_check(
                "combination", "ISP Email with Suspicious URL",
                "critical", 35,
                "Email from ISP/consumer account contains links to suspicious domains",
                f"Sender: {sender_domain}, Suspicious URLs: {', '.join(suspicious_details[:3])}",
                "phishing_general"
            )

    def _is_legitimate_trusted_domain(self, sender_domain: str) -> bool:
        """
        Check if sender domain is a LEGITIMATE trusted domain.

        Must verify domain actually ENDS with trusted suffix (not just contains it):
        - "duke.edu" → trusted ✓
        - "duke.edu.phishing.com" → NOT trusted ✗
        - "duke-edu.com" → NOT trusted ✗
        """
        if not sender_domain:
            return False

        # Check for legitimate TLD endings (must END with these)
        trusted_tlds = ['.edu', '.gov', '.mil', '.ac.uk', '.edu.au', '.edu.tw', '.gov.uk']

        for tld in trusted_tlds:
            if sender_domain.endswith(tld):
                # Additional check: reject suspicious patterns even in trusted TLDs
                suspicious_patterns = [
                    r'\d{5,}',  # Too many numbers (e.g., duke123456.edu)
                    r'(secure|verify|account|login|update|confirm)-',  # Suspicious prefix
                ]
                for pattern in suspicious_patterns:
                    if re.search(pattern, sender_domain):
                        return False
                return True

        return False

    def _check_government_postal_impersonation(self, from_addr: str, subject: str, body: str, urls: List[str]):
        """
        Check for government/postal service impersonation.
        These are high-value targets for phishing.

        Logic:
        1. If sender domain ENDS with .edu/.gov (verified), allow - legitimate institutions
           may discuss IRS/tax topics without being impersonators
        2. Fake lookalikes (duke.edu.fake.com) will NOT pass the endswith check
        3. Only check subject line for impersonation keywords (not body content)
        """
        from_domain = re.search(r'@([a-zA-Z0-9.-]+)', from_addr)
        sender_domain = from_domain.group(1).lower() if from_domain else ""

        # Skip if sender is from a VERIFIED legitimate trusted domain
        # This uses endswith() to prevent spoofs like "irs.gov.fake.com"
        if self._is_legitimate_trusted_domain(sender_domain):
            return  # Legitimate educational/government institution

        # Only check subject line for impersonation keywords, not body
        # (body may legitimately discuss these topics)
        combined = (from_addr + ' ' + subject).lower()

        for keyword, official_domain in self.GOVERNMENT_POSTAL_KEYWORDS.items():
            keyword_lower = keyword.lower()
            # Require keyword to appear in subject or from address (not just body)
            if keyword_lower in combined:
                # Check if sender domain matches official domain
                if official_domain not in sender_domain:
                    # Check if URLs also don't go to official domain
                    urls_suspicious = True
                    for url in urls[:5]:
                        if official_domain in url.lower():
                            urls_suspicious = False
                            break

                    if urls_suspicious:
                        self._add_check(
                            "impersonation", "Government/Postal Impersonation",
                            "critical", 40,
                            f"Email appears to impersonate {keyword} but sender/URLs don't match official domain",
                            f"Sender: {sender_domain}, Expected domain: {official_domain}",
                            "domain_spoofing"
                        )
                        return  # Only flag once

    def _check_email_tracking_urls(self, urls: List[str]):
        """
        Check for email tracking/marketing service URLs.
        These are often used to mask phishing URLs.
        """
        for url in urls[:10]:
            url_lower = url.lower()
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                # SMART TRUST: Skip if URL belongs to same company family as trusted sender
                if hasattr(self, 'sender_trust_context') and self._is_url_trusted_by_sender(domain, self.sender_trust_context):
                    logger.debug(f"Skipping tracking check for {domain} - trusted by sender context '{self.sender_trust_context}'")
                    continue

                # Skip legitimate enterprise security services (SafeLinks, Proofpoint, etc.)
                is_legit_security_service = False
                for legit_service in self.LEGITIMATE_EMAIL_SECURITY_SERVICES:
                    if legit_service in domain:
                        is_legit_security_service = True
                        break

                if is_legit_security_service:
                    continue  # Skip - this is a legitimate security service

                # Skip legitimate company tracking URLs (e.g., url3572.careers.tiktok.com)
                is_legit_company_tracking = False
                for pattern in self.LEGITIMATE_TRACKING_PATTERNS:
                    if re.search(pattern, domain):
                        is_legit_company_tracking = True
                        break

                # Also check if domain ends with a known legitimate company
                for company in self.LEGITIMATE_TECH_COMPANIES:
                    if domain.endswith(company) or domain.endswith('.' + company):
                        is_legit_company_tracking = True
                        break

                if is_legit_company_tracking:
                    continue  # Skip - this is a legitimate company tracking URL

                for tracking_service in self.EMAIL_TRACKING_SERVICES:
                    # Short patterns (like "t.", "l.", "e.") should only match at domain start
                    # to avoid false positives like "support.codesignal.com"
                    if len(tracking_service) <= 3:
                        matches = domain.startswith(tracking_service)
                    else:
                        matches = tracking_service in domain

                    if matches:
                        # Check if URL has encoded/obfuscated parameters
                        path = parsed.path + (parsed.query or '')
                        has_encoded_content = (
                            len(path) > 50 or  # Long encoded path
                            re.search(r'[A-Za-z0-9_-]{20,}', path) or  # Long random string
                            '%' in path  # URL encoded
                        )

                        if has_encoded_content:
                            self._add_check(
                                "url", "Email Tracking/Redirect Service",
                                "danger", 25,
                                "URL uses email tracking service with encoded redirect (may mask phishing)",
                                f"Service: {domain}",
                                "url_shorteners"
                            )
                            return  # Only flag once
            except Exception:
                pass

    def _build_result(self) -> PhishingAnalysisResult:
        """Build the final analysis result"""
        # Cap score at 100
        final_score = min(self.risk_score, 100)

        # Determine risk level
        if final_score >= self.SCORE_THRESHOLDS["critical"]:
            risk_level = "critical"
            is_phishing = True
            confidence = "high"
        elif final_score >= self.SCORE_THRESHOLDS["high"]:
            risk_level = "high"
            is_phishing = True
            confidence = "high"
        elif final_score >= self.SCORE_THRESHOLDS["medium"]:
            risk_level = "medium"
            is_phishing = True
            confidence = "medium"
        elif final_score >= 15:
            risk_level = "low"
            is_phishing = False
            confidence = "medium"
        else:
            # 0-14: Safe - no significant risk indicators found
            risk_level = "safe"
            is_phishing = False
            confidence = "high"

        # Generate recommendation
        if is_phishing:
            if risk_level == "critical":
                recommendation = "DO NOT interact with this email. Delete immediately and report to your IT security team. Do not click any links or download attachments."
            elif risk_level == "high":
                recommendation = "This email is likely a phishing attempt. Do not click any links or provide any information. Report to your IT security team."
            else:
                recommendation = "Exercise caution with this email. Verify the sender through official channels before taking any action."
        else:
            recommendation = "This email appears to be safe, but always verify unexpected requests through official channels."

        # Generate explanation
        danger_checks = [c for c in self.checks if c.status in ["danger", "critical"]]
        if danger_checks:
            explanation = f"Found {len(danger_checks)} high-risk indicators. " + danger_checks[0].description
        elif self.checks:
            explanation = f"Analysis found {len(self.checks)} indicators with a total risk score of {final_score}/100."
        else:
            explanation = "No significant phishing indicators detected."

        # Build scoring criteria for transparency
        scoring_criteria = [
            {"category": "Sender Analysis", "description": "Domain reputation, display name spoofing, typosquatting", "max_points": 35},
            {"category": "URL Analysis", "description": "Suspicious domains, IP addresses, URL shorteners, impersonation", "max_points": 40},
            {"category": "Content Analysis", "description": "Credential requests, threats, urgency tactics", "max_points": 30},
            {"category": "Attachment Analysis", "description": "Dangerous file types, executables, macros", "max_points": 40},
            {"category": "Authentication", "description": "SPF, DKIM, DMARC verification results", "max_points": 25},
            {"category": "Reference", "url": self.REFERENCES["phishing_general"], "description": "CISA Phishing Guide"}
        ]

        return PhishingAnalysisResult(
            is_phishing=is_phishing,
            confidence=confidence,
            risk_level=risk_level,
            risk_score=final_score,
            max_score=100,
            recommendation=recommendation,
            explanation=explanation,
            checks=self.checks,
            domain_analyses=self.domain_analyses,
            attachment_analyses=self.attachment_analyses,
            scoring_criteria=scoring_criteria,
            data_source=self.data_source_info
        )


def analyze_email(email_content: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to analyze an email"""
    analyzer = PhishingAnalyzer()
    result = analyzer.analyze(email_content)

    # Convert to dict for JSON serialization
    return {
        "is_phishing": result.is_phishing,
        "confidence": result.confidence,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "max_score": result.max_score,
        "recommendation": result.recommendation,
        "explanation": result.explanation,
        "checks": [
            {
                "category": c.category,
                "name": c.name,
                "status": c.status,
                "score": c.score,
                "description": c.description,
                "details": c.details,
                "reference_url": c.reference_url
            } for c in result.checks
        ],
        "domain_analyses": [
            {
                "domain": d.domain,
                "is_suspicious": d.is_suspicious,
                "risk_level": d.risk_level,
                "checks": [
                    {
                        "name": c.name,
                        "status": c.status,
                        "description": c.description,
                        "reference_url": c.reference_url
                    } for c in d.checks
                ]
            } for d in result.domain_analyses
        ],
        "attachment_analyses": [
            {
                "filename": a.filename,
                "extension": a.extension,
                "risk_level": a.risk_level,
                "description": a.description,
                "reference_url": a.reference_url
            } for a in result.attachment_analyses
        ],
        "scoring_criteria": result.scoring_criteria,
        "data_source": result.data_source
    }

"""
Email Parser Utility
Parses .eml files and extracts relevant information for phishing analysis
"""

import email
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EmailParser:
    """Parse email files and extract content for analysis"""

    # Common URL pattern
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )

    # Email address pattern
    EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        re.IGNORECASE
    )

    def parse_eml(self, content: bytes) -> Dict[str, Any]:
        """
        Parse .eml file content

        Args:
            content: Raw bytes of the .eml file

        Returns:
            Dictionary with parsed email data
        """
        try:
            msg = BytesParser(policy=policy.default).parsebytes(content)
            return self._extract_email_data(msg)
        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            return {
                "error": str(e),
                "raw_content": content.decode('utf-8', errors='ignore')[:1000]
            }

    def parse_text(self, text: str) -> Dict[str, Any]:
        """
        Parse plain text email content

        Args:
            text: Plain text email content

        Returns:
            Dictionary with parsed email data
        """
        # Try to extract headers from text
        lines = text.split('\n')
        headers = {}
        body_start = 0

        for i, line in enumerate(lines):
            if ':' in line and not line.startswith(' '):
                key, _, value = line.partition(':')
                key = key.strip().lower()
                if key in ['from', 'to', 'subject', 'date', 'reply-to']:
                    headers[key] = value.strip()
            elif line.strip() == '':
                body_start = i + 1
                break

        body = '\n'.join(lines[body_start:])
        urls = self._extract_urls(body)

        return {
            "from": headers.get('from', 'Unknown'),
            "to": headers.get('to', 'Unknown'),
            "subject": headers.get('subject', 'No subject'),
            "date": headers.get('date', ''),
            "reply_to": headers.get('reply-to'),
            "body": body,
            "body_html": None,
            "urls": urls,
            "attachments": [],
            "headers": headers
        }

    def _extract_email_data(self, msg: email.message.Message) -> Dict[str, Any]:
        """Extract data from parsed email message"""
        # Get basic headers
        from_addr = self._decode_header(msg.get('From', ''))
        to_addr = self._decode_header(msg.get('To', ''))
        subject = self._decode_header(msg.get('Subject', ''))
        date_str = msg.get('Date', '')
        reply_to = self._decode_header(msg.get('Reply-To', ''))
        return_path = msg.get('Return-Path', '')

        # Parse date
        date_parsed = None
        if date_str:
            try:
                date_parsed = email.utils.parsedate_to_datetime(date_str)
            except Exception:
                pass

        # Get body content
        body_text = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Check for attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append(self._decode_header(filename))
                elif content_type == "text/plain":
                    try:
                        body_text = part.get_content()
                    except Exception:
                        body_text = str(part.get_payload(decode=True), errors='ignore')
                elif content_type == "text/html":
                    try:
                        body_html = part.get_content()
                    except Exception:
                        body_html = str(part.get_payload(decode=True), errors='ignore')
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
                if content_type == "text/html":
                    body_html = content
                else:
                    body_text = content
            except Exception:
                body_text = str(msg.get_payload(decode=True), errors='ignore')

        # Extract URLs from both text and HTML
        all_content = body_text + " " + body_html
        urls = self._extract_urls(all_content)

        # Extract additional headers for analysis
        received_headers = msg.get_all('Received', [])
        x_headers = {k: v for k, v in msg.items() if k.lower().startswith('x-')}

        return {
            "from": from_addr,
            "to": to_addr,
            "subject": subject,
            "date": date_str,
            "date_parsed": date_parsed.isoformat() if date_parsed else None,
            "reply_to": reply_to,
            "return_path": return_path,
            "body": body_text or self._strip_html(body_html),
            "body_html": body_html,
            "urls": urls,
            "attachments": attachments,
            "received_headers": received_headers[:5],  # Limit for analysis
            "x_headers": dict(list(x_headers.items())[:10]),  # Limit for analysis
            "headers": {
                "message_id": msg.get('Message-ID', ''),
                "content_type": msg.get_content_type(),
                "spf": msg.get('Received-SPF', ''),
                "dkim": msg.get('DKIM-Signature', '')[:100] if msg.get('DKIM-Signature') else '',
                "dmarc": msg.get('Authentication-Results', '')[:200] if msg.get('Authentication-Results') else ''
            }
        }

    def _decode_header(self, header: str) -> str:
        """Decode email header value"""
        if not header:
            return ""
        try:
            decoded_parts = email.header.decode_header(header)
            result = []
            for part, charset in decoded_parts:
                if isinstance(part, bytes):
                    result.append(part.decode(charset or 'utf-8', errors='ignore'))
                else:
                    result.append(str(part))
            return ' '.join(result)
        except Exception:
            return str(header)

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        if not text:
            return []
        urls = self.URL_PATTERN.findall(text)
        # Clean and deduplicate
        clean_urls = []
        seen = set()
        for url in urls:
            # Remove trailing punctuation
            url = url.rstrip('.,;:!?')
            if url not in seen:
                seen.add(url)
                clean_urls.append(url)
        return clean_urls[:20]  # Limit to 20 URLs

    def _strip_html(self, html: str) -> str:
        """Simple HTML tag removal"""
        if not html:
            return ""
        # Remove script and style elements
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
        # Remove tags
        text = re.sub(r'<[^>]+>', ' ', html)
        # Clean whitespace
        text = re.sub(r'\s+', ' ', text)
        return text.strip()


# Singleton instance
_parser: Optional[EmailParser] = None


def get_email_parser() -> EmailParser:
    """Get or create email parser instance"""
    global _parser
    if _parser is None:
        _parser = EmailParser()
    return _parser

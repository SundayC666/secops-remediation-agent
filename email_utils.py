"""
Email Parsing Utilities for Cloud Airlock
Handles safe parsing of .eml files and extraction of content for analysis.
"""

import email
from email import policy
from email.message import EmailMessage
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_eml_file(uploaded_file) -> Optional[Dict]:
    """
    Parse an uploaded .eml file and extract relevant metadata and body.
    Performs static analysis to sanitize HTML content.

    Args:
        uploaded_file: The file object from Streamlit uploader

    Returns:
        Dictionary containing sender, subject, date, body, and extracted links
    """
    try:
        # Read bytes from the uploaded file
        bytes_content = uploaded_file.getvalue()
        
        # Parse the email object with default policy
        msg: EmailMessage = email.message_from_bytes(bytes_content, policy=policy.default)
        
        # Extract basic metadata
        metadata = {
            "subject": msg.get("subject", "No Subject"),
            "from": msg.get("from", "Unknown Sender"),
            "date": msg.get("date", "Unknown Date"),
            "body": "",
            "links": []
        }
        
        # Extract body content
        body_content = ""
        
        if msg.is_multipart():
            # Walk through email parts to find text or html
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                try:
                    part_content = part.get_content()
                except Exception:
                    # Skip parts that cannot be decoded
                    continue

                if content_type == "text/plain":
                    body_content += part_content + "\n"
                elif content_type == "text/html":
                    # Use BeautifulSoup to strip HTML tags and get clean text
                    soup = BeautifulSoup(part_content, 'html.parser')
                    body_content += soup.get_text(separator=' ') + "\n"
        else:
            # Single part email
            content_type = msg.get_content_type()
            part_content = msg.get_content()
            
            if content_type == "text/html":
                soup = BeautifulSoup(part_content, 'html.parser')
                body_content += soup.get_text(separator=' ')
            else:
                body_content = part_content

        # Clean up whitespace
        metadata["body"] = _clean_text(body_content)
        
        # Extract URLs for analysis (using regex)
        # Matches http/https URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        metadata["links"] = re.findall(url_pattern, metadata["body"])
        
        logger.info(f"Successfully parsed email: {metadata['subject']}")
        return metadata

    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        return None

def _clean_text(text: str) -> str:
    """Helper function to clean up excessive whitespace"""
    if not text:
        return ""
    # Replace multiple spaces/newlines with single space
    return " ".join(text.split())
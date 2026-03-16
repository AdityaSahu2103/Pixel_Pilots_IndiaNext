"""
CyberShield AI - Content Extraction Agent
Parses emails, URLs, text, and files to extract analyzable content.
"""
import re
import email
from email import policy
from urllib.parse import urlparse
from typing import Optional

import httpx
from bs4 import BeautifulSoup

from backend.models.schemas import ExtractedContent, SourceType


class ContentExtractorAgent:
    """
    Extracts and normalizes content from various input sources.
    Handles email parsing, URL content fetching, and text normalization.
    """

    AGENT_NAME = "content_extractor"

    # Common URL pattern
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        re.IGNORECASE
    )

    async def extract(self, source_type: SourceType, content: str, metadata: Optional[dict] = None) -> ExtractedContent:
        """
        Main extraction entry point. Routes to the appropriate parser.
        """
        if source_type == SourceType.EMAIL:
            return await self._extract_email(content, metadata)
        elif source_type == SourceType.URL:
            return await self._extract_url(content)
        elif source_type == SourceType.TEXT:
            return self._extract_text(content, metadata)
        elif source_type == SourceType.FILE:
            return self._extract_file(content, metadata)
        else:
            return ExtractedContent(
                source_type=source_type,
                plain_text=content,
                metadata=metadata or {}
            )

    async def _extract_email(self, raw_email: str, metadata: Optional[dict] = None) -> ExtractedContent:
        """Parse raw email content and extract all components."""
        try:
            msg = email.message_from_string(raw_email, policy=policy.default)
        except Exception:
            # If email parsing fails, treat as plain text
            return ExtractedContent(
                source_type=SourceType.EMAIL,
                plain_text=raw_email,
                urls=self._extract_urls(raw_email),
                metadata=metadata or {}
            )

        # Extract headers
        headers = {
            "from": str(msg.get("From", "")),
            "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "return_path": str(msg.get("Return-Path", "")),
            "received": [str(h) for h in msg.get_all("Received", [])],
            "authentication_results": str(msg.get("Authentication-Results", "")),
            "spf": str(msg.get("Received-SPF", "")),
            "dkim_signature": str(msg.get("DKIM-Signature", "")),
            "dmarc": str(msg.get("DMARC", "")),
            "x_mailer": str(msg.get("X-Mailer", "")),
            "reply_to": str(msg.get("Reply-To", "")),
        }

        # Extract body
        plain_text = ""
        html_content = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        plain_text += payload.decode("utf-8", errors="replace")
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        html_content = payload.decode("utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                plain_text = payload.decode("utf-8", errors="replace")
            content_type = msg.get_content_type()
            if content_type == "text/html":
                html_content = plain_text
                plain_text = BeautifulSoup(plain_text, "html.parser").get_text()

        # Extract attachments info
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        "filename": filename,
                        "content_type": part.get_content_type(),
                        "size": len(part.get_payload(decode=True) or b""),
                    })

        # Extract all URLs from text and HTML
        all_text = plain_text + (html_content or "")
        urls = self._extract_urls(all_text)

        return ExtractedContent(
            source_type=SourceType.EMAIL,
            plain_text=plain_text,
            html_content=html_content,
            urls=urls,
            sender=headers.get("from"),
            subject=headers.get("subject"),
            headers=headers,
            attachments=attachments,
            metadata=metadata or {}
        )

    async def _extract_url(self, url: str) -> ExtractedContent:
        """Fetch and parse URL content."""
        parsed = urlparse(url)
        extracted = ExtractedContent(
            source_type=SourceType.URL,
            plain_text=url,
            urls=[url],
            metadata={
                "domain": parsed.netloc,
                "scheme": parsed.scheme,
                "path": parsed.path,
                "query": parsed.query,
            }
        )

        # Try to fetch the URL content
        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                verify=False
            ) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")
                    if "text/html" in content_type:
                        extracted.html_content = response.text
                        soup = BeautifulSoup(response.text, "html.parser")
                        extracted.plain_text = soup.get_text(separator=" ", strip=True)
                        # Extract embedded URLs
                        for link in soup.find_all("a", href=True):
                            extracted.urls.append(link["href"])
                    else:
                        extracted.plain_text = response.text[:5000]

                    extracted.metadata["status_code"] = response.status_code
                    extracted.metadata["final_url"] = str(response.url)
                    extracted.metadata["redirect_count"] = len(response.history)
                    extracted.metadata["content_type"] = content_type
        except Exception as e:
            extracted.metadata["fetch_error"] = str(e)

        return extracted

    def _extract_text(self, text: str, metadata: Optional[dict] = None) -> ExtractedContent:
        """Process plain text content."""
        urls = self._extract_urls(text)
        return ExtractedContent(
            source_type=SourceType.TEXT,
            plain_text=text,
            urls=urls,
            metadata=metadata or {}
        )

    def _extract_file(self, content: str, metadata: Optional[dict] = None) -> ExtractedContent:
        """Process file content (base64 or text)."""
        return ExtractedContent(
            source_type=SourceType.FILE,
            plain_text=content,
            urls=self._extract_urls(content),
            metadata=metadata or {}
        )

    def _extract_urls(self, text: str) -> list[str]:
        """Extract all URLs from text."""
        urls = self.URL_PATTERN.findall(text)
        return list(set(urls))

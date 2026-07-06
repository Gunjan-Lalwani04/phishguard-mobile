"""Parses raw .eml text/bytes into plain values the engine can score."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

from core.util import extract_urls


class _AnchorExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href
                self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []


def _addr(header_value: str | None) -> str:
    if not header_value:
        return ""
    _, addr = parseaddr(header_value)
    return addr.lower()


def _display(header_value: str | None) -> str:
    if not header_value:
        return ""
    display, _ = parseaddr(header_value)
    return display


def parse_eml(raw_text: str) -> dict:
    """Parse raw .eml source text into a plain dict of fields the engine
    understands: subject, from_display, from_addr, reply_to_addr,
    return_path_addr, body_text, links (list of (href, anchor)),
    attachments (list of (filename, content_type)).
    """
    raw_bytes = raw_text.encode("utf-8", errors="replace")
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    body_text = ""
    body_html = ""
    attachments: list[tuple[str, str]] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()

            if filename and "attachment" in disposition.lower():
                attachments.append((filename, content_type))
                continue

            if content_type == "text/plain" and not body_text:
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
            elif content_type == "text/html" and not body_html:
                try:
                    body_html += part.get_content()
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if content_type == "text/html":
            body_html = content
        else:
            body_text = content

    links: list[tuple[str, str]] = []
    if body_html:
        extractor = _AnchorExtractor()
        try:
            extractor.feed(body_html)
        except Exception:
            pass
        links += extractor.links
    links += [(u, u) for u in extract_urls(body_text)]

    return {
        "subject": str(msg.get("Subject", "")),
        "from_display": _display(msg.get("From")),
        "from_addr": _addr(msg.get("From")),
        "reply_to_addr": _addr(msg.get("Reply-To")),
        "return_path_addr": _addr(msg.get("Return-Path")),
        "body_text": body_text,
        "body_html": body_html,
        "links": links,
        "attachments": attachments,
    }

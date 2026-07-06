"""Small shared helpers used by multiple analyzers."""

from __future__ import annotations

import re
from urllib.parse import urlsplit


def domain_of(addr_or_url: str) -> str:
    """Best-effort extraction of a registrable-ish domain from an email
    address, phone-like string, or URL. Not a full public-suffix-list
    implementation, but good enough for heuristic comparisons.
    """
    if not addr_or_url:
        return ""
    value = addr_or_url.strip()
    if "@" in value and "://" not in value:
        value = value.rsplit("@", 1)[-1]
    else:
        parts = urlsplit(value if "://" in value else f"//{value}")
        value = parts.netloc or parts.path
    value = value.split("@")[-1]  # strip userinfo@ tricks in URLs
    value = value.split(":")[0]  # strip port
    return value.lower().strip(".")


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance, iterative DP. Fine for short strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def is_ip_host(host: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host)) or bool(
        re.fullmatch(r"[0-9a-fA-F:]+", host) and ":" in host
    )


_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    return _URL_RE.findall(text or "")


def is_url(text: str) -> bool:
    text = (text or "").strip().lower()
    return text.startswith("http://") or text.startswith("https://")


def looks_like_domain(text: str) -> bool:
    text = (text or "").strip().lower()
    if not text:
        return False
    if text.startswith(("http://", "https://")):
        return True
    return "." in text and " " not in text and "://" not in text


def is_all_digits(text: str) -> bool:
    return bool(re.fullmatch(r"[+\d][\d\s\-()]*", (text or "").strip())) and any(
        c.isdigit() for c in text
    )


def is_short_code(text: str) -> bool:
    digits = re.sub(r"\D", "", text or "")
    return 3 <= len(digits) <= 6 and digits == re.sub(r"\s", "", (text or "").strip())

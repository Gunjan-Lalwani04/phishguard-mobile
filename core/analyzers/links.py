"""Analyzer: inspects hyperlinks for deception tactics.

Takes a plain list of (href, anchor_text) pairs so it works for HTML email
bodies, plain-text SMS bodies (anchor == href), and single URLs typed or
scanned from a QR code (anchor == href, list of one).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from core.brands import KNOWN_BRANDS, URL_SHORTENERS
from core.models import Finding, Severity
from core.util import domain_of, is_ip_host, levenshtein, looks_like_domain

_MAX_FINDINGS_PER_RULE = 3  # avoid flooding the report if there are many links
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _brand_lookalike(host: str) -> tuple[str, str, str, int] | None:
    """Look for a brand name hiding, slightly misspelled, inside any
    dot/hyphen-separated token of the host (e.g. 'paypa1' in
    'paypa1-support.com', or 'paypai' in 'paypai.com'). Returns
    (brand, matched_token, legit_domain, distance) or None.
    """
    if not host:
        return None

    for domains in KNOWN_BRANDS.values():
        if any(host == d or host.endswith("." + d) for d in domains):
            return None  # legitimate match, not a lookalike

    tokens = _TOKEN_RE.findall(host)
    best: tuple[str, str, str, int] | None = None
    for brand, domains in KNOWN_BRANDS.items():
        legit = sorted(domains)[0]
        for token in tokens:
            if len(token) < 4:
                continue
            dist = levenshtein(token, brand)
            # dist == 0: the exact brand name appears as its own token in a
            # domain that isn't the brand's real domain (e.g. brand name
            # plus an extra hyphenated word, "paypal-support.com"). dist ==
            # 1: a single-character typo of the brand name ("paypa1.com").
            # Both are strong impersonation signals once we already know
            # (from the "endswith" check above) this isn't the real domain.
            if dist <= 1 and len(brand) > 4 and (best is None or dist < best[3]):
                best = (brand, token, legit, dist)
    return best


def analyze_links(links: list[tuple[str, str]]) -> list[Finding]:
    """`links` is a list of (href, anchor_text) tuples."""
    findings: list[Finding] = []
    seen_categories: dict[str, int] = {}

    def add(category_key: str, finding: Finding) -> None:
        count = seen_categories.get(category_key, 0)
        if count >= _MAX_FINDINGS_PER_RULE:
            return
        seen_categories[category_key] = count + 1
        findings.append(finding)

    for href, anchor_text in links:
        if not href:
            continue
        href_host = domain_of(href)
        parts = urlsplit(href if "://" in href else f"//{href}")

        anchor = (anchor_text or "").strip()
        if anchor and anchor != href and looks_like_domain(anchor):
            anchor_host = domain_of(anchor)
            if (
                anchor_host
                and href_host
                and anchor_host != href_host
                and not href_host.endswith("." + anchor_host)
            ):
                add(
                    "mismatch",
                    Finding(
                        category="links",
                        title="Link text does not match its destination",
                        detail=f"The link displays '{anchor}' but actually points to '{href_host}'.",
                        severity=Severity.HIGH,
                        evidence=f"{anchor}  ->  {href}",
                    ),
                )

        if href_host and is_ip_host(href_host):
            add(
                "ip_host",
                Finding(
                    category="links",
                    title="Link uses a raw IP address",
                    detail="Legitimate organizations rarely link directly to a bare IP address.",
                    severity=Severity.HIGH,
                    evidence=href,
                ),
            )

        if "@" in parts.netloc:
            add(
                "at_trick",
                Finding(
                    category="links",
                    title="URL contains an '@' authority trick",
                    detail=(
                        "Text before '@' in a URL's authority section is cosmetic "
                        "and ignored by browsers, letting attackers disguise the "
                        "real destination."
                    ),
                    severity=Severity.HIGH,
                    evidence=href,
                ),
            )

        if href_host in URL_SHORTENERS:
            add(
                "shortener",
                Finding(
                    category="links",
                    title="Link uses a URL shortening service",
                    detail=f"'{href_host}' obscures the real destination of the link.",
                    severity=Severity.MEDIUM,
                    evidence=href,
                ),
            )

        if href_host and href_host.count(".") >= 4:
            add(
                "subdomains",
                Finding(
                    category="links",
                    title="Link uses an unusually long subdomain chain",
                    detail=(
                        "Long subdomain chains are often used to bury a familiar "
                        "brand name while the real, registrable domain is "
                        "something else."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=href_host,
                ),
            )

        lookalike = _brand_lookalike(href_host)
        if lookalike:
            brand, token, legit, dist = lookalike
            add(
                "lookalike",
                Finding(
                    category="links",
                    title="Link domain looks like a typosquat",
                    detail=(
                        f"'{href_host}' contains '{token}', only {dist} character(s) "
                        f"different from the legitimate {brand} name, but the domain "
                        f"is not '{legit}'."
                    ),
                    severity=Severity.HIGH,
                    evidence=href,
                ),
            )

    return findings

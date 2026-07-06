"""Analyzer: inspects email From / Reply-To / Return-Path for spoofing signals."""

from __future__ import annotations

from core.brands import KNOWN_BRANDS, SUSPICIOUS_TLDS
from core.models import Finding, Severity
from core.util import domain_of, levenshtein


def _mentioned_brand(text: str) -> str | None:
    lowered = (text or "").lower()
    for brand in KNOWN_BRANDS:
        if brand in lowered:
            return brand
    return None


def _closest_brand_domain(host: str) -> tuple[str, str, int] | None:
    if not host:
        return None
    best: tuple[str, str, int] | None = None
    for brand, domains in KNOWN_BRANDS.items():
        for legit in domains:
            if host == legit or host.endswith("." + legit):
                return None
            dist = levenshtein(host, legit)
            if best is None or dist < best[2]:
                best = (brand, legit, dist)
    if best and 0 < best[2] <= 2 and len(best[1]) > 4:
        return best
    return None


def analyze_email_sender(
    from_display: str = "",
    from_addr: str = "",
    reply_to_addr: str = "",
    return_path_addr: str = "",
) -> list[Finding]:
    findings: list[Finding] = []

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_to_addr)
    return_domain = domain_of(return_path_addr)

    mentioned = _mentioned_brand(from_display)
    if (
        mentioned
        and from_domain
        and from_domain not in KNOWN_BRANDS[mentioned]
        and not any(from_domain.endswith("." + d) for d in KNOWN_BRANDS[mentioned])
    ):
        findings.append(
            Finding(
                category="sender",
                title="Display name impersonates a known brand",
                detail=(
                    f"The sender display name references '{mentioned}' but the "
                    f"email actually comes from '{from_domain}', which is not an "
                    f"official {mentioned} domain."
                ),
                severity=Severity.HIGH,
                evidence=f'"{from_display}" <{from_addr}>',
            )
        )

    lookalike = _closest_brand_domain(from_domain)
    if lookalike:
        brand, legit, dist = lookalike
        findings.append(
            Finding(
                category="sender",
                title="Sender domain looks like a typosquat",
                detail=(
                    f"'{from_domain}' is only {dist} character(s) different from "
                    f"the legitimate {brand} domain '{legit}'."
                ),
                severity=Severity.HIGH,
                evidence=from_domain,
            )
        )

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(
            Finding(
                category="sender",
                title="Reply-To domain differs from From domain",
                detail=(
                    f"Replies would go to '{reply_domain}' instead of the apparent "
                    f"sender domain '{from_domain}'."
                ),
                severity=Severity.MEDIUM,
                evidence=reply_to_addr,
            )
        )

    if return_domain and from_domain and return_domain != from_domain:
        findings.append(
            Finding(
                category="sender",
                title="Return-Path differs from From domain",
                detail=(
                    f"The message actually originated from '{return_domain}' per "
                    f"Return-Path, but claims to be from '{from_domain}'."
                ),
                severity=Severity.MEDIUM,
                evidence=return_path_addr,
            )
        )

    if from_domain:
        tld = from_domain.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    category="sender",
                    title="Sender domain uses a high-risk TLD",
                    detail=f"'.{tld}' is disproportionately associated with throwaway phishing infrastructure.",
                    severity=Severity.LOW,
                    evidence=from_domain,
                )
            )

    return findings

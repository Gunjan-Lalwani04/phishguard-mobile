"""Analyzer: scans free text for social-engineering language.

Channel-agnostic: works the same for an email body, an SMS message, or text
decoded from a QR code.
"""

from __future__ import annotations

import re

from core.models import Finding, Severity

_URGENCY_PHRASES = [
    "act now",
    "act immediately",
    "urgent action required",
    "immediate action",
    "your account will be suspended",
    "account has been suspended",
    "account will be closed",
    "verify your account",
    "confirm your account",
    "unusual activity",
    "suspicious activity",
    "unauthorized access detected",
    "click here immediately",
    "within 24 hours",
    "within 48 hours",
    "final notice",
    "last warning",
    "avoid suspension",
    "limited time",
    "your package is on hold",
    "delivery failed",
    "payment declined",
]

_SENSITIVE_REQUEST_PHRASES = [
    "confirm your password",
    "enter your password",
    "verify your password",
    "social security number",
    "ssn",
    "credit card number",
    "card number and cvv",
    "confirm your identity",
    "update your billing",
    "update your payment",
    "provide your login",
    "enter your pin",
    "wire transfer",
    "gift card codes",
    "one-time code",
    "otp code",
    "verification code you received",
]

_GENERIC_GREETINGS = [
    "dear customer",
    "dear user",
    "dear valued customer",
    "dear account holder",
    "dear sir/madam",
    "dear sir or madam",
    "valued member",
]


def _find_phrases(text: str, phrases: list[str]) -> list[str]:
    lowered = (text or "").lower()
    return [p for p in phrases if p in lowered]


def analyze_content(text: str) -> list[Finding]:
    findings: list[Finding] = []
    text = text or ""

    urgency_hits = _find_phrases(text, _URGENCY_PHRASES)
    if urgency_hits:
        findings.append(
            Finding(
                category="content",
                title="Urgency / pressure language detected",
                detail=(
                    "Phishing relies on urgency to short-circuit careful "
                    "reading. Found phrase(s): " + ", ".join(f"'{h}'" for h in urgency_hits[:5])
                ),
                severity=Severity.MEDIUM,
                evidence="; ".join(urgency_hits[:5]),
            )
        )

    sensitive_hits = _find_phrases(text, _SENSITIVE_REQUEST_PHRASES)
    if sensitive_hits:
        findings.append(
            Finding(
                category="content",
                title="Requests sensitive information",
                detail=(
                    "Legitimate services rarely ask you to confirm credentials, "
                    "OTP codes, or financial details this way. Found phrase(s): "
                    + ", ".join(f"'{h}'" for h in sensitive_hits[:5])
                ),
                severity=Severity.HIGH,
                evidence="; ".join(sensitive_hits[:5]),
            )
        )

    greeting_hits = _find_phrases(text, _GENERIC_GREETINGS)
    if greeting_hits:
        findings.append(
            Finding(
                category="content",
                title="Generic, non-personalized greeting",
                detail="Doesn't address you by name, consistent with a mass-sent template.",
                severity=Severity.LOW,
                evidence="; ".join(greeting_hits[:3]),
            )
        )

    if re.search(r"!{2,}", text) or len(re.findall(r"\b[A-Z]{4,}\b", text)) >= 5:
        findings.append(
            Finding(
                category="content",
                title="Excessive urgency formatting",
                detail="Repeated exclamation marks or ALL-CAPS shouting, common in low-effort phishing.",
                severity=Severity.LOW,
                evidence="",
            )
        )

    return findings

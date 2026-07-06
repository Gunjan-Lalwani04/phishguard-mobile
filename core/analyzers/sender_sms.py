"""Analyzer: inspects SMS sender ID vs. message content for smishing signals.

SMS has no domain-based headers to check, so the signals are different from
email: alphanumeric sender-ID spoofing, brand names mentioned in the body
without a matching legitimate sender ID, and generic long phone numbers
pretending to represent a company.
"""

from __future__ import annotations

import re

from core.brands import KNOWN_BRANDS, KNOWN_SMS_SENDER_IDS
from core.models import Finding, Severity
from core.util import is_short_code, levenshtein


def _mentioned_brand(text: str) -> str | None:
    lowered = (text or "").lower()
    for brand in KNOWN_BRANDS:
        if brand in lowered:
            return brand
    return None


def _normalize_sender_id(sender_id: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (sender_id or "").lower())


def _closest_known_sender_id(norm_id: str) -> tuple[str, int] | None:
    if not norm_id or norm_id.isdigit():
        return None
    best: tuple[str, int] | None = None
    for known in KNOWN_SMS_SENDER_IDS:
        if norm_id == known:
            return None  # exact legitimate match
        dist = levenshtein(norm_id, known)
        if best is None or dist < best[1]:
            best = (known, dist)
    if best and 0 < best[1] <= 2 and len(best[0]) > 4:
        return best
    return None


def analyze_sms_sender(sender_id: str, message_body: str) -> list[Finding]:
    findings: list[Finding] = []
    sender_id = sender_id or ""
    message_body = message_body or ""
    norm_id = _normalize_sender_id(sender_id)
    stripped = sender_id.strip()
    is_numeric_sender = bool(re.fullmatch(r"[+\d][\d\s\-()]*", stripped)) if stripped else False

    lookalike = _closest_known_sender_id(norm_id)
    if lookalike:
        known, dist = lookalike
        findings.append(
            Finding(
                category="sender",
                title="Sender ID looks like a typosquat",
                detail=(
                    f"Sender ID '{sender_id}' is only {dist} character(s) "
                    f"different from the known legitimate sender ID '{known}'."
                ),
                severity=Severity.HIGH,
                evidence=sender_id,
            )
        )

    is_long_phone_number = is_numeric_sender and not is_short_code(sender_id)

    mentioned = _mentioned_brand(message_body)
    if mentioned and norm_id != mentioned and mentioned not in norm_id:
        if is_long_phone_number or not norm_id:
            findings.append(
                Finding(
                    category="sender",
                    title="Brand mentioned but sent from an unverified number",
                    detail=(
                        f"The message claims to be from '{mentioned}' but was sent "
                        f"from a plain phone number rather than that company's "
                        f"registered sender ID or short code."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=sender_id or "(no sender id)",
                )
            )
        elif not is_numeric_sender and not lookalike:
            findings.append(
                Finding(
                    category="sender",
                    title="Sender ID does not match the brand mentioned in the message",
                    detail=(
                        f"The message references '{mentioned}' but the sender ID "
                        f"'{sender_id}' doesn't match."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=sender_id,
                )
            )

    if is_long_phone_number and mentioned:
        findings.append(
            Finding(
                category="sender",
                title="Long phone number impersonating a company alert",
                detail=(
                    "Legitimate companies almost always send automated alerts "
                    "from a short code or a registered alphanumeric sender ID, "
                    "not a long ordinary phone number."
                ),
                severity=Severity.LOW,
                evidence=sender_id,
            )
        )

    return findings

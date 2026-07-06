"""Data models shared across the mobile app's channels (email/SMS/URL/QR)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Weight assigned to a single finding. Higher = more suspicious."""

    INFO = 0
    LOW = 2
    MEDIUM = 5
    HIGH = 9
    CRITICAL = 15

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    """A single piece of suspicious evidence discovered by an analyzer."""

    category: str  # e.g. "sender", "links", "content", "attachments"
    title: str
    detail: str
    severity: Severity
    evidence: str = ""


@dataclass
class ScanResult:
    """Result of scanning one item, regardless of channel."""

    channel: str  # "email" | "sms" | "url" | "qr"
    label: str  # short identifying string, e.g. subject or sender
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    risk_level: str = "LOW"

"""High-level scan functions the UI (or a CLI/tests) calls directly.

Each function takes plain strings/values, runs the relevant analyzers, and
returns a single ScanResult with an aggregated score and risk level.
"""

from __future__ import annotations

from core.analyzers.attachments import analyze_attachments
from core.analyzers.content import analyze_content
from core.analyzers.links import analyze_links
from core.analyzers.sender_email import analyze_email_sender
from core.analyzers.sender_sms import analyze_sms_sender
from core.eml_parser import parse_eml
from core.models import Finding, ScanResult, Severity
from core.qr import QrDecodeError, decode_qr_from_image
from core.scoring import risk_level_for_score, score_findings
from core.util import extract_urls, is_url


def _finalize(channel: str, label: str, findings: list[Finding]) -> ScanResult:
    score = score_findings(findings)
    return ScanResult(
        channel=channel,
        label=label,
        findings=findings,
        score=score,
        risk_level=risk_level_for_score(score),
    )


def scan_email_raw(raw_eml_text: str) -> ScanResult:
    """Scan raw .eml source text (e.g. pasted by the user, or read from a
    file the user picked on their device).
    """
    fields = parse_eml(raw_eml_text)
    findings: list[Finding] = []
    findings += analyze_email_sender(
        from_display=fields["from_display"],
        from_addr=fields["from_addr"],
        reply_to_addr=fields["reply_to_addr"],
        return_path_addr=fields["return_path_addr"],
    )
    findings += analyze_links(fields["links"])
    findings += analyze_content(
        f"{fields['subject']}\n{fields['body_text']}\n{fields['body_html']}"
    )
    findings += analyze_attachments(fields["attachments"])

    label = fields["subject"] or fields["from_addr"] or "(email)"
    return _finalize("email", label, findings)


def scan_sms(sender_id: str, message_body: str) -> ScanResult:
    """Scan an SMS/text message given its sender ID and body."""
    findings: list[Finding] = []
    findings += analyze_sms_sender(sender_id, message_body)
    urls = extract_urls(message_body)
    findings += analyze_links([(u, u) for u in urls])
    findings += analyze_content(message_body)

    label = sender_id or "(unknown sender)"
    return _finalize("sms", label, findings)


def scan_url(url: str) -> ScanResult:
    """Scan a single URL, e.g. one the user pasted or long-pressed to check
    before tapping.
    """
    url = (url or "").strip()
    findings = analyze_links([(url, url)])
    label = url or "(empty url)"
    return _finalize("url", label, findings)


def scan_qr_image(image_path: str) -> ScanResult:
    """Decode a QR code from an image file, then scan its payload.

    If the payload isn't a URL, it's still scanned for suspicious text
    content (e.g. urgency language, credential requests) rather than
    discarded.
    """
    try:
        decoded = decode_qr_from_image(image_path)
    except QrDecodeError as exc:
        finding = Finding(
            category="qr",
            title="Could not decode QR code",
            detail=str(exc),
            severity=Severity.INFO,
            evidence=image_path,
        )
        return _finalize("qr", image_path, [finding])

    findings: list[Finding] = []
    if is_url(decoded):
        findings += analyze_links([(decoded, decoded)])
    else:
        findings.append(
            Finding(
                category="qr",
                title="QR code contains non-URL content",
                detail=(
                    "This QR code doesn't encode a web link; reviewing its "
                    "raw content is recommended."
                ),
                severity=Severity.LOW,
                evidence=decoded[:200],
            )
        )
        findings += analyze_content(decoded)

    return _finalize("qr", decoded, findings)

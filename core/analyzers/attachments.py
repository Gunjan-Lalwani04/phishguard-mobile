"""Analyzer: flags risky email attachment types."""

from __future__ import annotations

from core.models import Finding, Severity

_DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".pif",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".msi",
    ".jar",
    ".hta",
    ".lnk",
    ".apk",
}
_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlsb"}
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}


def _ext(filename: str) -> str:
    name = (filename or "").lower().strip()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def analyze_attachments(attachments: list[tuple[str, str]]) -> list[Finding]:
    """`attachments` is a list of (filename, content_type) tuples."""
    findings: list[Finding] = []

    for filename, _content_type in attachments:
        name = filename or ""
        ext = _ext(name)
        dot_count = name.lower().count(".")

        if dot_count >= 2:
            findings.append(
                Finding(
                    category="attachments",
                    title="Attachment has a double extension",
                    detail=(
                        f"'{name}' uses multiple extensions, a classic trick to "
                        f"disguise an executable as a document."
                    ),
                    severity=Severity.HIGH,
                    evidence=name,
                )
            )

        if ext in _DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category="attachments",
                    title="Executable or script attachment",
                    detail=f"'{name}' has extension '{ext}', which can run code on the recipient's device.",
                    severity=Severity.CRITICAL,
                    evidence=name,
                )
            )
        elif ext in _MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    category="attachments",
                    title="Macro-enabled Office document",
                    detail=f"'{name}' is a macro-enabled Office file, a common malware delivery format.",
                    severity=Severity.HIGH,
                    evidence=name,
                )
            )
        elif ext in _ARCHIVE_EXTENSIONS:
            findings.append(
                Finding(
                    category="attachments",
                    title="Compressed archive attachment",
                    detail=f"'{name}' is an archive; archives are often used to smuggle malicious files.",
                    severity=Severity.LOW,
                    evidence=name,
                )
            )

    return findings

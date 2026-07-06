#!/usr/bin/env python3
"""Headless CLI for exercising the same detection engine the mobile app
uses, without needing to build/run the Kivy UI. Handy for quick manual
testing and CI smoke checks.

Usage:
    python scripts/demo_cli.py email path/to/file.eml
    python scripts/demo_cli.py sms "PayPal" "Your account is suspended, verify now: http://bit.ly/x"
    python scripts/demo_cli.py url "http://paypa1.com/login"
    python scripts/demo_cli.py qr path/to/image.png
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.engine import scan_email_raw, scan_qr_image, scan_sms, scan_url  # noqa: E402


def _print(result) -> None:
    print(
        f"[{result.risk_level}] score={result.score}/100  channel={result.channel}  label={result.label!r}"
    )
    for i, f in enumerate(result.findings, start=1):
        print(f"  {i}. [{f.severity.label}] ({f.category}) {f.title}")
        print(f"       {f.detail}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1

    command = argv[0]
    if command == "email":
        text = Path(argv[1]).read_text(encoding="utf-8", errors="replace")
        _print(scan_email_raw(text))
    elif command == "sms":
        _print(scan_sms(argv[1], argv[2]))
    elif command == "url":
        _print(scan_url(argv[1]))
    elif command == "qr":
        _print(scan_qr_image(argv[1]))
    else:
        print(f"Unknown command: {command}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

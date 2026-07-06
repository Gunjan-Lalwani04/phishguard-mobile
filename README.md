PhishGuard Mobile

Offline phishing detector for Android/iOS — scans emails, SMS, and links/QR codes on-device using transparent, rule-based heuristics.

Features


Email — paste raw .eml source or pick a file; checks sender spoofing, link deception, urgency language, and dangerous attachments.
SMS — paste a sender ID and message body; flags sender-ID typosquatting, brand impersonation, and phishing links.
Links / QR codes — paste a URL or scan a QR code; flags typosquats, IP-based links, URL shorteners, and other tricks.


No network calls, no cloud API — everything runs locally.

Quick start

bashpip install -r requirements.txt
python main.py

Try the detection engine without the UI:

bashpython scripts/demo_cli.py sms "PayPal" "Your account will be suspended: http://bit.ly/xyz"

Run tests

bashpip install -r requirements-dev.txt
pytest --cov=core

Build an APK

Push to GitHub — the included .github/workflows/build-apk.yml builds the APK automatically via GitHub Actions and uploads it as a downloadable artifact. Tag a release (git tag v0.1.0 && git push --tags) to attach it to a GitHub Release.

For a local build instead: pip install buildozer cython && buildozer android debug (Linux/WSL2 only).

How scoring works

Findings carry severity weights (LOW=2, MEDIUM=5, HIGH=9, CRITICAL=15), summed into a score capped at 100:

ScoreRisk level0-4LOW5-8MEDIUM9-14HIGH15+CRITICAL

Limitations

Heuristic, rule-based — not a machine-learning classifier. Doesn't verify SPF/DKIM/DMARC or follow redirects on shortened links. Treat it as a fast first-pass filter, not a replacement for dedicated mobile security software.
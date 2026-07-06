
# PhishGuard Mobile

A cross-platform (Android/iOS via Kivy) offline phishing detector. Covers
three channels in one app:

- **Email** — paste raw `.eml` source or pick a `.eml` file; same heuristics
  as the desktop PhishGuard tool (sender spoofing, link deception, urgency
  language, dangerous attachments).
- **SMS / text messages** — paste a sender ID and message body; flags
  smishing signals like sender-ID typosquatting, brand names sent from
  unverified phone numbers, and phishing links.
- **Links / QR codes** — paste a URL directly, scan a QR code with the
  camera, or pick a QR image from the gallery; flags typosquats, IP-based
  links, URL shorteners, and `@`-authority tricks.

Everything runs locally on the device. No network calls, no cloud API, no
data leaves the phone.

## Project layout

```
phishguard-mobile/
  core/                  channel-agnostic detection engine (no Kivy import)
    analyzers/            sender_email, sender_sms, links, content, attachments
    engine.py              scan_email_raw() / scan_sms() / scan_url() / scan_qr_image()
    eml_parser.py           raw .eml -> plain fields
    qr.py                   QR decoding via OpenCV
    scoring.py, models.py, brands.py, util.py
  app/                    Kivy UI layer
    screens.py              HomeScreen, EmailScreen, SmsScreen, LinkQrScreen, CameraScreen
    results_view.py          renders a ScanResult as widgets
    file_dialogs.py          cross-platform file picker (plyer + Kivy fallback)
  phishguard.kv           screen layouts
  main.py                 app entry point
  scripts/demo_cli.py     headless CLI for testing the engine without the UI
  tests/                  pytest suite for core/ (channel-agnostic, no Kivy needed)
  buildozer.spec          Android packaging config
```

The `core/` package has zero Kivy imports, so all detection logic is testable
with plain `pytest` — no emulator, device, or display required.

## Try it without building the app

```bash
pip install -r requirements-dev.txt
python scripts/demo_cli.py sms "PayPal" "Your account will be suspended, verify now: http://bit.ly/xyz"
python scripts/demo_cli.py url "http://paypa1-support.com/login"
python scripts/demo_cli.py email tests/fixtures/phishing_paypal.eml
```

## Run the app on your desktop (for development)

Kivy runs fine on Linux/macOS/Windows, so you can develop and click-test the
UI before packaging for a phone:

```bash
pip install -r requirements.txt
python main.py
```

Camera QR scanning uses Kivy's `Camera` widget, which will use your
laptop's webcam on desktop — useful for testing the capture flow before
building for Android.

## Build for Android

Requires a Linux machine (or WSL) with the Android SDK/NDK — `buildozer`
downloads and manages most of this for you the first time you run it.

```bash
pip install buildozer cython
buildozer android debug
```

The resulting APK is written to `bin/`. Install it on a connected device or
emulator with:

```bash
buildozer android deploy run
```

First builds take a while (Android SDK/NDK + all Python package downloads).
`buildozer.spec` is already configured with the `CAMERA` and storage
permissions the app needs for QR scanning and file picking.

## Build for iOS

iOS packaging requires `kivy-ios` and Xcode, which only run on macOS. This
repo doesn't include an iOS build step since it can't be produced or tested
from this environment, but the app code itself is not Android-specific —
`kivy-ios` consumes the same `main.py`/`core`/`app` structure. See
[kivy-ios docs](https://github.com/kivy/kivy-ios) for the toolchain setup.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest --cov=core
ruff check core app tests scripts
black --check core app tests scripts
```

QR-related tests use `qrcode` (to generate test images) and `opencv-python`
(to decode them) and are skipped automatically if those aren't installed.

## How scoring works

Every finding carries a severity weight (`LOW=2`, `MEDIUM=5`, `HIGH=9`,
`CRITICAL=15`). Weights are summed per scan and capped at 100:

| Score  | Risk level |
|--------|------------|
| 0-7    | LOW        |
| 8-17   | MEDIUM     |
| 18-34  | HIGH       |
| 35+    | CRITICAL   |

## Limitations

This is a heuristic, rule-based tool, not a machine-learning classifier or a
connection to a live threat-intelligence feed. It doesn't verify
SPF/DKIM/DMARC (not available from a saved `.eml`/pasted SMS) and it doesn't
follow redirects on shortened URLs (fully offline by design). Treat it as a
fast first-pass filter, not a replacement for your phone's built-in spam
protection or a dedicated mobile security app.

## License

MIT — see [LICENSE](LICENSE).

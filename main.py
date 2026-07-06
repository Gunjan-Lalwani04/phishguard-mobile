"""PhishGuard Mobile entry point.

Run for desktop development/testing with:

    python main.py

Package for Android with buildozer (see README.md):

    buildozer android debug
"""
from __future__ import annotations

from kivy.app import App

from app.screens import CameraScreen, EmailScreen, HomeScreen, LinkQrScreen, SmsScreen  # noqa: F401


class PhishGuardApp(App):
    """Auto-loads phishguard.kv (matches the class name minus 'App')."""

    title = "PhishGuard Mobile"


def main() -> None:
    PhishGuardApp().run()


if __name__ == "__main__":
    main()

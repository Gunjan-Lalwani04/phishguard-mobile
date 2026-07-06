[app]
title = PhishGuard Mobile
package.name = phishguard
package.domain = org.phishguard

source.dir = .
source.include_exts = py,kv,png,jpg,atlas
source.include_patterns = core/*.py,core/analyzers/*.py,app/*.py

version = 0.1.0

requirements = python3,kivy==2.3.0,opencv-python-headless,plyer,numpy

# Camera + storage access are needed for QR scanning (live camera capture
# and picking an existing image from the gallery) and for opening a raw
# .eml file the user has saved on their device.
android.permissions = CAMERA,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE

orientation = portrait
fullscreen = 0

android.api = 34
android.minapi = 24
android.archs = arm64-v8a,armeabi-v7a

icon.filename = %(source.dir)s/assets/icon.png

[buildozer]
log_level = 2
warn_on_root = 1

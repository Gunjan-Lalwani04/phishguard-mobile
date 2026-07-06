"""Decode a QR code from an image file.

Uses OpenCV's built-in QRCodeDetector rather than pyzbar/libzbar, because
opencv-python has a maintained python-for-android recipe and no separate
system shared library to bundle, which makes Android packaging simpler.
"""

from __future__ import annotations


class QrDecodeError(Exception):
    """Raised when the image can't be read or contains no decodable QR code."""


def decode_qr_from_image(image_path: str) -> str:
    try:
        import cv2  # noqa: WPS433 - optional/heavy dependency, imported lazily
    except ImportError as exc:  # pragma: no cover - exercised only without opencv
        raise QrDecodeError(
            "OpenCV is not installed. Install it with `pip install opencv-python-headless`."
        ) from exc

    image = cv2.imread(image_path)
    if image is None:
        raise QrDecodeError(f"Could not read image file: {image_path}")

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(image)

    if not data or points is None:
        raise QrDecodeError("No QR code found in the image.")

    return data

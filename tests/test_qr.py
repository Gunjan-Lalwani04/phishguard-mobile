import pytest

cv2 = pytest.importorskip("cv2")
qrcode = pytest.importorskip("qrcode")

from core.engine import scan_qr_image  # noqa: E402
from core.qr import decode_qr_from_image  # noqa: E402


def _make_qr_image(text: str, path: str) -> None:
    img = qrcode.make(text)
    img.save(path)


def test_decode_qr_roundtrip(tmp_path):
    target = "https://example.com/hello"
    image_path = str(tmp_path / "qr.png")
    _make_qr_image(target, image_path)
    assert decode_qr_from_image(image_path) == target


def test_scan_qr_image_flags_phishing_url(tmp_path):
    phishing_url = "http://paypa1-support.com/login"
    image_path = str(tmp_path / "qr_phish.png")
    _make_qr_image(phishing_url, image_path)

    result = scan_qr_image(image_path)
    assert result.channel == "qr"
    assert result.risk_level in ("HIGH", "CRITICAL")


def test_scan_qr_image_clean_url(tmp_path):
    clean_url = "https://github.com/notifications"
    image_path = str(tmp_path / "qr_clean.png")
    _make_qr_image(clean_url, image_path)

    result = scan_qr_image(image_path)
    assert result.risk_level == "LOW"

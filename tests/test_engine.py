from core.engine import scan_email_raw, scan_sms, scan_url
from tests.conftest import FIXTURES_DIR


def test_scan_email_raw_flags_phishing_fixture():
    raw = (FIXTURES_DIR / "phishing_paypal.eml").read_text()
    result = scan_email_raw(raw)
    assert result.channel == "email"
    assert result.risk_level in ("HIGH", "CRITICAL")
    assert len(result.findings) >= 3


def test_scan_email_raw_legit_fixture_is_low_risk():
    raw = (FIXTURES_DIR / "legit_newsletter.eml").read_text()
    result = scan_email_raw(raw)
    assert result.risk_level == "LOW"
    assert result.score == 0


def test_scan_sms_flags_smishing():
    result = scan_sms("Your Bank", "URGENT: verify your account now: http://bit.ly/xyz123")
    assert result.channel == "sms"
    assert result.score > 0


def test_scan_url_flags_lookalike():
    result = scan_url("http://paypa1-support.com/login")
    assert result.channel == "url"
    assert result.risk_level in ("HIGH", "CRITICAL")


def test_scan_url_clean():
    result = scan_url("https://github.com/notifications")
    assert result.risk_level == "LOW"
    assert result.score == 0

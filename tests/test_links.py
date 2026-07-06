from core.analyzers.links import analyze_links


def test_flags_anchor_href_mismatch():
    findings = analyze_links([("http://evil-domain.ru/steal", "https://www.paypal.com/verify")])
    assert any(f.title == "Link text does not match its destination" for f in findings)


def test_flags_raw_ip_host():
    findings = analyze_links([("http://185.23.44.10/secure/login", "Login")])
    assert any(f.title == "Link uses a raw IP address" for f in findings)


def test_flags_url_shortener():
    findings = analyze_links([("https://bit.ly/abc123", "https://bit.ly/abc123")])
    assert any(f.title == "Link uses a URL shortening service" for f in findings)


def test_flags_lookalike_link_domain():
    findings = analyze_links([("https://paypa1.com/login", "https://paypa1.com/login")])
    assert any(f.title == "Link domain looks like a typosquat" for f in findings)


def test_clean_link_no_findings():
    findings = analyze_links([("https://github.com/notifications", "View it online")])
    assert findings == []

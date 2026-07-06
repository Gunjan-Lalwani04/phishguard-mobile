from core.analyzers.content import analyze_content


def test_flags_urgency_language():
    findings = analyze_content("Your account will be suspended, act now!")
    assert any(f.title == "Urgency / pressure language detected" for f in findings)


def test_flags_sensitive_info_request():
    findings = analyze_content("Please confirm your password and enter your pin")
    assert any(f.title == "Requests sensitive information" for f in findings)


def test_flags_generic_greeting():
    findings = analyze_content("Dear Customer, thanks for your business.")
    assert any(f.title == "Generic, non-personalized greeting" for f in findings)


def test_clean_text_no_findings():
    findings = analyze_content("Hi Alex, here is your weekly digest.")
    assert findings == []

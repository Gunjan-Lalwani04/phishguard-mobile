from core.analyzers.sender_email import analyze_email_sender


def test_flags_brand_impersonation_in_display_name():
    findings = analyze_email_sender(
        from_display="PayPal Security", from_addr="service@totally-not-paypal.com"
    )
    assert any(f.title == "Display name impersonates a known brand" for f in findings)


def test_flags_typosquat_domain():
    findings = analyze_email_sender(from_display="Account Team", from_addr="service@paypa1.com")
    assert any(f.title == "Sender domain looks like a typosquat" for f in findings)


def test_flags_reply_to_mismatch():
    findings = analyze_email_sender(
        from_addr="alerts@example.com", reply_to_addr="reply@other-domain.com"
    )
    assert any(f.title == "Reply-To domain differs from From domain" for f in findings)


def test_clean_sender_no_findings():
    findings = analyze_email_sender(from_display="GitHub", from_addr="notifications@github.com")
    assert findings == []

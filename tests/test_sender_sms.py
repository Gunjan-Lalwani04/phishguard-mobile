from core.analyzers.sender_sms import analyze_sms_sender


def test_flags_lookalike_sender_id():
    findings = analyze_sms_sender("PayPaI", "Your account needs verification")
    assert any(f.title == "Sender ID looks like a typosquat" for f in findings)


def test_flags_brand_from_unverified_phone_number():
    findings = analyze_sms_sender(
        "+1 (415) 555-0138", "PayPal: your account will be suspended, verify now"
    )
    titles = [f.title for f in findings]
    assert "Brand mentioned but sent from an unverified number" in titles
    assert "Long phone number impersonating a company alert" in titles


def test_legit_known_sender_id_no_findings():
    findings = analyze_sms_sender("PayPal", "Your monthly statement is ready to view.")
    assert findings == []


def test_short_code_with_brand_mention_is_not_flagged():
    # Anonymous-looking short codes are the normal legitimate mechanism for
    # bulk brand SMS, so mentioning a brand from one shouldn't be flagged.
    findings = analyze_sms_sender("28777", "Amazon: your order has shipped")
    assert findings == []

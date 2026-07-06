from core.analyzers.attachments import analyze_attachments


def test_flags_executable_attachment():
    findings = analyze_attachments([("payload.exe", "application/octet-stream")])
    assert any(f.title == "Executable or script attachment" for f in findings)


def test_flags_double_extension():
    findings = analyze_attachments([("invoice.pdf.exe", "application/octet-stream")])
    titles = [f.title for f in findings]
    assert "Attachment has a double extension" in titles
    assert "Executable or script attachment" in titles


def test_clean_attachment_no_findings():
    findings = analyze_attachments([("report.pdf", "application/pdf")])
    assert findings == []

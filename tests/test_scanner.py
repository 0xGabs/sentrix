import tempfile
from core import scanner

SAMPLE_PATTERNS = [
    {
        "regex": r"API_KEY\s*=\s*[\'\"]\w+[\'\"]",
        "severity": "high",
        "message": "Hardcoded API Key"
    }
]

def test_scan_file_detects_api_key():
    code = 'API_KEY = "12345SECRET"'

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        tmp.flush()
        findings = scanner.scan_file(tmp.name, SAMPLE_PATTERNS)

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "Hardcoded API Key" in findings[0]["message"]

def test_should_scan_recognizes_sensitive_name():
    assert scanner.should_scan("config/passwords.env") is True
    assert scanner.should_scan("readme.md") is False

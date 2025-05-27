def test_load_patterns_valid_yaml(tmp_path):
    test_yaml = tmp_path / "patterns.yml"
    test_yaml.write_text("""
patterns:
  - regex: 'password\\s*=\\s*\\S+'
    severity: high
    message: "Hardcoded password"
""")

    from core.scanner import load_patterns
    patterns = load_patterns([str(test_yaml)])

    assert len(patterns) == 1
    assert patterns[0]["severity"] == "high"
    assert "password" in patterns[0]["regex"]

import pytest

def test_load_patterns_invalid_yaml(tmp_path):
    test_yaml = tmp_path / "broken.yml"
    test_yaml.write_text("patterns: [")  # completamente inválido

    from core.scanner import load_patterns

    with pytest.raises(Exception):
        load_patterns([str(test_yaml)])

def test_print_findings_shows_output(capsys):
    from core.scanner import print_findings

    fake_results = [{
        "file": "secrets.py",
        "line": 5,
        "line_text": "password = '1234'",
        "regex": "password\\s*=\\s*\\S+",
        "severity": "high",
        "message": "Hardcoded password"
    }]

    print_findings(fake_results)

    captured = capsys.readouterr()
    assert "secrets.py" in captured.out
    assert "Hardcoded password" in captured.out

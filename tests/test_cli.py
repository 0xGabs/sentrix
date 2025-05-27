import subprocess
import tempfile
import os
import textwrap

def test_cli_scan_file(tmp_path):
    pattern_file = tmp_path / "patterns.yml"
    pattern_file.write_text(textwrap.dedent("""
        patterns:
          - regex: 'API_KEY\\s*=\\s*\\S+'
            severity: high
            message: "Hardcoded API Key"
    """))

    code_file = tmp_path / "main.py"
    code_file.write_text('API_KEY = "SECRET123"\n')

    env = os.environ.copy()
    env["PYTHONPATH"] = "src"  

    result = subprocess.run(
        [
            "python", "src/cli.py",
            str(code_file),
            "--patterns", str(pattern_file)
        ],
        capture_output=True,
        text=True,
        env=env  
    )

    assert result.returncode == 0
    assert "Hardcoded API Key" in result.stdout

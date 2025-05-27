# scanner.py
import os
import re
import yaml
import logging
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from sentrix.config import SCAN_EXTENSIONS, COMMON_SENSITIVE_PATHS, SEVERITY_COLORS

# Initialize Rich console and logger
console = Console()
logger = logging.getLogger(__name__)


def load_patterns(files: List[str]) -> List[Dict[str, Any]]:
    """
    Load scanning patterns from YAML files.

    :param files: List of YAML file paths containing patterns.
    :return: List of pattern dicts.
    """
    patterns: List[Dict[str, Any]] = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error("Pattern file not found: %s", path)
            continue

        new_patterns = data.get("patterns", [])
        if not new_patterns:
            logger.warning("No patterns defined in %s", path)
        patterns.extend(new_patterns)
    return patterns


def should_scan(filepath: str) -> bool:
    """
    Determine if a file should be scanned based on extension or name.

    :param filepath: Path to the file.
    :return: True if it should be scanned.
    """
    _, ext = os.path.splitext(filepath.lower())
    name = os.path.basename(filepath).lower()
    return ext in SCAN_EXTENSIONS or any(token in name for token in COMMON_SENSITIVE_PATHS)


def scan_file(path: str, patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Scan a single file for pattern matches.

    :param path: File path to scan.
    :param patterns: List of pattern dicts with keys 'regex', 'severity', 'message'.
    :return: List of findings.
    """
    findings: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logger.error("Failed to read file %s: %s", path, e)
        return findings

    for pat in patterns:
        regex = pat.get("regex")
        severity = pat.get("severity", "low")
        message = pat.get("message", "")
        for match in re.finditer(regex, content):
            findings.append({
                "file": path,
                "line": content[:match.start()].count("\n") + 1,
                "severity": severity,
                "message": message,
                "match": match.group(0),
            })
    return findings


def print_findings(findings: List[Dict[str, Any]]) -> None:
    """
    Print findings in a Rich-formatted table.

    :param findings: List of finding dicts.
    """
    if not findings:
        console.print("[green]No findings detected.[/green]")
        return

    table = Table(title="Security Findings")
    table.add_column("File", style="dim")
    table.add_column("Line", justify="right")
    table.add_column("Severity")
    table.add_column("Message")

    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "white")
        table.add_row(
            f["file"],
            str(f["line"]),
            f"[{color}]{f['severity']}[/{color}]",
            f["message"],
        )
    console.print(table)
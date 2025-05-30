import argparse
import logging
import os

from importlib.metadata import version as get_version
from sentrix.scanner import load_patterns, scan_file, print_findings
from sentrix.watcher import watch
from sentrix.config import SCAN_EXTENSIONS, IGNORE_DIRS

try:
    VERSION = get_version("sentrix")
except Exception:
    VERSION = "dev"

def scan_directory(path: str, patterns, exclude_dirs=None):
    if exclude_dirs is None:
        exclude_dirs = []

    findings = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            full_path = os.path.join(root, file)
            if full_path.lower().endswith(tuple(SCAN_EXTENSIONS)):
                findings.extend(scan_file(full_path, patterns))
    return findings


def handle_paths(paths, patterns, exclude_dirs=None):
    findings = []
    for path in paths:
        if os.path.isfile(path):
            findings.extend(scan_file(path, patterns))
        elif os.path.isdir(path):
            findings.extend(scan_directory(path, patterns, exclude_dirs=exclude_dirs))
        else:
            logging.warning(f"Invalid path: {path}")
    return findings

def main():
    parser = argparse.ArgumentParser(
        prog=f"Sentrix {VERSION}",
        description=(
            "Sentrix Sensitive file scanning and real-time monitoring\n"
            "https://github.com/0xGabs"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage="sentrix [OPTIONS] <paths...>"
    )

    # === TARGET SPECIFICATION ===
    scan_group = parser.add_argument_group("TARGET SPECIFICATION")
    scan_group.add_argument(
        "paths",
        nargs="+",
        help="File(s) or directory path(s) to scan."
    )
    scan_group.add_argument(
        "--patterns",
        nargs="+",
        metavar="FILE",
        required=True,
        help="YAML file(s) with regex patterns to detect sensitive data."
    )

    # === SCAN BEHAVIOR ===
    behavior_group = parser.add_argument_group("SCAN BEHAVIOR")
    behavior_group.add_argument(
        "--watch",
        action="store_true",
        help="Enable real-time file watching and re-scan on changes."
    )
    behavior_group.add_argument(
        "--exclude",
        nargs="+",
        metavar="DIR",
        help="Directory name(s) to exclude from recursive scan."
    )

    # === UTILITY FLAG ===
    util_group = parser.add_argument_group("UTILITY FLAG")
    util_group.add_argument(
        "--version",
        action="version",
        version=f"Sentrix {VERSION}",
        help="Show program version and exit."
    )

    # === EXAMPLES ===
    parser.epilog = """\
EXAMPLES:
  sentrix ./src --patterns patterns/secrets.yaml
      Scan files inside ./src recursively using the provided YAML rules.

  sentrix config.py main.py --patterns patterns/secrets.yaml
      Scan specific files.

  sentrix ./app --patterns secrets.yaml --watch
      Watch ./app and re-scan on changes using secrets.yaml.

  sentrix ./app --patterns secrets.yaml --exclude venv __pycache__
      Watch .app excluding the venv and __pycache__ directories.
"""

    args = parser.parse_args()
    patterns = load_patterns(args.patterns)

    if args.watch:
        watch(args.paths, patterns)
    else:
        findings = handle_paths(args.paths, patterns, exclude_dirs=args.exclude or [])
        if findings:
            print_findings(findings)


if __name__ == "__main__":
    main()

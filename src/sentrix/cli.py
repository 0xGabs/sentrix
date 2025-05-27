import argparse
import logging
import os
from importlib.metadata import version as get_version
from core.scanner import load_patterns, scan_file, print_findings
from core.watcher import watch

try:
    VERSION = get_version("sentrix")
except Exception:
    VERSION = "dev"

def main():
    parser = argparse.ArgumentParser(
        prog=f"Sentrix {VERSION}",
        description=(
            "Sentrix Sensitive file scanning and real-time monitoring\n"
            "https://github.com/0xGabs/sentrix.git"
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

    # === UTILITY FLAGS ===
    util_group = parser.add_argument_group("UTILITY FLAGS")
    util_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging output."
    )
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
      Scan all files inside ./src recursively using the provided YAML rules.

  sentrix config.py main.py --patterns patterns/secrets.yaml
      Scan specific files.

  sentrix ./app --patterns secrets.yaml --watch
      Watch ./app and re-scan on changes using secrets.yaml.

  sentrix ./api --patterns patterns/secrets.yaml --verbose
      Scan ./api and show debug logs.
"""

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    patterns = load_patterns(args.patterns)

    if args.watch:
        watch(args.paths, args.patterns)
    else:
        for path in args.paths:
            if os.path.isfile(path) or os.path.isdir(path):
                findings = scan_file(path, patterns)
                print_findings(findings)
            else:
                logging.warning(f"Invalid path: {path}")

if __name__ == "__main__":
    main()

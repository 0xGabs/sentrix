import time
import logging
from typing import List, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from sentrix.scanner import load_patterns, should_scan, scan_file, print_findings

logger = logging.getLogger(__name__)


class ScanHandler(FileSystemEventHandler):
    """Event handler that scans files on modification."""

    def __init__(self, pattern_files: List[str]):
        super().__init__()
        self.pattern_files = pattern_files
        self.patterns: List[Dict[str, Any]] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        self.patterns = load_patterns(self.pattern_files)

    def on_modified(self, event):
        if not event.is_directory and should_scan(event.src_path):
            logger.info("File modified: %s", event.src_path)
            self._load_patterns()
            findings = scan_file(event.src_path, self.patterns)
            print_findings(findings)


def watch(paths: List[str], pattern_files: List[str]) -> None:
    """
    Start watching directories for file changes.

    :param paths: List of directory or file paths to watch.
    :param pattern_files: List of YAML pattern file paths.
    """
    handler = ScanHandler(pattern_files)
    observer = Observer()
    for p in paths:
        observer.schedule(handler, p, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

"""Scanner protocol contract."""

from pathlib import Path
from typing import Protocol

from omnipatch.models import Finding


class Scanner(Protocol):
    """Interface implemented by scanners."""

    name: str

    def is_available(self) -> bool:
        """False when the backing tool is missing. Must never raise."""
        ...

    def scan(self, repo_root: Path) -> list[Finding]:
        """Raise ScannerError on failure. Never return [] to mask an error."""
        ...

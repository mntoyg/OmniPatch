"""Built-in scanner registry."""

from collections.abc import Sequence

from omnipatch.defaults import DEFAULT_SCAN_TIMEOUT_SECONDS, EXCLUDED_DIRS
from omnipatch.errors import ScannerError
from omnipatch.scanners.bandit_scanner import BanditScanner
from omnipatch.scanners.base import Scanner
from omnipatch.scanners.stub import StubScanner


def build_scanner(
    name: str,
    timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    excluded_dirs: Sequence[str] = EXCLUDED_DIRS,
    *,
    report_scope: bool = True,
) -> Scanner:
    """Return the scanner registered under name, or raise ScannerError."""
    if name == "bandit":
        return BanditScanner(
            timeout_seconds=timeout_seconds,
            excluded_dirs=excluded_dirs,
            report_scope=report_scope,
        )
    if name == "stub":
        return StubScanner()
    raise ScannerError(f"Unknown scanner '{name}'. Valid scanners: bandit, stub")

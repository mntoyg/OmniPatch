"""Fixture-backed stub scanner."""

import json
from pathlib import Path
from typing import cast

from omnipatch.errors import ScannerError
from omnipatch.models import Finding


class StubScanner:
    """Load sample findings from packaged fixture data."""

    name = "stub"

    def __init__(self, fixture: Path | None = None) -> None:
        """Use the packaged fixture unless an explicit path is given."""
        self._fixture = fixture or _default_fixture()

    def is_available(self) -> bool:
        """True when the fixture file is readable. Never raises."""
        try:
            with self._fixture.open("rb"):
                return True
        except OSError:
            return False

    def scan(self, repo_root: Path) -> list[Finding]:
        """Load and parse the fixture findings."""
        del repo_root
        try:
            raw = json.loads(self._fixture.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise TypeError("fixture root must be a list")
            return [
                Finding.from_json_dict(cast(dict[str, object], item)) for item in raw
            ]
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ScannerError(f"Unable to load stub findings fixture: {exc}") from exc


def _default_fixture() -> Path:
    """Path to the fixture shipped inside the package."""
    return Path(__file__).resolve().parent / "data" / "stub_findings.json"

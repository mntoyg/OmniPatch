"""Ensure the published runtime requirements are an exact export of uv.lock."""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCKED_REQUIREMENTS = ROOT / "requirements-runtime.txt"


def verify(generated: Path) -> None:
    if generated.read_bytes() != LOCKED_REQUIREMENTS.read_bytes():
        raise ValueError(
            "generated runtime requirements differ from the tracked lock export"
        )
    print("Runtime requirements match the tracked hash-pinned lock export.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "generated", type=Path, help="requirements exported from uv.lock"
    )
    args = parser.parse_args()
    verify(args.generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

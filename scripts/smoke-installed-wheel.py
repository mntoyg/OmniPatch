"""Smoke-test the installed wheel's entry point against the synthetic fixture."""

from __future__ import annotations

import argparse
import json
import subprocess
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_cli(
    executable: Path, arguments: list[str]
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(executable), *arguments],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"installed CLI command {arguments[0]!r} failed with "
            f"exit code {result.returncode}"
        )
    return result


def verify(executable: Path, fixture: Path) -> None:
    executable = executable.resolve(strict=True)
    fixture = fixture.resolve(strict=True)
    try:
        fixture.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(
            "wheel smoke fixture must remain inside the repository"
        ) from exc

    installed_version = version("omnipatch")
    version_result = _run_cli(executable, ["version"])
    if version_result.stdout.strip() != installed_version:
        raise RuntimeError("installed CLI version does not match wheel metadata")

    help_result = _run_cli(executable, ["--help"])
    if "scan" not in help_result.stdout:
        raise RuntimeError("installed CLI help does not list the scan command")

    scan_result = _run_cli(
        executable,
        ["scan", "--repo", str(fixture), "--json"],
    )
    try:
        findings = json.loads(scan_result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("installed CLI scan did not return valid JSON") from exc
    if not isinstance(findings, list) or not any(
        isinstance(item, dict) and item.get("rule_id") == "B105" for item in findings
    ):
        raise RuntimeError("installed CLI scan did not detect fixture rule B105")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path, help="installed omnipatch entry point")
    parser.add_argument("fixture", type=Path, help="in-repository synthetic fixture")
    args = parser.parse_args()
    verify(args.cli, args.fixture)
    print("Installed wheel version, help, and offline fixture scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

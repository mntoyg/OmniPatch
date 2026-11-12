"""Verify the wheel includes the full generated third-party notice inventory."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _expected_packages() -> set[tuple[str, str]]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    excluded = {
        _normalize(str(dependency["name"]))
        for package in lock["package"]
        for dependency in package.get("dependencies", [])
        if "sys_platform == 'emscripten'" in dependency.get("marker", "")
    }
    return {
        (_normalize(str(package["name"])), str(package["version"]))
        for package in lock["package"]
        if package["name"] != "omnipatch"
        and _normalize(str(package["name"])) not in excluded
    }


def _manifest_packages(content: bytes) -> set[tuple[str, str]]:
    text = content.decode("utf-8")
    manifest = text.split("\n## License and notice file contents", maxsplit=1)[0]
    return {
        (_normalize(match.group(1).strip()), match.group(2).strip())
        for line in manifest.splitlines()
        if not line.startswith(("| Distribution", "|---"))
        if (match := re.match(r"\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", line))
    }


def verify(wheel_directory: Path) -> None:
    wheels = sorted(wheel_directory.glob("omnipatch-*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected one OmniPatch wheel, found {len(wheels)}")
    notice_source = ROOT / "THIRD_PARTY_NOTICES.md"
    source_bytes = notice_source.read_bytes()
    expected = _expected_packages()
    if _manifest_packages(source_bytes) != expected:
        raise ValueError("third-party notice manifest does not match uv.lock")
    if not re.search(
        rb"Included locked third-party distributions: \d+\.", source_bytes
    ):
        raise ValueError("third-party notice count is missing")
    if len(re.findall(rb"<!-- SHA-256: [0-9a-f]{64} -->", source_bytes)) == 0:
        raise ValueError("third-party license file hashes are missing")

    with ZipFile(wheels[0]) as wheel:
        names = set(wheel.namelist())
        license_paths = sorted(
            name
            for name in names
            if name.startswith("omnipatch-") and "/licenses/" in name
        )
        required_suffixes = {
            "/licenses/LICENSE",
            "/licenses/NOTICE",
            "/licenses/THIRD_PARTY_NOTICES.md",
        }
        if not all(
            any(path.endswith(suffix) for path in license_paths)
            for suffix in required_suffixes
        ):
            raise ValueError(
                f"wheel is missing required license files: {license_paths}"
            )
        bundled_notice = next(
            path
            for path in license_paths
            if path.endswith("/licenses/THIRD_PARTY_NOTICES.md")
        )
        if wheel.read(bundled_notice) != source_bytes:
            raise ValueError(
                "wheel third-party notices differ from the checked-in inventory"
            )
    print(
        f"Verified {len(expected)} locked third-party distributions in {wheels[0].name}."
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify-wheel-notices.py WHEEL_DIRECTORY")
    verify(Path(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

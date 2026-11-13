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
    return {
        (_normalize(str(package["name"])), str(package["version"]))
        for package in _locked_supported_packages().values()
    }


def _locked_supported_packages() -> dict[str, dict[str, object]]:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    excluded = {
        _normalize(str(dependency["name"]))
        for package in lock["package"]
        for dependency in package.get("dependencies", [])
        if "sys_platform == 'emscripten'" in dependency.get("marker", "")
    }
    return {
        _normalize(str(package["name"])): package
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


def _manifest_source_artifacts(content: bytes) -> dict[str, tuple[str, str, str]]:
    text = content.decode("utf-8")
    manifest = text.split("\n## License and notice file contents", maxsplit=1)[0]
    artifacts: dict[str, tuple[str, str, str]] = {}
    for line in manifest.splitlines():
        if not line.startswith("|") or line.startswith(("| Distribution", "|---")):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) != 6:
            continue
        name, version, _license, source_link, digest, _files = columns
        match = re.fullmatch(
            r"\[sdist\]\((https://files\.pythonhosted\.org/[^)]+)\)", source_link
        )
        digest_match = re.fullmatch(r"`([0-9a-f]{64})`", digest)
        if not match or not digest_match:
            continue
        artifacts[_normalize(name)] = (version, match.group(1), digest_match.group(1))
    return artifacts


def _expected_source_artifacts() -> dict[str, tuple[str, str, str]]:
    artifacts: dict[str, tuple[str, str, str]] = {}
    for name, package in _locked_supported_packages().items():
        sdist = package.get("sdist")
        if not isinstance(sdist, dict):
            raise TypeError(f"locked package has no source distribution: {name}")
        url = str(sdist.get("url", ""))
        digest = str(sdist.get("hash", ""))
        if not url.startswith("https://files.pythonhosted.org/") or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", digest
        ):
            raise ValueError(f"invalid locked source artifact for {name}")
        artifacts[name] = (str(package["version"]), url, digest.removeprefix("sha256:"))
    return artifacts


def verify(wheel_directory: Path) -> None:
    wheels = sorted(wheel_directory.glob("omnipatch-*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected one OmniPatch wheel, found {len(wheels)}")
    notice_source = ROOT / "THIRD_PARTY_NOTICES.md"
    source_bytes = notice_source.read_bytes()
    expected = _expected_packages()
    if _manifest_packages(source_bytes) != expected:
        raise ValueError("third-party notice manifest does not match uv.lock")
    if _manifest_source_artifacts(source_bytes) != _expected_source_artifacts():
        raise ValueError("third-party source archive list does not match uv.lock")
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

"""Generate notices from the locked third-party distributions installed in the venv."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import tomllib
from importlib.metadata import Distribution, distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "uv.lock"
NOTICE_PATH = ROOT / "THIRD_PARTY_NOTICES.md"
_CODE_SUFFIXES = {".c", ".h", ".js", ".json", ".py", ".pyi", ".toml", ".yaml", ".yml"}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked_supported_packages() -> dict[str, dict[str, object]]:
    lock = tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))
    packages = {
        _normalize(str(package["name"])): package
        for package in lock["package"]
        if package["name"] != "omnipatch"
    }
    emscripten_only = {
        _normalize(str(dependency["name"]))
        for package in lock["package"]
        for dependency in package.get("dependencies", [])
        if "sys_platform == 'emscripten'" in dependency.get("marker", "")
    }
    return {
        name: package
        for name, package in packages.items()
        if name not in emscripten_only
    }


def _license_files(distribution: Distribution) -> list[tuple[str, bytes, str]]:
    site_packages = Path(distribution.locate_file("")).resolve(strict=True)
    files: list[tuple[str, bytes, str]] = []
    for item in distribution.files or ():
        relative = Path(str(item))
        basename = relative.name.lower()
        if not basename.startswith(("license", "copying", "notice")):
            continue
        if relative.suffix.lower() in _CODE_SUFFIXES:
            continue
        if ".." in relative.parts:
            raise ValueError(
                f"unsafe license file path in package metadata: {relative}"
            )
        source = Path(distribution.locate_file(item)).resolve(strict=True)
        source.relative_to(site_packages)
        if not source.is_file():
            continue
        content = source.read_bytes()
        content.decode("utf-8-sig", errors="strict")
        files.append(
            (
                relative.as_posix(),
                content,
                hashlib.sha256(content).hexdigest(),
            )
        )
    if not files:
        name = distribution.metadata.get("Name", "unknown distribution")
        raise ValueError(f"no license or notice files found for {name}")
    return sorted(files, key=lambda item: item[0].casefold())


def _license_metadata(distribution: Distribution) -> str:
    metadata = distribution.metadata
    declared = metadata.get("License-Expression") or metadata.get("License") or ""
    classifiers = [
        classifier.removeprefix("License :: ")
        for classifier in metadata.get_all("Classifier", [])
        if classifier.startswith("License :: ")
    ]
    if not declared and classifiers:
        declared = "; ".join(classifiers)
    return declared or "No SPDX/License field; see included text"


def build_notice() -> bytes:
    locked = _locked_supported_packages()
    installed: dict[str, Distribution] = {}
    for distribution in distributions():
        name = distribution.metadata.get("Name")
        if name and _normalize(name) != "omnipatch":
            installed[_normalize(name)] = distribution
    if set(installed) != set(locked):
        missing = sorted(set(locked) - set(installed))
        extra = sorted(set(installed) - set(locked))
        raise ValueError(
            f"installed distributions do not match the locked Windows superset; "
            f"missing={missing}, extra={extra}"
        )

    records: list[tuple[str, str, str, list[tuple[str, bytes, str]]]] = []
    for normalized_name, distribution in installed.items():
        locked_version = str(locked[normalized_name]["version"])
        if distribution.version != locked_version:
            raise ValueError(
                f"version mismatch for {normalized_name}: "
                f"lock={locked_version}, installed={distribution.version}"
            )
        records.append(
            (
                distribution.metadata.get("Name", normalized_name),
                distribution.version,
                _license_metadata(distribution),
                _license_files(distribution),
            )
        )
    records.sort(key=lambda record: record[0].casefold())

    chunks = [
        (
            "# Third-party notices\n\n"
            "This file aggregates the license and notice files shipped inside the locked "
            "third-party distributions used by the supported Windows/Linux environment. "
            "Package versions are pinned in `uv.lock`; artifact URLs and SHA-256 hashes are "
            "recorded there. Contents are copied verbatim from the installed distribution files. "
            "Where supported-platform artifacts differ only in line endings, both exact variants "
            "are included. "
            "This inventory is technical evidence, not a legal determination of redistribution "
            "obligations. The Emscripten-only `httpx2-jsfetch` dependency is excluded because "
            "Emscripten is not a supported runtime platform.\n\n"
            f"Included locked third-party distributions: {len(records)}.\n\n"
            "| Distribution | Version | License metadata | Included files |\n"
            "|---|---:|---|---|\n"
        ).encode()
    ]
    for name, version, declared, files in records:
        entries: list[str] = []
        for path, content, _digest in files:
            entries.append(f"`{path}`")
            if b"\r\n" in content:
                entries.append(f"`{path} [LF line endings]`")
        paths = ", ".join(entries)
        paths = paths.replace("|", r"\|")
        declared = declared.replace("|", r"\|")
        chunks.append(f"| {name} | {version} | {declared} | {paths} |\n".encode())

    chunks.append(b"\n## License and notice file contents\n")
    for name, version, _declared, files in records:
        chunks.append(f"\n### {name} {version}\n".encode())
        for path, content, digest in files:
            variants = [(path, content, digest)]
            lf_content = content.replace(b"\r\n", b"\n")
            if lf_content != content:
                variants.append(
                    (
                        f"{path} [LF line endings]",
                        lf_content,
                        hashlib.sha256(lf_content).hexdigest(),
                    )
                )
            for variant_path, variant_content, variant_digest in variants:
                chunks.append(
                    f"\n#### `{variant_path}`\n\n<!-- SHA-256: {variant_digest} -->\n\n".encode()
                )
                fence_length = max(
                    3,
                    max(
                        (
                            len(match.group(0))
                            for match in re.finditer(rb"`+", variant_content)
                        ),
                        default=0,
                    )
                    + 1,
                )
                fence = b"`" * fence_length
                chunks.extend((fence + b"text\n", variant_content))
                if not variant_content.endswith((b"\n", b"\r")):
                    chunks.append(b"\n")
                chunks.append(fence + b"\n")
    return b"".join(chunks)


def _manifest_packages(content: bytes) -> set[tuple[str, str]]:
    text = content.decode("utf-8")
    manifest = text.split("\n## License and notice file contents", maxsplit=1)[0]
    return {
        (_normalize(match.group(1).strip()), match.group(2).strip())
        for line in manifest.splitlines()
        if not line.startswith(("| Distribution", "|---"))
        if (match := re.match(r"\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|", line))
    }


def _check_notice() -> None:
    if not NOTICE_PATH.is_file():
        raise SystemExit("THIRD_PARTY_NOTICES.md is missing")
    current = NOTICE_PATH.read_bytes()
    locked = _locked_supported_packages()
    if _manifest_packages(current) != {
        (name, str(package["version"])) for name, package in locked.items()
    }:
        raise SystemExit(
            "third-party notice package/version list does not match uv.lock"
        )

    installed: dict[str, Distribution] = {}
    for distribution in distributions():
        name = distribution.metadata.get("Name")
        if name and _normalize(name) != "omnipatch":
            installed[_normalize(name)] = distribution
    extra = sorted(set(installed) - set(locked))
    if extra:
        raise SystemExit(f"installed packages are absent from uv.lock: {extra}")

    missing_assets: list[str] = []
    for normalized_name, distribution in installed.items():
        locked_version = str(locked[normalized_name]["version"])
        if distribution.version != locked_version:
            raise SystemExit(
                f"version mismatch for {normalized_name}: "
                f"lock={locked_version}, installed={distribution.version}"
            )
        for path, content, digest in _license_files(distribution):
            headings = (
                f"#### `{path}`".encode(),
                f"#### `{path} [LF line endings]`".encode(),
            )
            checksum = f"<!-- SHA-256: {digest} -->".encode()
            if (
                not any(heading in current for heading in headings)
                or checksum not in current
                or content not in current
            ):
                missing_assets.append(f"{distribution.metadata['Name']}:{path}")
    if missing_assets:
        raise SystemExit(
            "third-party notices omit locked artifact license/notice files: "
            + ", ".join(missing_assets)
        )
    print(
        f"Notice covers all {len(installed)} installed locked distributions and "
        "their license/notice files."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in notice differs from the installed locked artifacts",
    )
    args = parser.parse_args()
    if args.check:
        _check_notice()
        return 0
    if os.name != "nt":
        raise SystemExit("Regenerate the combined supported-platform notice on Windows")
    generated = build_notice()
    NOTICE_PATH.write_bytes(generated)
    print(f"Wrote {NOTICE_PATH.name} ({len(generated)} bytes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

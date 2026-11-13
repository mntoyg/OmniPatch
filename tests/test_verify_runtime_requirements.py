from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "verify-runtime-requirements.py"
)
SPEC = importlib.util.spec_from_file_location("verify_runtime_requirements", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Could not load runtime requirements verifier")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_accepts_platform_newline_conversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tracked = tmp_path / "tracked.txt"
    generated = tmp_path / "generated.txt"
    tracked.write_bytes(b"package==1.0\r\n--hash=sha256:abc\r\n")
    generated.write_bytes(b"package==1.0\n--hash=sha256:abc\n")
    monkeypatch.setattr(MODULE, "LOCKED_REQUIREMENTS", tracked)

    MODULE.verify(generated)


def test_rejects_dependency_or_hash_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tracked = tmp_path / "tracked.txt"
    generated = tmp_path / "generated.txt"
    tracked.write_bytes(b"package==1.0\r\n--hash=sha256:abc\r\n")
    generated.write_bytes(b"package==1.0\n--hash=sha256:def\n")
    monkeypatch.setattr(MODULE, "LOCKED_REQUIREMENTS", tracked)

    with pytest.raises(ValueError, match="differ from the tracked lock export"):
        MODULE.verify(generated)

"""Tests for immutable data contracts."""

import json
from pathlib import PurePosixPath

import pytest

from omnipatch.models import Finding, Patch, PatchResult, Severity, make_finding_id


def build_finding() -> Finding:
    """Build a representative finding."""
    return Finding(
        "abc",
        "B608",
        "SQL injection",
        Severity.HIGH,
        PurePosixPath("src/a.py"),
        2,
        3,
        "message",
        "stub",
    )


def test_finding_round_trip() -> None:
    """Finding serialization is reversible."""
    finding = build_finding()
    assert Finding.from_json_dict(finding.to_json_dict()) == finding


def test_finding_id_is_deterministic_and_location_sensitive() -> None:
    """Finding IDs vary with line number."""
    path = PurePosixPath("src/a.py")
    assert make_finding_id("B608", path, 2) == make_finding_id("B608", path, 2)
    assert make_finding_id("B608", path, 2) != make_finding_id("B608", path, 3)


def test_finding_id_is_twelve_lowercase_hex_characters() -> None:
    """Finding IDs use the stable 12-character hexadecimal format."""
    finding_id = make_finding_id("B608", PurePosixPath("src/a.py"), 2)
    assert len(finding_id) == 12
    assert all(character in "0123456789abcdef" for character in finding_id)


@pytest.mark.parametrize(("value", "expected"), [(22.0, 22), ("22", 22)])
def test_finding_json_integer_fields_accept_valid_values(
    value: object, expected: int
) -> None:
    """JSON line fields accept integral floats and integer strings."""
    raw = build_finding().to_json_dict()
    raw["line_start"] = value
    raw["line_end"] = value
    finding = Finding.from_json_dict(raw)
    assert finding.line_start == expected
    assert finding.line_end == expected


@pytest.mark.parametrize("value", [22.5, True, None])
def test_finding_json_integer_fields_reject_invalid_values(value: object) -> None:
    """Fractional, boolean, and missing numeric values are rejected."""
    raw = build_finding().to_json_dict()
    raw["line_start"] = value
    raw["line_end"] = value
    with pytest.raises(ValueError):
        Finding.from_json_dict(raw)


@pytest.mark.parametrize(
    "path", [PurePosixPath("/absolute.py"), PurePosixPath("src/../a.py")]
)
def test_finding_rejects_invalid_path(path: PurePosixPath) -> None:
    """Absolute and parent-traversal paths are rejected."""
    with pytest.raises(ValueError):
        Finding("abc", "B1", "title", Severity.LOW, path, 1, 1, "message", "stub")


@pytest.mark.parametrize(
    ("unified_diff", "touched_files"),
    [("", (PurePosixPath("src/a.py"),)), ("diff", ())],
)
def test_patch_rejects_missing_content(
    unified_diff: str, touched_files: tuple[PurePosixPath, ...]
) -> None:
    """Patches require a diff and at least one touched file."""
    with pytest.raises(ValueError):
        Patch("finding", unified_diff, "explanation", touched_files, "model")


def test_b105_findings_and_patch_artifacts_do_not_serialize_synthetic_secret() -> None:
    """B105 reports and serialized diffs redact the removed synthetic literal."""
    canary = "SELF_LABELLED_PRIVACY_CANARY_DO_NOT_USE"
    finding = Finding(
        "b105-id",
        "B105",
        f"Possible hardcoded password: {canary}",
        Severity.LOW,
        PurePosixPath("app.py"),
        2,
        2,
        f"Possible hardcoded password: {canary}",
        "bandit",
    )
    unified_diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
        '-password = "SELF_LABELLED_PRIVACY_CANARY_DO_NOT_USE"\n'
        '+password = os.environ["APP_PASSWORD"]\n'
        ' public_label = "PUBLIC_LABEL_REMAINS"\n'
    )
    patch = Patch(
        finding.id,
        unified_diff,
        "Replace hardcoded value with required environment lookup",
        (PurePosixPath("app.py"),),
        "offline-test-model",
    )

    serialized_finding = json.dumps(finding.to_json_dict())
    serialized_result = json.dumps(PatchResult(patch, True, True).to_json_dict())

    if any(
        canary in value
        for value in (serialized_finding, repr(finding), serialized_result, repr(patch))
    ):
        pytest.fail("synthetic canary appeared in a serialized representation")
    assert "PUBLIC_LABEL_REMAINS" in serialized_result
    assert patch.to_json_dict()["unified_diff_redacted"] is True

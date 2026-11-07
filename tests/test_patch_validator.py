"""Offline tests for one-file in-memory patch validation."""

from pathlib import PurePosixPath

import pytest

from omnipatch.errors import PatchGenerationError
from omnipatch.models import Finding, Severity
from omnipatch.validation import validate_patch


@pytest.fixture
def finding() -> Finding:
    """Return a stable finding for validator tests."""
    return Finding(
        id="finding-1",
        rule_id="B608",
        title="SQL injection",
        severity=Severity.HIGH,
        file=PurePosixPath("app.py"),
        line_start=1,
        line_end=1,
        message="unsafe query",
        source="test",
    )


def test_valid_diff_returns_deterministic_patch(finding: Finding) -> None:
    """A valid patch carries finding metadata and a deterministic explanation."""
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-query = input()\n+query = safe(input())\n"
    patch = validate_patch(diff, finding, "query = input()\n", "fake-model")
    assert patch.finding_id == finding.id
    assert patch.touched_files == (finding.file,)
    assert patch.model == "fake-model"
    assert patch.explanation == "B608: SQL injection (app.py:1)"


@pytest.mark.parametrize(
    ("old_path", "new_path", "message"),
    [
        ("a/other.py", "b/other.py", "does not match finding file"),
        ("/tmp/app.py", "/tmp/app.py", "must be relative"),
        ("a/../app.py", "b/../app.py", "traversal"),
        ("/dev/null", "b/app.py", "cannot create or delete"),
        ("a/app.py", "/dev/null", "cannot create or delete"),
    ],
)
def test_rejects_unsafe_or_mismatched_paths(
    finding: Finding, old_path: str, new_path: str, message: str
) -> None:
    """The validator confines diffs to the finding's relative file."""
    diff = (
        f"--- {old_path}\n+++ {new_path}\n@@ -1 +1 @@\n"
        "-query = input()\n+query = safe(input())\n"
    )
    with pytest.raises(PatchGenerationError, match=message):
        validate_patch(diff, finding, "query = input()\n", "fake")


def test_rejects_two_file_diff_and_names_injected_path(finding: Finding) -> None:
    """A malicious snippet cannot make the proposal touch an additional file."""
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-query = input()\n"
        "+query = safe(input())\n--- a/other.py\n+++ b/other.py\n"
        "@@ -1 +1 @@\n-x = 1\n+x = 2\n"
    )
    with pytest.raises(PatchGenerationError, match="exactly one file"):
        validate_patch(diff, finding, "query = input()\n", "fake")


def test_rejects_hunk_line_count_mismatch(finding: Finding) -> None:
    """Declared hunk arithmetic must match its body."""
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1 @@\n-query = input()\n+query = safe(input())\n"
    with pytest.raises(PatchGenerationError, match="declares"):
        validate_patch(diff, finding, "query = input()\n", "fake")


def test_rejects_context_mismatch(finding: Finding) -> None:
    """Context and removal lines are checked against original source."""
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-wrong = input()\n+query = safe(input())\n"
    with pytest.raises(PatchGenerationError, match="context mismatch"):
        validate_patch(diff, finding, "query = input()\n", "fake")


def test_rejects_invalid_python(finding: Finding) -> None:
    """A cleanly applied diff must still parse as Python."""
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-query = input()\n+if :\n"
    with pytest.raises(PatchGenerationError, match="invalid"):
        validate_patch(diff, finding, "query = input()\n", "fake")


def test_rejects_noop_patch(finding: Finding) -> None:
    """A syntactically valid but unchanged result is not a patch."""
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-query = input()\n+query = input()\n"
    )
    with pytest.raises(PatchGenerationError, match="does not change"):
        validate_patch(diff, finding, "query = input()\n", "fake")


def test_accepts_optional_diff_fence(finding: Finding) -> None:
    """One optional surrounding Markdown fence is removed."""
    diff = (
        "```diff\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
        "-query = input()\n+query = safe(input())\n```"
    )
    patch = validate_patch(diff, finding, "query = input()\n", "fake")
    assert patch.unified_diff.startswith("--- a/app.py")

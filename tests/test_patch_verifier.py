"""Offline and Bandit integration tests for patch verification."""

import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from omnipatch.cli import app
from omnipatch.models import Finding, Patch, PatchResult, Severity
from omnipatch.scanners.base import Scanner
from omnipatch.validation.patch_validator import validate_patch
from omnipatch.verification.patch_verifier import verify_patch

SOURCE = "query = input()\n"
DIFF = (
    "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
    "-query = input()\n+query = safe(input())\n"
)


class SequenceScanner:
    """Return the next recorded scan result for an isolated verification."""

    name = "fake"

    def __init__(self, *results: list[Finding]) -> None:
        """Store baseline and sandbox scan findings."""
        self._results = list(results)
        self._calls = 0

    def is_available(self) -> bool:
        """Report that the fake scanner is available."""
        return True

    def scan(self, repo_root: Path) -> list[Finding]:
        """Return the configured result for this scan invocation."""
        result = self._results[min(self._calls, len(self._results) - 1)]
        self._calls += 1
        return result


def make_finding(
    rule: str = "B999",
    file: str = "app.py",
    line: int = 1,
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Build a test finding with a location-sensitive ID."""
    return Finding(
        id=f"{rule}-{file}-{line}",
        rule_id=rule,
        title=f"Finding {rule}",
        severity=severity,
        file=PurePosixPath(file),
        line_start=line,
        line_end=line,
        message="test finding",
        source="test",
    )


def make_patch(finding: Finding, original: str = SOURCE) -> Patch:
    """Return a validated patch for the finding's file."""
    return validate_patch(DIFF, finding, original, "fake")


def test_verify_succeeds_when_target_is_gone(tmp_path: Path) -> None:
    """The target absent and no new pairs makes verification successful."""
    finding = make_finding()
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    scanner = SequenceScanner([])
    result = verify_patch(make_patch(finding), finding, tmp_path, scanner, [finding])
    assert result.applied is True
    assert result.verified is True
    assert result.error is None
    assert result.introduced == ()


def test_verify_reports_target_that_survived(tmp_path: Path) -> None:
    """A remaining target rule/file pair fails verification."""
    finding = make_finding()
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    scanner = SequenceScanner([make_finding(line=2)])
    result = verify_patch(make_patch(finding), finding, tmp_path, scanner, [finding])
    assert result.verified is False
    assert result.error is not None and "survived" in result.error


def test_verify_fails_when_new_rule_is_introduced(tmp_path: Path) -> None:
    """A new rule/file pair fails even when the target itself is resolved."""
    finding = make_finding()
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    scanner = SequenceScanner([make_finding("B602", line=2)])
    result = verify_patch(make_patch(finding), finding, tmp_path, scanner, [finding])
    assert result.verified is False
    assert result.error is not None and "B602" in result.error


@pytest.mark.parametrize(
    ("target_severity", "new_severity", "expected_verified"),
    [
        (Severity.HIGH, Severity.LOW, True),
        (Severity.HIGH, Severity.HIGH, False),
        (Severity.MEDIUM, Severity.HIGH, False),
        (Severity.MEDIUM, Severity.MEDIUM, False),
        (Severity.LOW, Severity.LOW, False),
    ],
)
def test_severity_policy_blocks_equal_or_higher_findings(
    tmp_path: Path,
    target_severity: Severity,
    new_severity: Severity,
    expected_verified: bool,
) -> None:
    """Only introduced findings below the target severity are tolerated."""
    target = make_finding(severity=target_severity)
    introduced = make_finding("B602", severity=new_severity)
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")

    result = verify_patch(
        make_patch(target), target, tmp_path, SequenceScanner([introduced]), [target]
    )

    assert result.verified is expected_verified
    if new_severity.rank < target_severity.rank:
        assert result.error is None
        assert result.introduced == ("B602 in app.py",)
    else:
        assert result.error is not None and "B602 in app.py" in result.error
        assert result.introduced == ()


def test_mixed_blocking_and_tolerated_findings_are_both_reported(
    tmp_path: Path,
) -> None:
    """Blocking findings fail, while tolerated lower findings remain visible."""
    target = make_finding(severity=Severity.HIGH)
    low_one = make_finding("B404", severity=Severity.LOW)
    low_two = make_finding("B603", severity=Severity.LOW)
    blocking = make_finding("B607", severity=Severity.HIGH)
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")

    result = verify_patch(
        make_patch(target),
        target,
        tmp_path,
        SequenceScanner([low_one, low_two, blocking]),
        [target],
    )

    assert result.verified is False
    assert result.error is not None and "B607 in app.py" in result.error
    assert result.introduced == ("B404 in app.py", "B603 in app.py")


def test_strict_policy_fails_on_any_introduced_finding(tmp_path: Path) -> None:
    """Strict policy restores the former presence-based blocking behavior."""
    target = make_finding(severity=Severity.HIGH)
    low_finding = make_finding("B404", severity=Severity.LOW)
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")

    result = verify_patch(
        make_patch(target),
        target,
        tmp_path,
        SequenceScanner([low_finding]),
        [target],
        policy="strict",
    )

    assert result.verified is False
    assert result.error is not None and "B404 in app.py" in result.error
    assert result.introduced == ()


def test_target_absent_from_baseline_still_fails(tmp_path: Path) -> None:
    """A post-patch scan cannot verify a target absent from the baseline."""
    target = make_finding(severity=Severity.HIGH)
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")

    result = verify_patch(make_patch(target), target, tmp_path, SequenceScanner([]), [])

    assert result.verified is False
    assert result.error is not None and "absent from the baseline" in result.error


def test_line_shift_does_not_count_as_new_finding(tmp_path: Path) -> None:
    """Existing rule/file pairs stay stable when their finding IDs shift."""
    finding = make_finding("B608", line=11)
    baseline = [finding, make_finding("B602", line=18)]
    after = [make_finding("B602", line=17)]
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    result = verify_patch(
        make_patch(finding), finding, tmp_path, SequenceScanner(after), baseline
    )
    assert result.verified is True
    assert result.error is None
    assert result.introduced == ()


def test_findings_in_unscanned_files_are_not_called_resolved(tmp_path: Path) -> None:
    """Only pairs from the patched file participate in the verdict."""
    finding = make_finding()
    unrelated = make_finding("B105", file="other.py", line=9)
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    result = verify_patch(
        make_patch(finding),
        finding,
        tmp_path,
        SequenceScanner([]),
        [finding, unrelated],
    )
    assert result.verified is True
    assert result.error is None


def test_patch_result_json_includes_every_field(tmp_path: Path) -> None:
    """The result method returns JSON-compatible patch and verdict fields."""
    finding = make_finding()
    patch = make_patch(finding)
    result = PatchResult(
        patch,
        applied=True,
        verified=False,
        error="introduced B602",
        introduced=("B404 in app.py",),
    )
    payload = result.to_json_dict()
    assert json.loads(json.dumps(payload)) == {
        "patch": patch.to_json_dict(),
        "applied": True,
        "verified": False,
        "error": "introduced B602",
        "introduced": ["B404 in app.py"],
    }


def _cli_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after: list[Finding],
) -> tuple[Finding, bytes]:
    """Configure a fake scanner and completion client for CLI verification."""
    finding = make_finding()
    target = tmp_path / "app.py"
    original = SOURCE.encode("utf-8")
    target.write_bytes(original)
    monkeypatch.setenv("OMNIPATCH_LLM_API_KEY", "offline-test-key")
    scanner = SequenceScanner([finding], after)
    monkeypatch.setattr("omnipatch.cli.build_scanner", lambda *args, **kwargs: scanner)

    client = SimpleNamespace(
        model="fake",
        complete=lambda system, user: DIFF,
    )
    monkeypatch.setattr("omnipatch.cli.build_llm_client", lambda settings: client)
    return finding, original


def test_verify_cli_exit_codes_and_source_immutability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify exits 0/1 by outcome and does not alter the source file."""
    finding, original = _cli_setup(tmp_path, monkeypatch, [])
    result = CliRunner().invoke(
        app,
        ["verify", "--repo", str(tmp_path), "--rule", finding.rule_id, "--json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)[0]["verified"] is True
    assert (tmp_path / "app.py").read_bytes() == original
    finding, original = _cli_setup(tmp_path, monkeypatch, [finding])
    result = CliRunner().invoke(
        app,
        ["verify", "--repo", str(tmp_path), "--rule", finding.rule_id, "--json"],
    )
    assert result.exit_code == 1
    assert json.loads(result.stdout)[0]["verified"] is False
    assert (tmp_path / "app.py").read_bytes() == original


def test_verify_cli_reports_tolerated_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Text output reports tolerated findings alongside a blocking finding."""
    finding, _ = _cli_setup(
        tmp_path,
        monkeypatch,
        [
            make_finding("B404", severity=Severity.LOW),
            make_finding("B607", severity=Severity.HIGH),
        ],
    )
    result = CliRunner().invoke(
        app,
        ["verify", "--repo", str(tmp_path), "--rule", finding.rule_id],
    )
    assert result.exit_code == 1, result.output
    assert "B404 in app.py" in result.output
    assert "B607 in app.py" in result.output


@pytest.mark.integration
def test_real_bandit_verifies_known_good_b608_patch() -> None:
    """Bandit no longer reports B608 and retains other fixture findings."""
    from omnipatch.scanners.bandit_scanner import BanditScanner

    fixture = Path("tests/fixtures/vulnerable_app").resolve()

    class CapturingBanditScanner:
        """Record both the baseline and isolated Bandit reports."""

        name = "bandit"

        def __init__(self) -> None:
            """Create the real adapter and its scan history."""
            self._scanner = BanditScanner()
            self.scans: list[list[Finding]] = []

        def is_available(self) -> bool:
            """Delegate the real adapter's availability check."""
            return self._scanner.is_available()

        def scan(self, repo_root: Path) -> list[Finding]:
            """Run Bandit and retain the observed finding set."""
            results = self._scanner.scan(repo_root)
            self.scans.append(results)
            return results

    scanner: Scanner = CapturingBanditScanner()
    baseline = scanner.scan(fixture)
    finding = next(item for item in baseline if item.rule_id == "B608")
    source_path = fixture / finding.file.as_posix()
    original = source_path.read_text(encoding="utf-8")
    patch_text = (
        "--- a/app.py\n+++ b/app.py\n@@ -11,2 +11 @@\n"
        "-    query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n"
        "-    cursor.execute(query)\n"
        '+    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    )
    patch = validate_patch(patch_text, finding, original, "test-model")
    result = verify_patch(patch, finding, fixture, scanner, baseline)
    assert result.verified is True, result.error
    after_rules = {
        item.rule_id for item in scanner.scans[-1] if item.file == finding.file
    }
    assert {"B404", "B105", "B602"} <= after_rules
    assert "B608" not in after_rules
    assert (
        next(item.line_start for item in scanner.scans[-1] if item.rule_id == "B602")
        == 17
    )
    assert {item.rule_id for item in baseline if item.file == finding.file} >= {
        "B404",
        "B105",
        "B608",
        "B602",
    }

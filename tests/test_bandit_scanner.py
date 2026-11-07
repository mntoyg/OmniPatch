"""Tests for Bandit report parsing and scanner execution behavior."""

import json
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from omnipatch.defaults import EXCLUDED_DIRS
from omnipatch.errors import ScannerError
from omnipatch.models import Finding, Severity, make_finding_id
from omnipatch.scanners import bandit_scanner
from omnipatch.scanners.bandit_scanner import (
    _SEVERITY_BY_BANDIT,
    BanditScanner,
    _parse_report,
    _relative_posix,
)
from omnipatch.scanners.registry import build_scanner
from omnipatch.scanners.stub import StubScanner

REPORT_PATH = Path(__file__).parent / "fixtures" / "bandit_output.json"
VULNERABLE_REPO = Path("tests/fixtures/vulnerable_app")


def read_report() -> dict[str, object]:
    """Load the recorded Bandit JSON report."""
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    assert isinstance(report, dict)
    return cast(dict[str, object], report)


def findings_from_recorded_report() -> list[Finding]:
    """Parse the recorded report without starting Bandit."""
    return _parse_report(read_report(), VULNERABLE_REPO.resolve())


def test_recorded_report_maps_to_expected_findings() -> None:
    """The Bandit report maps the expected vulnerability rules to Findings."""
    findings = findings_from_recorded_report()
    assert {finding.rule_id for finding in findings} >= {"B608", "B602", "B105"}
    sql_finding = next(finding for finding in findings if finding.rule_id == "B608")
    assert sql_finding.rule_id == "B608"
    assert (
        sql_finding.title
        == "Possible SQL injection vector through string-based query construction."
    )
    assert sql_finding.file.as_posix() == "app.py"
    assert sql_finding.line_start == 11
    assert sql_finding.line_end == 11
    assert sql_finding.severity is Severity.MEDIUM
    assert sql_finding.message == (
        "Possible SQL injection vector through string-based query construction. "
        "(https://bandit.readthedocs.io/en/1.9.4/plugins/"
        "b608_hardcoded_sql_expressions.html)"
    )
    assert sql_finding.source == "bandit"
    assert sql_finding.cwe == "CWE-89"


def test_b105_finding_metadata_does_not_retain_scanner_literal() -> None:
    """Bandit issue text for B105 is replaced before logs or JSON serialization."""
    canary = "SELF_LABELLED_BANDIT_CANARY_DO_NOT_USE"
    report = {
        "errors": [],
        "results": [
            {
                "filename": "app.py",
                "test_id": "B105",
                "issue_text": f"Possible hardcoded password: '{canary}'",
                "issue_severity": "LOW",
                "line_number": 1,
                "line_range": [1],
            }
        ],
    }

    finding = _parse_report(report, Path("/synthetic/root"))[0]
    serialized = json.dumps(finding.to_json_dict())

    if any(
        canary in value
        for value in (finding.message, finding.title, repr(finding), serialized)
    ):
        pytest.fail("synthetic canary appeared in finding output")
    assert "Hardcoded credential finding" in serialized


def test_bandit_scanner_does_not_echo_reported_error_details(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Scanner-provided error reasons stay out of warnings and exceptions."""
    canary = "SELF_LABELLED_SCANNER_ERROR_CANARY_DO_NOT_USE"
    report = {
        "errors": [{"filename": str(tmp_path / "app.py"), "reason": canary}],
        "results": [],
    }

    findings = _parse_report(report, tmp_path)
    warning = capsys.readouterr().err

    assert findings == []
    if canary in warning:
        pytest.fail("synthetic canary appeared in scanner warning")
    assert "scanner reported an error" in warning


def test_bandit_process_diagnostics_are_not_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Subprocess stderr that may contain source is omitted from scanner errors."""
    canary = "SELF_LABELLED_BANDIT_STDERR_CANARY_DO_NOT_USE"

    def failed_run(
        args: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 2, stdout="", stderr=canary)

    monkeypatch.setattr(bandit_scanner.subprocess, "run", failed_run)
    with pytest.raises(ScannerError) as caught:
        BanditScanner().scan(tmp_path)

    if canary in str(caught.value):
        pytest.fail("synthetic canary appeared in scanner error")
    assert "diagnostics omitted" in str(caught.value)


def test_relative_posix_accepts_clean_posix_filename(tmp_path: Path) -> None:
    """POSIX-style paths become repository-relative POSIX paths."""
    assert _relative_posix("src/app.py", tmp_path).as_posix() == "src/app.py"


@pytest.mark.skipif(os.name != "nt", reason="Windows mixed-separator path")
def test_relative_posix_accepts_windows_mixed_separators() -> None:
    """Windows paths with mixed separators normalize to POSIX separators."""
    assert (
        _relative_posix("C:/repo/src\\app.py", Path("C:/repo")).as_posix()
        == "src/app.py"
    )


def test_relative_posix_ignores_process_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Relative report paths resolve only from the repository root."""
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    (repo_root / "src" / "app.py").write_text("x = 1", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cwd_relative_filename = f"../{tmp_path.name}/repo/src/app.py"
    with pytest.raises(ScannerError):
        _relative_posix(cwd_relative_filename, repo_root)


@pytest.mark.parametrize(
    ("bandit_severity", "severity"),
    [
        ("LOW", Severity.LOW),
        ("MEDIUM", Severity.MEDIUM),
        ("HIGH", Severity.HIGH),
        ("UNDEFINED", Severity.LOW),
    ],
)
def test_severity_mapping(bandit_severity: str, severity: Severity) -> None:
    """Known Bandit severities map to OmniPatch severity levels."""
    assert _SEVERITY_BY_BANDIT[bandit_severity] is severity


def test_unknown_severity_raises_scanner_error() -> None:
    """Unknown Bandit severities never silently default."""
    report = read_report()
    results = cast(list[dict[str, object]], report["results"])
    results[0]["issue_severity"] = "EXTREME"
    with pytest.raises(ScannerError, match="unknown severity"):
        _parse_report(report, VULNERABLE_REPO.resolve())


@pytest.mark.parametrize("remove_line_range", [False, True])
def test_line_end_uses_max_or_falls_back(remove_line_range: bool) -> None:
    """Line end is the maximum range entry or the start line when absent."""
    report = read_report()
    results = cast(list[dict[str, object]], report["results"])
    results[0]["line_number"] = 10
    if remove_line_range:
        results[0].pop("line_range")
        expected = 10
    else:
        results[0]["line_range"] = [10, 14, 12]
        expected = 14
    finding = _parse_report(report, VULNERABLE_REPO.resolve())[0]
    assert finding.line_end == expected


def test_root_scan_error_invalidates_report(tmp_path: Path) -> None:
    """An error naming the repository root invalidates the whole scan."""
    report: dict[str, object] = {
        "errors": [{"filename": str(tmp_path), "reason": "missing path"}],
        "results": [],
    }
    with pytest.raises(ScannerError, match="repository root"):
        _parse_report(report, tmp_path)


def test_file_scan_error_warns_and_keeps_findings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An individual file error warns while retaining valid findings."""
    report = read_report()
    report["errors"] = [
        {
            "filename": str(VULNERABLE_REPO.resolve() / "broken.py"),
            "reason": "syntax error while parsing AST from file",
        }
    ]
    findings = _parse_report(report, VULNERABLE_REPO.resolve())
    captured = capsys.readouterr()
    assert {finding.rule_id for finding in findings} >= {"B608", "B602", "B105"}
    assert "warning: bandit skipped broken.py:" in captured.err


def test_nonstandard_return_code_omits_scanner_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return codes other than zero or one omit scanner diagnostics."""
    monkeypatch.setattr(
        bandit_scanner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 2, stdout="{}", stderr="scanner failed"
        ),
    )
    with pytest.raises(ScannerError, match="diagnostics omitted"):
        BanditScanner().scan(Path("."))


def test_scan_uses_required_argument_vector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Bandit is invoked with the specified argv and subprocess options."""
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Capture the process request and return an empty valid report."""
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args, 0, stdout='{"errors": [], "results": []}', stderr=""
        )

    command = ("python", "-m", "bandit")
    scanner = BanditScanner(command=command, timeout_seconds=7)
    monkeypatch.setattr(bandit_scanner.subprocess, "run", fake_run)
    assert scanner.scan(tmp_path / ".") == []
    assert captured["args"] == [
        *command,
        "-r",
        str(tmp_path.resolve()),
        "-f",
        "json",
        "-q",
        "-x",
        ",".join(f"*/{directory.strip('/')}/*" for directory in scanner._excluded_dirs),
    ]
    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "check": False,
        "timeout": 7,
    }


def test_scan_omits_exclusion_argument_when_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty exclusion list does not pass Bandit an empty -x value."""
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Capture the process request and return an empty valid report."""
        captured["args"] = args
        return subprocess.CompletedProcess(
            args, 0, stdout='{"errors": [], "results": []}', stderr=""
        )

    monkeypatch.setattr(bandit_scanner.subprocess, "run", fake_run)
    assert BanditScanner(excluded_dirs=()).scan(tmp_path) == []
    assert "-x" not in captured["args"]


def test_timeout_raises_scanner_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scanner timeout is translated to ScannerError."""

    def raise_timeout(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        """Raise a simulated subprocess timeout."""
        raise subprocess.TimeoutExpired("bandit", 1)

    monkeypatch.setattr(bandit_scanner.subprocess, "run", raise_timeout)
    with pytest.raises(ScannerError, match="timed out"):
        BanditScanner(timeout_seconds=1).scan(Path("."))


def test_missing_bandit_command_is_not_available() -> None:
    """An unavailable executable returns False without raising."""
    assert not BanditScanner(command=("omnipatch-no-such-command",)).is_available()


def test_build_scanner_registry() -> None:
    """The registry returns built-ins and rejects unknown names."""
    assert isinstance(build_scanner("bandit"), BanditScanner)
    assert isinstance(build_scanner("stub"), StubScanner)
    with pytest.raises(ScannerError, match="bandit, stub"):
        build_scanner("nope")


def test_build_scanner_forwards_bandit_options() -> None:
    """The scanner registry forwards timeout and exclusions to BanditScanner."""
    scanner = build_scanner(
        "bandit", timeout_seconds=17, excluded_dirs=("custom", "dist")
    )
    assert isinstance(scanner, BanditScanner)
    assert scanner._timeout_seconds == 17
    assert scanner._excluded_dirs == ("custom", "dist")


def test_default_exclusions_do_not_include_test_fixtures() -> None:
    """Source-bearing tests/fixtures trees remain scannable by default."""
    assert "tests/fixtures" not in EXCLUDED_DIRS


@pytest.mark.integration
def test_bandit_scans_vulnerable_fixture() -> None:
    """The real Bandit process reports all fixture vulnerabilities."""
    findings = BanditScanner().scan(VULNERABLE_REPO.resolve())
    assert {finding.rule_id for finding in findings} >= {"B105", "B608", "B602"}
    b602_finding = next(finding for finding in findings if finding.rule_id == "B602")
    assert b602_finding.severity is Severity.HIGH
    assert all(
        finding.id == make_finding_id(finding.rule_id, finding.file, finding.line_start)
        for finding in findings
    )


@pytest.mark.integration
def test_bandit_reports_vulnerability_under_fixture_directory(tmp_path: Path) -> None:
    """The default scanner reports a HIGH finding below tests/fixtures."""
    fixture = tmp_path / "tests" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / "seed.py").write_text(
        "import subprocess\n"
        'subprocess.call("echo " + __import__("sys").argv[1], shell=True)\n',
        encoding="utf-8",
    )
    findings = BanditScanner().scan(tmp_path.resolve())
    assert "B602" in {finding.rule_id for finding in findings}


def test_configured_exclusion_warns_when_dropping_findings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The post-filter warns if Bandit emits a finding under an excluded path."""
    report = {
        "errors": [],
        "results": [
            {
                "filename": str(tmp_path / "tests" / "fixtures" / "seed.py"),
                "test_id": "B602",
                "issue_text": "shell=True",
                "issue_severity": "HIGH",
                "line_number": 1,
                "line_range": [1],
            }
        ],
    }
    monkeypatch.setattr(
        bandit_scanner.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(report), stderr=""
        ),
    )
    findings = BanditScanner(excluded_dirs=("tests/fixtures",)).scan(tmp_path)
    captured = capsys.readouterr()
    assert "B602" not in {finding.rule_id for finding in findings}
    assert "warning:" in captured.err
    assert "scan-exclude (tests/fixtures)" in captured.err


@pytest.mark.integration
def test_empty_exclusions_do_not_drop_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty exclusion sequence disables exclusions completely."""
    fixture = tmp_path / "tests" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / "seed.py").write_text(
        "import subprocess\n"
        'subprocess.call("echo " + __import__("sys").argv[1], shell=True)\n',
        encoding="utf-8",
    )
    findings = BanditScanner(excluded_dirs=()).scan(tmp_path.resolve())
    captured = capsys.readouterr()
    assert "B602" in {finding.rule_id for finding in findings}
    assert "warning:" not in captured.err

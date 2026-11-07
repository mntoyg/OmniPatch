"""OP-27 — an exclusion must never be silent, and a nested checkout in scope must be named."""

import json
import subprocess
from pathlib import Path

import pytest

from omnipatch.scanners import bandit_scanner
from omnipatch.scanners.bandit_scanner import BanditScanner


def stub_report(monkeypatch: pytest.MonkeyPatch, report: dict[str, object]) -> None:
    """Replace the Bandit subprocess so only OmniPatch's own behaviour is under test."""
    monkeypatch.setattr(
        bandit_scanner.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(report), stderr=""
        ),
    )


def write_py(root: Path, relative: str, body: str = "value = 1\n") -> None:
    """Create a Python file and every directory above it."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_excluded_python_files_are_reported_as_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The operator is told how many Python files an exclusion kept out of the scan."""
    write_py(tmp_path, "app.py")
    write_py(tmp_path, "vendored/one.py")
    write_py(tmp_path, "vendored/nested/two.py")
    stub_report(monkeypatch, {"errors": [], "results": []})

    BanditScanner(excluded_dirs=("vendored",)).scan(tmp_path)

    err = capsys.readouterr().err
    assert "warning:" in err
    assert "2 python file(s)" in err
    assert "vendored" in err


def test_no_exclusion_match_reports_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An exclusion that matches no directory must stay quiet."""
    write_py(tmp_path, "app.py")
    stub_report(monkeypatch, {"errors": [], "results": []})

    BanditScanner(excluded_dirs=("vendored",)).scan(tmp_path)

    assert "python file(s)" not in capsys.readouterr().err


def test_nested_checkout_in_scope_is_reported_and_not_excluded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directory with its own .git is named, and its findings are still returned."""
    write_py(tmp_path, "models/upstream/mod.py")
    (tmp_path / "models" / "upstream" / ".git").mkdir(parents=True)
    report = {
        "errors": [],
        "results": [
            {
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "issue_severity": "HIGH",
                "issue_text": "shell=True identified",
                "filename": str(tmp_path / "models" / "upstream" / "mod.py"),
                "line_number": 1,
                "line_range": [1],
            }
        ],
    }
    stub_report(monkeypatch, report)

    findings = BanditScanner(excluded_dirs=()).scan(tmp_path)

    err = capsys.readouterr().err
    assert "nested checkout" in err
    assert "models/upstream" in err
    assert [finding.rule_id for finding in findings] == ["B602"], (
        "a nested checkout is reported, never silently excluded"
    )


def test_nested_checkout_inside_an_exclusion_is_not_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Already out of scope is not worth an operator warning."""
    write_py(tmp_path, "vendored/upstream/mod.py")
    (tmp_path / "vendored" / "upstream" / ".git").mkdir(parents=True)
    stub_report(monkeypatch, {"errors": [], "results": []})

    BanditScanner(excluded_dirs=("vendored",)).scan(tmp_path)

    assert "nested checkout" not in capsys.readouterr().err


def test_post_filter_drops_an_excluded_name_at_depth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backstop matches an excluded name at any depth, as Bandit's glob already does."""
    report = {
        "errors": [],
        "results": [
            {
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "issue_severity": "HIGH",
                "issue_text": "shell=True identified",
                "filename": str(tmp_path / "src" / "build" / "mod.py"),
                "line_number": 1,
                "line_range": [1],
            },
            {
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "issue_severity": "LOW",
                "issue_text": "possible hardcoded password",
                "filename": str(tmp_path / "src" / "app.py"),
                "line_number": 1,
                "line_range": [1],
            },
        ],
    }
    stub_report(monkeypatch, report)

    findings = BanditScanner(excluded_dirs=("build",)).scan(tmp_path)

    assert [finding.rule_id for finding in findings] == ["B105"]


def test_default_exclusions_stay_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A documented default exclusion is the baseline a reader already assumes.

    Reporting it on every run is noise, which is the contract
    `test_scan_excludes_virtualenv_without_warning_or_slowdown` holds the scanner to.
    """
    write_py(tmp_path, "app.py")
    write_py(tmp_path, "__pycache__/cached.py")
    stub_report(monkeypatch, {"errors": [], "results": []})

    BanditScanner(excluded_dirs=("__pycache__",)).scan(tmp_path)

    assert "python file(s)" not in capsys.readouterr().err

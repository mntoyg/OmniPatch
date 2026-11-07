"""Tests for the command line interface and stub scanner."""

import json
from pathlib import Path, PurePosixPath
from time import perf_counter

import pytest
from typer.testing import CliRunner

from omnipatch.cli import _echo_patch_diff, app
from omnipatch.errors import ScannerError
from omnipatch.models import Finding, Severity, make_finding_id
from omnipatch.scanners.stub import StubScanner


def test_scan_json_returns_three_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON scan output is a pipeable array."""
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "10")
    result = CliRunner().invoke(
        app, ["scan", "--scanner", "stub", "--repo", ".", "--json"]
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert all(isinstance(item, dict) for item in parsed)
    assert {item["rule_id"] for item in parsed} >= {"B101", "B608", "CVE-2024-1234"}


def test_displayed_patch_diff_redacts_removed_value_and_preserves_public_literal(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Text output marks redacted diff display without altering public literals."""
    canary = "SELF_LABELLED_PATCH_OUTPUT_CANARY_DO_NOT_USE"
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
        f'-password = "{canary}"\n'
        '+password = os.environ["APP_PASSWORD"]\n'
        ' public_label = "PUBLIC_OUTPUT_LITERAL_REMAINS"\n'
    )

    _echo_patch_diff(diff)
    output = capsys.readouterr()

    if canary in output.out or canary in output.err:
        pytest.fail("synthetic canary appeared in CLI output")
    assert "PUBLIC_OUTPUT_LITERAL_REMAINS" in output.out
    assert "not directly applicable" in output.err


@pytest.mark.integration
def test_synthetic_b105_cli_reports_are_secret_safe(tmp_path: Path) -> None:
    """Scan and context JSON retain public context but omit the B105 canary."""
    canary = "SELF_LABELLED_CLI_REPORT_CANARY_DO_NOT_USE"
    public_literal = "PUBLIC_CLI_CONTEXT_REMAINS"
    (tmp_path / "app.py").write_text(
        f'stored_pass = "{canary}"\npublic_label = "{public_literal}"\n',
        encoding="utf-8",
    )

    scan_result = CliRunner().invoke(
        app, ["scan", "--repo", str(tmp_path), "--scanner", "bandit", "--json"]
    )
    context_result = CliRunner().invoke(
        app,
        [
            "context",
            "--repo",
            str(tmp_path),
            "--scanner",
            "bandit",
            "--rule",
            "B105",
            "--json",
        ],
    )

    if canary in scan_result.stdout or canary in scan_result.stderr:
        pytest.fail("synthetic canary appeared in scan CLI output")
    if canary in context_result.stdout or canary in context_result.stderr:
        pytest.fail("synthetic canary appeared in context CLI output")
    assert scan_result.exit_code == 0
    assert context_result.exit_code == 0
    assert public_literal in context_result.stdout


def test_scan_rejects_malformed_fixture(
    tmp_path: Path,
) -> None:
    """Malformed fixture content raises ScannerError."""
    fixture = tmp_path / "stub_findings.json"
    fixture.write_text("{invalid", encoding="utf-8")
    with pytest.raises(ScannerError):
        StubScanner(fixture=fixture).scan(tmp_path)


def test_missing_fixture_is_not_available(tmp_path: Path) -> None:
    """A missing fixture is reported as unavailable without raising."""
    assert not StubScanner(fixture=tmp_path / "missing.json").is_available()


def test_packaged_fixture_ids_match_locations() -> None:
    """Packaged fixture IDs match the deterministic location IDs."""
    result = CliRunner().invoke(
        app, ["scan", "--scanner", "stub", "--repo", ".", "--json"]
    )
    assert result.exit_code == 0
    for finding in json.loads(result.stdout):
        assert finding["id"] == make_finding_id(
            finding["rule_id"],
            PurePosixPath(finding["file"]),
            finding["line_start"],
        )


def test_scan_honors_max_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The configured maximum truncates JSON findings."""
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "1")
    result = CliRunner().invoke(
        app, ["scan", "--scanner", "stub", "--repo", ".", "--json"]
    )
    assert result.exit_code == 0
    assert len(json.loads(result.stdout)) == 1


@pytest.mark.integration
def test_scan_excludes_virtualenv_without_warning_or_slowdown() -> None:
    """A repository scan prunes the virtualenv and stays below ten seconds."""
    started = perf_counter()
    result = CliRunner().invoke(app, ["scan", "--repo", ".", "--json"])
    elapsed = perf_counter() - started
    assert result.exit_code == 0
    assert ".venv" not in result.stderr
    assert "warning:" not in result.stderr
    assert elapsed < 10


@pytest.mark.integration
def test_context_json_extracts_b608_function() -> None:
    """The context command returns the function containing the SQL finding."""
    result = CliRunner().invoke(
        app,
        [
            "context",
            "--repo",
            "tests/fixtures/vulnerable_app",
            "--rule",
            "B608",
            "--json",
        ],
    )
    assert result.exit_code == 0
    contexts = json.loads(result.stdout)
    assert len(contexts) == 1
    assert contexts[0]["symbol"] == "load_user"
    assert "f\"SELECT * FROM users WHERE id = '{user_id}'\"" in contexts[0]["snippet"]


@pytest.mark.integration
def test_context_json_redacts_b105_credential() -> None:
    """The B105 context does not expose its hardcoded password value."""
    result = CliRunner().invoke(
        app,
        [
            "context",
            "--repo",
            "tests/fixtures/vulnerable_app",
            "--rule",
            "B105",
            "--json",
        ],
    )
    assert result.exit_code == 0
    contexts = json.loads(result.stdout)
    assert len(contexts) == 1
    assert "changeme-not-a-real-secret" not in result.stdout


def test_context_rejects_non_directory_repository(tmp_path: Path) -> None:
    """Context preserves the CLI's invalid repository exit code."""
    source_file = tmp_path / "not-a-directory"
    source_file.write_text("source", encoding="utf-8")
    result = CliRunner().invoke(app, ["context", "--repo", str(source_file), "--json"])
    assert result.exit_code == 2
    assert "is not a directory" in result.stderr


def test_verify_reports_all_missing_b105_mappings_before_provider_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unmapped B105 targets fail closed together before provider construction."""
    (tmp_path / "app.py").write_text(
        'def get_password():\n    PASSWORD = "SELF-LABELLED-PASSWORD"\n'
        "    return PASSWORD\n\n"
        'def get_api_token():\n    API_TOKEN = "SELF-LABELLED-TOKEN"\n'
        "    return API_TOKEN\n",
        encoding="utf-8",
    )
    findings = [
        Finding(
            id="password-finding",
            rule_id="B105",
            title="Hardcoded password",
            severity=Severity.LOW,
            file=PurePosixPath("app.py"),
            line_start=2,
            line_end=2,
            message="Possible hardcoded password",
            source="test",
        ),
        Finding(
            id="token-finding",
            rule_id="B105",
            title="Hardcoded password",
            severity=Severity.LOW,
            file=PurePosixPath("app.py"),
            line_start=6,
            line_end=6,
            message="Possible hardcoded password",
            source="test",
        ),
    ]

    class FakeScanner:
        name = "fake"

        def is_available(self) -> bool:
            return True

        def scan(self, repo_root: Path) -> list[Finding]:
            return findings

    provider_constructions: list[object] = []
    monkeypatch.setenv("OMNIPATCH_SECRET_ENVIRONMENT", "{}")
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "10")
    monkeypatch.setattr("omnipatch.cli.build_scanner", lambda *a, **k: FakeScanner())
    monkeypatch.setattr(
        "omnipatch.cli.build_llm_client",
        lambda settings: provider_constructions.append(settings),
    )
    result = CliRunner().invoke(
        app, ["verify", "--repo", str(tmp_path), "--rule", "B105", "--json"]
    )

    assert result.exit_code == 1
    assert "app.py::get_password" in result.output
    assert "app.py::get_api_token" in result.output
    assert "OMNIPATCH_SECRET_ENVIRONMENT" in result.output
    assert "SELF-LABELLED-PASSWORD" not in result.output
    assert "SELF-LABELLED-TOKEN" not in result.output
    assert provider_constructions == []

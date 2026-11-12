"""Tests for the command line interface and stub scanner."""

import json
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

import omnipatch.cli as cli_module
from omnipatch.cli import _echo_patch_diff, app
from omnipatch.errors import ScannerError
from omnipatch.models import Finding, Severity, make_finding_id
from omnipatch.scanners import bandit_scanner
from omnipatch.scanners.stub import StubScanner


def test_scan_json_returns_three_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """JSON scan output is a pipeable array."""
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "10")
    result = CliRunner().invoke(
        app,
        ["scan", "--scanner", "stub", "--repo", str(tmp_path), "--json"],
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


def test_scan_reports_findings_omitted_by_maximum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON remains bounded and stderr reports the omitted findings."""
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "1")
    result = CliRunner().invoke(
        app, ["scan", "--scanner", "stub", "--repo", ".", "--json"]
    )
    assert result.exit_code == 0
    assert len(json.loads(result.stdout)) == 1
    assert "2 matching finding(s) omitted" in result.stderr
    assert "OMNIPATCH_MAX_FINDINGS" in result.stderr


def test_context_reads_the_captured_snapshot_after_live_root_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scanner and context use the captured tree even if the live path changes."""
    root = tmp_path / "repo"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "original"
    root.mkdir()
    replacement.mkdir()
    (root / "app.py").write_text("inside_value = 1\n", encoding="utf-8")
    (replacement / "app.py").write_text("outside_value = 2\n", encoding="utf-8")
    finding = _limit_finding("synthetic", "B999", Severity.LOW, "app.py")
    captured_roots: list[Path] = []

    class RootSwappingScanner:
        name = "root-swapping-scanner"

        def scan(self, repo_root: Path) -> list[Finding]:
            captured_roots.append(repo_root)
            assert repo_root != root
            assert (repo_root / "app.py").read_text(encoding="utf-8") == (
                "inside_value = 1\n"
            )
            root.rename(moved)
            replacement.rename(root)
            return [finding]

    monkeypatch.setattr(
        cli_module, "build_scanner", lambda *args, **kwargs: RootSwappingScanner()
    )

    result = CliRunner().invoke(app, ["context", "--repo", str(root), "--json"])

    assert result.exit_code == 0, result.output
    assert len(captured_roots) == 1
    assert "inside_value" in result.stdout
    assert "outside_value" not in result.stdout


def _limit_finding(
    finding_id: str, rule_id: str, severity: Severity, filename: str
) -> Finding:
    return Finding(
        id=finding_id,
        rule_id=rule_id,
        title=f"{rule_id} synthetic finding",
        severity=severity,
        file=PurePosixPath(filename),
        line_start=1,
        line_end=1,
        message="Synthetic finding for result-limit coverage",
        source="test",
    )


def _mixed_limit_findings() -> list[Finding]:
    return [
        _limit_finding("high-b999", "B999", Severity.HIGH, "high.py"),
        _limit_finding("critical-b608", "B608", Severity.CRITICAL, "critical.py"),
        _limit_finding("medium-b602", "B602", Severity.MEDIUM, "medium.py"),
        _limit_finding("medium-b999", "B999", Severity.MEDIUM, "matched.py"),
        _limit_finding("low-b999", "B999", Severity.LOW, "low.py"),
        _limit_finding("low-b105", "B105", Severity.LOW, "credential.py"),
    ]


class _LimitScanner:
    name = "fake-limit-scanner"

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.calls = 0

    def is_available(self) -> bool:
        return True

    def scan(self, repo_root: Path) -> list[Finding]:
        self.calls += 1
        return self.findings if self.calls == 1 else []


class _LimitCompletionClient:
    model = "fake-limit-model"

    def __init__(self) -> None:
        self.files: list[str] = []

    def complete(self, system: str, user: str) -> str:
        filename = str(json.loads(user)["file"])
        self.files.append(filename)
        return (
            f"--- a/{filename}\n+++ b/{filename}\n@@ -1 +1 @@\n"
            "-value = input()\n+value = str(input())\n"
        )


def _write_limit_sources(repo: Path, findings: list[Finding]) -> None:
    for finding in findings:
        path = repo.joinpath(*finding.file.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = input()\n", encoding="utf-8")


def _configure_limit_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, findings: list[Finding]
) -> tuple[_LimitScanner, _LimitCompletionClient]:
    _write_limit_sources(tmp_path, findings)
    scanner = _LimitScanner(findings)
    client = _LimitCompletionClient()
    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "2")
    monkeypatch.setenv("OMNIPATCH_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OMNIPATCH_LLM_OUTPUT", "diff")
    monkeypatch.setenv("OMNIPATCH_LLM_API_KEY", "offline-fake-key")
    monkeypatch.setattr("omnipatch.cli.build_scanner", lambda *a, **k: scanner)
    monkeypatch.setattr("omnipatch.cli.build_llm_client", lambda settings: client)
    return scanner, client


def _assert_omission_warning(stderr: str, omitted: int) -> None:
    marker = "matching finding(s) omitted from this command"
    if omitted == 0:
        assert marker not in stderr
        assert "OMNIPATCH_MAX_FINDINGS" not in stderr
        return
    assert f"{omitted} {marker}" in stderr
    assert "OMNIPATCH_MAX_FINDINGS" in stderr


def _command_ids(command: str, payload: list[dict[str, object]]) -> list[str]:
    if command == "scan":
        return [str(item["id"]) for item in payload]
    if command == "verify":
        return [str(item["patch"]["finding_id"]) for item in payload]  # type: ignore[index]
    return [str(item["finding_id"]) for item in payload]


@pytest.mark.parametrize("command", ["scan", "context", "patch", "verify"])
def test_cli_result_limit_warns_after_each_commands_filter(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = _mixed_limit_findings()
    scanner, client = _configure_limit_command(tmp_path, monkeypatch, findings)
    args = [
        command,
        "--repo",
        str(tmp_path),
        "--scanner",
        "fake-limit-scanner",
        "--json",
    ]
    if command == "scan":
        args.extend(("--min-severity", "medium"))
        expected_ids = ["high-b999", "critical-b608"]
        omitted = 2
    else:
        args.extend(("--rule", "B999"))
        expected_ids = ["high-b999", "medium-b999"]
        omitted = 1

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert _command_ids(command, payload) == expected_ids
    assert len(payload) <= 2
    _assert_omission_warning(result.stderr, omitted)
    assert "OMNIPATCH_MAX_FINDINGS" not in result.stdout
    assert scanner.calls == (3 if command == "verify" else 1)
    if command in {"patch", "verify"}:
        assert client.files == ["high.py", "matched.py"]
    else:
        assert client.files == []


@pytest.mark.parametrize("command", ["scan", "context", "patch", "verify"])
@pytest.mark.parametrize("matching_count", [0, 2])
def test_cli_result_limit_zero_and_exact_boundary_after_filter(
    command: str,
    matching_count: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if command == "scan":
        findings = (
            [
                _limit_finding("zero-low-b999", "B999", Severity.LOW, "zero.py"),
                _limit_finding("zero-low-b608", "B608", Severity.LOW, "foreign.py"),
            ]
            if matching_count == 0
            else [
                _limit_finding("boundary-high-b999", "B999", Severity.HIGH, "high.py"),
                _limit_finding(
                    "boundary-medium-b608", "B608", Severity.MEDIUM, "medium.py"
                ),
                _limit_finding("boundary-low-b999", "B999", Severity.LOW, "low.py"),
            ]
        )
        expected_ids = (
            []
            if matching_count == 0
            else ["boundary-high-b999", "boundary-medium-b608"]
        )
    elif matching_count == 0:
        findings = [
            _limit_finding("zero-b608", "B608", Severity.CRITICAL, "foreign.py"),
            _limit_finding("zero-b105", "B105", Severity.LOW, "credential.py"),
        ]
        expected_ids = []
    else:
        findings = [
            _limit_finding("boundary-high-b999", "B999", Severity.HIGH, "high.py"),
            _limit_finding(
                "boundary-critical-b608", "B608", Severity.CRITICAL, "foreign.py"
            ),
            _limit_finding(
                "boundary-medium-b999", "B999", Severity.MEDIUM, "medium.py"
            ),
        ]
        expected_ids = ["boundary-high-b999", "boundary-medium-b999"]

    _scanner, client = _configure_limit_command(tmp_path, monkeypatch, findings)
    args = [
        command,
        "--repo",
        str(tmp_path),
        "--scanner",
        "fake-limit-scanner",
        "--json",
    ]
    args.extend(
        ("--min-severity", "medium") if command == "scan" else ("--rule", "B999")
    )

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert _command_ids(command, payload) == expected_ids
    assert len(payload) <= 2
    _assert_omission_warning(result.stderr, 0)
    if command in {"patch", "verify"}:
        expected_files = [
            finding.file.as_posix()
            for finding in findings
            if finding.id in expected_ids
        ]
        assert client.files == expected_files
    else:
        assert client.files == []


def test_missing_selection_warning_is_detected_by_assertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A no-warning negative control trips the same assertion as the cap regressions."""
    findings = _mixed_limit_findings()
    _scanner, _client = _configure_limit_command(tmp_path, monkeypatch, findings)

    # Simulate a broken CLI path that truncates results but omits the required warning.
    monkeypatch.setattr(
        "omnipatch.cli._select_findings",
        lambda items, maximum: items[:maximum],
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--repo",
            str(tmp_path),
            "--scanner",
            "fake-limit-scanner",
            "--min-severity",
            "medium",
            "--json",
        ],
    )

    assert result.exit_code == 0
    assert _command_ids("scan", json.loads(result.stdout)) == [
        "high-b999",
        "critical-b608",
    ]
    with pytest.raises(AssertionError):
        _assert_omission_warning(result.stderr, 2)


@pytest.mark.integration
def test_scan_excludes_virtualenv_from_bandit_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The CLI passes virtualenv pruning to the real Bandit scan."""
    repo_root = tmp_path / "repo"
    virtualenv = repo_root / ".venv"
    virtualenv.mkdir(parents=True)
    (virtualenv / "probe.py").write_text("probe = True\n", encoding="utf-8")
    real_run = bandit_scanner.subprocess.run
    bandit_invocations: list[tuple[str, ...]] = []

    def capture_run(command: Sequence[str], *args: object, **kwargs: object) -> object:
        if "-x" in command:
            bandit_invocations.append(tuple(command))
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(bandit_scanner.subprocess, "run", capture_run)
    result = CliRunner().invoke(app, ["scan", "--repo", str(repo_root), "--json"])
    assert result.exit_code == 0
    assert ".venv" not in result.stderr
    assert "scan-exclude" not in result.stderr
    assert len(bandit_invocations) == 1
    exclusion_index = bandit_invocations[0].index("-x")
    patterns = bandit_invocations[0][exclusion_index + 1].split(",")
    assert "*/.venv/*" in patterns


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

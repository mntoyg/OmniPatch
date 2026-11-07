"""Offline tests for the complete run command's dry-run and verification gates."""

import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from omnipatch.cli import app
from omnipatch.models import Finding, PatchResult, Severity

SOURCE = "query = input()\n"
DIFF = (
    "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-query = input()\n+query = str(input())\n"
)


class RunScanner:
    """Return one target finding, then a configured verification result."""

    name = "fake"

    def __init__(self, after: list[Finding]) -> None:
        """Store the verification findings and initialize scan count."""
        self.after = after
        self.calls = 0

    def is_available(self) -> bool:
        """Report that the test scanner is available."""
        return True

    def scan(self, repo_root: Path) -> list[Finding]:
        """Return the baseline once and the configured post-patch findings."""
        self.calls += 1
        return [FINDING] if self.calls == 1 else self.after


FINDING = Finding(
    id="run-finding-1",
    rule_id="B999",
    title="SQL query construction",
    severity=Severity.HIGH,
    file=PurePosixPath("app.py"),
    line_start=1,
    line_end=1,
    message="SQL injection vector",
    source="test",
    cwe="CWE-89",
)


def configure_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after: list[Finding],
) -> bytes:
    """Prepare an offline model and scanner around an unchanged source file."""
    original = SOURCE.encode()
    (tmp_path / "app.py").write_bytes(original)
    monkeypatch.setenv("OMNIPATCH_LLM_API_KEY", "offline-llm-key")
    monkeypatch.setenv("OMNIPATCH_GITHUB_TOKEN", "")
    scanner = RunScanner(after)
    monkeypatch.setattr("omnipatch.cli.build_scanner", lambda *args, **kwargs: scanner)
    monkeypatch.setattr(
        "omnipatch.cli.build_llm_client",
        lambda settings: SimpleNamespace(model="fake", complete=lambda *_: DIFF),
    )
    return original


def test_run_dry_run_prints_plan_and_makes_zero_github_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verified dry run displays branch and diff without constructing a publisher."""
    original = configure_run(tmp_path, monkeypatch, [])
    monkeypatch.setenv("OMNIPATCH_DRY_RUN", "false")
    publisher_constructions: list[object] = []
    monkeypatch.setattr(
        "omnipatch.cli.GitHubPullRequestPublisher",
        lambda **kwargs: publisher_constructions.append(kwargs),
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--repo",
            str(tmp_path),
            "--rule",
            FINDING.rule_id,
            "--github-repo",
            "acme/app",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "branch: omnipatch/b999-run-finding-1" in result.output
    assert "+query = str(input())" in result.output
    assert publisher_constructions == []
    assert (tmp_path / "app.py").read_bytes() == original


def test_run_failing_verification_exits_one_and_does_not_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failed verification is visible and cannot reach the publisher."""
    original = configure_run(tmp_path, monkeypatch, [FINDING])
    monkeypatch.setenv("OMNIPATCH_GITHUB_TOKEN", "ghp_SENTINEL_DO_NOT_LOG")
    publish_calls: list[object] = []

    class FakePublisher:
        """Record any attempted publication from the CLI."""

        def __init__(self, **kwargs: object) -> None:
            """Accept the configured publisher constructor options."""

        def publish(self, *args: object) -> str:
            """Record a forbidden publication attempt."""
            publish_calls.append(args)
            return "https://example.invalid/pull/1"

    monkeypatch.setattr("omnipatch.cli.GitHubPullRequestPublisher", FakePublisher)
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--repo",
            str(tmp_path),
            "--rule",
            FINDING.rule_id,
            "--github-repo",
            "acme/app",
            "--apply",
            "--json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload[0]["verified"] is False
    assert payload[0]["pull_request_url"] is None
    assert publish_calls == []
    assert (tmp_path / "app.py").read_bytes() == original


def test_run_passes_mapped_b105_environment_name_to_publisher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLI carries the required variable name into the draft PR renderer."""
    source = 'PASSWORD = "SELF-LABELLED-PASSWORD"\n'
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    original_bytes = (tmp_path / "app.py").read_bytes()
    finding = Finding(
        id="run-b105-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=1,
        line_end=1,
        message="Hardcoded password",
        source="test",
    )

    class Scanner:
        name = "fake"

        def __init__(self) -> None:
            self.calls = 0

        def is_available(self) -> bool:
            return True

        def scan(self, repo_root: Path) -> list[Finding]:
            self.calls += 1
            return [finding] if self.calls == 1 else []

    class CompletionClient:
        model = "fake-model"

        def complete(self, system: str, user: str) -> str:
            return 'import os\nPASSWORD = os.environ["APP_PASSWORD"]'

    published_environment: list[tuple[str, ...]] = []
    published_verified: list[bool] = []

    class FakePublisher:
        def __init__(self, **kwargs: object) -> None:
            pass

        def publish(
            self,
            result: PatchResult,
            target_finding: Finding,
            patched_source: str,
            *,
            required_environment: tuple[str, ...] = (),
            sql_paramstyle: str | None = None,
        ) -> str:
            published_environment.append(required_environment)
            published_verified.append(result.verified)
            return "https://example.invalid/pull/1"

    scanner = Scanner()
    monkeypatch.setenv("OMNIPATCH_GITHUB_TOKEN", "fake-token")
    monkeypatch.setenv(
        "OMNIPATCH_SECRET_ENVIRONMENT", '{"app.py::<module>":"APP_PASSWORD"}'
    )
    monkeypatch.setenv("OMNIPATCH_LLM_OUTPUT", "function")
    monkeypatch.setattr("omnipatch.cli.build_scanner", lambda *a, **k: scanner)
    monkeypatch.setattr(
        "omnipatch.cli.build_llm_client", lambda settings: CompletionClient()
    )
    monkeypatch.setattr("omnipatch.cli.GitHubPullRequestPublisher", FakePublisher)

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--repo",
            str(tmp_path),
            "--rule",
            "B105",
            "--github-repo",
            "acme/app",
            "--apply",
        ],
    )

    assert result.exit_code == 0, result.output
    assert published_environment == [("APP_PASSWORD",)]
    assert published_verified == [True]
    assert (tmp_path / "app.py").read_bytes() == original_bytes


def test_run_missing_apply_token_fails_before_scan_or_publisher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing apply credentials are reported before scanning or API setup."""
    configure_run(tmp_path, monkeypatch, [])
    scanner_calls: list[object] = []
    publisher_constructions: list[object] = []
    monkeypatch.setattr(
        "omnipatch.cli.build_scanner",
        lambda *args, **kwargs: scanner_calls.append(args),
    )
    monkeypatch.setattr(
        "omnipatch.cli.GitHubPullRequestPublisher",
        lambda **kwargs: publisher_constructions.append(kwargs),
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--repo",
            str(tmp_path),
            "--rule",
            FINDING.rule_id,
            "--github-repo",
            "acme/app",
            "--apply",
        ],
    )

    assert result.exit_code == 1
    assert "OMNIPATCH_GITHUB_TOKEN is required" in result.output
    assert "Traceback" not in result.output
    assert scanner_calls == []
    assert publisher_constructions == []


def test_run_missing_explicit_repository_fails_before_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dry run still requires an explicit owner/name repository."""
    configure_run(tmp_path, monkeypatch, [])
    monkeypatch.setenv("OMNIPATCH_GITHUB_REPO", "")
    scanner_calls: list[object] = []
    monkeypatch.setattr(
        "omnipatch.cli.build_scanner",
        lambda *args, **kwargs: scanner_calls.append(args),
    )

    result = CliRunner().invoke(
        app,
        ["run", "--repo", str(tmp_path), "--rule", FINDING.rule_id],
    )

    assert result.exit_code == 1
    assert "OMNIPATCH_GITHUB_REPO or --github-repo is required" in result.output
    assert "Traceback" not in result.output
    assert scanner_calls == []

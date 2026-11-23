"""Offline tests for the complete run command's dry-run and verification gates."""

import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import omnipatch.cli as cli_module
import omnipatch.codebase.snapshot as snapshot_module
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


def test_run_publishes_only_after_snapshot_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verified payloads are sent to the publisher only after cleanup succeeds."""
    configure_run(tmp_path, monkeypatch, [])
    monkeypatch.setenv("OMNIPATCH_GITHUB_TOKEN", "offline-fake-token")
    real_factory = cli_module._repository_snapshot
    state = {"cleaned": False}

    class TrackingSnapshot:
        def __init__(self, repo_root: Path, settings: object) -> None:
            self.snapshot = real_factory(repo_root, settings)

        def __enter__(self) -> snapshot_module.RepositorySnapshot:
            return self.snapshot.__enter__()

        def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
            result = self.snapshot.__exit__(exc_type, exc, tb)
            state["cleaned"] = True
            return result

    monkeypatch.setattr(
        cli_module,
        "_repository_snapshot",
        lambda repo_root, settings: TrackingSnapshot(repo_root, settings),
    )

    class FakePublisher:
        def __init__(self, **kwargs: object) -> None:
            pass

        def publish(self, *args: object, **kwargs: object) -> str:
            assert state["cleaned"]
            return "https://example.invalid/draft/1"

    monkeypatch.setattr(cli_module, "GitHubPullRequestPublisher", FakePublisher)
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

    assert result.exit_code == 0, result.output
    assert state["cleaned"]
    assert "draft PR: https://example.invalid/draft/1" in result.output


def test_run_cleanup_failure_prevents_all_publisher_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cleanup failure aborts run before any queued publication is sent."""
    configure_run(tmp_path, monkeypatch, [])
    monkeypatch.setenv("OMNIPATCH_GITHUB_TOKEN", "offline-fake-token")
    created_roots: list[Path] = []
    publish_calls: list[object] = []
    remove_tree = snapshot_module._remove_tree_no_follow

    def fail_cleanup(path: Path) -> None:
        created_roots.append(path)
        raise OSError("synthetic cleanup failure")

    class FakePublisher:
        def __init__(self, **kwargs: object) -> None:
            pass

        def publish(self, *args: object, **kwargs: object) -> str:
            publish_calls.append(args)
            return "https://example.invalid/draft/1"

    monkeypatch.setattr(snapshot_module, "_remove_tree_no_follow", fail_cleanup)
    monkeypatch.setattr(cli_module, "GitHubPullRequestPublisher", FakePublisher)
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
    assert "clean up repository snapshot" in result.output
    assert publish_calls == []
    assert len(created_roots) == 1
    monkeypatch.setattr(snapshot_module, "_remove_tree_no_follow", remove_tree)
    remove_tree(created_roots[0])


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


def _bounded_run_finding(
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
        message="Synthetic result-limit test finding",
        source="test",
    )


class BoundedRunScanner:
    name = "fake-run-limit-scanner"

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        self.calls = 0

    def is_available(self) -> bool:
        return True

    def scan(self, repo_root: Path) -> list[Finding]:
        self.calls += 1
        return self.findings if self.calls == 1 else []


class BoundedRunClient:
    model = "fake-run-limit-model"

    def __init__(self) -> None:
        self.files: list[str] = []

    def complete(self, system: str, user: str) -> str:
        filename = str(json.loads(user)["file"])
        self.files.append(filename)
        return (
            f"--- a/{filename}\n+++ b/{filename}\n@@ -1 +1 @@\n"
            "-value = input()\n+value = str(input())\n"
        )


def _configure_bounded_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    findings: list[Finding],
) -> tuple[BoundedRunScanner, BoundedRunClient, list[str]]:
    for finding in findings:
        path = tmp_path.joinpath(*finding.file.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = input()\n", encoding="utf-8")

    scanner = BoundedRunScanner(findings)
    client = BoundedRunClient()
    publisher_calls: list[str] = []

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
            assert result.verified
            publisher_calls.append(target_finding.id)
            return "https://example.invalid/draft/1"

    monkeypatch.setenv("OMNIPATCH_MAX_FINDINGS", "2")
    monkeypatch.setenv("OMNIPATCH_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OMNIPATCH_LLM_OUTPUT", "diff")
    monkeypatch.setenv("OMNIPATCH_LLM_API_KEY", "offline-fake-key")
    monkeypatch.setenv("OMNIPATCH_GITHUB_TOKEN", "offline-fake-token")
    monkeypatch.setattr("omnipatch.cli.build_scanner", lambda *a, **k: scanner)
    monkeypatch.setattr("omnipatch.cli.build_llm_client", lambda settings: client)
    monkeypatch.setattr("omnipatch.cli.GitHubPullRequestPublisher", FakePublisher)
    return scanner, client, publisher_calls


def _assert_run_omission_warning(stderr: str, omitted: int) -> None:
    if omitted == 0:
        assert "matching finding(s) omitted from this command" not in stderr
        assert "OMNIPATCH_MAX_FINDINGS" not in stderr
        return
    assert f"{omitted} matching finding(s) omitted from this command" in stderr
    assert "OMNIPATCH_MAX_FINDINGS" in stderr


def _run_limit_findings(matching_count: int = 3) -> list[Finding]:
    findings = [
        _bounded_run_finding("run-high-b999", "B999", Severity.HIGH, "run_high.py"),
        _bounded_run_finding(
            "run-critical-b608", "B608", Severity.CRITICAL, "run_foreign.py"
        ),
        _bounded_run_finding(
            "run-medium-b999", "B999", Severity.MEDIUM, "run_medium.py"
        ),
    ]
    if matching_count == 3:
        findings.append(
            _bounded_run_finding("run-low-b999", "B999", Severity.LOW, "run_low.py")
        )
        findings.append(
            _bounded_run_finding(
                "run-low-b105", "B105", Severity.LOW, "run_credential.py"
            )
        )
    elif matching_count == 0:
        findings = [
            _bounded_run_finding(
                "run-zero-b608", "B608", Severity.CRITICAL, "run_foreign.py"
            ),
            _bounded_run_finding(
                "run-zero-b105", "B105", Severity.LOW, "run_credential.py"
            ),
        ]
    return findings


def _invoke_bounded_run(tmp_path: Path) -> object:
    return CliRunner().invoke(
        app,
        [
            "run",
            "--repo",
            str(tmp_path),
            "--scanner",
            "fake-run-limit-scanner",
            "--rule",
            "B999",
            "--github-repo",
            "acme/offline-test",
            "--apply",
            "--json",
        ],
    )


def test_run_reports_omitted_findings_after_rule_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = _run_limit_findings()
    scanner, client, publisher_calls = _configure_bounded_run(
        tmp_path, monkeypatch, findings
    )

    result = _invoke_bounded_run(tmp_path)

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    selected_ids = [outcome["finding_id"] for outcome in payload]
    assert selected_ids == ["run-high-b999", "run-medium-b999"]
    assert len(payload) <= 2
    _assert_run_omission_warning(result.stderr, 1)
    assert "OMNIPATCH_MAX_FINDINGS" not in result.stdout
    assert client.files == ["run_high.py", "run_medium.py"]
    assert publisher_calls == selected_ids
    assert scanner.calls == 3


@pytest.mark.parametrize("matching_count", [0, 2])
def test_run_zero_and_exact_limit_are_computed_after_rule_filter(
    matching_count: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings = _run_limit_findings(matching_count)
    _scanner, client, publisher_calls = _configure_bounded_run(
        tmp_path, monkeypatch, findings
    )

    result = _invoke_bounded_run(tmp_path)

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    expected_ids = [] if matching_count == 0 else ["run-high-b999", "run-medium-b999"]
    assert [outcome["finding_id"] for outcome in payload] == expected_ids
    assert len(payload) <= 2
    _assert_run_omission_warning(result.stderr, 0)
    expected_files = [] if matching_count == 0 else ["run_high.py", "run_medium.py"]
    assert client.files == expected_files
    assert publisher_calls == expected_ids

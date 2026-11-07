"""Offline tests for the development-only benchmark runner."""

import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import benchmarks.v1.evaluate as evaluate_module
import omnipatch.cli as omnipatch_cli
from benchmarks.v1.evaluate import (
    DEVELOPMENT_CASE_IDS,
    DEVELOPMENT_ROOT,
    VerifyExecution,
    _aggregate_report,
    _case_configuration,
    _case_metadata,
    _external_output_directory,
    _git_provenance,
    _parser,
    evaluate_development,
    main,
    parse_verify_output,
)
from benchmarks.v1.oracles import candidate_matches_approved_reference
from omnipatch.errors import PatchGenerationError

STATIC_SQL_PATCH = """--- a/app.py
+++ b/app.py
@@ -3,4 +3,4 @@
     cursor = connection.cursor()
-    query = f"SELECT username FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT username FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchall()
"""


class FakeProvider:
    """A network-free injected completion provider for CLI tests."""

    model = "fake-offline-provider"

    def __init__(self, response: str | Exception) -> None:
        self.response = response
        self.requests: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.requests.append(user)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _invoke_verify_with_fake(
    fake: FakeProvider,
    monkeypatch: pytest.MonkeyPatch,
    expected_target: Path,
) -> tuple[VerifyExecution, list[str]]:
    """Run the real verify CLI in-process with a fake completion transport."""
    monkeypatch.setenv("OMNIPATCH_LLM_OUTPUT", "diff")
    monkeypatch.setattr(omnipatch_cli, "build_llm_client", lambda settings: fake)
    target_contents: list[str] = []

    def record_target(settings: object, user: str) -> str:
        target_contents.extend(sorted(path.name for path in expected_target.iterdir()))
        fake.requests.append(user)
        if isinstance(fake.response, Exception):
            raise fake.response
        return fake.response

    class RecordingProvider:
        model = fake.model

        def complete(self, system: str, user: str) -> str:
            return record_target(system, user)

    monkeypatch.setattr(
        omnipatch_cli, "build_llm_client", lambda settings: RecordingProvider()
    )
    result = CliRunner().invoke(
        omnipatch_cli.app,
        ["verify", "--repo", str(expected_target), "--rule", "B608", "--json"],
    )
    command = (
        sys.executable,
        "-m",
        "omnipatch",
        "verify",
        "--repo",
        str(expected_target),
        "--rule",
        "B608",
        "--json",
    )
    return VerifyExecution(
        command, result.output, result.exit_code, 0.001
    ), target_contents


def test_case_selection_is_explicit_and_approval_metadata_is_current() -> None:
    assert DEVELOPMENT_CASE_IDS == (
        "dev-b608-static-query",
        "dev-b608-concatenated-query",
        "dev-b105-module-constant",
        "dev-b105-function-local",
        "dev-b602-direct-call",
        "dev-b602-wrapper-call",
    )
    with pytest.raises(ValueError, match="Unsupported development case"):
        _case_metadata("unknown-development-case")
    for case_id in DEVELOPMENT_CASE_IDS:
        metadata = _case_metadata(case_id)
        assert metadata["reference_fix_status"] == "approved_by_owner"
        assert metadata["reference_fix_approved_on"] == "2026-10-27"
        if metadata["rule_id"] == "B608":
            assert metadata["sql_paramstyle"]
        if metadata["rule_id"] == "B105":
            assert metadata["secret_environment"]


def test_case_without_required_rule_mapping_fails_before_verify_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_id = "dev-b608-static-query"
    metadata = _case_metadata(case_id)
    metadata.pop("sql_paramstyle")
    monkeypatch.setattr(
        "benchmarks.v1.evaluate._case_metadata", lambda selected: metadata
    )
    calls: list[str] = []
    report = evaluate_development(
        tmp_path / "missing-map",
        case_ids=(case_id,),
        verify_runner=lambda target, rule: calls.append(rule),
    )
    case = cast(dict[str, object], report["cases"][0])
    assert calls == []
    assert "B608 case metadata requires sql_paramstyle mapping" in str(
        case["invalid_run"]
    )


def test_metadata_mapping_helper_rejects_empty_required_mapping() -> None:
    with (
        pytest.raises(
            ValueError, match="B105 case metadata requires secret_environment"
        ),
        _case_configuration({"rule_id": "B105"}),
    ):
        pytest.fail("missing mapping must stop before runner")


def test_output_directory_must_be_new_and_outside_repository(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        _external_output_directory(existing)
    with pytest.raises(ValueError, match="outside every Git repository"):
        _external_output_directory(DEVELOPMENT_ROOT / "runner-output")


def test_output_directory_refuses_every_git_repository_and_accepts_external(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "external-output"
    assert _external_output_directory(outside) == outside.resolve()

    repository = tmp_path / "nested-project"
    (repository / ".git").mkdir(parents=True)
    with pytest.raises(ValueError, match="outside every Git repository"):
        _external_output_directory(repository / "artifacts" / "run")

    sibling_project = tmp_path / "OmniAgent"
    sibling_project.mkdir()
    (sibling_project / ".git").write_text(
        "gitdir: .git/worktrees/example", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="outside every Git repository"):
        _external_output_directory(sibling_project / "op13-artifacts" / "run")


def _fake_git_runner(
    status: bytes, diff: bytes = b""
) -> tuple[Callable[[list[str]], subprocess.CompletedProcess[bytes]], list[list[str]]]:
    calls: list[list[str]] = []

    def run(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        calls.append(arguments)
        stdout = {
            ("rev-parse", "HEAD"): b"0123456789abcdef0123456789abcdef01234567\n",
            ("status", "--porcelain"): status,
            ("diff", "HEAD"): diff,
        }.get(tuple(arguments), b"")
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    return run, calls


@pytest.mark.parametrize(
    ("status", "diff", "expected_dirty"),
    [(b"", b"", False), (b" M app.py\n", b"diff body sentinel\r\n", True)],
)
def test_run_json_records_git_head_dirty_state_and_only_diff_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: bytes,
    diff: bytes,
    expected_dirty: bool,
) -> None:
    case_id = "dev-b608-static-query"
    git_runner, calls = _fake_git_runner(status, diff)
    output_dir = tmp_path / f"provenance-{expected_dirty}"
    refusal = VerifyExecution(
        (sys.executable, "-m", "omnipatch", "verify"),
        "Model did not produce a valid patch: fake refusal",
        1,
        0.01,
    )

    evaluate_development(
        output_dir,
        case_ids=(case_id,),
        verify_runner=lambda target, rule: refusal,
        git_runner=git_runner,
    )

    run = json.loads((output_dir / "run.json").read_text(encoding="utf-8"))
    provenance = run["source_revision"]
    assert provenance["head"] == "0123456789abcdef0123456789abcdef01234567"
    assert provenance["dirty"] is expected_dirty
    if expected_dirty:
        normalized_diff = diff.replace(b"\r\n", b"\n")
        assert provenance["diff_sha256"] == hashlib.sha256(normalized_diff).hexdigest()
    else:
        assert "diff_sha256" not in provenance
    assert b"diff body sentinel" not in (output_dir / "run.json").read_bytes()
    assert calls[:2] == [["rev-parse", "HEAD"], ["status", "--porcelain"]]
    assert calls[-1] == (
        ["diff", "HEAD"] if expected_dirty else ["status", "--porcelain"]
    )


@pytest.mark.parametrize(
    "failure",
    ["missing", "nonzero"],
)
def test_missing_or_failing_git_is_unknown_and_dirty(failure: str) -> None:
    def run(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
        if failure == "missing":
            raise FileNotFoundError("git")
        return subprocess.CompletedProcess(arguments, 127, b"", b"git unavailable")

    assert _git_provenance(run) == {"head": "unknown", "dirty": True}


def test_dirty_live_run_requires_acknowledgement_and_offline_run_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_runner, _ = _fake_git_runner(b" M app.py\n", b"diff --git app.py\n")
    calls: list[str] = []

    def offline_live_stub(target: Path, rule_id: str) -> VerifyExecution:
        calls.append(rule_id)
        return VerifyExecution(("fake-verify",), "Provider refusal: offline", 1, 0.01)

    monkeypatch.setattr(evaluate_module, "_live_verify", offline_live_stub)
    output = tmp_path / "dirty-live-refused"
    with pytest.raises(ValueError, match="--allow-dirty"):
        evaluate_development(
            output,
            case_ids=("dev-b608-static-query",),
            verify_runner=offline_live_stub,
            git_runner=git_runner,
        )
    assert calls == []
    assert not output.exists()

    allowed_git, _ = _fake_git_runner(b" M app.py\n", b"diff --git app.py\n")
    allowed = tmp_path / "dirty-live-allowed"
    evaluate_development(
        allowed,
        case_ids=("dev-b608-static-query",),
        verify_runner=offline_live_stub,
        allow_dirty=True,
        git_runner=allowed_git,
    )
    run = json.loads((allowed / "run.json").read_text(encoding="utf-8"))
    assert run["source_revision"]["dirty"] is True
    assert run["source_revision"]["diff_sha256"]
    assert calls == ["B608"]

    offline_git, _ = _fake_git_runner(b" M app.py\n", b"offline diff\n")
    offline_output = tmp_path / "dirty-offline"
    evaluate_development(
        offline_output,
        case_ids=("dev-b608-static-query",),
        verify_runner=lambda target, rule: VerifyExecution(
            ("fake-verify",), "Provider refusal: offline", 1, 0.01
        ),
        git_runner=offline_git,
    )
    assert (
        json.loads((offline_output / "run.json").read_text(encoding="utf-8"))[
            "source_revision"
        ]["dirty"]
        is True
    )


def test_cli_live_dirty_flag_refuses_then_proceeds_when_acknowledged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    def fake_git_provenance(
        git_runner: Callable[[list[str]], subprocess.CompletedProcess[bytes]]
        | None = None,
    ) -> dict[str, object]:
        return {
            "head": "0123456789abcdef0123456789abcdef01234567",
            "dirty": True,
            "diff_sha256": "a" * 64,
        }

    def fake_live_verify(target: Path, rule_id: str) -> VerifyExecution:
        calls.append(rule_id)
        return VerifyExecution(("fake-verify",), "Provider refusal: offline", 1, 0.01)

    monkeypatch.setattr(evaluate_module, "_git_provenance", fake_git_provenance)
    monkeypatch.setattr(evaluate_module, "_live_verify", fake_live_verify)
    refused_output = tmp_path / "cli-live-refused"
    assert (
        main(
            [
                "--live",
                "--output-dir",
                str(refused_output),
                "--case",
                "dev-b608-static-query",
            ]
        )
        == 2
    )
    assert "--allow-dirty" in capsys.readouterr().err
    assert calls == []
    assert not refused_output.exists()

    allowed_output = tmp_path / "cli-live-allowed"
    assert (
        main(
            [
                "--live",
                "--allow-dirty",
                "--output-dir",
                str(allowed_output),
                "--case",
                "dev-b608-static-query",
            ]
        )
        == 0
    )
    assert calls == ["B608"]
    run = json.loads((allowed_output / "run.json").read_text(encoding="utf-8"))
    assert run["live_model_requested"] is True
    assert run["source_revision"]["dirty"] is True
    assert (
        _parser()
        .parse_args(
            ["--live", "--allow-dirty", "--output-dir", str(tmp_path / "parser")]
        )
        .allow_dirty
        is True
    )


def test_live_verify_runs_from_isolated_target_without_project_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(command, 0, "[]", "")

    monkeypatch.setattr(evaluate_module.subprocess, "run", fake_run)
    execution = evaluate_module._live_verify(target, "B608")
    assert execution.exit_code == 0
    assert observed["cwd"] == target
    assert observed["command"] == [
        sys.executable,
        "-m",
        "omnipatch",
        "verify",
        "--repo",
        str(target),
        "--rule",
        "B608",
        "--json",
    ]


def test_live_provider_is_opt_in(tmp_path: Path) -> None:
    output = tmp_path / "must-not-be-created"
    with pytest.raises(SystemExit) as error:
        main(["--output-dir", str(output)])
    assert error.value.code == 2
    assert not output.exists()


@pytest.mark.parametrize(
    ("output", "classification"),
    [
        ('[{"patch": {"unified_diff": "diff"}}]', None),
        ("Provider refusal: policy declined", "refusal"),
        ("Model did not produce a valid patch: bad hunk", "invalid_patch"),
        ("not-json", "invalid_run"),
    ],
)
def test_verify_output_parser_classifies_results(
    output: str, classification: str | None
) -> None:
    result, actual_classification = parse_verify_output(output)
    assert actual_classification == classification
    if classification is None:
        assert result is not None and result["patch"] == {"unified_diff": "diff"}
    else:
        assert result is None


def test_verify_output_traceback_is_invalid_run_even_if_frame_names_patch_error() -> (
    None
):
    output = (
        "Traceback (most recent call last):\n"
        '  File "synthetic/llm_agent.py", line 12, in propose\n'
        "    except PatchGenerationError as exc:\n"
        "ValueError: synthetic invalid endpoint\n"
    )

    result, classification = parse_verify_output(output)

    assert result is None
    assert classification == "invalid_run"


def test_verify_output_patch_generation_rejection_remains_invalid_patch() -> None:
    result, classification = parse_verify_output(
        "Model did not produce a valid patch: synthetic rejected patch"
    )

    assert result is None
    assert classification == "invalid_patch"


def test_verify_output_valid_json_still_parses() -> None:
    result, classification = parse_verify_output(
        '[{"patch": {"unified_diff": "synthetic diff"}}]'
    )

    assert classification is None
    assert result is not None
    assert result["patch"] == {"unified_diff": "synthetic diff"}


def test_aggregate_metrics_keep_refusals_invalids_and_introductions_separate() -> None:
    cases: list[dict[str, object]] = [
        {
            "verified_secure_repairs": 1,
            "candidate_materialized": True,
            "verification_passed": True,
            "matches_reference": True,
            "blocking_introduced_findings": False,
            "post_scan_errors": [],
            "refusals": 0,
            "invalid_patches": 0,
            "surviving_target_findings": [],
            "invalid_run": None,
            "regression_test": {"status": "passed"},
            "latency_seconds": 2.0,
            "introduced_findings_by_severity": {
                "LOW": [{"rule_id": "B603", "file": "app.py"}],
                "MEDIUM": [],
                "HIGH": [],
                "CRITICAL": [],
            },
        },
        {
            "verified_secure_repairs": 0,
            "candidate_materialized": False,
            "refusals": 1,
            "invalid_patches": 0,
            "surviving_target_findings": None,
            "invalid_run": None,
            "regression_test": {"status": "not_run"},
            "latency_seconds": 1.0,
            "introduced_findings_by_severity": None,
        },
    ]
    report = _aggregate_report({"provider_settings": {"provider": "fake"}}, cases)
    aggregate = cast(dict[str, object], report["aggregate"])
    assert aggregate["verified_secure_repairs"] == 1
    assert aggregate["refusals"] == 1
    assert aggregate["invalid_patches"] == 0
    grouped = cast(
        dict[str, list[dict[str, str]]], report["introduced_findings_by_severity"]
    )
    assert grouped["LOW"] == [{"rule_id": "B603", "file": "app.py"}]
    assert grouped["HIGH"] == []


def test_runner_uses_only_vulnerable_source_and_real_verify_without_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_id = "dev-b608-static-query"
    case_root = DEVELOPMENT_ROOT / case_id
    source_path = case_root / "vulnerable.py"
    reference_path = case_root / "reference_fix.py"
    source_before = source_path.read_bytes()
    reference_before = reference_path.read_bytes()
    reference_text = reference_path.read_text(encoding="utf-8")
    fake = FakeProvider(STATIC_SQL_PATCH)
    output_dir = tmp_path / "successful-run"
    target_path = output_dir / "cases" / case_id / "target"
    execution_holder: list[VerifyExecution] = []
    contents_seen: list[str] = []

    def verify_runner(target: Path, rule_id: str) -> VerifyExecution:
        assert rule_id == "B608"
        assert json.loads(os.environ["OMNIPATCH_SQL_PARAMSTYLE"]) == {
            "app.py::lookup_username": "qmark"
        }
        assert json.loads(os.environ["OMNIPATCH_SECRET_ENVIRONMENT"]) == {}
        execution, contents = _invoke_verify_with_fake(fake, monkeypatch, target)
        execution_holder.append(execution)
        contents_seen.extend(contents)
        return execution

    def forbidden_publisher(*args: object, **kwargs: object) -> None:
        raise AssertionError("Benchmark runner must not create a GitHub publisher")

    monkeypatch.setattr(
        omnipatch_cli, "GitHubPullRequestPublisher", forbidden_publisher
    )
    monkeypatch.setenv("OMNIPATCH_LLM_API_KEY", "TEST_SECRET_DO_NOT_RECORD")
    report = evaluate_development(
        output_dir, case_ids=(case_id,), verify_runner=verify_runner
    )

    case_report = cast(dict[str, object], report["cases"][0])
    assert case_report["verified_secure_repairs"] == 1
    assert case_report["regression_test"] == {"status": "passed", "reason": None}
    assert case_report["surviving_target_findings"] == []
    assert contents_seen == ["app.py"]
    assert sorted(path.name for path in target_path.iterdir()) == ["app.py"]
    assert reference_text not in "\n".join(fake.requests)
    assert "--apply" not in execution_holder[0].command
    assert "verify" in execution_holder[0].command
    assert source_path.read_bytes() == source_before
    assert reference_path.read_bytes() == reference_before
    output_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in output_dir.rglob("*")
        if path.is_file()
    )
    assert "TEST_SECRET_DO_NOT_RECORD" not in output_text


def test_runner_records_fake_provider_refusal_without_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case_id = "dev-b608-static-query"
    fake = FakeProvider(PatchGenerationError("Provider refusal: fake offline refusal"))

    def verify_runner(target: Path, rule_id: str) -> VerifyExecution:
        execution, _ = _invoke_verify_with_fake(fake, monkeypatch, target)
        return execution

    report = evaluate_development(
        tmp_path / "refusal-run",
        case_ids=(case_id,),
        verify_runner=verify_runner,
    )
    result = cast(dict[str, object], report["cases"][0])
    assert result["refusals"] == 1
    assert result["verified_secure_repairs"] == 0
    assert result["outcome"] == "refused"
    assert result["skipped"] == "refused"
    assert result["surviving_target_findings"] is None


def test_runner_classifies_unmaterializable_candidate_as_invalid_patch(
    tmp_path: Path,
) -> None:
    case_id = "dev-b608-static-query"
    execution = VerifyExecution(
        (sys.executable, "-m", "omnipatch", "verify"),
        '[{"applied": true, "patch": '
        '{"touched_files": ["app.py"], "unified_diff": "not a diff"}}]',
        1,
        0.25,
    )
    report = evaluate_development(
        tmp_path / "invalid-patch-run",
        case_ids=(case_id,),
        verify_runner=lambda target, rule: execution,
    )
    result = cast(dict[str, object], report["cases"][0])
    assert result["invalid_patches"] == 1
    assert result["verified_secure_repairs"] == 0
    assert result["outcome"] == "not_measured"
    assert result["skipped"] == "not_measured"
    assert "PatchGenerationError" in str(result["invalid_run"])


def test_approved_oracles_run_for_all_six_reference_fixes(tmp_path: Path) -> None:
    from benchmarks.v1.oracles import run_behavioral_oracle

    for case_id in DEVELOPMENT_CASE_IDS:
        case_root = DEVELOPMENT_ROOT / case_id
        reference = case_root / "reference_fix.py"
        candidate_dir = tmp_path / case_id
        candidate_dir.mkdir()
        candidate = candidate_dir / "app.py"
        candidate.write_text(reference.read_text(encoding="utf-8"), encoding="utf-8")
        run_behavioral_oracle(case_id, candidate, reference)


def test_changed_candidate_is_not_executed(tmp_path: Path) -> None:
    from benchmarks.v1.oracles import run_behavioral_oracle

    reference = DEVELOPMENT_ROOT / "dev-b608-static-query" / "reference_fix.py"
    marker = tmp_path / "should-not-exist"
    candidate = tmp_path / "app.py"
    candidate.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="differs from its owner-approved"):
        run_behavioral_oracle("dev-b608-static-query", candidate, reference)
    assert not marker.exists()


def _outcome_case(**overrides: object) -> dict[str, object]:
    """Create a minimal verification record for summary outcome tests."""
    record: dict[str, object] = {
        "case_id": "dev-b608-static-query",
        "verified_secure_repairs": 1,
        "refusals": 0,
        "invalid_patches": 0,
        "invalid_run": None,
        "candidate_materialized": True,
        "verification_passed": True,
        "matches_reference": True,
        "surviving_target_findings": [],
        "introduced_findings_by_severity": {
            "LOW": [],
            "MEDIUM": [],
            "HIGH": [],
            "CRITICAL": [],
        },
        "blocking_introduced_findings": False,
        "post_scan_errors": [],
        "regression_test": {"status": "passed", "reason": None},
        "candidate_path": "cases/dev-b608-static-query/candidate/app.py",
        "latency_seconds": 1.0,
    }
    record.update(overrides)
    return record


def _summary_outcomes(cases: list[dict[str, object]]) -> dict[str, object]:
    return _aggregate_report({"provider_settings": {"provider": "fake"}}, cases)


def test_measured_gemma_candidate_is_reported_unscored() -> None:
    """The verified B602 candidate with only tolerated B603 is not scored zero."""
    measured_case = _outcome_case(
        case_id="dev-b602-direct-call",
        verified_secure_repairs=0,
        matches_reference=False,
        regression_test={
            "status": "not_run",
            "reason": "candidate executable AST differs from the owner-approved reference fix",
        },
        introduced_findings_by_severity={
            "LOW": [{"file": "app.py", "rule_id": "B603"}],
            "MEDIUM": [],
            "HIGH": [],
            "CRITICAL": [],
        },
        candidate_path="cases/dev-b602-direct-call/candidate/app.py",
    )

    report = _summary_outcomes([measured_case])

    result = cast(list[dict[str, object]], report["cases"])[0]
    assert result["outcome"] == "verified_unscored"
    assert result["verified_secure_repairs"] == 0
    assert result["matches_reference"] is False


@pytest.mark.parametrize(
    ("expected", "overrides"),
    [
        ("not_measured", {"invalid_run": "verify timed out"}),
        (
            "invalid_patch",
            {"invalid_patches": 1, "candidate_materialized": False},
        ),
        ("refused", {"refusals": 1, "candidate_materialized": False}),
        (
            "verified_failed",
            {
                "verification_passed": False,
                "surviving_target_findings": [
                    {"rule_id": "B608", "file": "app.py", "severity": "HIGH"}
                ],
                "verified_secure_repairs": 0,
            },
        ),
        (
            "verified_unscored",
            {
                "matches_reference": False,
                "regression_test": {"status": "not_run", "reason": "AST differs"},
                "verified_secure_repairs": 0,
            },
        ),
        ("verified_secure_repair", {}),
    ],
)
def test_each_case_outcome_is_reachable_and_exclusive(
    expected: str, overrides: dict[str, object]
) -> None:
    case = _outcome_case(**overrides)

    report = _summary_outcomes([case])

    result = cast(list[dict[str, object]], report["cases"])[0]
    assert result["outcome"] == expected
    counts = cast(dict[str, int], report["aggregate"]["outcome_counts"])
    assert counts[expected] == 1
    assert sum(counts.values()) == 1


def test_timeout_is_not_measured_and_excluded_from_scored_denominator() -> None:
    cases = [
        _outcome_case(),
        _outcome_case(
            case_id="dev-b105-module-constant",
            invalid_run="verify timed out",
            verification_passed=False,
            candidate_materialized=False,
            verified_secure_repairs=0,
            regression_test={"status": "not_run", "reason": "not_started"},
        ),
    ]

    report = _summary_outcomes(cases)

    aggregate = cast(dict[str, object], report["aggregate"])
    score = cast(dict[str, object], aggregate["scored_repair_rate"])
    assert cast(dict[str, int], aggregate["outcome_counts"])["not_measured"] == 1
    assert score["scored_cases"] == 1
    assert score["verified_secure_repairs"] == 1
    assert cast(dict[str, int], score["excluded"])["not_measured"] == 1


def test_scored_rate_reports_denominator_and_unscored_counts() -> None:
    cases = [
        _outcome_case(),
        _outcome_case(
            case_id="dev-b608-concatenated-query",
            verification_passed=False,
            surviving_target_findings=[
                {"rule_id": "B608", "file": "app.py", "severity": "HIGH"}
            ],
            verified_secure_repairs=0,
        ),
        _outcome_case(
            case_id="dev-b602-direct-call",
            matches_reference=False,
            regression_test={"status": "not_run", "reason": "AST differs"},
            verified_secure_repairs=0,
        ),
        _outcome_case(
            case_id="dev-b602-wrapper-call",
            matches_reference=False,
            regression_test={"status": "not_run", "reason": "AST differs"},
            verified_secure_repairs=0,
        ),
        _outcome_case(
            case_id="dev-b105-module-constant",
            invalid_run="verify timed out",
            verification_passed=False,
            candidate_materialized=False,
            verified_secure_repairs=0,
        ),
        _outcome_case(
            case_id="dev-b105-function-local",
            invalid_run="verify output was not a single JSON result",
            verification_passed=False,
            candidate_materialized=False,
            verified_secure_repairs=0,
        ),
    ]

    report = _summary_outcomes(cases)

    aggregate = cast(dict[str, object], report["aggregate"])
    score = cast(dict[str, object], aggregate["scored_repair_rate"])
    assert score["scored_cases"] == 2
    assert score["verified_secure_repairs"] == 1
    assert score["verified_failed"] == 1
    assert score["rate"] == "50.0% (1 verified secure repair among 2 scored cases)"
    excluded = cast(dict[str, int], score["excluded"])
    assert excluded["verified_unscored"] == 2
    assert excluded["not_measured"] == 2
    assert not re.search(r"\b\d+/6\b", json.dumps(report))


def test_rate_is_not_computed_when_no_case_was_scored() -> None:
    report = _summary_outcomes(
        [
            _outcome_case(
                case_id="dev-b602-direct-call",
                matches_reference=False,
                regression_test={"status": "not_run", "reason": "AST differs"},
                verified_secure_repairs=0,
            )
        ]
    )

    score = cast(
        dict[str, object],
        cast(dict[str, object], report["aggregate"])["scored_repair_rate"],
    )
    assert score["scored_cases"] == 0
    assert score["rate"] == "not computed (no scored cases)"


def test_unscored_candidate_summary_lists_only_case_and_candidate_path() -> None:
    case = _outcome_case(
        case_id="dev-b602-direct-call",
        matches_reference=False,
        regression_test={"status": "not_run", "reason": "AST differs"},
        verified_secure_repairs=0,
        candidate_path="cases/dev-b602-direct-call/candidate/app.py",
        model_prose="private completion text",
        source_content="private candidate body",
    )

    report = _summary_outcomes([case])

    assert report["unscored_candidates"] == [
        {
            "case_id": "dev-b602-direct-call",
            "candidate_path": "cases/dev-b602-direct-call/candidate/app.py",
        }
    ]
    serialized = json.dumps(report["unscored_candidates"])
    assert "private completion text" not in serialized
    assert "private candidate body" not in serialized


def test_execution_gates_reject_measured_b602_candidate_before_side_effect(
    tmp_path: Path,
) -> None:
    from benchmarks.v1.oracles import run_behavioral_oracle

    reference = DEVELOPMENT_ROOT / "dev-b602-direct-call" / "reference_fix.py"
    marker = tmp_path / "side-effect-ran"
    reference_source = reference.read_text(encoding="utf-8")
    measured_candidate = reference_source.replace(
        'return subprocess.run(\n        [sys.executable, "-c", SEARCH_SCRIPT, pattern],',
        'command = [sys.executable, "-c", SEARCH_SCRIPT, pattern]\n'
        "    return subprocess.run(\n        command,",
    )
    candidate = tmp_path / "app.py"
    candidate.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
        + measured_candidate,
        encoding="utf-8",
    )

    assert candidate_matches_approved_reference(candidate, reference) is False
    with pytest.raises(ValueError, match="differs from its owner-approved"):
        run_behavioral_oracle("dev-b602-direct-call", candidate, reference)
    assert marker.exists() is False

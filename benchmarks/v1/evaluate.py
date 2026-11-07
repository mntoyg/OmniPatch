"""Opt-in evaluator for the six v1 synthetic development cases only."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast
from unittest.mock import patch

from benchmarks.v1.oracles import (
    DEVELOPMENT_CASE_IDS,
    candidate_matches_approved_reference,
    run_behavioral_oracle,
)
from omnipatch.config import load_settings
from omnipatch.errors import OmniPatchError, PatchGenerationError
from omnipatch.models import Finding
from omnipatch.scanners.registry import build_scanner
from omnipatch.validation.patch_validator import materialize_patch_source

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEVELOPMENT_ROOT = REPOSITORY_ROOT / "benchmarks" / "v1" / "development"
TARGET_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
CASE_OUTCOMES = (
    "not_measured",
    "invalid_patch",
    "refused",
    "verified_failed",
    "verified_unscored",
    "verified_secure_repair",
)


@dataclass(frozen=True)
class VerifyExecution:
    """Captured result from the existing `omnipatch verify` command."""

    command: tuple[str, ...]
    output: str
    exit_code: int
    duration_seconds: float


VerifyRunner = Callable[[Path, str], VerifyExecution]
GitRunner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


def _external_output_directory(path: Path) -> Path:
    """Create a unique, non-existing run directory outside every Git repository."""
    output = path.resolve()
    candidates = (output, *output.parents)
    if any(
        (candidate / ".git").exists() or (candidate / ".git").is_symlink()
        for candidate in candidates
    ):
        raise ValueError(
            "Benchmark output directory must be outside every Git repository"
        )
    output.mkdir(parents=True, exist_ok=False)
    return output


def _case_metadata(case_id: str) -> dict[str, object]:
    """Read one explicitly selected development case manifest."""
    if case_id not in DEVELOPMENT_CASE_IDS:
        raise ValueError(f"Unsupported development case: {case_id}")
    path = DEVELOPMENT_ROOT / case_id / "case.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))
    if metadata.get("split") != "development" or metadata.get("case_id") != case_id:
        raise ValueError(f"Invalid development case metadata: {case_id}")
    if (
        metadata.get("reference_fix_status") != "approved_by_owner"
        or metadata.get("reference_fix_approved_on") != "2026-10-27"
    ):
        raise ValueError(f"Reference fix approval is missing for {case_id}")
    return cast(dict[str, object], metadata)


@contextmanager
def _case_configuration(metadata: dict[str, object]) -> Iterator[None]:
    """Temporarily configure the normal CLI from reviewed case metadata."""
    rule_id = metadata.get("rule_id")
    settings: dict[str, dict[str, str]] = {
        "secret_environment": {},
        "sql_paramstyle": {},
    }
    if rule_id == "B105":
        mapping = metadata.get("secret_environment")
        if (
            not isinstance(mapping, dict)
            or not mapping
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in mapping.items()
            )
        ):
            raise ValueError("B105 case metadata requires secret_environment mapping")
        settings["secret_environment"] = cast(dict[str, str], mapping)
    elif rule_id == "B608":
        mapping = metadata.get("sql_paramstyle")
        if (
            not isinstance(mapping, dict)
            or not mapping
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in mapping.items()
            )
        ):
            raise ValueError("B608 case metadata requires sql_paramstyle mapping")
        settings["sql_paramstyle"] = cast(dict[str, str], mapping)
    elif rule_id != "B602":
        raise ValueError("Unsupported rule in development case metadata")
    with patch.dict(
        os.environ,
        {
            "OMNIPATCH_SECRET_ENVIRONMENT": json.dumps(settings["secret_environment"]),
            "OMNIPATCH_SQL_PARAMSTYLE": json.dumps(settings["sql_paramstyle"]),
        },
    ):
        yield


def _bandit_json(
    scan_root: Path, output_path: Path
) -> tuple[dict[str, object], int, list[str]]:
    """Run Bandit in JSON mode and preserve the exact report outside its target."""
    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(scan_root),
        "-f",
        "json",
        "-q",
    ]
    result = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output_path.write_text(result.stdout, encoding="utf-8")
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Bandit exited with {result.returncode}: {result.stderr[-500:]}"
        )
    report = json.loads(result.stdout)
    if not isinstance(report, dict):
        raise TypeError("Bandit returned a non-object JSON report")
    if not isinstance(report.get("errors"), list) or not isinstance(
        report.get("results"), list
    ):
        raise TypeError("Bandit JSON is missing errors or results")
    return cast(dict[str, object], report), result.returncode, command


def _finding_file(filename: str, scan_root: Path) -> str:
    """Normalize one Bandit filename relative to the scanned target root."""
    normalized = filename.replace("\\", os.sep).replace("/", os.sep)
    raw_path = Path(normalized)
    resolved_root = scan_root.resolve()
    candidate = raw_path if raw_path.is_absolute() else (Path.cwd() / raw_path)
    resolved = candidate.resolve()
    try:
        return resolved.relative_to(resolved_root).as_posix()
    except ValueError:
        candidate_under_root = (resolved_root / raw_path).resolve()
        return candidate_under_root.relative_to(resolved_root).as_posix()


def _identities(report: dict[str, object], scan_root: Path) -> list[dict[str, str]]:
    """Return rule/file/severity identities from one validated Bandit report."""
    raw_results = report["results"]
    if not isinstance(raw_results, list):
        raise TypeError("Bandit results must be a list")
    findings: list[dict[str, str]] = []
    for raw in raw_results:
        if not isinstance(raw, dict):
            raise TypeError("Bandit result must be an object")
        filename = raw.get("filename")
        rule_id = raw.get("test_id")
        severity = raw.get("issue_severity")
        if not all(isinstance(value, str) for value in (filename, rule_id, severity)):
            raise ValueError("Bandit result has invalid identity fields")
        findings.append(
            {
                "rule_id": cast(str, rule_id),
                "file": _finding_file(cast(str, filename), scan_root),
                "severity": cast(str, severity),
            }
        )
    return findings


def parse_verify_output(output: str) -> tuple[dict[str, object] | None, str | None]:
    """Parse the verify JSON array or classify a sanitized command refusal/error."""
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        if _is_traceback_or_exception(output):
            return None, "invalid_run"
        lowered = output.lower()
        if "refus" in lowered or "cannot safely" in lowered:
            return None, "refusal"
        if any(
            phrase in lowered
            for phrase in (
                "did not produce a valid patch",
                "invalid patch",
                "malformed diff",
            )
        ):
            return None, "invalid_patch"
        return None, "invalid_run"
    if not isinstance(payload, list) or len(payload) != 1:
        return None, "invalid_run"
    item = payload[0]
    if not isinstance(item, dict):
        return None, "invalid_run"
    patch = item.get("patch")
    if not isinstance(patch, dict):
        return None, "refusal"
    return cast(dict[str, object], item), None


_PYTHON_EXCEPTION_TYPE = re.compile(
    r"(?:[A-Z][A-Za-z0-9_.]*(?:Error|Exception|Exit|Interrupt|StopIteration))"
)


def _is_traceback_or_exception(output: str) -> bool:
    """Keep Python failures out of patch/refusal classifications."""
    lowered = output.lower()
    if "traceback (most recent call last)" in lowered:
        return True

    for line in output.splitlines():
        frame = line.strip().lstrip("│").strip()
        if frame.startswith('File "') and ", line " in frame and ", in " in frame:
            return True
        if re.search(r"\.py:\d+\s+in\s+[\w<>]+", frame):
            return True

    last_line = next(
        (line.strip() for line in reversed(output.splitlines()) if line.strip()), ""
    )
    exception_type = last_line.partition(":")[0]
    return bool(_PYTHON_EXCEPTION_TYPE.fullmatch(exception_type))


def _live_verify(target_root: Path, rule_id: str) -> VerifyExecution:
    """Invoke only the existing verify command; no publish command is available."""
    command = (
        sys.executable,
        "-m",
        "omnipatch",
        "verify",
        "--repo",
        str(target_root),
        "--rule",
        rule_id,
        "--json",
    )
    started = time.perf_counter()
    try:
        result = subprocess.run(
            list(command),
            cwd=target_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        output = result.stdout + result.stderr
        exit_code = result.returncode
    except subprocess.TimeoutExpired as exc:
        output = f"verify timed out: {exc.timeout} seconds"
        exit_code = 124
    return VerifyExecution(
        command=command,
        output=output,
        exit_code=exit_code,
        duration_seconds=time.perf_counter() - started,
    )


def _sanitize_output(value: str) -> str:
    """Remove secret-valued environment variables before storing raw output."""
    sanitized = value
    for name, secret in os.environ.items():
        if secret and any(
            term in name.upper()
            for term in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
        ):
            sanitized = sanitized.replace(secret, "[REDACTED]")
    return sanitized


def _safe_candidate_patch(
    result: dict[str, object], finding: Finding, original_source: str
) -> str:
    """Rematerialize a CLI-validated patch using the project's public validator."""
    raw_patch = result.get("patch")
    if not isinstance(raw_patch, dict):
        raise TypeError("verify result has no patch object")
    paths = raw_patch.get("touched_files")
    diff = raw_patch.get("unified_diff")
    if (
        not isinstance(paths, list)
        or paths != [finding.file.as_posix()]
        or not isinstance(diff, str)
    ):
        raise ValueError("verify returned unexpected patch metadata")
    return materialize_patch_source(diff, finding, original_source)


def _new_findings_by_severity(
    before: list[dict[str, str]], after: list[dict[str, str]]
) -> dict[str, list[dict[str, str]]]:
    """Compare findings by rule/file identity and group newly introduced items."""
    before_pairs = {(item["rule_id"], item["file"]) for item in before}
    grouped: dict[str, list[dict[str, str]]] = {
        severity: [] for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    }
    for item in after:
        pair = (item["rule_id"], item["file"])
        if pair not in before_pairs and item["severity"] in grouped:
            grouped[item["severity"]].append(
                {"rule_id": item["rule_id"], "file": item["file"]}
            )
    return grouped


def _git_provenance(git_runner: GitRunner | None = None) -> dict[str, object]:
    """Describe HEAD and dirty state without storing uncommitted diff content."""
    runner = git_runner or (
        lambda arguments: subprocess.run(
            ["git", *arguments],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=False,
        )
    )
    try:
        head_result = runner(["rev-parse", "HEAD"])
        status_result = runner(["status", "--porcelain"])
    except OSError:
        return {"head": "unknown", "dirty": True}
    if head_result.returncode != 0 or status_result.returncode != 0:
        return {"head": "unknown", "dirty": True}
    head = head_result.stdout.decode("utf-8", errors="replace").strip()
    if not head:
        return {"head": "unknown", "dirty": True}
    dirty = bool(status_result.stdout.strip())
    provenance: dict[str, object] = {"head": head, "dirty": dirty}
    if not dirty:
        return provenance
    try:
        diff_result = runner(["diff", "HEAD"])
    except OSError:
        return {"head": "unknown", "dirty": True}
    if diff_result.returncode != 0:
        return {"head": "unknown", "dirty": True}
    normalized_diff = diff_result.stdout.replace(b"\r\n", b"\n")
    provenance["diff_sha256"] = hashlib.sha256(normalized_diff).hexdigest()
    return provenance


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _case_outcome(case: dict[str, object]) -> str:
    """Classify one verification result without treating an unscored run as failure."""
    if case.get("invalid_run") is not None:
        return "not_measured"
    if cast(int, case.get("invalid_patches", 0)) > 0:
        return "invalid_patch"
    if cast(int, case.get("refusals", 0)) > 0:
        return "refused"
    if case.get("candidate_materialized") is not True:
        return "invalid_patch"

    regression = case.get("regression_test")
    status = regression.get("status") if isinstance(regression, dict) else None
    failed_verification = (
        case.get("verification_passed") is not True
        or bool(case.get("surviving_target_findings"))
        or case.get("blocking_introduced_findings") is True
        or bool(case.get("post_scan_errors"))
        or status == "failed"
    )
    if failed_verification:
        return "verified_failed"
    if status == "passed" and case.get("matches_reference") is True:
        return "verified_secure_repair"
    if status == "not_run" and case.get("matches_reference") is False:
        return "verified_unscored"
    return "verified_failed"


def _write_case_result(path: Path, case: dict[str, object]) -> None:
    """Persist an explicit outcome and keep the legacy skipped field as an alias."""
    outcome = _case_outcome(case)
    case["outcome"] = outcome
    case["skipped"] = None if outcome == "verified_secure_repair" else outcome
    _write_json(path, case)


def evaluate_development(
    output_dir: Path,
    *,
    case_ids: tuple[str, ...] = DEVELOPMENT_CASE_IDS,
    verify_runner: VerifyRunner,
    allow_dirty: bool = False,
    git_runner: GitRunner | None = None,
) -> dict[str, object]:
    """Run verified-only development cases into a new external artifact directory."""
    if not case_ids or any(case_id not in DEVELOPMENT_CASE_IDS for case_id in case_ids):
        raise ValueError("Only the six explicit development cases may be selected")
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("Development case selection contains duplicates")
    source_provenance = _git_provenance(git_runner)
    if (
        verify_runner is _live_verify
        and source_provenance["dirty"] is True
        and not allow_dirty
    ):
        raise ValueError(
            "Live benchmark runs from a dirty or unknown Git tree are refused; "
            "pass --allow-dirty to acknowledge the source state"
        )
    output_root = _external_output_directory(output_dir)
    cases_output = output_root / "cases"
    cases_output.mkdir()

    settings = load_settings()
    provider_settings = {
        "provider": settings.llm_provider,
        "model": settings.llm_model,
        "output_mode": settings.llm_output,
    }
    run_metadata = {
        "benchmark": "omnipatch-synthetic-v1-development",
        "source_revision": source_provenance,
        "provider_settings": provider_settings,
        "case_ids": list(case_ids),
        "live_model_requested": verify_runner is _live_verify,
    }
    _write_json(output_root / "run.json", run_metadata)

    case_results: list[dict[str, object]] = []
    for case_id in case_ids:
        metadata = _case_metadata(case_id)
        rule_id = str(metadata["rule_id"])
        case_root = (DEVELOPMENT_ROOT / case_id).resolve()
        case_source = (case_root / str(metadata["vulnerable_source"])).resolve()
        reference_source = (case_root / str(metadata["reference_fix_source"])).resolve()
        if (
            not case_source.is_relative_to(case_root)
            or case_source.name != "vulnerable.py"
            or not reference_source.is_relative_to(case_root)
            or reference_source.name != "reference_fix.py"
            or case_source == reference_source
        ):
            raise ValueError(f"Invalid source paths in development metadata: {case_id}")
        case_output = cases_output / case_id
        case_output.mkdir()
        target_root = case_output / "target"
        target_root.mkdir()
        target_file = target_root / "app.py"
        original_source = case_source.read_text(encoding="utf-8")
        target_file.write_text(original_source, encoding="utf-8")
        case_record: dict[str, object] = {
            "case_id": case_id,
            "rule_id": rule_id,
            "reference_fix_status": metadata["reference_fix_status"],
            "reference_fix_approved_on": metadata["reference_fix_approved_on"],
            "provider": settings.llm_provider,
            "model": settings.llm_model,
            "source_sha256": hashlib.sha256(
                original_source.encode("utf-8")
            ).hexdigest(),
            "target_contents": ["app.py"],
            "verified_secure_repairs": 0,
            "candidate_materialized": False,
            "verification_passed": False,
            "matches_reference": False,
            "candidate_path": None,
            "blocking_introduced_findings": False,
            "post_scan_errors": None,
            "refusals": 0,
            "invalid_patches": 0,
            "surviving_target_findings": None,
            "introduced_findings_by_severity": None,
            "regression_test": {"status": "not_run", "reason": "not_started"},
            "latency_seconds": None,
            "skipped": None,
            "invalid_run": None,
        }

        try:
            baseline_report, baseline_exit, baseline_command = _bandit_json(
                target_root, case_output / "baseline-bandit.json"
            )
            baseline_json_findings = _identities(baseline_report, target_root)
            baseline_findings = [
                item for item in baseline_json_findings if item["file"] == "app.py"
            ]
            _write_json(
                case_output / "baseline-bandit-meta.json",
                {
                    "command_argv": baseline_command,
                    "exit_status": baseline_exit,
                    "errors": baseline_report["errors"],
                    "findings": baseline_json_findings,
                },
            )
            configured_scanner = build_scanner(
                settings.scanner,
                timeout_seconds=settings.scan_timeout_seconds,
                excluded_dirs=settings.scan_exclude_dirs,
            )
            findings = configured_scanner.scan(target_root)
            matching_findings = [
                item
                for item in findings
                if item.rule_id == rule_id and item.file == PurePosixPath("app.py")
            ]
            if (
                baseline_report["errors"]
                or not any(
                    item["rule_id"] == rule_id and item["file"] == "app.py"
                    for item in baseline_findings
                )
                or not matching_findings
            ):
                case_record["invalid_run"] = (
                    "baseline target missing or Bandit reported errors"
                )
                case_results.append(case_record)
                _write_case_result(case_output / "result.json", case_record)
                continue

            with _case_configuration(metadata):
                execution = verify_runner(target_root, rule_id)
            case_record["latency_seconds"] = round(execution.duration_seconds, 4)
            raw_output = _sanitize_output(execution.output)
            (case_output / "verify-output.txt").write_text(raw_output, encoding="utf-8")
            _write_json(
                case_output / "verify-command.json",
                {
                    "command_argv": list(execution.command),
                    "exit_status": execution.exit_code,
                    "duration_seconds": case_record["latency_seconds"],
                    "provider_settings": provider_settings,
                },
            )
            verify_result, classification = parse_verify_output(execution.output)
            if verify_result is None:
                if classification == "refusal":
                    case_record["refusals"] = 1
                elif classification == "invalid_patch":
                    case_record["invalid_patches"] = 1
                elif execution.exit_code == 124:
                    case_record["invalid_run"] = "verify timed out"
                else:
                    case_record["invalid_run"] = (
                        "verify output was not a single JSON result"
                    )
                case_results.append(case_record)
                _write_case_result(case_output / "result.json", case_record)
                continue

            if verify_result.get("applied") is not True:
                case_record["invalid_patches"] = 1
                case_results.append(case_record)
                _write_case_result(case_output / "result.json", case_record)
                continue

            finding = matching_findings[0]
            try:
                candidate_source = _safe_candidate_patch(
                    verify_result, finding, original_source
                )
            except (PatchGenerationError, TypeError, ValueError) as exc:
                case_record["invalid_patches"] = 1
                case_record["invalid_run"] = _sanitize_output(
                    f"{type(exc).__name__}: {exc}"
                )
                case_results.append(case_record)
                _write_case_result(case_output / "result.json", case_record)
                continue
            candidate_root = case_output / "candidate"
            candidate_root.mkdir()
            candidate_file = candidate_root / "app.py"
            candidate_file.write_text(candidate_source, encoding="utf-8")
            case_record["candidate_materialized"] = True
            case_record["candidate_path"] = str(candidate_file)
            case_record["verification_passed"] = verify_result.get("verified") is True

            matches_reference = candidate_matches_approved_reference(
                candidate_file, reference_source
            )
            case_record["matches_reference"] = matches_reference
            if matches_reference:
                oracle_root = case_output / "oracle-copy"
                oracle_root.mkdir()
                oracle_candidate = oracle_root / "app.py"
                oracle_candidate.write_text(candidate_source, encoding="utf-8")
                try:
                    run_behavioral_oracle(case_id, oracle_candidate, reference_source)
                    case_record["regression_test"] = {
                        "status": "passed",
                        "reason": None,
                    }
                except (
                    AssertionError,
                    ImportError,
                    KeyError,
                    OSError,
                    RuntimeError,
                    sqlite3.Error,
                    TypeError,
                    UnicodeError,
                    ValueError,
                ) as exc:
                    case_record["regression_test"] = {
                        "status": "failed",
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
            else:
                case_record["regression_test"] = {
                    "status": "not_run",
                    "reason": "candidate executable AST differs from the owner-approved reference fix",
                }

            after_report, after_exit, after_command = _bandit_json(
                candidate_root, case_output / "post-bandit.json"
            )
            after_findings = _identities(after_report, candidate_root)
            _write_json(
                case_output / "post-bandit-meta.json",
                {
                    "command_argv": after_command,
                    "exit_status": after_exit,
                    "errors": after_report["errors"],
                    "findings": after_findings,
                },
            )
            target_survivors = [
                item
                for item in after_findings
                if item["rule_id"] == rule_id and item["file"] == "app.py"
            ]
            introduced = _new_findings_by_severity(baseline_findings, after_findings)
            case_record["surviving_target_findings"] = target_survivors
            case_record["introduced_findings_by_severity"] = introduced
            case_record["post_scan_errors"] = after_report["errors"]
            regression_result = cast(dict[str, object], case_record["regression_test"])
            target_severity = max(
                (item.severity.rank for item in matching_findings), default=0
            )
            has_blocking_introduced = any(
                TARGET_SEVERITY_RANK.get(severity, 0) >= target_severity
                and findings_for_severity
                for severity, findings_for_severity in introduced.items()
            )
            case_record["blocking_introduced_findings"] = has_blocking_introduced
            case_record["verified_secure_repairs"] = int(
                verify_result.get("verified") is True
                and regression_result["status"] == "passed"
                and not target_survivors
                and not after_report["errors"]
                and not has_blocking_introduced
            )
        except (
            OmniPatchError,
            OSError,
            ValueError,
            RuntimeError,
            json.JSONDecodeError,
        ) as exc:
            case_record["invalid_run"] = _sanitize_output(
                f"{type(exc).__name__}: {exc}"
            )

        case_results.append(case_record)
        _write_case_result(case_output / "result.json", case_record)

    report = _aggregate_report(run_metadata, case_results)
    _write_json(output_root / "summary.json", report)
    return report


def _aggregate_report(
    run_metadata: dict[str, object], cases: list[dict[str, object]]
) -> dict[str, object]:
    """Build explicit per-case and aggregate benchmark metrics."""
    normalized_cases: list[dict[str, object]] = []
    for original_case in cases:
        case = dict(original_case)
        outcome = _case_outcome(case)
        case["outcome"] = outcome
        case["skipped"] = None if outcome == "verified_secure_repair" else outcome
        normalized_cases.append(case)

    latencies: list[float] = []
    for case in normalized_cases:
        latency = case.get("latency_seconds")
        if isinstance(latency, (int, float)):
            latencies.append(float(latency))
    outcome_counts = {
        outcome: sum(case["outcome"] == outcome for case in normalized_cases)
        for outcome in CASE_OUTCOMES
    }
    secure_repairs = outcome_counts["verified_secure_repair"]
    verified_failed = outcome_counts["verified_failed"]
    scored_cases = secure_repairs + verified_failed
    rate = (
        f"{secure_repairs / scored_cases:.1%} ({secure_repairs} verified secure repair"
        f"{'s' if secure_repairs != 1 else ''} among {scored_cases} scored cases)"
        if scored_cases
        else "not computed (no scored cases)"
    )
    unscored_candidates: list[dict[str, str]] = []
    for case in normalized_cases:
        if case["outcome"] == "verified_unscored":
            candidate_path = case.get("candidate_path")
            case_id = case.get("case_id")
            if not isinstance(candidate_path, str) or not isinstance(case_id, str):
                raise ValueError(
                    "Unscored candidate is missing its case or candidate path"
                )
            unscored_candidates.append(
                {"case_id": case_id, "candidate_path": candidate_path}
            )
    counts = {
        "verified_secure_repairs": sum(
            cast(int, case["verified_secure_repairs"]) for case in cases
        ),
        "refusals": sum(cast(int, case["refusals"]) for case in cases),
        "invalid_patches": sum(cast(int, case["invalid_patches"]) for case in cases),
        "surviving_target_findings": sum(
            len(cast(list[object], case["surviving_target_findings"]))
            for case in cases
            if isinstance(case.get("surviving_target_findings"), list)
        ),
        "invalid_runs": sum(case.get("invalid_run") is not None for case in cases),
        "outcome_counts": outcome_counts,
        "scored_repair_rate": {
            "verified_secure_repairs": secure_repairs,
            "verified_failed": verified_failed,
            "scored_cases": scored_cases,
            "rate": rate,
            "excluded": {
                outcome: outcome_counts[outcome]
                for outcome in (
                    "verified_unscored",
                    "not_measured",
                    "invalid_patch",
                    "refused",
                )
            },
        },
        "regression_results": {
            status: sum(
                isinstance(case.get("regression_test"), dict)
                and cast(dict[str, object], case["regression_test"]).get("status")
                == status
                for case in cases
            )
            for status in ("passed", "failed", "not_run")
        },
        "latency_seconds": {
            "median": statistics.median(latencies) if latencies else None,
            "p95": sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)]
            if latencies
            else None,
            "timeouts": sum(
                case.get("invalid_run") is not None
                and "timed out" in str(case.get("invalid_run")).lower()
                for case in cases
            ),
        },
    }
    introduced: dict[str, list[dict[str, str]]] = {
        severity: [] for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    }
    for case in normalized_cases:
        by_severity = case.get("introduced_findings_by_severity")
        if isinstance(by_severity, dict):
            for severity, target_items in introduced.items():
                items = by_severity.get(severity)
                if isinstance(items, list):
                    target_items.extend(cast(list[dict[str, str]], items))
    return {
        "run": run_metadata,
        "aggregate": counts,
        "introduced_findings_by_severity": introduced,
        "unscored_candidates": unscored_candidates,
        "cases": normalized_cases,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Explicitly allow verify to call the configured live model provider.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Acknowledge and record a dirty source tree for a live run.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New output directory outside this repository; it must not already exist.",
    )
    parser.add_argument(
        "--case",
        action="append",
        choices=DEVELOPMENT_CASE_IDS,
        help="Limit to a development case; may be repeated. Holdout IDs are not accepted.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.live:
        _parser().error("live provider access is opt-in; pass --live to evaluate")
    try:
        report = evaluate_development(
            args.output_dir,
            case_ids=tuple(args.case) if args.case else DEVELOPMENT_CASE_IDS,
            verify_runner=_live_verify,
            allow_dirty=args.allow_dirty,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(
            f"benchmark evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr
        )
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

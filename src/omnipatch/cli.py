"""Typer command line interface."""

import json
from pathlib import Path, PurePosixPath
from typing import Annotated

import typer

from omnipatch import __version__
from omnipatch.agents.llm_agent import LLMPatchAgent
from omnipatch.agents.registry import build_llm_client
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.codebase.redaction import redact
from omnipatch.codebase.snapshot import RepositorySnapshot, SnapshotReport
from omnipatch.codebase.source import read_finding_source
from omnipatch.config import Settings, load_settings
from omnipatch.defaults import EXCLUDED_DIRS
from omnipatch.errors import ConfigError, OmniPatchError, PatchGenerationError
from omnipatch.models import CodeContext, Finding, Severity
from omnipatch.reporting.pr_body import pull_request_title
from omnipatch.reporting.selection import select_findings
from omnipatch.scanners.registry import build_scanner
from omnipatch.secret_environment import (
    missing_secret_environment_keys,
    missing_sql_paramstyle_keys,
)
from omnipatch.vcs.github_client import GitHubPullRequestPublisher
from omnipatch.verification.patch_verifier import verify_patch
from omnipatch.workflows.run import (
    PreparedPublication,
    execute_run_workflow,
    publish_prepared_outcomes,
)

app = typer.Typer(name="omnipatch", no_args_is_help=True)


def _select_findings(findings: list[Finding], maximum: int) -> list[Finding]:
    """Apply the configured result bound and report every omitted finding."""
    selected, omitted = select_findings(findings, maximum)
    if omitted:
        typer.echo(
            f"warning: max findings limit {maximum} reached; {omitted} matching "
            "finding(s) omitted from this command. Set "
            "OMNIPATCH_MAX_FINDINGS to raise the limit.",
            err=True,
        )
    return selected


def _resolve_repository_root(repo: Path) -> Path:
    """Check the CLI target shape; the snapshot captures its identity once."""
    if not repo.is_dir():
        typer.echo(f"Repository path is not a directory: {repo}", err=True)
        raise typer.Exit(code=2)
    return repo


def _repository_snapshot(repo_root: Path, settings: Settings) -> RepositorySnapshot:
    """Build one bounded snapshot using validated settings."""
    return RepositorySnapshot(
        repo_root,
        excluded_dirs=settings.scan_exclude_dirs,
        max_bytes=settings.snapshot_max_bytes,
        max_file_bytes=settings.snapshot_max_file_bytes,
        max_entries=settings.snapshot_max_entries,
        max_metadata_entries=settings.snapshot_max_metadata_entries,
        timeout_seconds=settings.snapshot_timeout_seconds,
    )


def _render_snapshot_report(report: SnapshotReport, settings: Settings) -> None:
    """Render bounded metadata notices once; paths are JSON-quoted, never content."""
    custom_rules = {
        tuple(PurePosixPath(rule.replace("\\", "/")).parts): rule
        for rule in settings.scan_exclude_dirs
        if tuple(PurePosixPath(rule.replace("\\", "/")).parts)
        not in {tuple(PurePosixPath(item).parts) for item in EXCLUDED_DIRS}
    }
    emitted = 0
    omitted = 0
    for notice in report.notices:
        if emitted >= 100:
            omitted += 1
            continue
        quoted = _quote_snapshot_path(notice.path)
        if notice.category == "excluded":
            parts = tuple(PurePosixPath(notice.path).parts)
            matching = [
                rule
                for rule_parts, rule in custom_rules.items()
                if len(parts) >= len(rule_parts)
                and parts[-len(rule_parts) :] == rule_parts
            ]
            if not matching or not notice.count:
                continue
            typer.echo(
                f"warning: {notice.count} python file(s) under scan-exclude "
                f"({', '.join(json.dumps(rule, ensure_ascii=True) for rule in matching)}) "
                "were not scanned",
                err=True,
            )
        elif notice.category == "count_unavailable":
            typer.echo(
                f"warning: python file count unavailable under {quoted}; "
                "the exclusion remains active",
                err=True,
            )
        elif notice.category == "excluded_link":
            typer.echo(
                f"warning: scan-exclude path {quoted} was not traversed; "
                "python file count unavailable (link or inspection failure)",
                err=True,
            )
        elif notice.category == "nested_checkout":
            typer.echo(
                f"warning: {quoted} is a nested checkout still in scope; its "
                "findings are reported as this repository's",
                err=True,
            )
        emitted += 1
    if omitted:
        typer.echo(f"warning: {omitted} additional snapshot notices omitted", err=True)


def _quote_snapshot_path(path: str) -> str:
    """Quote and cap an untrusted repository-relative path for terminal output."""
    bounded = path[:512]
    if len(path) > 512:
        bounded += "..."
    return json.dumps(bounded, ensure_ascii=True)


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


@app.command()
def scan(
    repo: Annotated[Path, typer.Option("--repo")] = Path("."),
    as_json: Annotated[bool, typer.Option("--json")] = False,
    min_severity: Annotated[Severity | None, typer.Option("--min-severity")] = None,
    scanner: Annotated[str | None, typer.Option("--scanner")] = None,
) -> None:
    """Scan a repository with the configured scanner."""
    repo_root = _resolve_repository_root(repo)
    try:
        settings = load_settings()
        with _repository_snapshot(repo_root, settings) as snapshot:
            scanner_adapter = build_scanner(
                scanner or settings.scanner,
                timeout_seconds=settings.scan_timeout_seconds,
                excluded_dirs=settings.scan_exclude_dirs,
                report_scope=False,
            )
            if snapshot.root is None:
                raise PatchGenerationError("Repository snapshot was not created")
            findings = scanner_adapter.scan(snapshot.root)
            _render_snapshot_report(snapshot.report, settings)
    except OmniPatchError as exc:
        typer.echo(redact(str(exc)), err=True)
        raise typer.Exit(code=1) from exc
    if min_severity is not None:
        findings = [
            finding
            for finding in findings
            if finding.severity.rank >= min_severity.rank
        ]
    findings = _select_findings(findings, settings.max_findings)
    if as_json:
        typer.echo(json.dumps([item.to_json_dict() for item in findings]))
        return
    for item in findings:
        typer.echo(
            f"{item.severity.value.upper():8} {item.file}:{item.line_start} {item.title}"
        )


@app.command()
def context(
    repo: Annotated[Path, typer.Option("--repo")] = Path("."),
    scanner: Annotated[str | None, typer.Option("--scanner")] = None,
    rule: Annotated[str | None, typer.Option("--rule")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print bounded, redacted source context for scanner findings."""
    repo_root = _resolve_repository_root(repo)
    try:
        settings = load_settings()
        with _repository_snapshot(repo_root, settings) as snapshot:
            scanner_adapter = build_scanner(
                scanner or settings.scanner,
                timeout_seconds=settings.scan_timeout_seconds,
                excluded_dirs=settings.scan_exclude_dirs,
                report_scope=False,
            )
            if snapshot.root is None or snapshot.root_identity is None:
                raise PatchGenerationError(
                    "Repository snapshot identity is unavailable"
                )
            findings = scanner_adapter.scan(snapshot.root)
            _render_snapshot_report(snapshot.report, settings)
            if rule is not None:
                findings = [finding for finding in findings if finding.rule_id == rule]
            findings = _select_findings(findings, settings.max_findings)
            contexts = [
                extract_context(
                    finding,
                    snapshot.root,
                    settings.context_max_lines,
                    root_identity=snapshot.root_identity,
                )
                for finding in findings
            ]
    except OmniPatchError as exc:
        typer.echo(redact(str(exc)), err=True)
        raise typer.Exit(code=1) from exc
    if as_json:
        typer.echo(json.dumps([context.to_json_dict() for context in contexts]))
        return
    for finding, item in zip(findings, contexts, strict=True):
        typer.echo(item.symbol or "<module>")
        typer.echo(f"{finding.file}:{finding.line_start}")
        typer.echo(item.snippet)


@app.command()
def patch(
    repo: Annotated[Path, typer.Option("--repo")],
    rule: Annotated[str, typer.Option("--rule")],
    scanner: Annotated[str | None, typer.Option("--scanner")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Propose validated security patches without modifying the repository."""
    repo_root = _resolve_repository_root(repo)
    try:
        settings = load_settings()
        client = build_llm_client(settings) if rule != "B105" else None
        with _repository_snapshot(repo_root, settings) as snapshot:
            scanner_adapter = build_scanner(
                scanner or settings.scanner,
                timeout_seconds=settings.scan_timeout_seconds,
                excluded_dirs=settings.scan_exclude_dirs,
                report_scope=False,
            )
            if snapshot.root is None or snapshot.root_identity is None:
                raise PatchGenerationError(
                    "Repository snapshot identity is unavailable"
                )
            baseline = scanner_adapter.scan(snapshot.root)
            _render_snapshot_report(snapshot.report, settings)
            findings = _select_findings(
                [item for item in baseline if item.rule_id == rule],
                settings.max_findings,
            )
            contexts = _prepare_finding_contexts(
                findings, snapshot.root, settings, snapshot.root_identity
            )
            if client is None:
                client = build_llm_client(settings)
            agent = LLMPatchAgent(
                client,
                output_mode=settings.llm_output,
                secret_environment=settings.secret_environment,
                sql_paramstyle=settings.sql_paramstyle,
            )
            patches = []
            for finding in findings:
                context_item = contexts[finding.id]
                original_source = read_finding_source(
                    finding, snapshot.root, root_identity=snapshot.root_identity
                )
                patches.append(agent.propose(finding, context_item, original_source))
    except OmniPatchError as exc:
        typer.echo(redact(str(exc)), err=True)
        raise typer.Exit(code=1) from exc
    if as_json:
        typer.echo(json.dumps([item.to_json_dict() for item in patches]))
        return
    for item in patches:
        typer.echo(item.explanation)
        _echo_patch_diff(item.unified_diff)


@app.command()
def verify(
    repo: Annotated[Path, typer.Option("--repo")],
    rule: Annotated[str, typer.Option("--rule")],
    scanner: Annotated[str | None, typer.Option("--scanner")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Propose patches and verify them by rescanning in a temporary sandbox."""
    repo_root = _resolve_repository_root(repo)
    try:
        settings = load_settings()
        client = build_llm_client(settings) if rule != "B105" else None
        with _repository_snapshot(repo_root, settings) as snapshot:
            scanner_adapter = build_scanner(
                scanner or settings.scanner,
                timeout_seconds=settings.scan_timeout_seconds,
                excluded_dirs=settings.scan_exclude_dirs,
                report_scope=False,
            )
            if snapshot.root is None or snapshot.root_identity is None:
                raise PatchGenerationError(
                    "Repository snapshot identity is unavailable"
                )
            baseline = scanner_adapter.scan(snapshot.root)
            _render_snapshot_report(snapshot.report, settings)
            findings = _select_findings(
                [finding for finding in baseline if finding.rule_id == rule],
                settings.max_findings,
            )
            contexts = _prepare_finding_contexts(
                findings, snapshot.root, settings, snapshot.root_identity
            )
            if client is None:
                client = build_llm_client(settings)
            agent = LLMPatchAgent(
                client,
                output_mode=settings.llm_output,
                secret_environment=settings.secret_environment,
                sql_paramstyle=settings.sql_paramstyle,
            )
            results = []
            for finding in findings:
                context_item = contexts[finding.id]
                original_source = read_finding_source(
                    finding, snapshot.root, root_identity=snapshot.root_identity
                )
                proposed = agent.propose(finding, context_item, original_source)
                results.append(
                    verify_patch(
                        proposed,
                        finding,
                        snapshot.root,
                        scanner_adapter,
                        baseline,
                        policy=settings.verify_policy,
                        root_identity=snapshot.root_identity,
                    )
                )
    except OmniPatchError as exc:
        typer.echo(redact(str(exc)), err=True)
        raise typer.Exit(code=1) from exc
    all_verified = all(item.verified for item in results)
    if as_json:
        typer.echo(json.dumps([item.to_json_dict() for item in results]))
    else:
        for item in results:
            verdict = (
                "verified"
                if item.verified
                else f"not verified: {redact(item.error or '')}"
            )
            typer.echo(verdict)
            if item.introduced:
                typer.echo(
                    f"tolerated lower-severity findings: {', '.join(item.introduced)}"
                )
            typer.echo(item.patch.explanation)
            _echo_patch_diff(item.patch.unified_diff)
    if not all_verified:
        raise typer.Exit(code=1)


@app.command()
def run(
    repo: Annotated[Path, typer.Option("--repo")],
    rule: Annotated[str, typer.Option("--rule")],
    scanner: Annotated[str | None, typer.Option("--scanner")] = None,
    github_repo: Annotated[str | None, typer.Option("--github-repo")] = None,
    base_branch: Annotated[str | None, typer.Option("--base-branch")] = None,
    apply_changes: Annotated[bool, typer.Option("--apply")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Generate, verify, and optionally publish one draft PR per finding."""
    repo_root = _resolve_repository_root(repo)
    try:
        settings = load_settings()
        target_repository = github_repo or settings.require_github_repo()
        if len(target_repository.split("/")) != 2 or any(
            not part or any(character.isspace() for character in part)
            for part in target_repository.split("/")
        ):
            raise ConfigError("GitHub repository must be explicit as owner/name")
        token = settings.require_github_token() if apply_changes else None
        client = build_llm_client(settings) if rule != "B105" else None
        publisher = (
            GitHubPullRequestPublisher(
                token=token or "",
                repository=target_repository,
                base_branch=base_branch,
                timeout_seconds=settings.github_timeout_seconds,
            )
            if apply_changes
            else None
        )
        prepared_publications: list[PreparedPublication] = []
        with _repository_snapshot(repo_root, settings) as snapshot:
            scanner_adapter = build_scanner(
                scanner or settings.scanner,
                timeout_seconds=settings.scan_timeout_seconds,
                excluded_dirs=settings.scan_exclude_dirs,
                report_scope=False,
            )
            if snapshot.root is None or snapshot.root_identity is None:
                raise PatchGenerationError(
                    "Repository snapshot identity is unavailable"
                )
            baseline = scanner_adapter.scan(snapshot.root)
            _render_snapshot_report(snapshot.report, settings)
            findings = _select_findings(
                [item for item in baseline if item.rule_id == rule],
                settings.max_findings,
            )
            contexts = _prepare_finding_contexts(
                findings, snapshot.root, settings, snapshot.root_identity
            )
            if client is None:
                client = build_llm_client(settings)
            agent = LLMPatchAgent(
                client,
                output_mode=settings.llm_output,
                secret_environment=settings.secret_environment,
                sql_paramstyle=settings.sql_paramstyle,
            )
            outcomes = execute_run_workflow(
                findings,
                contexts,
                snapshot.root,
                settings,
                agent,
                scanner_adapter,
                baseline,
                publisher,
                root_identity=snapshot.root_identity,
                prepared_publications=prepared_publications if apply_changes else None,
            )
    except OmniPatchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if publisher is not None and prepared_publications:
        outcomes = publish_prepared_outcomes(outcomes, prepared_publications, publisher)
    if as_json:
        typer.echo(json.dumps([outcome.to_json_dict() for outcome in outcomes]))
    else:
        for outcome in outcomes:
            if outcome.error is not None:
                typer.echo(outcome.error, err=True)
                continue
            result = outcome.result
            patch = outcome.patch
            if result is None or patch is None:
                raise RuntimeError("Run workflow returned an incomplete outcome")
            if result.introduced:
                typer.echo(
                    f"tolerated lower-severity findings: {', '.join(result.introduced)}"
                )
            if result.verified:
                typer.echo(
                    f"branch: omnipatch/{outcome.finding.rule_id.lower()}-"
                    f"{outcome.finding.id}"
                )
                typer.echo(f"title: {pull_request_title(outcome.finding)}")
                _echo_patch_diff(patch.unified_diff)
                typer.echo(
                    f"draft PR: {outcome.pull_request_url}"
                    if outcome.pull_request_url
                    else "dry run: no GitHub API calls"
                )
            else:
                typer.echo(redact(result.error or "Verification failed"), err=True)
    if any(
        outcome.error is not None
        or (outcome.result is not None and not outcome.result.verified)
        for outcome in outcomes
    ):
        raise typer.Exit(code=1)


def _prepare_finding_contexts(
    findings: list[Finding],
    repo_root: Path,
    settings: Settings,
    root_identity: tuple[int, int],
) -> dict[str, CodeContext]:
    """Extract contexts and fail before provider construction for unmapped targets."""
    # Keep this helper independent of model transport construction: missing secret
    # mappings must be actionable before any provider is called.
    contexts = {
        finding.id: extract_context(
            finding,
            repo_root,
            settings.context_max_lines,
            root_identity=root_identity,
        )
        for finding in findings
    }
    missing = missing_secret_environment_keys(
        findings, contexts, settings.secret_environment
    )
    if missing:
        targets = ", ".join(missing)
        raise ConfigError(
            "B105 repair requires explicit environment-variable mappings for: "
            f"{targets}. Add these keys to OMNIPATCH_SECRET_ENVIRONMENT as JSON, "
            'for example {"app.py::configured_password": "APP_PASSWORD", '
            '"settings.py::<module>": "DATABASE_PASSWORD"}. Values must be '
            "environment-variable names, never secret values."
        )
    missing_sql = missing_sql_paramstyle_keys(
        findings, contexts, settings.sql_paramstyle
    )
    if missing_sql:
        targets = ", ".join(missing_sql)
        raise ConfigError(
            "B608 repair requires explicit SQL parameter style mappings for: "
            f"{targets}. Add these keys to OMNIPATCH_SQL_PARAMSTYLE as JSON using "
            "one of qmark, numeric, named, format, pyformat, for example "
            '{"app.py::lookup_item": "qmark"}.'
        )
    return contexts


def _echo_patch_diff(unified_diff: str) -> None:
    """Print a redacted display diff without exposing removed credential literals."""
    safe_diff = redact(unified_diff)
    if safe_diff != unified_diff:
        typer.echo(
            "warning: displayed diff contains redacted values and is not directly applicable",
            err=True,
        )
    typer.echo(safe_diff)

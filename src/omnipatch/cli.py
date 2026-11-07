"""Typer command line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer

from omnipatch import __version__
from omnipatch.agents.llm_agent import LLMPatchAgent
from omnipatch.agents.registry import build_llm_client
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.codebase.redaction import redact
from omnipatch.config import Settings, load_settings
from omnipatch.errors import ConfigError, OmniPatchError, PatchGenerationError
from omnipatch.models import CodeContext, Finding, PatchResult, Severity
from omnipatch.reporting.pr_body import pull_request_title
from omnipatch.scanners.registry import build_scanner
from omnipatch.secret_environment import (
    missing_secret_environment_keys,
    missing_sql_paramstyle_keys,
    secret_environment_key,
    sql_paramstyle_key,
)
from omnipatch.validation.patch_validator import materialize_patch_source
from omnipatch.vcs.github_client import GitHubPullRequestPublisher
from omnipatch.verification.patch_verifier import verify_patch

app = typer.Typer(name="omnipatch", no_args_is_help=True)


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
    repo_root = repo.resolve()
    if not repo_root.is_dir():
        typer.echo(f"Repository path is not a directory: {repo_root}", err=True)
        raise typer.Exit(code=2)
    try:
        settings = load_settings()
        scanner_adapter = build_scanner(
            scanner or settings.scanner,
            timeout_seconds=settings.scan_timeout_seconds,
            excluded_dirs=settings.scan_exclude_dirs,
        )
        findings = scanner_adapter.scan(repo_root)
    except OmniPatchError as exc:
        typer.echo(redact(str(exc)), err=True)
        raise typer.Exit(code=1) from exc
    if min_severity is not None:
        findings = [
            finding
            for finding in findings
            if finding.severity.rank >= min_severity.rank
        ]
    findings = findings[: settings.max_findings]
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
    repo_root = repo.resolve()
    if not repo_root.is_dir():
        typer.echo(f"Repository path is not a directory: {repo_root}", err=True)
        raise typer.Exit(code=2)
    try:
        settings = load_settings()
        scanner_adapter = build_scanner(
            scanner or settings.scanner,
            timeout_seconds=settings.scan_timeout_seconds,
            excluded_dirs=settings.scan_exclude_dirs,
        )
        findings = scanner_adapter.scan(repo_root)
        if rule is not None:
            findings = [finding for finding in findings if finding.rule_id == rule]
        findings = findings[: settings.max_findings]
        contexts = [
            extract_context(finding, repo_root, settings.context_max_lines)
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
    repo_root = repo.resolve()
    if not repo_root.is_dir():
        typer.echo(f"Repository path is not a directory: {repo_root}", err=True)
        raise typer.Exit(code=2)
    try:
        settings = load_settings()
        client = build_llm_client(settings) if rule != "B105" else None
        scanner_adapter = build_scanner(
            scanner or settings.scanner,
            timeout_seconds=settings.scan_timeout_seconds,
            excluded_dirs=settings.scan_exclude_dirs,
        )
        findings = [
            finding
            for finding in scanner_adapter.scan(repo_root)
            if finding.rule_id == rule
        ][: settings.max_findings]
        contexts = _prepare_finding_contexts(findings, repo_root, settings)
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
            source_path = (repo_root / Path(*finding.file.parts)).resolve()
            if not source_path.is_relative_to(repo_root):
                raise PatchGenerationError(
                    f"Finding path resolves outside repository: {finding.file}"
                )
            try:
                original_source = source_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise PatchGenerationError(
                    f"Could not read finding source {finding.file}"
                ) from exc
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
    repo_root = repo.resolve()
    if not repo_root.is_dir():
        typer.echo(f"Repository path is not a directory: {repo_root}", err=True)
        raise typer.Exit(code=2)
    try:
        settings = load_settings()
        client = build_llm_client(settings) if rule != "B105" else None
        scanner_adapter = build_scanner(
            scanner or settings.scanner,
            timeout_seconds=settings.scan_timeout_seconds,
            excluded_dirs=settings.scan_exclude_dirs,
        )
        baseline = scanner_adapter.scan(repo_root)
        findings = [finding for finding in baseline if finding.rule_id == rule][
            : settings.max_findings
        ]
        contexts = _prepare_finding_contexts(findings, repo_root, settings)
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
            source_path = (repo_root / Path(*finding.file.parts)).resolve()
            if not source_path.is_relative_to(repo_root):
                raise PatchGenerationError(
                    f"Finding path resolves outside repository: {finding.file}"
                )
            try:
                original_source = source_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise PatchGenerationError(
                    f"Could not read finding source {finding.file}"
                ) from exc
            proposed = agent.propose(finding, context_item, original_source)
            results.append(
                verify_patch(
                    proposed,
                    finding,
                    repo_root,
                    scanner_adapter,
                    baseline,
                    policy=settings.verify_policy,
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
    repo_root = repo.resolve()
    if not repo_root.is_dir():
        typer.echo(f"Repository path is not a directory: {repo_root}", err=True)
        raise typer.Exit(code=2)
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
        scanner_adapter = build_scanner(
            scanner or settings.scanner,
            timeout_seconds=settings.scan_timeout_seconds,
            excluded_dirs=settings.scan_exclude_dirs,
        )
        baseline = scanner_adapter.scan(repo_root)
        findings = [item for item in baseline if item.rule_id == rule][
            : settings.max_findings
        ]
        contexts = _prepare_finding_contexts(findings, repo_root, settings)
        if client is None:
            client = build_llm_client(settings)
        agent = LLMPatchAgent(
            client,
            output_mode=settings.llm_output,
            secret_environment=settings.secret_environment,
            sql_paramstyle=settings.sql_paramstyle,
        )
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
    except OmniPatchError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    outcomes: list[dict[str, object]] = []
    failed = False
    for finding in findings:
        verified = False
        try:
            context_item = contexts[finding.id]
            original_source = _read_finding_source(finding, repo_root)
            patch_item = agent.propose(finding, context_item, original_source)
            patched_source = materialize_patch_source(
                patch_item.unified_diff, finding, original_source
            )
            result = verify_patch(
                patch_item,
                finding,
                repo_root,
                scanner_adapter,
                baseline,
                policy=settings.verify_policy,
            )
            verified = result.verified
            required_environment = (
                (
                    settings.secret_environment[
                        secret_environment_key(finding, context_item)
                    ],
                )
                if finding.rule_id == "B105"
                else ()
            )
            url = (
                publisher.publish(
                    result,
                    finding,
                    patched_source,
                    required_environment=required_environment,
                    sql_paramstyle=(
                        settings.sql_paramstyle[
                            sql_paramstyle_key(finding, context_item)
                        ]
                        if finding.rule_id == "B608"
                        else None
                    ),
                )
                if publisher is not None and result.verified
                else None
            )
            outcome = _run_outcome(finding, result, url)
            if not result.verified:
                failed = True
            if as_json:
                outcomes.append(outcome)
            else:
                if result.introduced:
                    typer.echo(
                        "tolerated lower-severity findings: "
                        f"{', '.join(result.introduced)}"
                    )
                if result.verified:
                    typer.echo(
                        f"branch: omnipatch/{finding.rule_id.lower()}-{finding.id}"
                    )
                    typer.echo(f"title: {pull_request_title(finding)}")
                    _echo_patch_diff(patch_item.unified_diff)
                    typer.echo(
                        f"draft PR: {url}" if url else "dry run: no GitHub API calls"
                    )
                else:
                    typer.echo(redact(result.error or "Verification failed"), err=True)
        except OmniPatchError as exc:
            failed = True
            outcome = {
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "file": finding.file.as_posix(),
                "verified": verified,
                "pull_request_url": None,
                "error": redact(str(exc)),
                "introduced": [],
            }
            if as_json:
                outcomes.append(outcome)
            else:
                typer.echo(redact(str(exc)), err=True)
    if as_json:
        typer.echo(json.dumps(outcomes))
    if failed:
        raise typer.Exit(code=1)


def _read_finding_source(finding: Finding, repo_root: Path) -> str:
    """Read the real source for a finding after enforcing repository confinement."""
    source_path = (repo_root / Path(*finding.file.parts)).resolve()
    if not source_path.is_relative_to(repo_root):
        raise PatchGenerationError(
            f"Finding path resolves outside repository: {finding.file}"
        )
    try:
        return source_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise PatchGenerationError(
            f"Could not read finding source {finding.file}"
        ) from exc


def _prepare_finding_contexts(
    findings: list[Finding], repo_root: Path, settings: Settings
) -> dict[str, CodeContext]:
    """Extract contexts and fail before provider construction for unmapped targets."""
    # Keep this helper independent of model transport construction: missing secret
    # mappings must be actionable before any provider is called.
    contexts = {
        finding.id: extract_context(finding, repo_root, settings.context_max_lines)
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


def _run_outcome(
    finding: Finding, result: PatchResult, pull_request_url: str | None
) -> dict[str, object]:
    """Build one JSON run outcome without including source snippets or secrets."""
    return {
        "finding_id": finding.id,
        "rule_id": finding.rule_id,
        "file": finding.file.as_posix(),
        "verified": result.verified,
        "pull_request_url": pull_request_url,
        "error": None if result.error is None else redact(result.error),
        "introduced": list(result.introduced),
    }


def _echo_patch_diff(unified_diff: str) -> None:
    """Print a redacted display diff without exposing removed credential literals."""
    safe_diff = redact(unified_diff)
    if safe_diff != unified_diff:
        typer.echo(
            "warning: displayed diff contains redacted values and is not directly applicable",
            err=True,
        )
    typer.echo(safe_diff)

"""Generate, verify, and optionally publish patches for selected findings."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from omnipatch.agents.base import PatchAgent
from omnipatch.codebase.redaction import redact
from omnipatch.codebase.source import read_finding_source
from omnipatch.config import Settings
from omnipatch.errors import OmniPatchError
from omnipatch.models import CodeContext, Finding, Patch, PatchResult
from omnipatch.scanners.base import Scanner
from omnipatch.secret_environment import secret_environment_key, sql_paramstyle_key
from omnipatch.validation.patch_validator import materialize_patch_source
from omnipatch.vcs.github_client import PullRequestPublisher
from omnipatch.verification.patch_verifier import verify_patch


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """One finding's workflow result, safe for CLI presentation."""

    finding: Finding
    verified: bool
    patch: Patch | None = None
    result: PatchResult | None = None
    pull_request_url: str | None = None
    error: str | None = None

    def to_json_dict(self) -> dict[str, object]:
        """Serialize metadata only, excluding source and patch contents."""
        if self.error is not None:
            return {
                "finding_id": self.finding.id,
                "rule_id": self.finding.rule_id,
                "file": self.finding.file.as_posix(),
                "verified": self.verified,
                "pull_request_url": None,
                "error": self.error,
                "introduced": [],
            }
        result = self.result
        if result is None:
            raise ValueError("Run outcome requires a result or an error")
        return {
            "finding_id": self.finding.id,
            "rule_id": self.finding.rule_id,
            "file": self.finding.file.as_posix(),
            "verified": result.verified,
            "pull_request_url": self.pull_request_url,
            "error": None if result.error is None else redact(result.error),
            "introduced": list(result.introduced),
        }


@dataclass(frozen=True, slots=True)
class PreparedPublication:
    """Verified payload retained in memory until snapshot cleanup completes."""

    result: PatchResult
    finding: Finding
    source: str
    required_environment: tuple[str, ...]
    sql_paramstyle: str | None


def execute_run_workflow(
    findings: Sequence[Finding],
    contexts: Mapping[str, CodeContext],
    repo_root: Path,
    settings: Settings,
    agent: PatchAgent,
    scanner: Scanner,
    baseline: Sequence[Finding],
    publisher: PullRequestPublisher | None,
    *,
    root_identity: tuple[int, int],
    prepared_publications: list[PreparedPublication] | None = None,
) -> list[RunOutcome]:
    """Execute proposal, verification, and optional publication per finding."""
    outcomes: list[RunOutcome] = []
    for finding in findings:
        verified = False
        try:
            context = contexts[finding.id]
            original_source = read_finding_source(
                finding, repo_root, root_identity=root_identity
            )
            patch = agent.propose(finding, context, original_source)
            patched_source = materialize_patch_source(
                patch.unified_diff, finding, original_source
            )
            result = verify_patch(
                patch,
                finding,
                repo_root,
                scanner,
                baseline,
                policy=settings.verify_policy,
                root_identity=root_identity,
            )
            verified = result.verified
            required_environment = (
                (settings.secret_environment[secret_environment_key(finding, context)],)
                if finding.rule_id == "B105"
                else ()
            )
            sql_paramstyle = (
                settings.sql_paramstyle[sql_paramstyle_key(finding, context)]
                if finding.rule_id == "B608"
                else None
            )
            pull_request_url = None
            if publisher is not None and result.verified:
                if prepared_publications is None:
                    pull_request_url = publisher.publish(
                        result,
                        finding,
                        patched_source,
                        required_environment=required_environment,
                        sql_paramstyle=sql_paramstyle,
                    )
                else:
                    prepared_publications.append(
                        PreparedPublication(
                            result,
                            finding,
                            patched_source,
                            required_environment,
                            sql_paramstyle,
                        )
                    )
            outcomes.append(
                RunOutcome(
                    finding=finding,
                    verified=result.verified,
                    patch=patch,
                    result=result,
                    pull_request_url=pull_request_url,
                )
            )
        except OmniPatchError as exc:
            outcomes.append(
                RunOutcome(
                    finding=finding,
                    verified=verified,
                    error=redact(str(exc)),
                )
            )
    return outcomes


def publish_prepared_outcomes(
    outcomes: Sequence[RunOutcome],
    prepared: Sequence[PreparedPublication],
    publisher: PullRequestPublisher,
) -> list[RunOutcome]:
    """Publish only queued verified results after their snapshot is cleaned up."""
    by_finding = {outcome.finding.id: outcome for outcome in outcomes}
    for item in prepared:
        outcome = by_finding[item.finding.id]
        try:
            url = publisher.publish(
                item.result,
                item.finding,
                item.source,
                required_environment=item.required_environment,
                sql_paramstyle=item.sql_paramstyle,
            )
            by_finding[item.finding.id] = replace(outcome, pull_request_url=url)
        except OmniPatchError as exc:
            by_finding[item.finding.id] = replace(
                outcome, error=redact(str(exc)), pull_request_url=None
            )
    return [by_finding[outcome.finding.id] for outcome in outcomes]

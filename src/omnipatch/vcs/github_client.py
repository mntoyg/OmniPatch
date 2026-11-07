"""Publish verified source through the GitHub Contents API."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol, cast

from pydantic import SecretStr

from omnipatch.codebase.redaction import redact
from omnipatch.errors import VcsError
from omnipatch.models import Finding, PatchResult
from omnipatch.reporting.pr_body import (
    pull_request_title,
    render_pull_request_body,
)

_PULL_CREATION_UNCERTAIN = (
    "GitHub draft PR creation outcome is unknown; inspect for an existing draft PR "
    "and branch before retrying or cleaning up"
)


class GitHubContentLike(Protocol):
    """The repository file fields needed to update a file."""

    path: str
    sha: str


class GitHubCommitLike(Protocol):
    """The commit SHA used to create a branch."""

    sha: str


class GitHubBranchLike(Protocol):
    """A branch and its head commit."""

    name: str
    commit: GitHubCommitLike


class GitHubRefLike(Protocol):
    """A newly created branch reference that can be rolled back."""

    def delete(self) -> None:
        """Delete this reference from the repository."""


class GitHubPullRequestLike(Protocol):
    """The resulting pull request URL."""

    html_url: str


class GitHubRepositoryLike(Protocol):
    """Subset of repository APIs required for draft publication."""

    default_branch: str

    def get_branch(self, branch: str) -> GitHubBranchLike:
        """Return a branch or raise the SDK's translated error."""

    def create_git_ref(self, ref: str, sha: str) -> GitHubRefLike:
        """Create a new branch ref."""

    def get_contents(
        self, path: str, ref: str
    ) -> GitHubContentLike | list[GitHubContentLike]:
        """Read a file at a ref to obtain its blob SHA."""

    def update_file(
        self, path: str, message: str, content: str, sha: str, *, branch: str
    ) -> object:
        """Commit new file content to a branch."""

    def create_pull(
        self, base: str, head: str, *, title: str, body: str, draft: bool
    ) -> GitHubPullRequestLike:
        """Open a pull request."""


class GitHubSdkLike(Protocol):
    """Subset of the PyGithub client used by the publisher."""

    def get_repo(self, full_name: str) -> GitHubRepositoryLike:
        """Return an explicitly named repository."""


class _GitHubExceptionDetails(Protocol):
    """Typed diagnostic fields exposed by PyGithub exceptions."""

    status: int
    headers: Mapping[str, str] | None


class PullRequestPublisher(Protocol):
    """Publish a verified patch and return its draft pull request URL."""

    def publish(
        self,
        result: PatchResult,
        finding: Finding,
        patched_source: str,
        required_environment: tuple[str, ...] = (),
        sql_paramstyle: str | None = None,
    ) -> str:
        """Return the draft pull request URL, or raise VcsError."""


class GitHubPullRequestPublisher:
    """Create a deterministic branch and draft PR through PyGithub."""

    def __init__(
        self,
        token: str,
        repository: str,
        base_branch: str | None = None,
        sdk_client: GitHubSdkLike | None = None,
        timeout_seconds: int = 15,
    ) -> None:
        """Configure credentials, explicit repository, and injected SDK transport."""
        if (
            not repository
            or len(repository.split("/")) != 2
            or any(not part for part in repository.split("/"))
        ):
            raise VcsError("GitHub repository must be explicit as owner/name")
        if not token.strip():
            raise VcsError("GitHub token is required for publication")
        if timeout_seconds < 1:
            raise VcsError("GitHub timeout must be at least one second")
        self._token = SecretStr(token)
        self._repository = repository
        self._base_branch = base_branch
        self._timeout_seconds = timeout_seconds
        if sdk_client is None:
            try:
                self._sdk = _create_sdk(token, timeout_seconds)
            except Exception as exc:  # noqa: BLE001 -- Translate SDK initialization errors here.
                translated = _translate_sdk_error(exc, "")
                if translated is not None:
                    raise translated from None
                raise VcsError("Could not initialize GitHub client") from None
        else:
            self._sdk = sdk_client

    def __repr__(self) -> str:
        """Return a representation that never includes the GitHub token."""
        token = self._token.get_secret_value()
        safe_repository = self._repository.replace(token, "[redacted]")
        return f"{type(self).__name__}(repository={safe_repository!r})"

    def branch_name(self, finding: Finding) -> str:
        """Return the deterministic branch name for a finding."""
        return f"omnipatch/{finding.rule_id.lower()}-{finding.id}"

    def publish(
        self,
        result: PatchResult,
        finding: Finding,
        patched_source: str,
        required_environment: tuple[str, ...] = (),
        sql_paramstyle: str | None = None,
    ) -> str:
        """Publish only verified, validator-produced source as a draft pull request."""
        if not result.verified:
            raise VcsError(result.error or "Patch has not passed verification")
        if result.patch.finding_id != finding.id:
            raise VcsError("Verified patch does not match the finding")
        if finding.file.is_absolute() or ".." in finding.file.parts:
            raise VcsError("Finding path is not repository-relative")

        branch = self.branch_name(finding)
        if self._token.get_secret_value() in branch:
            raise VcsError("Finding identifier cannot contain credential material")
        title = pull_request_title(finding)
        body = render_pull_request_body(
            result,
            finding,
            required_environment=required_environment,
            sql_paramstyle=sql_paramstyle,
        )
        commit_message = f"{title}\n\n{redact(result.patch.explanation)}"
        created_ref: GitHubRefLike | None = None
        pull_creation_attempted = False
        try:
            repository = self._sdk.get_repo(self._repository)
            base = repository.get_branch(self._base_branch or repository.default_branch)
            try:
                created_ref = repository.create_git_ref(
                    ref=f"refs/heads/{branch}", sha=base.commit.sha
                )
            except Exception as exc:
                status = _exception_status(exc)
                if _is_github_exception(exc) and status == 422:
                    raise VcsError(
                        f"GitHub branch already exists: {branch} (HTTP 422)"
                    ) from None
                raise
            content = repository.get_contents(finding.file.as_posix(), ref=branch)
            if isinstance(content, list):
                raise VcsError(f"GitHub path is not a file: {finding.file.as_posix()}")
            repository.update_file(
                content.path,
                commit_message,
                patched_source,
                content.sha,
                branch=branch,
            )
            pull_creation_attempted = True
            pull = repository.create_pull(
                base=base.name,
                head=branch,
                title=title,
                body=body,
                draft=True,
            )
            created_ref = None
            return pull.html_url
        except VcsError:
            if pull_creation_attempted:
                raise VcsError(_PULL_CREATION_UNCERTAIN) from None
            _rollback_ref(created_ref, branch)
            raise
        except Exception as exc:
            if pull_creation_attempted:
                raise VcsError(_PULL_CREATION_UNCERTAIN) from None
            _rollback_ref(created_ref, branch)
            translated = _translate_sdk_error(exc, branch)
            if translated is None:
                raise
            raise translated from None


def _create_sdk(token: str, timeout_seconds: int) -> GitHubSdkLike:
    """Construct PyGithub lazily so offline tests can guard its import binding."""
    from github import Auth, Github

    return cast(GitHubSdkLike, Github(auth=Auth.Token(token), timeout=timeout_seconds))


def _format_reset(value: str) -> str:
    """Format a rate-limit reset timestamp without exposing response contents."""
    try:
        return datetime.fromtimestamp(int(value), tz=UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        return "time unavailable"


def _rollback_ref(created_ref: GitHubRefLike | None, branch: str) -> None:
    """Delete a ref created by this call and report cleanup failures."""
    if created_ref is None:
        return
    try:
        created_ref.delete()
    except Exception:  # noqa: BLE001 -- cleanup must not replace the original failure.
        print(f"warning: unable to delete orphaned branch {branch}", file=sys.stderr)


def _exception_status(exc: Exception) -> int | None:
    """Read the integer status from a third-party exception without Any."""
    if not _is_github_exception(exc) or type(exc).__name__ == "BadAttributeException":
        return None
    return cast(_GitHubExceptionDetails, exc).status


def _is_github_exception(exc: Exception) -> bool:
    """Identify PyGithub exceptions by their defining module."""
    return type(exc).__module__.startswith("github.")


def _translate_sdk_error(exc: Exception, branch: str) -> VcsError | None:
    """Translate known SDK/network exceptions without leaking response data."""
    name = type(exc).__name__
    status = _exception_status(exc)
    suffix = f" (HTTP {status})" if status is not None else ""
    if name == "BadCredentialsException":
        return VcsError(f"GitHub authentication failed{suffix}")
    if name == "RateLimitExceededException":
        headers = cast(_GitHubExceptionDetails, exc).headers
        reset = headers.get("X-RateLimit-Reset") if headers is not None else None
        detail = f"; reset at {_format_reset(str(reset))}" if reset is not None else ""
        return VcsError(f"GitHub rate limit exceeded{suffix}{detail}")
    if name == "UnknownObjectException":
        return VcsError(f"GitHub repository or branch was not found{suffix}")
    if name == "BadUserAgentException":
        return VcsError(f"GitHub rejected the client user agent{suffix}")
    if name == "TwoFactorException":
        return VcsError(f"GitHub requires additional authentication{suffix}")
    if name == "BadAttributeException":
        return VcsError(f"GitHub SDK rejected a request attribute{suffix}")
    if _is_github_exception(exc):
        return VcsError(f"GitHub API request failed{suffix}")
    if type(exc).__module__.startswith("requests."):
        return VcsError("Could not connect to GitHub")
    return None

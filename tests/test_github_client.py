"""Offline unit tests for GitHub publishing and pull request rendering."""

from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import cast

import github
import pytest
from github import (
    BadAttributeException,
    BadCredentialsException,
    BadUserAgentException,
    GithubException,
    RateLimitExceededException,
    TwoFactorException,
    UnknownObjectException,
)
from requests.exceptions import RequestException

from omnipatch.codebase.ast_tools import extract_context
from omnipatch.errors import VcsError
from omnipatch.models import Finding, PatchResult, Severity
from omnipatch.reporting.pr_body import pull_request_title, render_pull_request_body
from omnipatch.validation.patch_validator import (
    materialize_patch_source,
    validate_patch,
)
from omnipatch.vcs.github_client import GitHubPullRequestPublisher, GitHubSdkLike

TOKEN = "ghp_SENTINEL_DO_NOT_LOG"
API_KEY = "sk-ant-SENTINEL_DO_NOT_LOG"
ORIGINAL = 'PASSWORD = "realsecret"\nquery = input()\n'
DIFF = (
    "--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n-query = input()\n+query = str(input())\n"
)


class FakeRepository:
    """Capture expected repository methods and emulate PyGithub objects."""

    default_branch = "main"

    def __init__(
        self,
        *,
        ref_error: Exception | None = None,
        contents: object = None,
        failures: dict[str, Exception] | None = None,
        delete_error: Exception | None = None,
        pull_response_lost: bool = False,
    ) -> None:
        """Configure optional failures and record each SDK call."""
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.ref_error = ref_error
        self.failures = failures or {}
        self.delete_error = delete_error
        self.pull_response_lost = pull_response_lost
        self.accepted_pulls: list[dict[str, object]] = []
        self.contents = (
            contents
            if contents is not None
            else SimpleNamespace(path="app.py", sha="blob-sha")
        )

    def _fail(self, method: str) -> None:
        """Raise the configured failure after recording a method call."""
        error = self.failures.get(method)
        if error is not None:
            raise error

    def get_branch(self, branch: str) -> SimpleNamespace:
        """Return a fake base branch."""
        self.calls.append(("get_branch", (branch,), {}))
        self._fail("get_branch")
        return SimpleNamespace(name=branch, commit=SimpleNamespace(sha="base-sha"))

    def create_git_ref(self, *, ref: str, sha: str) -> object:
        """Record the create-ref write or raise its configured error."""
        self.calls.append(("create_git_ref", (), {"ref": ref, "sha": sha}))
        if self.ref_error is not None:
            raise self.ref_error
        return SimpleNamespace(delete=self._delete_ref)

    def _delete_ref(self) -> None:
        """Record deletion of the ref created by this fake repository."""
        self.calls.append(("delete_ref", (), {}))
        if self.delete_error is not None:
            raise self.delete_error

    def get_contents(self, path: str, *, ref: str) -> object:
        """Return a file object or a directory listing."""
        self.calls.append(("get_contents", (path,), {"ref": ref}))
        self._fail("get_contents")
        return self.contents

    def update_file(
        self, path: str, message: str, content: str, sha: str, *, branch: str
    ) -> None:
        """Record the real content sent to the API."""
        self.calls.append(
            ("update_file", (path, message, content, sha), {"branch": branch})
        )
        self._fail("update_file")

    def create_pull(
        self, base: str, head: str, *, title: str, body: str, draft: bool
    ) -> SimpleNamespace:
        """Record keyword-only draft pull request arguments."""
        self.calls.append(
            (
                "create_pull",
                (base, head),
                {"title": title, "body": body, "draft": draft},
            )
        )
        if self.pull_response_lost:
            self.accepted_pulls.append({"base": base, "head": head, "draft": draft})
            raise RequestException("response lost")
        self._fail("create_pull")
        self.accepted_pulls.append({"base": base, "head": head, "draft": draft})
        return SimpleNamespace(html_url="https://github.com/acme/app/pull/7")


class FakeSdk:
    """Return one injected repository while recording the explicit name."""

    def __init__(self, repository: FakeRepository) -> None:
        """Store the repository and initialize call history."""
        self.repository = repository
        self.calls: list[str] = []

    def get_repo(self, full_name: str) -> FakeRepository:
        """Return only the named repository."""
        self.calls.append(full_name)
        return self.repository


def fixture() -> tuple[Finding, PatchResult, str]:
    """Build a verified patch whose real source contains a credential."""
    finding = Finding(
        id="finding-123",
        rule_id="B608",
        title="SQL query construction",
        severity=Severity.HIGH,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="SQL injection vector",
        source="bandit",
        cwe="CWE-89",
    )
    patch = validate_patch(DIFF, finding, ORIGINAL, "fake-model")
    result = PatchResult(patch, applied=True, verified=True)
    return finding, result, materialize_patch_source(DIFF, finding, ORIGINAL)


def publisher(repository: FakeRepository) -> GitHubPullRequestPublisher:
    """Build a publisher backed by the offline fake SDK."""
    return GitHubPullRequestPublisher(
        TOKEN, "acme/app", sdk_client=cast(object, FakeSdk(repository))
    )


def test_github_is_not_bound_when_transport_module_is_imported() -> None:
    """The SDK constructor is resolved only when a live client is requested."""
    import omnipatch.vcs.github_client as transport

    assert "Github" not in vars(transport)
    assert github.Github is not None


def test_publish_uses_contents_api_and_always_creates_a_draft() -> None:
    """Publish in order through a branch, file update, and draft pull request."""
    finding, result, patched_source = fixture()
    repository = FakeRepository()
    sdk = FakeSdk(repository)
    client = GitHubPullRequestPublisher(
        TOKEN, "acme/app", sdk_client=cast(GitHubSdkLike, sdk)
    )

    url = client.publish(result, finding, patched_source)

    assert url == "https://github.com/acme/app/pull/7"
    assert sdk.calls == ["acme/app"]
    assert [call[0] for call in repository.calls] == [
        "get_branch",
        "create_git_ref",
        "get_contents",
        "update_file",
        "create_pull",
    ]
    assert not any(
        call[0] in {"merge", "enable_automerge"} for call in repository.calls
    )
    assert repository.calls[-1][2]["draft"] is True
    assert not any(call[0] == "delete_ref" for call in repository.calls)
    assert repository.calls[1][2] == {
        "ref": "refs/heads/omnipatch/b608-finding-123",
        "sha": "base-sha",
    }


def test_default_sdk_uses_named_auth_and_configured_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live SDK constructor uses Auth.Token and an explicit timeout."""
    captured: dict[str, object] = {}

    def fake_github(*args: object, **kwargs: object) -> FakeSdk:
        """Capture constructor arguments while returning an offline SDK."""
        captured["args"] = args
        captured.update(kwargs)
        return FakeSdk(FakeRepository())

    monkeypatch.setattr(github, "Github", fake_github)
    client = GitHubPullRequestPublisher(TOKEN, "acme/app", timeout_seconds=23)

    assert isinstance(client, GitHubPullRequestPublisher)
    assert captured["args"] == ()
    assert "auth" in captured
    assert captured["timeout"] == 23


def test_unverified_patch_makes_zero_api_calls() -> None:
    """The publication gate rejects unverified results before the transport."""
    finding, result, source = fixture()
    bad_result = PatchResult(
        result.patch, applied=True, verified=False, error="B602 remains"
    )
    repository = FakeRepository()
    sdk = FakeSdk(repository)
    client = GitHubPullRequestPublisher(TOKEN, "acme/app", sdk_client=cast(object, sdk))

    with pytest.raises(VcsError, match="B602 remains"):
        client.publish(bad_result, finding, source)

    assert sdk.calls == []
    assert repository.calls == []


def test_real_patched_source_preserves_credential_for_contents_api(
    tmp_path: Path,
) -> None:
    """Publishing uses validator output, never redacted model context."""
    finding, result, patched_source = fixture()
    (tmp_path / finding.file.as_posix()).write_text(ORIGINAL, encoding="utf-8")
    context = extract_context(finding, tmp_path, 80)
    assert "<redacted by omnipatch>" in context.snippet
    assert API_KEY not in context.snippet
    repository = FakeRepository()

    publisher(repository).publish(result, finding, patched_source)

    update_call = next(call for call in repository.calls if call[0] == "update_file")
    sent_content = update_call[1][2]
    assert isinstance(sent_content, str)
    assert 'PASSWORD = "realsecret"' in sent_content
    assert "<redacted by omnipatch>" not in sent_content


def test_deterministic_branch_and_secret_redaction() -> None:
    """Repeated publication names match and secrets stay out of metadata."""
    finding, result, source = fixture()
    first_repo = FakeRepository()
    second_repo = FakeRepository()
    first = publisher(first_repo)
    second = publisher(second_repo)

    first.publish(result, finding, source)
    second.publish(result, finding, source)

    branch_a = first_repo.calls[1][2]["ref"]
    branch_b = second_repo.calls[1][2]["ref"]
    commit_message = next(
        call for call in first_repo.calls if call[0] == "update_file"
    )[1][1]
    body = render_pull_request_body(result, finding)
    assert branch_a == branch_b == "refs/heads/omnipatch/b608-finding-123"
    assert TOKEN not in repr(first)
    assert TOKEN not in str(commit_message)
    assert TOKEN not in body and API_KEY not in body
    assert pull_request_title(finding).startswith("fix(B608):")
    assert len(pull_request_title(finding)) <= 72


def test_repr_redacts_token_even_if_it_matches_repository_text() -> None:
    """Unusual explicit repository names cannot echo the configured token."""
    client = GitHubPullRequestPublisher(
        TOKEN,
        f"acme/{TOKEN}",
        sdk_client=cast(GitHubSdkLike, FakeSdk(FakeRepository())),
    )

    assert TOKEN not in repr(client)


def test_existing_branch_is_reported_without_opening_pull_request() -> None:
    """HTTP 422 on create-ref is a visible collision and stops publication."""
    finding, result, source = fixture()
    repository = FakeRepository(ref_error=GithubException(422, {"message": TOKEN}))

    with pytest.raises(
        VcsError, match="branch already exists: omnipatch/b608-finding-123"
    ) as captured:
        publisher(repository).publish(result, finding, source)

    assert not any(call[0] == "create_pull" for call in repository.calls)
    assert not any(call[0] == "delete_ref" for call in repository.calls)
    assert TOKEN not in str(captured.value)


def test_failure_before_ref_creation_has_no_remote_cleanup() -> None:
    """A base-branch lookup failure occurs before any ref or file side effect."""
    finding, result, source = fixture()
    repository = FakeRepository(
        failures={"get_branch": GithubException(500, {"message": TOKEN})}
    )

    with pytest.raises(VcsError, match="HTTP 500"):
        publisher(repository).publish(result, finding, source)

    assert [call[0] for call in repository.calls] == ["get_branch"]


def test_directory_get_contents_is_a_vcs_error() -> None:
    """A list from get_contents is rejected as a directory, not indexed."""
    finding, result, source = fixture()
    repository = FakeRepository(contents=[])

    with pytest.raises(VcsError, match="path is not a file"):
        publisher(repository).publish(result, finding, source)

    assert not any(call[0] == "create_pull" for call in repository.calls)
    assert any(call[0] == "delete_ref" for call in repository.calls)


@pytest.mark.parametrize("failed_method", ["get_contents", "update_file"])
def test_failed_delivery_rolls_back_created_ref_and_retry_can_succeed(
    failed_method: str,
) -> None:
    """A failed post-ref API call removes only its new branch and allows retry."""
    finding, result, source = fixture()
    failed_repository = FakeRepository(
        failures={failed_method: GithubException(500, {"message": TOKEN})}
    )

    with pytest.raises(VcsError, match="HTTP 500") as captured:
        publisher(failed_repository).publish(result, finding, source)

    assert "HTTP 500" in str(captured.value)
    expected_calls = {
        "get_contents": [
            "get_branch",
            "create_git_ref",
            "get_contents",
            "delete_ref",
        ],
        "update_file": [
            "get_branch",
            "create_git_ref",
            "get_contents",
            "update_file",
            "delete_ref",
        ],
    }
    assert [call[0] for call in failed_repository.calls] == expected_calls[
        failed_method
    ]
    retry_repository = FakeRepository()
    assert publisher(retry_repository).publish(result, finding, source) == (
        "https://github.com/acme/app/pull/7"
    )


@pytest.mark.parametrize(
    ("accepted", "pull_response_lost"),
    [(True, True), (False, False)],
    ids=["accepted-response-lost", "not-accepted-error"],
)
def test_pull_creation_failure_preserves_ref_and_requires_inspection(
    accepted: bool, pull_response_lost: bool
) -> None:
    """Any PR attempt preserves its branch because remote acceptance is ambiguous."""
    finding, result, source = fixture()
    failure = (
        {} if accepted else {"create_pull": GithubException(500, {"message": TOKEN})}
    )
    repository = FakeRepository(failures=failure, pull_response_lost=pull_response_lost)

    with pytest.raises(VcsError) as captured:
        publisher(repository).publish(result, finding, source)

    calls = [call[0] for call in repository.calls]
    assert calls.count("create_pull") == 1
    assert "delete_ref" not in calls
    assert repository.accepted_pulls == (
        [{"base": "main", "head": "omnipatch/b608-finding-123", "draft": True}]
        if accepted
        else []
    )
    message = str(captured.value)
    assert "outcome is unknown" in message
    assert "inspect for an existing draft PR and branch" in message
    assert "before retrying or cleaning up" in message
    assert TOKEN not in message
    assert API_KEY not in message
    assert source not in message


def test_request_exception_rolls_back_created_ref() -> None:
    """Network failures after ref creation also trigger compensating cleanup."""
    finding, result, source = fixture()
    repository = FakeRepository(failures={"update_file": RequestException("offline")})

    with pytest.raises(VcsError, match="Could not connect to GitHub"):
        publisher(repository).publish(result, finding, source)

    assert [call[0] for call in repository.calls].count("delete_ref") == 1


def test_rollback_failure_warns_and_preserves_original_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed delete is visible but cannot replace the delivery error."""
    finding, result, source = fixture()
    repository = FakeRepository(
        failures={"update_file": GithubException(500, {})},
        delete_error=RequestException("cleanup unavailable"),
    )

    with pytest.raises(VcsError, match="HTTP 500"):
        publisher(repository).publish(result, finding, source)

    assert "warning: unable to delete orphaned branch omnipatch/b608-finding-123" in (
        capsys.readouterr().err
    )


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (BadCredentialsException(401, {}), "authentication failed"),
        (UnknownObjectException(404, {}), "was not found"),
        (BadUserAgentException(400, {}), "user agent"),
        (TwoFactorException(401, {}), "additional authentication"),
        (BadAttributeException("x", str, None), "request attribute"),
        (RequestException("offline"), "Could not connect to GitHub"),
        (GithubException(500, {"message": TOKEN}), "HTTP 500"),
    ],
)
def test_sdk_errors_are_translated_without_leaking_token(
    exception: Exception, message: str
) -> None:
    """Each known SDK class maps to a safe operator-facing VcsError."""
    finding, result, source = fixture()

    class BrokenSdk:
        """Raise one configured API exception on the first call."""

        def get_repo(self, full_name: str) -> object:
            """Raise the configured error regardless of repository name."""
            raise exception

    client = GitHubPullRequestPublisher(
        TOKEN, "acme/app", sdk_client=cast(object, BrokenSdk())
    )
    with pytest.raises(VcsError, match=message) as captured:
        client.publish(result, finding, source)
    assert TOKEN not in str(captured.value)


def test_rate_limit_message_includes_reset_time() -> None:
    """A rate-limit diagnostic includes its reset timestamp when available."""
    finding, result, source = fixture()

    class LimitedSdk:
        """Raise a rate-limit exception with a reset epoch."""

        def get_repo(self, full_name: str) -> object:
            """Raise the configured rate-limit response."""
            raise RateLimitExceededException(
                403, {}, {"X-RateLimit-Reset": "1893456000"}
            )

    client = GitHubPullRequestPublisher(
        TOKEN, "acme/app", sdk_client=cast(object, LimitedSdk())
    )
    with pytest.raises(VcsError, match="2030-01-01"):
        client.publish(result, finding, source)


def test_pull_request_body_contains_required_metadata_only() -> None:
    """The body names the finding, verification, and human review requirement."""
    finding, result, _ = fixture()
    body = render_pull_request_body(result, finding)

    for expected in (
        "B608",
        "high",
        "CWE-89",
        "app.py",
        "| 2 |",
        "re-scanned in isolation",
        "target finding is gone",
        "no new finding appeared",
        "human must review",
    ):
        assert expected in body
    assert TOKEN not in body and API_KEY not in body


def test_b105_pull_request_discloses_required_environment_and_still_requires_verified() -> (
    None
):
    """A verified B105 draft names mandatory environment configuration."""
    finding, result, _ = fixture()
    finding = replace(
        finding,
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
    )
    result = PatchResult(
        replace(result.patch, finding_id=finding.id), applied=True, verified=True
    )

    body = render_pull_request_body(
        result, finding, required_environment=("APP_PASSWORD",)
    )

    assert "### Required environment" in body
    assert "`APP_PASSWORD`" in body
    assert "reads these environment variables at import" in body
    assert "will fail to start if any is unset" in body
    assert render_pull_request_body(result, finding, ()) == render_pull_request_body(
        result, finding
    )
    with pytest.raises(ValueError, match="unverified patch"):
        render_pull_request_body(
            replace(result, verified=False),
            finding,
            required_environment=("APP_PASSWORD",),
        )

    repository = FakeRepository()
    publisher(repository).publish(
        result,
        finding,
        "import os\nPASSWORD = os.environ['APP_PASSWORD']\n",
        required_environment=("APP_PASSWORD",),
    )
    pull_request = next(call for call in repository.calls if call[0] == "create_pull")
    assert "`APP_PASSWORD`" in str(pull_request[2]["body"])


def test_pull_request_body_discloses_tolerated_lower_severity_findings() -> None:
    """PR copy names the introduced findings and asks human review."""
    finding, result, _ = fixture()
    result = PatchResult(
        result.patch,
        applied=True,
        verified=True,
        introduced=("B404 in app.py", "B603 in app.py"),
    )
    body = render_pull_request_body(result, finding)
    assert "B404 in app.py" in body
    assert "B603 in app.py" in body
    assert "severity trade-off" in body
    assert "no new finding appeared" not in body


def test_pull_request_body_redacts_sentinels_in_finding_metadata() -> None:
    """Credential-shaped scanner metadata never enters the pull request body."""
    finding, result, source = fixture()
    finding = replace(finding, title=f"password {TOKEN} {API_KEY}")
    result = PatchResult(
        replace(result.patch, explanation=f"B608: {TOKEN} {API_KEY}"),
        applied=True,
        verified=True,
    )

    body = render_pull_request_body(result, finding)
    repository = FakeRepository()
    publisher(repository).publish(result, finding, source)
    branch = repository.calls[1][2]["ref"]
    commit_message = next(
        call for call in repository.calls if call[0] == "update_file"
    )[1][1]

    assert TOKEN not in body
    assert API_KEY not in body
    assert TOKEN not in str(branch) and API_KEY not in str(branch)
    assert TOKEN not in str(commit_message) and API_KEY not in str(commit_message)


def test_sql_paramstyle_pr_assumption_is_optional_and_explicit() -> None:
    finding, result, _ = fixture()
    default_body = render_pull_request_body(result, finding)
    configured_body = render_pull_request_body(result, finding, sql_paramstyle="qmark")
    assert "### Assumptions" not in default_body
    assert "### Assumptions" in configured_body
    assert "`qmark`" in configured_body
    assert "came from explicit configuration" in configured_body
    assert "not detected from the source" in configured_body
    assert (
        render_pull_request_body(result, finding, sql_paramstyle=None) == default_body
    )
    repository = FakeRepository()
    publisher(repository).publish(
        result,
        finding,
        "query = 'SELECT 1'\n",
        sql_paramstyle="qmark",
    )
    pull_request = next(call for call in repository.calls if call[0] == "create_pull")
    assert "SQL parameter style: `qmark`" in str(pull_request[2]["body"])

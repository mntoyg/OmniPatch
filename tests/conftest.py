"""Global offline guard for unit tests."""

import urllib.request

import anthropic
import github
import pytest


@pytest.fixture(autouse=True)
def prevent_real_anthropic_client(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail if a non-integration test tries to construct the network client."""
    if request.node.get_closest_marker("integration") is None:
        # Paired with the `import anthropic` lookup in agents/anthropic_client.py.
        def forbidden_client(*args: object, **kwargs: object) -> None:
            """Reject accidental real Anthropic client construction."""
            raise AssertionError("A unit test constructed a real Anthropic client")

        monkeypatch.setattr(anthropic, "Anthropic", forbidden_client)
        # Paired with the lazy `from github import Auth, Github` in vcs/github_client.py.
        monkeypatch.setattr(github, "Github", forbidden_client)
        # Paired with the dynamically built urllib opener in agents/ollama_client.py.
        monkeypatch.setattr(urllib.request, "urlopen", forbidden_client)
        monkeypatch.setattr(urllib.request, "build_opener", forbidden_client)

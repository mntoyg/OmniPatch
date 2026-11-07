"""Regression proving the B105 module rewrite never edits unrelated bindings."""

from pathlib import Path

from omnipatch.agents.llm_agent import LLMPatchAgent
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.scanners.bandit_scanner import BanditScanner
from omnipatch.validation.patch_validator import materialize_patch_source


class FakeCompletionClient:
    """Return a configured model completion without network access."""

    model = "fake-model"

    def complete(self, system: str, user: str) -> str:
        return (
            "import os\n\n"
            'CONFIGURED_PASSWORD = os.environ["APP_PASSWORD"]\n'
            'API_TOKEN_SECRET = os.getenv("API_TOKEN_SECRET")'
        )


def test_b105_unmapped_sensitive_constant_is_not_rewritten(tmp_path: Path) -> None:
    """A mapped finding is repaired without rewriting a neighboring constant."""
    original = (
        "import os\n\n"
        'CONFIGURED_PASSWORD = "SELF-LABELLED-PASSWORD"\n'
        'API_TOKEN_SECRET = "SELF-LABELLED-TOKEN"\n'
    )
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "app.py").write_text(original, encoding="utf-8")
    finding = next(
        item
        for item in BanditScanner().scan(target_root)
        if item.rule_id == "B105" and item.line_start == 3
    )
    context = extract_context(finding, target_root)
    patch = LLMPatchAgent(
        FakeCompletionClient(),
        output_mode="function",
        secret_environment={"app.py::<module>": "APP_PASSWORD"},
    ).propose(finding, context, original)
    published = materialize_patch_source(patch.unified_diff, finding, original)

    assert 'API_TOKEN_SECRET = os.getenv("API_TOKEN_SECRET")' in published
    assert "os.environ['API_TOKEN_SECRET']" not in published

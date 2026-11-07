"""Offline tests for rewrite-scope diff generation and validation."""

import ast
import json
import sqlite3
from pathlib import Path, PurePosixPath
from textwrap import dedent

import pytest

from omnipatch.agents.function_rewrite import rewrite_scope_to_diff
from omnipatch.agents.llm_agent import (
    LLMPatchAgent,
    _validate_b105_environment_candidate,
)
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.codebase.redaction import REDACTION_MARKER
from omnipatch.errors import PatchGenerationError
from omnipatch.models import CodeContext, Finding, PatchResult, Severity
from omnipatch.scanners.bandit_scanner import BanditScanner
from omnipatch.validation.patch_validator import (
    materialize_patch_source,
    strip_fence,
    validate_patch,
)
from omnipatch.verification.patch_verifier import verify_patch


class FakeCompletionClient:
    """Return a configured rewritten scope and record its prompt."""

    model = "fake-model"

    def __init__(self, *responses: str) -> None:
        """Store the model output."""
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        """Record the request and return the configured response."""
        self.calls.append((system, user))
        return self.responses[len(self.calls) - 1]


def _finding() -> Finding:
    """Return a stable finding for the test module's app.py scope."""
    return Finding(
        id="function-finding",
        rule_id="B999",
        title="Unsafe input query",
        severity=Severity.HIGH,
        file=PurePosixPath("app.py"),
        line_start=4,
        line_end=4,
        message="SQL injection",
        source="test",
    )


def _context(snippet: str, start: int = 2) -> CodeContext:
    """Return function context beginning at the configured source line."""
    return CodeContext("function-finding", snippet, start, "load_user", ())


def test_rewritten_scope_splices_exactly_and_diff_revalidates() -> None:
    """Only the context line range changes and the standard validator accepts it."""
    finding = _finding()
    original = (
        'PASSWORD = "outside-secret"\n'
        "def load_user():\n"
        "    query = input()\n"
        "    return query\n"
        "AFTER = True\n"
    )
    snippet = "def load_user():\n    query = input()\n    return query"
    rewritten = "def load_user():\n    query = str(input())\n    return query"
    context = _context(snippet)

    diff = rewrite_scope_to_diff(rewritten, context, original, finding)
    patch = validate_patch(diff, finding, original, "fake-model")

    assert patch.unified_diff == diff
    patched = materialize_patch_source(patch.unified_diff, finding, original)
    assert patched == (
        'PASSWORD = "outside-secret"\n'
        "def load_user():\n"
        "    query = str(input())\n"
        "    return query\n"
        "AFTER = True\n"
    )


def test_splice_uses_original_source_not_redacted_snippet() -> None:
    """Real source outside a redacted context remains present in the patch result."""
    finding = _finding()
    original = (
        'PASSWORD = "real-credential"\n'
        "def load_user():\n"
        '    API_KEY = "scope-credential"\n'
        "    query = input()\n"
    )
    redacted_context = _context(
        "def load_user():\n"
        '    API_KEY = "<redacted by omnipatch>"\n'
        "    query = input()",
    )
    rewritten = "def load_user():\n    query = str(input())\n    return query"

    diff = rewrite_scope_to_diff(rewritten, redacted_context, original, finding)
    patched = materialize_patch_source(diff, finding, original)

    assert 'PASSWORD = "real-credential"' in patched
    assert "<redacted by omnipatch>" not in patched


def test_sensitive_return_secret_fails_closed_before_fake_provider(
    tmp_path: Path,
) -> None:
    """Unsupported return targets fail closed without exposing their secret."""
    original = (
        "import os\n"
        'API_KEY = "UNRELATED-REAL-CREDENTIAL"\n'
        "def get_password():\n"
        '    return "SELF-LABELLED-RETURN-SECRET"\n'
    )
    (tmp_path / "app.py").write_text(original, encoding="utf-8")
    finding = Finding(
        id="sensitive-return-finding",
        rule_id="B105",
        title="Hard-coded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=4,
        line_end=4,
        message="Possible hard-coded password",
        source="test",
    )
    context = extract_context(finding, tmp_path)
    client = FakeCompletionClient("unused")
    with pytest.raises(
        PatchGenerationError, match="direct string assignment"
    ) as caught:
        LLMPatchAgent(
            client,
            output_mode="function",
            secret_environment={"app.py::get_password": "APP_PASSWORD"},
        ).propose(finding, context, original)
    assert client.calls == []
    assert "SELF-LABELLED-RETURN-SECRET" not in str(caught.value)
    assert "SELF-LABELLED-RETURN-SECRET" not in context.snippet
    assert REDACTION_MARKER in context.snippet


def test_b105_without_explicit_mapping_never_calls_provider(
    tmp_path: Path,
) -> None:
    """The agent refuses to guess a variable name when no mapping is supplied."""
    original = 'def configured_password():\n    return "SELF-LABELLED-SECRET"\n'
    (tmp_path / "app.py").write_text(original, encoding="utf-8")
    finding = Finding(
        id="missing-map-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Possible hardcoded password",
        source="test",
    )
    context = extract_context(finding, tmp_path)
    client = FakeCompletionClient("unused")

    with pytest.raises(PatchGenerationError, match="app.py::configured_password"):
        LLMPatchAgent(client, output_mode="function").propose(
            finding, context, original
        )
    assert client.calls == []


def test_b105_candidate_must_use_exact_mapping_without_original_literal(
    tmp_path: Path,
) -> None:
    """A model cannot ignore the mapped name or retain the source literal."""
    original = (
        "def configured_password():\n"
        '    password = "SELF-LABELLED-SECRET"\n'
        "    return password\n"
    )
    (tmp_path / "app.py").write_text(original, encoding="utf-8")
    finding = Finding(
        id="mapped-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Possible hardcoded password",
        source="test",
    )
    context = extract_context(finding, tmp_path)
    client = FakeCompletionClient(
        "import os\n\n"
        "def configured_password():\n"
        '    password = os.environ["OTHER_PASSWORD"]\n'
        "    return password\n"
    )

    with pytest.raises(
        PatchGenerationError, match="configured required environment lookup"
    ):
        LLMPatchAgent(
            client,
            max_repair_attempts=0,
            output_mode="function",
            secret_environment={"app.py::configured_password": "APP_PASSWORD"},
        ).propose(finding, context, original)


def test_b105_required_lookup_must_replace_the_original_assignment() -> None:
    """A required lookup is accepted only at the original secret binding."""
    original = (
        "def configured_password():\n"
        '    password = "SELF-LABELLED-SECRET"\n'
        "    return password\n"
    )
    candidate = (
        "import os\n\n"
        "def configured_password():\n"
        '    password = os.environ["APP_PASSWORD"]\n'
        "    return password\n"
    )
    finding = Finding(
        id="target-binding-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Possible hardcoded password",
        source="test",
    )

    _validate_b105_environment_candidate(original, candidate, finding, "APP_PASSWORD")


def _op16_b105_target(tmp_path: Path, source: str) -> tuple[Finding, CodeContext]:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    finding = next(
        item for item in BanditScanner().scan(tmp_path) if item.rule_id == "B105"
    )
    return finding, extract_context(finding, tmp_path)


def _op16_candidate() -> str:
    return (
        "def configured_password():\n"
        '    """Return a deliberately hardcoded, self-labelled fake password."""\n'
        '    password = os.environ["APP_PASSWORD"]\n'
        "    return password"
    )


def test_b105_measured_unbound_os_candidate_is_refused(
    tmp_path: Path,
) -> None:
    """The measured valid-syntax candidate is refused for its missing binding."""
    sentinel = "FAKE_BENCHMARK_OP16_PASSWORD_DO_NOT_USE"
    source = (
        "def configured_password():\n"
        '    """Return a deliberately hardcoded, self-labelled fake password."""\n'
        f'    password = "{sentinel}"\n'
        "    return password\n"
    )
    finding, context = _op16_b105_target(tmp_path, source)
    client = FakeCompletionClient(_op16_candidate())
    with pytest.raises(PatchGenerationError) as caught:
        LLMPatchAgent(
            client,
            max_repair_attempts=0,
            output_mode="function",
            secret_environment={"app.py::configured_password": "APP_PASSWORD"},
        ).propose(finding, context, source)
    expected = (
        "Model did not produce a valid patch: B105 candidate uses os.environ but the "
        "patched module does not import os; add a top-level 'import os'"
    )
    assert str(caught.value) == expected
    assert len(client.calls) == 1
    assert sentinel not in str(caught.value)
    assert all(line not in str(caught.value) for line in source.splitlines())


def test_b105_repair_attempt_can_satisfy_module_binding_requirement(
    tmp_path: Path,
) -> None:
    """The model can add the required import on its bounded repair attempt."""
    sentinel = "FAKE_BENCHMARK_OP16_PASSWORD_DO_NOT_USE"
    source = (
        "def configured_password():\n"
        f'    password = "{sentinel}"\n'
        "    return password\n"
    )
    finding, context = _op16_b105_target(tmp_path, source)
    repaired = "import os\n\n" + _op16_candidate()
    client = FakeCompletionClient(_op16_candidate(), repaired)
    patch = LLMPatchAgent(
        client,
        output_mode="function",
        secret_environment={"app.py::configured_password": "APP_PASSWORD"},
    ).propose(finding, context, source)
    published = materialize_patch_source(patch.unified_diff, finding, source)
    assert len(client.calls) == 2
    assert "add a top-level 'import os'" in client.calls[1][1]
    assert published == repaired + "\n"
    assert sentinel not in published


@pytest.mark.parametrize("import_line", ["import os", "import os.path"])
def test_b105_accepts_module_binding_forms_without_post_edit(
    tmp_path: Path, import_line: str
) -> None:
    sentinel = "FAKE_BENCHMARK_OP16_PASSWORD_DO_NOT_USE"
    source = (
        "def configured_password():\n"
        f'    password = "{sentinel}"\n'
        "    return password\n"
    )
    finding, context = _op16_b105_target(tmp_path, source)
    model_source = (
        f"{import_line}\n\n"
        "def configured_password():\n"
        '    password = os.environ["APP_PASSWORD"]\n'
        "    return password"
    )
    patch = LLMPatchAgent(
        FakeCompletionClient(model_source),
        max_repair_attempts=0,
        output_mode="function",
        secret_environment={"app.py::configured_password": "APP_PASSWORD"},
    ).propose(finding, context, source)
    assert materialize_patch_source(patch.unified_diff, finding, source) == (
        model_source + "\n"
    )


@pytest.mark.parametrize(
    "import_line",
    [
        "from os import environ",
        "import os as o",
        "def configured_password():\n    import os",
        "if True:\n    import os",
    ],
)
def test_b105_refuses_import_forms_that_do_not_bind_module_os(
    import_line: str,
) -> None:
    """These conservative refusals are intentional, not oversights."""
    sentinel = "FAKE_BENCHMARK_OP16_PASSWORD_DO_NOT_USE"
    source = (
        "def configured_password():\n"
        f'    password = "{sentinel}"\n'
        "    return password\n"
    )
    if import_line.startswith("def configured_password"):
        candidate = (
            "def configured_password():\n"
            "    import os\n"
            '    password = os.environ["APP_PASSWORD"]\n'
            "    return password\n"
        )
    else:
        candidate = (
            f"{import_line}\n"
            "def configured_password():\n"
            '    password = os.environ["APP_PASSWORD"]\n'
            "    return password\n"
        )
    finding = Finding(
        id="op16-refused-import",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Hardcoded password",
        source="test",
    )
    with pytest.raises(PatchGenerationError) as caught:
        _validate_b105_environment_candidate(source, candidate, finding, "APP_PASSWORD")
    assert "add a top-level 'import os'" in str(caught.value)
    assert sentinel not in str(caught.value)
    assert all(line not in str(caught.value) for line in source.splitlines())


def _long_function_b105_source(sentinel: str, bind_os: bool) -> str:
    prefix = "import os\n" if bind_os else ""
    prefix += "".join(f"VALUE_{index} = {index}\n" for index in range(30))
    return (
        prefix
        + "def configured_password():\n"
        + f'    password = "{sentinel}"\n'
        + "    return password\n"
    )


def test_b105_unbound_long_function_refuses_before_provider_call(
    tmp_path: Path,
) -> None:
    """An unsatisfiable function-only target stops before model invocation."""
    sentinel = "FAKE_BENCHMARK_OP16_PASSWORD_DO_NOT_USE"
    source = _long_function_b105_source(sentinel, bind_os=False)
    finding, context = _op16_b105_target(tmp_path, source)
    assert context.symbol == "configured_password"
    assert context.snippet_line_start > 1
    client = FakeCompletionClient("unused")
    with pytest.raises(PatchGenerationError) as caught:
        LLMPatchAgent(
            client,
            output_mode="function",
            secret_environment={"app.py::configured_password": "APP_PASSWORD"},
        ).propose(finding, context, source)
    assert str(caught.value) == (
        "B105 function-scope target cannot add the required top-level 'import os' "
        "because the original module does not bind os; review or refactor the target "
        "manually."
    )
    assert client.calls == []
    assert sentinel not in str(caught.value)
    assert all(line not in str(caught.value) for line in context.snippet.splitlines())


def test_b105_long_function_with_existing_module_binding_is_repairable(
    tmp_path: Path,
) -> None:
    """A long function target remains repairable when the original binds os."""
    sentinel = "FAKE_BENCHMARK_OP16_PASSWORD_DO_NOT_USE"
    source = _long_function_b105_source(sentinel, bind_os=True)
    finding, context = _op16_b105_target(tmp_path, source)
    reply = (
        "def configured_password():\n"
        '    password = os.environ["APP_PASSWORD"]\n'
        "    return password"
    )
    client = FakeCompletionClient(reply)
    patch = LLMPatchAgent(
        client,
        max_repair_attempts=0,
        output_mode="function",
        secret_environment={"app.py::configured_password": "APP_PASSWORD"},
    ).propose(finding, context, source)
    published = materialize_patch_source(patch.unified_diff, finding, source)
    assert len(client.calls) == 1
    assert 'password = os.environ["APP_PASSWORD"]' in published
    assert sentinel not in published


def test_b105_unused_environment_lookup_cannot_satisfy_target_guard() -> None:
    """A decoy lookup in the same function cannot replace the secret binding."""
    original = (
        "def configured_password():\n"
        '    password = "SELF-LABELLED-SECRET"\n'
        "    return password\n"
    )
    candidate = (
        "def configured_password():\n"
        '    password = "public fallback"\n'
        '    decoy = os.environ["APP_PASSWORD"]\n'
        "    return password\n"
    )
    finding = Finding(
        id="decoy-binding-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Possible hardcoded password",
        source="test",
    )

    with pytest.raises(PatchGenerationError, match="replace the original assignment"):
        _validate_b105_environment_candidate(
            original, candidate, finding, "APP_PASSWORD"
        )


def test_b105_secret_literal_in_target_is_rejected_even_with_decoy_lookup() -> None:
    """A correct lookup elsewhere cannot excuse retaining the target literal."""
    sentinel = "SELF-LABELLED-SECRET"
    original = f'def configured_password():\n    password = "{sentinel}"\n'
    candidate = (
        f'def configured_password():\n    password = "{sentinel}"\n'
        '    decoy = os.environ["APP_PASSWORD"]\n'
    )
    finding = Finding(
        id="retained-literal-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Possible hardcoded password",
        source="test",
    )

    with pytest.raises(PatchGenerationError) as caught:
        _validate_b105_environment_candidate(
            original, candidate, finding, "APP_PASSWORD"
        )
    assert sentinel not in str(caught.value)


def test_b105_return_literal_shape_fails_closed_without_secret_in_error() -> None:
    """Unsupported non-assignment B105 shapes require manual review safely."""
    sentinel = "SELF-LABELLED-RETURN-SECRET"
    original = f'def configured_password():\n    return "{sentinel}"\n'
    candidate = (
        "def configured_password():\n"
        '    decoy = os.environ["APP_PASSWORD"]\n'
        "    return None\n"
    )
    finding = Finding(
        id="unsupported-return-finding",
        rule_id="B105",
        title="Hardcoded password",
        severity=Severity.LOW,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="Possible hardcoded password",
        source="test",
    )

    with pytest.raises(
        PatchGenerationError, match="direct string assignment"
    ) as caught:
        _validate_b105_environment_candidate(
            original, candidate, finding, "APP_PASSWORD"
        )
    assert sentinel not in str(caught.value)


def test_rewrite_rejects_added_import_statement() -> None:
    """A model cannot strand a newly invented import inside a replaced scope."""
    finding = _finding()
    original = "def load_user():\n    return 1\n"
    context = _context("def load_user():\n    return 1", 1)

    with pytest.raises(PatchGenerationError) as caught:
        rewrite_scope_to_diff(
            "def load_user():\n    import subprocess\n    return 1",
            context,
            original,
            finding,
        )

    assert "Added import statement 'import subprocess'" in str(caught.value)
    assert "imports are supplied separately in the request" in str(caught.value)
    assert "must be left exactly as they are" in str(caught.value)


def test_rewrite_rejects_dropped_import_statement() -> None:
    """A model cannot remove an import the replaced scope originally used."""
    finding = _finding()
    original = "def load_user():\n    import os\n    return os.getcwd()\n"
    context = _context("def load_user():\n    import os\n    return os.getcwd()", 1)

    with pytest.raises(PatchGenerationError) as caught:
        rewrite_scope_to_diff(
            "def load_user():\n    return os.getcwd()",
            context,
            original,
            finding,
        )

    assert "Removed import statement 'import os'" in str(caught.value)
    assert "imports are supplied separately in the request" in str(caught.value)


def test_rewrite_accepts_an_identical_import_set() -> None:
    """An unchanged import statement does not block an otherwise valid rewrite."""
    finding = _finding()
    original = "def load_user():\n    import os\n    return os.getcwd()\n"
    context = _context("def load_user():\n    import os\n    return os.getcwd()", 1)
    rewritten = "def load_user():\n    import os\n    return os.path.abspath('.')"

    diff = rewrite_scope_to_diff(rewritten, context, original, finding)

    assert "import os" in diff
    assert "os.path.abspath" in diff


def test_fixture_b105_module_window_keeps_its_imports() -> None:
    """A line window can retain imports without parsing the original window."""
    fixture_root = Path("tests/fixtures/vulnerable_app").resolve()
    finding = next(
        item for item in BanditScanner().scan(fixture_root) if item.rule_id == "B105"
    )
    context = extract_context(finding, fixture_root)
    original = (fixture_root / finding.file.as_posix()).read_text(encoding="utf-8")
    assert "import subprocess" in context.snippet
    assert "from typing import Any" in context.snippet
    assert context.snippet.endswith("    return subprocess.call(command, shell=True)")

    rewritten = context.snippet.replace(
        'PASSWORD = "<redacted by omnipatch>"', 'PASSWORD = ""'
    )
    diff = rewrite_scope_to_diff(rewritten, context, original, finding)

    assert diff.startswith("--- a/app.py\n+++ b/app.py\n")
    assert "+import subprocess" not in diff
    assert "+from typing import Any" not in diff


def test_multiline_import_reformatting_is_rejected() -> None:
    """Line matching conservatively rejects a reformatted multiline import."""
    finding = _finding()
    original = (
        "def load_user():\n"
        "    from os import (\n"
        "        path,\n"
        "        getcwd,\n"
        "    )\n"
        "    return path\n"
    )
    context = _context("\n".join(original.splitlines()), 1)
    rewritten = "def load_user():\n    from os import path, getcwd\n    return path"

    with pytest.raises(PatchGenerationError, match="import statement"):
        rewrite_scope_to_diff(rewritten, context, original, finding)


def test_indented_method_rewrite_without_imports_is_unchanged() -> None:
    """An indented class method with no imports still produces a diff."""
    finding = _finding()
    original = "class Store:\n    def load_user(self):\n        return 1\n"
    context = _context("class Store:\n    def load_user(self):\n        return 1", 1)

    diff = rewrite_scope_to_diff(
        "class Store:\n    def load_user(self):\n        return 2",
        context,
        original,
        finding,
    )

    assert "-        return 1" in diff
    assert "+        return 2" in diff


def test_empty_and_out_of_range_contexts_remain_rejected() -> None:
    """Empty contexts, rewrites, and out-of-range spans remain explicit errors."""
    finding = _finding()
    with pytest.raises(PatchGenerationError, match="empty context snippet"):
        rewrite_scope_to_diff(
            "def load_user():\n    return None", _context(""), "", finding
        )
    with pytest.raises(PatchGenerationError, match="Rewritten scope is empty"):
        rewrite_scope_to_diff(
            "", _context("def load_user():\n    return 1", 1), "", finding
        )
    with pytest.raises(PatchGenerationError, match="line range is outside"):
        rewrite_scope_to_diff(
            "def load_user():\n    return 2",
            _context("def load_user():\n    return 1", 2),
            "def load_user():\n    return 1\n",
            finding,
        )


def test_truncated_context_is_rejected() -> None:
    """A truncation marker prevents an unsafe partial-scope replacement."""
    finding = _finding()
    context = _context(
        "def load_user():\n    query = input()\n"
        "# ... truncated by omnipatch: 3 more line(s)"
    )

    with pytest.raises(PatchGenerationError, match="truncated context snippet"):
        rewrite_scope_to_diff("def load_user():\n    return None", context, "", finding)


def test_function_output_accepts_fence_and_returns_validator_patch() -> None:
    """A fenced rewritten scope is stripped, diffed, and validated normally."""
    finding = _finding()
    original = "def load_user():\n    query = input()\n    return query\n"
    context = _context("def load_user():\n    query = input()\n    return query", 1)
    response = (
        "```python\ndef load_user():\n    query = str(input())\n    return query\n```"
    )
    client = FakeCompletionClient(response)

    patch = LLMPatchAgent(
        client,
        output_mode="function",
        sql_paramstyle={"app.py::load_user": "qmark"},
    ).propose(finding, context, original)
    verified_patch = validate_patch(patch.unified_diff, finding, original, "fake-model")

    assert verified_patch == patch
    assert "```" not in patch.unified_diff
    assert "complete rewritten function" in client.calls[0][0]
    assert "untrusted data" in client.calls[0][0]


def test_invalid_python_function_reply_is_rejected_without_diff_relaxation() -> None:
    """Function output must parse before generated diffs reach validation."""
    finding = _finding()
    context = _context("def load_user():\n    query = input()", 1)
    client = FakeCompletionClient("def load_user(:\n    return None")

    with pytest.raises(PatchGenerationError, match="valid patch"):
        LLMPatchAgent(client, max_repair_attempts=0, output_mode="function").propose(
            finding, context, "def load_user():\n    query = input()\n"
        )
    assert len(client.calls) == 1


def test_function_output_repair_attempt_is_still_capped_at_one() -> None:
    """The function-mode repair prompt requests rewritten scope and stops at two calls."""
    finding = _finding()
    context = _context("def load_user():\n    query = input()", 1)
    client = FakeCompletionClient("def invalid(:", "def broken(:", "third")

    with pytest.raises(PatchGenerationError):
        LLMPatchAgent(client, output_mode="function").propose(
            finding, context, "def load_user():\n    query = input()\n"
        )
    assert len(client.calls) == 2
    assert "rewritten scope" in client.calls[1][1]


def test_blank_context_reproduction_keeps_all_eight_lines() -> None:
    """A one-space context marker survives stripping at both diff boundaries."""
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,4 +1,4 @@\n"
        " def f():\n-    return 1\n+    return 2\n \n \n"
    )

    assert len(diff.splitlines()) == 8
    assert len(strip_fence(diff).splitlines()) == 8


def test_blank_context_diff_is_accepted_by_patch_validator() -> None:
    """Two blank context lines at the end of a hunk remain part of its counts."""
    finding = _finding()
    original = "def f():\n    return 1\n\n\n"
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,4 +1,4 @@\n"
        " def f():\n-    return 1\n+    return 2\n \n \n"
    )

    patch = validate_patch(diff, finding, original, "fake-model")
    assert materialize_patch_source(patch.unified_diff, finding, original) == (
        "def f():\n    return 2\n\n\n"
    )


def test_fixture_b608_recorded_function_reply_yields_valid_diff() -> None:
    """The real fixture scope produces a diff accepted by the normal validator."""
    fixture_root = Path("tests/fixtures/vulnerable_app").resolve()
    finding = next(
        item for item in BanditScanner().scan(fixture_root) if item.rule_id == "B608"
    )
    context = extract_context(finding, fixture_root)
    original = (fixture_root / finding.file.as_posix()).read_text(encoding="utf-8")
    reply = (
        "def load_user(cursor: Any, user_id: str) -> Any:\n"
        '    """Load one user using an intentionally unsafe SQL query."""\n'
        '    query = "SELECT * FROM users WHERE id = ?"\n'
        "    cursor.execute(query, (user_id,))\n"
        "    return cursor.fetchone()"
    )
    client = FakeCompletionClient(reply)

    patch = LLMPatchAgent(
        client,
        output_mode="function",
        sql_paramstyle={"app.py::load_user": "qmark"},
    ).propose(finding, context, original)
    assert validate_patch(patch.unified_diff, finding, original, "fake-model") == patch


def test_b105_nonconforming_getenv_reply_is_refused_without_post_edit(
    tmp_path: Path,
) -> None:
    """A model-authored optional lookup is refused rather than rewritten."""
    case_root = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "v1"
        / "development"
        / "dev-b105-module-constant"
    )
    original = (case_root / "vulnerable.py").read_text(encoding="utf-8")
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "app.py").write_text(original, encoding="utf-8")
    finding = next(
        item for item in BanditScanner().scan(target_root) if item.rule_id == "B105"
    )
    context = extract_context(finding, target_root)
    reply = (
        'import os\n\nAPP_PASSWORD = os.getenv("APP_PASSWORD")\n\n'
        "def configured_password():\n"
        '    """Return the password supplied by the runtime environment."""\n'
        "    return APP_PASSWORD"
    )
    client = FakeCompletionClient(reply)

    with pytest.raises(
        PatchGenerationError, match="configured required environment lookup"
    ):
        LLMPatchAgent(
            client,
            max_repair_attempts=0,
            output_mode="function",
            secret_environment={"app.py::<module>": "APP_PASSWORD"},
        ).propose(finding, context, original)

    assert len(client.calls) == 1


def test_b105_repair_attempt_can_return_required_lookup_and_verify(
    tmp_path: Path,
) -> None:
    """A rejected optional lookup can be repaired by the model on its one retry."""
    from benchmarks.v1.oracles import run_behavioral_oracle

    case_root = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "v1"
        / "development"
        / "dev-b105-module-constant"
    )
    original = (case_root / "vulnerable.py").read_text(encoding="utf-8")
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "app.py").write_text(original, encoding="utf-8")
    scanner = BanditScanner()
    baseline = scanner.scan(target_root)
    finding = next(item for item in baseline if item.rule_id == "B105")
    context = extract_context(finding, target_root)
    nonconforming = (
        'import os\n\nAPP_PASSWORD = os.getenv("APP_PASSWORD")\n\n'
        "def configured_password():\n"
        '    """Return the password supplied by the runtime environment."""\n'
        "    return APP_PASSWORD"
    )
    conforming = (
        'import os\n\nAPP_PASSWORD = os.environ["APP_PASSWORD"]\n\n'
        "def configured_password():\n"
        '    """Return the password supplied by the runtime environment."""\n'
        "    return APP_PASSWORD"
    )
    client = FakeCompletionClient(nonconforming, conforming)
    patch = LLMPatchAgent(
        client,
        output_mode="function",
        secret_environment={"app.py::<module>": "APP_PASSWORD"},
    ).propose(finding, context, original)
    candidate_source = materialize_patch_source(patch.unified_diff, finding, original)

    assert len(client.calls) == 2
    assert "configured required environment lookup" in client.calls[1][1]
    assert 'APP_PASSWORD = os.environ["APP_PASSWORD"]' in candidate_source
    assert all(
        line in candidate_source.splitlines() for line in conforming.splitlines()
    )
    verification = verify_patch(patch, finding, target_root, scanner, baseline)
    assert verification.verified is True
    oracle_root = tmp_path / "oracle"
    oracle_root.mkdir()
    candidate_path = oracle_root / "app.py"
    candidate_path.write_text(candidate_source, encoding="utf-8")
    run_behavioral_oracle(
        "dev-b105-module-constant", candidate_path, case_root / "reference_fix.py"
    )


def test_b105_function_local_module_reply_uses_existing_import_guard_and_oracle(
    tmp_path: Path,
) -> None:
    """A complete-module reply for a whole-file function scope can add its import."""
    from benchmarks.v1.oracles import run_behavioral_oracle

    case_root = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "v1"
        / "development"
        / "dev-b105-function-local"
    )
    original = (case_root / "vulnerable.py").read_text(encoding="utf-8")
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "app.py").write_text(original, encoding="utf-8")
    scanner = BanditScanner()
    baseline = scanner.scan(target_root)
    finding = next(item for item in baseline if item.rule_id == "B105")
    context = extract_context(finding, target_root)
    model_reply = (
        "import os\n\n\n"
        "def configured_password():\n"
        '    """Return the password supplied by the runtime environment."""\n'
        '    password = os.environ["APP_PASSWORD"]\n'
        "    return password"
    )
    client = FakeCompletionClient(model_reply)
    patch = LLMPatchAgent(
        client,
        output_mode="function",
        secret_environment={"app.py::configured_password": "APP_PASSWORD"},
    ).propose(finding, context, original)
    candidate_source = materialize_patch_source(patch.unified_diff, finding, original)
    request = json.loads(client.calls[0][1])
    assert request["symbol"] is None
    assert "FAKE_BENCHMARK_LOCAL_PASSWORD_DO_NOT_USE" not in client.calls[0][1]
    assert "required environment variable" in client.calls[0][0]
    assert "APP_PASSWORD" in client.calls[0][0]
    assert request["required_environment_variable"] == "APP_PASSWORD"
    assert (case_root / "reference_fix.py").read_text(
        encoding="utf-8"
    ) not in client.calls[0][1]
    assert "FAKE_BENCHMARK_LOCAL_PASSWORD_DO_NOT_USE" not in candidate_source
    assert 'password = os.environ["APP_PASSWORD"]' in candidate_source

    verification = verify_patch(patch, finding, target_root, scanner, baseline)
    assert verification.verified is True
    oracle_root = tmp_path / "oracle"
    oracle_root.mkdir()
    candidate_path = oracle_root / "app.py"
    candidate_path.write_text(candidate_source, encoding="utf-8")
    run_behavioral_oracle(
        "dev-b105-function-local",
        candidate_path,
        case_root / "reference_fix.py",
    )


def _verified_b608_function_rewrite(
    tmp_path: Path, original: str, rewritten_scope: str
) -> tuple[str, PatchResult]:
    """Generate and isolate-verify a synthetic B608 function rewrite offline."""
    (tmp_path / "app.py").write_text(original, encoding="utf-8")
    scanner = BanditScanner()
    baseline = scanner.scan(tmp_path)
    finding = next(item for item in baseline if item.rule_id == "B608")
    context = extract_context(finding, tmp_path)
    client = FakeCompletionClient(rewritten_scope)
    patch = LLMPatchAgent(
        client,
        max_repair_attempts=0,
        output_mode="function",
        sql_paramstyle={f"app.py::{context.symbol}": "qmark"},
    ).propose(finding, context, original)
    patched = materialize_patch_source(patch.unified_diff, finding, original)
    result = verify_patch(patch, finding, tmp_path, scanner, baseline)
    return patched, result


def test_b608_static_parameter_query_with_f_prefix_is_refused(
    tmp_path: Path,
) -> None:
    """The candidate gate refuses an interpolated query expression."""
    original = (
        "def lookup_username(connection, username):\n"
        "    query = f\"SELECT username FROM accounts WHERE username = '{username}'\"\n"
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    rewritten = (
        "def lookup_username(connection, username):\n"
        '    query = f"SELECT username FROM accounts WHERE username = ?"\n'
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query, (username,))\n"
        "    return cursor.fetchall()"
    )

    with pytest.raises(PatchGenerationError, match="interpolation or concatenation"):
        _verified_b608_function_rewrite(tmp_path, original, rewritten)


def test_b608_concatenated_parameter_query_still_verifies(tmp_path: Path) -> None:
    """The existing concatenation repair shape remains parameterized and clean."""
    original = (
        "def lookup_item(connection, item_id):\n"
        '    query = "SELECT item_id FROM inventory WHERE item_id = \'" + item_id + "\'"\n'
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    rewritten = (
        "def lookup_item(connection, item_id):\n"
        '    query = "SELECT item_id FROM inventory WHERE item_id = ?"\n'
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query, (item_id,))\n"
        "    return cursor.fetchall()"
    )

    patched, result = _verified_b608_function_rewrite(tmp_path, original, rewritten)
    assert 'query = "SELECT item_id FROM inventory WHERE item_id = ?"' in patched
    assert "cursor.execute(query, (item_id,))" in patched
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE inventory (item_id TEXT NOT NULL)")
    connection.executemany("INSERT INTO inventory VALUES (?)", [("1",), ("2",)])
    injected_value = "1' OR 1=1 -- "
    assert (
        connection.execute(
            "SELECT item_id FROM inventory WHERE item_id = ?", (injected_value,)
        ).fetchall()
        == []
    )
    connection.close()
    assert result.verified is True
    assert result.error is None


def test_b608_rewrite_preserves_model_literals_verbatim() -> None:
    """Function rewriting does not post-edit f-string prefixes or other text."""
    original = (
        "def lookup_username(connection, username):\n"
        "    query = f\"SELECT username FROM accounts WHERE username = '{username}'\"\n"
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    context = _context(original.rstrip(), 1)
    rewritten = (
        "def lookup_username(connection, username):\n"
        '    label = f"{{username}}"\n'
        '    query = "SELECT username FROM accounts WHERE username = ?"\n'
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query, (username,))\n"
        "    return cursor.fetchall()"
    )

    diff = rewrite_scope_to_diff(rewritten, context, original, _finding())
    assert '+    label = f"{{username}}"' in diff
    assert '+    query = "SELECT username FROM accounts WHERE username = ?"' in diff


def test_b608_system_and_repair_prompts_request_prefix_removal() -> None:
    """The model request and repair instruction carry the stale-prefix rule."""
    original = (
        "def lookup_username(connection, username):\n"
        "    query = f\"SELECT username FROM accounts WHERE username = '{username}'\"\n"
        "    return connection.execute(query).fetchall()\n"
    )
    finding = Finding(
        id="b608-prefix-prompt",
        rule_id="B608",
        title="SQL query construction",
        severity=Severity.MEDIUM,
        file=PurePosixPath("app.py"),
        line_start=2,
        line_end=2,
        message="SQL injection",
        source="test",
    )
    context = CodeContext(finding.id, original.rstrip(), 1, "lookup_username", ())
    client = FakeCompletionClient(
        "not valid rewritten python",
        "def lookup_username(connection, username):\n"
        '    query = "SELECT username FROM accounts WHERE username = ?"\n'
        "    return connection.execute(query, (username,)).fetchall()",
    )

    LLMPatchAgent(
        client,
        output_mode="function",
        sql_paramstyle={"app.py::lookup_username": "qmark"},
    ).propose(finding, context, original)

    assert "no interpolation fields" in client.calls[0][0]
    assert "verification may still report B608 solely" in client.calls[1][1]
    assert "remove that prefix" in client.calls[1][1]


def test_snapped_b105_module_window_splices_and_validates() -> None:
    """A module-level rewrite changes only the password line and validates."""
    fixture_root = Path("tests/fixtures/vulnerable_app").resolve()
    finding = next(
        item for item in BanditScanner().scan(fixture_root) if item.rule_id == "B105"
    )
    original = (fixture_root / finding.file.as_posix()).read_text(encoding="utf-8")
    context = extract_context(finding, fixture_root)
    rewritten = context.snippet.replace(
        f'PASSWORD = "{REDACTION_MARKER}"', 'PASSWORD = ""'
    )
    assert rewritten != context.snippet

    diff = rewrite_scope_to_diff(rewritten, context, original, finding)
    patch = validate_patch(diff, finding, original, "fake-model")
    patched = materialize_patch_source(patch.unified_diff, finding, original)

    assert 'PASSWORD = ""' in patched
    assert "changeme-not-a-real-secret" not in patched


@pytest.mark.integration
def test_snapped_b105_import_fix_validates_and_verifies_in_isolation(
    tmp_path: Path,
) -> None:
    """A required leading import passes the guard, validator, and Bandit re-scan."""
    fixture_root = Path("tests/fixtures/vulnerable_app").resolve()
    source = (fixture_root / "app.py").read_text(encoding="utf-8")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    scanner = BanditScanner()
    baseline = scanner.scan(tmp_path)
    finding = next(item for item in baseline if item.rule_id == "B105")
    context = extract_context(finding, tmp_path)
    rewritten = context.snippet.replace(
        f'PASSWORD = "{REDACTION_MARKER}"',
        'PASSWORD = os.environ["APP_PASSWORD"]',
    ).replace("import subprocess", "import os\nimport subprocess", 1)

    diff = rewrite_scope_to_diff(rewritten, context, source, finding)
    patch = validate_patch(diff, finding, source, "fake-model")
    patched = materialize_patch_source(patch.unified_diff, finding, source)
    result = verify_patch(patch, finding, tmp_path, scanner, baseline)

    assert 'PASSWORD = os.environ["APP_PASSWORD"]' in patched
    assert "import os" in patched
    assert "changeme-not-a-real-secret" not in patched
    assert result.verified is True
    assert result.error is None
    patched_root = tmp_path / "patched-scan"
    patched_root.mkdir()
    (patched_root / "app.py").write_text(patched, encoding="utf-8")
    assert not any(
        item.rule_id == "B105" and item.file == finding.file
        for item in scanner.scan(patched_root)
    )


@pytest.mark.parametrize(
    ("nested", "message"),
    [
        ("def run():\n    import os\n    return 1", "direct top-level"),
        ("class Runner:\n    import os", "direct top-level"),
        ("if True:\n    import os", "direct top-level"),
    ],
)
def test_module_context_rejects_imports_outside_leading_region(
    nested: str, message: str
) -> None:
    """Imports in function, class, and conditional bodies are not authorized."""
    original = '"""Module."""\nimport json\n\nVALUE = 1\ndef run():\n    return 1\n'
    context = CodeContext("finding", original.rstrip(), 1, None, ("import json",))
    rewritten = original.replace("VALUE = 1", f"VALUE = 1\n{nested}").rstrip()

    with pytest.raises(PatchGenerationError, match=message):
        rewrite_scope_to_diff(rewritten, context, original, _finding())


def test_module_context_without_complete_import_region_rejects_addition() -> None:
    """A window beginning after imports cannot authorize adding another import."""
    original = '"""Module."""\nimport json\nVALUE = 1\n'
    context = CodeContext("finding", "VALUE = 1", 3, None, ())

    with pytest.raises(PatchGenerationError, match="complete leading import region"):
        rewrite_scope_to_diff("import os\nVALUE = 1", context, original, _finding())


def test_module_context_rejects_import_after_leading_region() -> None:
    """A direct module import after ordinary statements is not in the import region."""
    original = '"""Module."""\nimport json\nVALUE = 1\n'
    context = CodeContext("finding", original.rstrip(), 1, None, ("import json",))
    rewritten = '"""Module."""\nimport json\nVALUE = 1\nimport os'

    with pytest.raises(PatchGenerationError, match="leading module import region"):
        rewrite_scope_to_diff(rewritten, context, original, _finding())


def test_module_context_without_import_block_can_add_leading_import() -> None:
    """A complete module without imports can add one before its first statement."""
    original = 'PASSWORD = "<redacted by omnipatch>"\n'
    context = CodeContext("finding", original.rstrip(), 1, None, ())

    diff = rewrite_scope_to_diff(
        'import os\nPASSWORD = os.environ["APP_PASSWORD"]',
        context,
        original,
        _finding(),
    )

    assert "+import os" in diff


def test_module_context_rejects_import_region_cut_off_at_end() -> None:
    """A window that stops before an existing import is incomplete."""
    original = '"""Module."""\nimport json\nVALUE = 1\n'
    context = CodeContext("finding", '"""Module."""', 1, None, ())

    with pytest.raises(PatchGenerationError, match="complete leading import region"):
        rewrite_scope_to_diff('"""Module."""\nimport os', context, original, _finding())


@pytest.mark.parametrize(
    ("rewritten", "message"),
    [
        ('"""Module."""\nVALUE = 1', "Removed import statement 'import json'"),
        (
            '"""Module."""\nimport os\nVALUE = 1',
            "Removed import statement 'import json'",
        ),
    ],
)
def test_module_context_still_rejects_removed_or_changed_imports(
    rewritten: str, message: str
) -> None:
    original = '"""Module."""\nimport json\nVALUE = 1\n'
    context = CodeContext("finding", original.rstrip(), 1, None, ("import json",))

    with pytest.raises(PatchGenerationError, match=message):
        rewrite_scope_to_diff(rewritten, context, original, _finding())


def test_module_context_rejects_relocating_an_existing_import() -> None:
    """An existing import cannot be moved into a function during a rewrite."""
    original = '"""Module."""\nimport json\ndef run():\n    return 1\n'
    context = CodeContext("finding", original.rstrip(), 1, None, ("import json",))
    rewritten = '"""Module."""\ndef run():\n    import json\n    return 1'

    with pytest.raises(PatchGenerationError, match="Existing imports must remain"):
        rewrite_scope_to_diff(rewritten, context, original, _finding())


def test_module_context_rejects_relocating_an_import_across_a_statement() -> None:
    """An existing top-level import cannot cross another module statement."""
    original = '"""Module."""\nVALUE = 1\nimport json\n'
    context = CodeContext("finding", original.rstrip(), 1, None, ("import json",))
    rewritten = '"""Module."""\nimport json\nVALUE = 1'

    with pytest.raises(PatchGenerationError, match="Existing imports must remain"):
        rewrite_scope_to_diff(rewritten, context, original, _finding())


def test_truncated_and_invalid_original_module_cannot_authorize_imports() -> None:
    """Truncated contexts and malformed source fail closed for import additions."""
    truncated = CodeContext(
        "finding", '"""Module."""\n# ... truncated by omnipatch: cap', 1, None, ()
    )
    with pytest.raises(PatchGenerationError, match="truncated context"):
        rewrite_scope_to_diff(
            '"""Module."""\nimport os', truncated, '"""Module."""\n', _finding()
        )

    invalid_original = '"""Module."""\nimport json\nVALUE = 1\ndef broken(:\n'
    complete = CodeContext("finding", invalid_original.rstrip(), 1, None, ())
    with pytest.raises(PatchGenerationError, match="invalid original module"):
        rewrite_scope_to_diff(
            '"""Module."""\nimport os\nimport json\nVALUE = 1',
            complete,
            invalid_original,
            _finding(),
        )


def test_indented_method_reply_keeps_first_line_indentation() -> None:
    """Code-fence removal preserves indentation needed by a class method scope."""
    reply = "\n    def find(self, user_id):\n        return user_id\n"

    stripped = strip_fence(reply)

    assert stripped.startswith("    def find")
    ast.parse(dedent(stripped))


def test_fenced_diff_and_fenced_python_reply_are_still_supported() -> None:
    """The public fence helper supports both diff and Python reply fences."""
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2"
    python_reply = "```python\ndef f():\n    return 2\n```"

    assert strip_fence(f"```diff\n{diff}\n```") == diff
    assert strip_fence(python_reply) == "def f():\n    return 2"


def test_only_exactly_empty_outer_lines_are_removed() -> None:
    """Empty lines are trimmed while whitespace-only content remains intact."""
    assert strip_fence("\n\ntext\n\n") == "text"
    assert strip_fence("\n \ntext\n \n") == " \ntext\n "


def test_incomplete_or_empty_fence_is_rejected() -> None:
    """An unfinished or content-free fence cannot silently become source text."""
    with pytest.raises(PatchGenerationError, match="incomplete"):
        strip_fence("```python\ndef f():\n    return 1")
    with pytest.raises(PatchGenerationError, match="no content"):
        strip_fence("```\n```")


def _b602_target() -> tuple[str, Finding, CodeContext]:
    """Build a synthetic shell-based target without touching the vulnerable fixture."""
    original = (
        "import os\n"
        "import shutil\n"
        "import subprocess\n"
        "import sys\n"
        "\n"
        "def print_user_value(user_input):\n"
        '    return subprocess.run("printf " + user_input, shell=True)\n'
    )
    finding = Finding(
        id="b602-executable",
        rule_id="B602",
        title="subprocess call with shell=True",
        severity=Severity.HIGH,
        file=PurePosixPath("app.py"),
        line_start=7,
        line_end=7,
        message="subprocess call with shell=True",
        source="bandit",
    )
    context = CodeContext(
        finding.id,
        "def print_user_value(user_input):\n"
        '    return subprocess.run("printf " + user_input, shell=True)',
        6,
        "print_user_value",
        ("import os", "import shutil", "import subprocess", "import sys"),
    )
    return original, finding, context


def _propose_b602(
    *responses: str,
    max_repair_attempts: int = 0,
    rule_id: str = "B602",
) -> tuple[str, str, FakeCompletionClient]:
    """Return materialized source, original source and the fake provider."""
    original, finding, context = _b602_target()
    if rule_id != "B602":
        finding = Finding(
            id=finding.id,
            rule_id=rule_id,
            title=finding.title,
            severity=finding.severity,
            file=finding.file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            message=finding.message,
            source=finding.source,
        )
    client = FakeCompletionClient(*responses)
    patch = LLMPatchAgent(
        client,
        max_repair_attempts=max_repair_attempts,
        output_mode="function",
    ).propose(finding, context, original)
    return (
        materialize_patch_source(patch.unified_diff, finding, original),
        original,
        client,
    )


_MEASURED_BARE_PRINTF_REPLY = (
    "def print_user_value(user_input):\n"
    '    """Print the user input safely."""\n'
    "    command = ['printf', user_input]\n"
    "    return subprocess.run(\n"
    "        command, check=False, capture_output=True, text=True\n"
    "    )"
)
_SYS_EXECUTABLE_REPLY = (
    "def print_user_value(user_input):\n"
    "    command = [sys.executable, '-c', 'print(1)', user_input]\n"
    "    return subprocess.run(command, check=False)"
)
_B602_EXECUTABLE_MESSAGE = (
    "Model did not produce a valid patch: B602 executable must be sys.executable, "
    "an absolute path literal, or shutil.which(...); manual review required"
)


def _assert_b602_refusal_is_value_free(reply: str, error: PatchGenerationError) -> None:
    message = str(error)
    assert all(line not in message for line in reply.splitlines() if line.strip())
    assert "FAKE_BENCHMARK_SECRET_DO_NOT_USE" not in message
    assert "sk-" not in message


def test_b602_measured_bare_executable_candidate_is_refused() -> None:
    """The measured full-module candidate with variable-bound printf must fail closed."""
    original = (
        "import subprocess\n\n\n"
        "def print_user_value(user_input):\n"
        '    return subprocess.run("printf " + user_input, shell=True)\n'
    )
    finding = Finding(
        id="b602-measured-candidate",
        rule_id="B602",
        title="subprocess call with shell=True",
        severity=Severity.HIGH,
        file=PurePosixPath("app.py"),
        line_start=5,
        line_end=5,
        message="subprocess call with shell=True",
        source="bandit",
    )
    context = CodeContext(
        finding.id,
        original.rstrip(),
        1,
        None,
        ("import subprocess",),
    )
    client = FakeCompletionClient(
        "import subprocess\n\n\n"
        "def print_user_value(user_input):\n"
        '    """Print the user input safely."""\n'
        "    command = ['printf', user_input]\n"
        "    return subprocess.run(\n"
        "        command, check=False, capture_output=True, text=True\n"
        "    )"
    )

    with pytest.raises(PatchGenerationError) as caught:
        LLMPatchAgent(client, max_repair_attempts=0, output_mode="function").propose(
            finding, context, original
        )

    assert str(caught.value) == _B602_EXECUTABLE_MESSAGE
    _assert_b602_refusal_is_value_free(client.responses[0], caught.value)


@pytest.mark.parametrize(
    "reply",
    [
        _MEASURED_BARE_PRINTF_REPLY,
        (
            "def print_user_value(user_input):\n"
            "    return subprocess.run(['printf', user_input], check=False)"
        ),
    ],
    ids=("same-scope-variable", "inline-list"),
)
def test_b602_variable_and_inline_bare_executables_are_refused(reply: str) -> None:
    """Both argv shapes must be checked, including the Bandit-evasive variable."""
    with pytest.raises(PatchGenerationError, match="B602 executable must") as caught:
        _propose_b602(reply)

    _assert_b602_refusal_is_value_free(reply, caught.value)


@pytest.mark.parametrize(
    "executable",
    [
        "sys.executable",
        '"/usr/bin/printf"',
        'r"C:\\Windows\\System32\\cmd.exe"',
        'r"\\\\server\\share\\tool.exe"',
        'shutil.which("printf")',
    ],
    ids=("sys-executable", "posix-absolute", "windows-drive", "unc", "shutil-which"),
)
def test_b602_accepts_trusted_executable_forms_without_rewriting(
    executable: str,
) -> None:
    """Accepted argv executables are materialized exactly as returned by the model."""
    reply = (
        "def print_user_value(user_input):\n"
        f"    command = [{executable}, '-c', 'print(1)', user_input]\n"
        "    return subprocess.run(command, check=False)"
    )

    published, original, _ = _propose_b602(reply)

    assert published == original.replace(_b602_target()[2].snippet, reply)


@pytest.mark.parametrize(
    "executable",
    [
        '"printf"',
        'f"/usr/bin/{user_input}"',
        "executable",
        '"/usr/bin/" + executable',
        'os.path.join("/usr/bin", "printf")',
    ],
    ids=("bare-name", "f-string", "unknown-name", "concatenation", "path-join"),
)
def test_b602_refuses_untrusted_executable_expressions(executable: str) -> None:
    """Unsupported executable expressions fail closed without disclosing code."""
    reply = (
        "def print_user_value(user_input):\n"
        f"    command = [{executable}, user_input]\n"
        "    return subprocess.run(command, check=False)"
    )
    if executable.startswith("os.path.join"):
        # Conservative refusal: do not resolve os.path.join, even with an absolute base.
        reply = (
            "def print_user_value(user_input):\n    # FAKE_BENCHMARK_SECRET_DO_NOT_USE\n"
            + reply.split("\n", 1)[1]
        )

    with pytest.raises(PatchGenerationError, match="B602 executable must") as caught:
        _propose_b602(reply)

    _assert_b602_refusal_is_value_free(reply, caught.value)


def test_b602_unresolvable_argv_requires_manual_review() -> None:
    """A non-list argv value is refused instead of guessed or executed."""
    reply = (
        "def print_user_value(user_input):\n"
        "    command = build_command(user_input)\n"
        "    return subprocess.run(command, check=False)"
    )

    with pytest.raises(PatchGenerationError, match="manual review required") as caught:
        _propose_b602(reply)

    _assert_b602_refusal_is_value_free(reply, caught.value)


def test_b602_repair_attempt_can_replace_a_bare_name_with_sys_executable() -> None:
    """One repair can satisfy the executable requirement without a post-edit."""
    published, original, client = _propose_b602(
        _MEASURED_BARE_PRINTF_REPLY,
        _SYS_EXECUTABLE_REPLY,
        max_repair_attempts=1,
    )

    assert len(client.calls) == 2
    assert published == original.replace(
        _b602_target()[2].snippet, _SYS_EXECUTABLE_REPLY
    )


def test_b602_executable_control_is_scoped_to_b602() -> None:
    """A non-B602 target with a bare executable is outside this rule's control."""
    reply = _MEASURED_BARE_PRINTF_REPLY

    published, original, _ = _propose_b602(reply, rule_id="B999")

    assert published == original.replace(_b602_target()[2].snippet, reply)

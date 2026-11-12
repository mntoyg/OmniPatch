"""Tests for AST-based code context extraction."""

import ast
from pathlib import Path, PurePosixPath

import pytest

from omnipatch.agents.function_rewrite import rewrite_scope_to_diff
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.codebase.redaction import REDACTION_MARKER
from omnipatch.defaults import DEFAULT_MODULE_WINDOW_LINES
from omnipatch.errors import PatchGenerationError
from omnipatch.models import Finding, Severity


def make_finding(file: str, line: int) -> Finding:
    """Build a finding for a source line."""
    return Finding(
        "finding-1",
        "B105",
        "credential",
        Severity.LOW,
        PurePosixPath(file),
        line,
        line,
        "hardcoded credential",
        "test",
    )


def write_source(root: Path, source: str, file: str = "sample.py") -> Path:
    """Write UTF-8 source under a test repository root."""
    path = root / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_extracts_enclosing_function_with_true_bounds(tmp_path: Path) -> None:
    """Function context reports its source bounds and symbol."""
    write_source(tmp_path, "def run():\n    first = 1\n    return first\n")
    context = extract_context(make_finding("sample.py", 2), tmp_path)
    assert context.symbol == "run"
    assert context.snippet_line_start == 1
    assert context.snippet.splitlines() == [
        "def run():",
        "    first = 1",
        "    return first",
    ]


def test_extracts_dotted_nested_scope_symbol(tmp_path: Path) -> None:
    """Nested classes and methods form a dotted scope symbol."""
    source = "class Outer:\n    class Inner:\n        def method(self):\n            return 1\n"
    write_source(tmp_path, source)
    context = extract_context(make_finding("sample.py", 4), tmp_path)
    assert context.symbol == "Outer.Inner.method"
    assert context.snippet_line_start == 3


def test_decorated_scope_includes_decorators(tmp_path: Path) -> None:
    """Decorators appear in context and determine its first line."""
    write_source(tmp_path, "@cache\n@wrap(1)\ndef load():\n    return 1\n")
    context = extract_context(make_finding("sample.py", 4), tmp_path)
    assert context.symbol == "load"
    assert context.snippet_line_start == 1
    assert context.snippet.startswith("@cache\n@wrap(1)\ndef load():")


def test_module_context_uses_clamped_line_window(tmp_path: Path) -> None:
    """Module findings grow across complete adjacent statements to their budget."""
    source = "\n".join(f"value_{line} = {line}" for line in range(1, 31))
    write_source(tmp_path, source)
    context = extract_context(make_finding("sample.py", 15), tmp_path)
    assert context.symbol is None
    assert context.snippet_line_start == 5
    assert len(context.snippet.splitlines()) == DEFAULT_MODULE_WINDOW_LINES


def _module_window_cases() -> list[tuple[str, str | None, int, int, int, int]]:
    """Return the eleven specified module-window shapes and expected line bounds."""
    gap_source = (
        '"""Doc."""\n\nimport os\n\n# a comment in a gap\n\nX = 1\n\n\ndef f():\n'
        "    return X\n"
    )
    assignments = "\n".join(f"value_{line} = {line}" for line in range(1, 12)) + "\n"
    oversized = "before = 1\n\nLONG = (\n"
    oversized += "".join(f"    {line},\n" for line in range(30))
    oversized += ")\nafter = 1\n"
    conditional = (
        "if True:\n    first = 1\n    target = 2\nelse:\n    first = 3\n"
        "after_1 = 1\nafter_2 = 2\nafter_3 = 3\nafter_4 = 4\nafter_5 = 5\n"
    )
    decorated = (
        "ONE = 1\nTWO = 2\n\n\n@staticmethod\ndef decorated():\n"
        "    return 1\nTHREE = 3\nFOUR = 4\nFIVE = 5\n"
    )
    trailing_comment = "FIRST = 1\n\nPASSWORD = 'value'\n# trailing comment\n"
    gap_budget_source = (
        '"""Doc."""\n\nimport os\n\n# a comment in a gap\n\nX = 1\n\n\ndef f():\n'
        "    return X\n"
    )
    return [
        ("fixture B105", None, 6, 21, 1, 18),
        ("comment between statements", gap_source, 5, 21, 1, 11),
        ("oversized anchor", oversized, 10, 21, 3, 34),
        ("first line", assignments, 1, 21, 1, 11),
        ("last line", assignments, 11, 21, 1, 11),
        ("assignment in top-level if/else", conditional, 3, 21, 1, 10),
        ("neighboring decorated statement", decorated, 3, 21, 1, 10),
        ("single statement", "ONLY = 1\n", 1, 21, 1, 1),
        ("docstring only", '"""Only a docstring."""\n', 1, 21, 1, 1),
        ("before trailing comment", trailing_comment, 3, 21, 1, 3),
        ("gap with tight budget", gap_budget_source, 5, 2, 7, 7),
    ]


@pytest.mark.parametrize(
    ("case", "source", "line", "budget", "expected_start", "expected_end"),
    _module_window_cases(),
    ids=[case[0] for case in _module_window_cases()],
)
def test_module_level_shapes_snap_to_parseable_statement_boundaries(
    tmp_path: Path,
    case: str,
    source: str | None,
    line: int,
    budget: int,
    expected_start: int,
    expected_end: int,
) -> None:
    """Every specified module window is a parseable contiguous statement range."""
    if source is None:
        root = Path("tests/fixtures/vulnerable_app").resolve()
        file = "app.py"
    else:
        root = tmp_path
        file = "sample.py"
        write_source(root, source, file)
    context = extract_context(
        make_finding(file, line), root, module_window_lines=budget
    )
    snippet_lines = context.snippet.splitlines()

    assert context.symbol is None, case
    assert context.snippet_line_start == expected_start, case
    assert len(snippet_lines) == expected_end - expected_start + 1, case
    ast.parse(context.snippet)


def test_fixture_b105_context_is_parseable_and_complete() -> None:
    """The snapped B105 context ends at the complete final top-level statement."""
    root = Path("tests/fixtures/vulnerable_app").resolve()
    context = extract_context(make_finding("app.py", 6), root)

    ast.parse(context.snippet)
    assert context.snippet_line_start == 1
    assert (
        context.snippet.splitlines()[-1]
        == "    return subprocess.call(command, shell=True)"
    )


def test_raw_pre_snap_b105_window_reproduces_syntax_error() -> None:
    """The former inline plus/minus ten window still reproduces the defect."""
    root = Path("tests/fixtures/vulnerable_app").resolve()
    source = (root / "app.py").read_text(encoding="utf-8")
    lines = source.splitlines()
    line_number = 6
    start = max(1, line_number - 10)
    end = min(len(lines), line_number + 10)
    raw_window = "\n".join(lines[start - 1 : end])

    with pytest.raises(SyntaxError, match="expected an indented block"):
        ast.parse(raw_window)


def test_module_context_line_slice_matches_real_contiguous_source(
    tmp_path: Path,
) -> None:
    """The snapped context length and line start preserve splice arithmetic."""
    source = "import os\n\nVALUE = 'hello'\n\n\ndef f():\n    return VALUE\n"
    root = tmp_path
    write_source(root, source, "unused-never-write.py")
    context = extract_context(make_finding("unused-never-write.py", 3), root)
    start = context.snippet_line_start - 1
    snippet_lines = context.snippet.splitlines()
    real_window = source.splitlines()[start : start + len(snippet_lines)]

    assert len(snippet_lines) == len(real_window)
    assert real_window == snippet_lines


def test_gap_after_last_statement_anchors_to_the_last_statement(
    tmp_path: Path,
) -> None:
    """A gap with no following statement falls back to the final statement."""
    source = "FIRST = 1\n\n# trailing comment\n"
    write_source(tmp_path, source)
    context = extract_context(
        make_finding("sample.py", 3), tmp_path, module_window_lines=2
    )

    assert context.snippet_line_start == 1
    assert context.snippet == "FIRST = 1"


def test_oversized_anchor_stays_whole_then_truncation_blocks_rewrite(
    tmp_path: Path,
) -> None:
    """An oversized anchor remains parseable and truncation still blocks splice."""
    source = "LONG = (\n" + "".join(f"    {line},\n" for line in range(30)) + ")\n"
    write_source(tmp_path, source)
    finding = make_finding("sample.py", 10)
    whole = extract_context(finding, tmp_path, module_window_lines=5)
    assert whole.snippet_line_start == 1
    assert len(whole.snippet.splitlines()) == 32
    ast.parse(whole.snippet)

    truncated = extract_context(
        finding, tmp_path, max_snippet_lines=10, module_window_lines=5
    )
    assert truncated.snippet.splitlines()[-1] == (
        "# ... truncated by omnipatch: 22 more line(s)"
    )
    with pytest.raises(PatchGenerationError, match="truncated context snippet"):
        rewrite_scope_to_diff("LONG = ()", truncated, source, finding)


def test_module_window_budget_must_be_positive(tmp_path: Path) -> None:
    """An invalid injectable module-window budget raises a domain error."""
    write_source(tmp_path, "PASSWORD = 'value'\n")
    with pytest.raises(PatchGenerationError, match="Module context window line limit"):
        extract_context(make_finding("sample.py", 1), tmp_path, module_window_lines=0)


def test_imports_are_module_level_ordered_and_deduplicated(tmp_path: Path) -> None:
    """All distinct top-level import statements retain source order."""
    source = "import os\nfrom pathlib import Path\nimport os\n\nvalue = 1\n"
    write_source(tmp_path, source)
    context = extract_context(make_finding("sample.py", 5), tmp_path)
    assert context.imports == ("import os", "from pathlib import Path")


def test_import_context_is_redacted_before_construction(tmp_path: Path) -> None:
    """Credential-shaped values in module import text are redacted."""
    secret = "github_pat_01234567890123456789"
    write_source(tmp_path, f"import {secret}\nvalue = 1\n")
    context = extract_context(make_finding("sample.py", 2), tmp_path)
    assert secret not in context.snippet
    assert all(secret not in imported for imported in context.imports)
    assert context.imports == (f"import {REDACTION_MARKER}",)


def test_truncation_is_visible_and_keeps_the_line_budget(tmp_path: Path) -> None:
    """Oversized scopes keep the prefix and append a count marker."""
    source = (
        "def large():\n" + "\n".join(f"    value_{i} = {i}" for i in range(5)) + "\n"
    )
    write_source(tmp_path, source)
    context = extract_context(make_finding("sample.py", 3), tmp_path, 3)
    lines = context.snippet.splitlines()
    assert len(lines) == 4
    assert lines[-1] == "# ... truncated by omnipatch: 3 more line(s)"


def test_path_resolving_outside_repository_is_rejected(tmp_path: Path) -> None:
    """A source symlink that escapes the root is never read."""
    root = tmp_path / "repo"
    outside = tmp_path / "outside.py"
    root.mkdir()
    outside.write_text("PASSWORD = 'outside-secret'\n", encoding="utf-8")
    link = root / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    with pytest.raises(PatchGenerationError, match="outside the repository"):
        extract_context(make_finding("escape.py", 1), root)


def test_syntax_error_is_wrapped(tmp_path: Path) -> None:
    """Invalid Python source raises PatchGenerationError."""
    write_source(tmp_path, "def broken(:\n    pass\n")
    with pytest.raises(PatchGenerationError, match="Unable to parse"):
        extract_context(make_finding("sample.py", 1), tmp_path)


def test_non_utf8_source_is_rejected(tmp_path: Path) -> None:
    """Source decoding is strict and wrapped as PatchGenerationError."""
    (tmp_path / "sample.py").write_bytes(b"PASSWORD = '\xff'\n")
    with pytest.raises(PatchGenerationError, match="Unable to read"):
        extract_context(make_finding("sample.py", 1), tmp_path)


def test_unreadable_source_is_wrapped(tmp_path: Path) -> None:
    """Filesystem read failures raise PatchGenerationError."""
    (tmp_path / "sample.py").mkdir()
    with pytest.raises(PatchGenerationError, match="Unable to read|not a regular file"):
        extract_context(make_finding("sample.py", 1), tmp_path)


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ('PASSWORD = "fixture-password-value"\n', "fixture-password-value"),
        ("TOKEN = 'sk-0123456789abcdef'\n", "sk-0123456789abcdef"),
        ("TOKEN = 'ghp_01234567890123456789'\n", "ghp_01234567890123456789"),
        (
            "TOKEN = 'github_pat_0123456789abcdefghijklmn'\n",
            "github_pat_0123456789abcdefghijklmn",
        ),
        ("TOKEN = 'AKIA1234567890ABCDEF'\n", "AKIA1234567890ABCDEF"),
        ("TOKEN = 'xoxb-1234567890-abcd'\n", "xoxb-1234567890-abcd"),
        (
            (
                'PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----\n'
                "private-key-material\n"
                "-----END PRIVATE KEY-----\n"
                '"""\n'
            ),
            "private-key-material",
        ),
    ],
)
def test_extract_context_redacts_secrets_from_the_choke_point(
    tmp_path: Path, source: str, secret: str
) -> None:
    """Every context snippet is redacted before CodeContext is constructed."""
    write_source(tmp_path, source)
    context = extract_context(make_finding("sample.py", 1), tmp_path)
    assert secret not in context.snippet
    assert all(secret not in imported for imported in context.imports)
    assert REDACTION_MARKER in context.snippet


def test_code_context_json_contains_every_field(tmp_path: Path) -> None:
    """CodeContext serialization exposes all fields as JSON-compatible values."""
    source = "import os\nvalue = 1\n"
    write_source(tmp_path, source, "serializer_context_fixture.py")
    context = extract_context(
        make_finding("serializer_context_fixture.py", 2), tmp_path
    )
    assert context.to_json_dict() == {
        "finding_id": "finding-1",
        "snippet": source.rstrip("\n"),
        "snippet_line_start": 1,
        "symbol": None,
        "imports": ["import os"],
    }

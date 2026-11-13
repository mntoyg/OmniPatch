"""OP-25 — redaction must not turn a parseable scope into one that will not parse.

Every fixture secret here is self-labelling, as `AGENTS.md` section 2 requires.
"""

import ast
import secrets
import textwrap
from pathlib import Path, PurePosixPath

import pytest

from omnipatch.codebase import ast_tools
from omnipatch.codebase.ast_tools import extract_context
from omnipatch.codebase.redaction import REDACTION_MARKER, redact
from omnipatch.models import Finding, Severity

SECRET = secrets.token_urlsafe(24)  # Synthetic test value; no live credential.


def parses(source: str) -> bool:
    """Report whether a scope parses once dedented, as the pipeline parses it."""
    try:
        ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError):
        return False
    return True


def make_finding(file: str, line: int, rule_id: str = "B608") -> Finding:
    """Build a finding whose source is not bandit, keeping the snippet redaction path."""
    return Finding(
        "finding-op25",
        rule_id,
        "query built from string",
        Severity.MEDIUM,
        PurePosixPath(file),
        line,
        line,
        "possible SQL injection",
        "test",
    )


@pytest.mark.parametrize(
    "shape",
    [
        pytest.param(
            "def build(d: dict) -> str:\n"
            f"    return f\"password={SECRET}&k={{d['k']}}\"\n",
            id="replacement-field-with-inner-quote",
        ),
        pytest.param(
            "def build(user: str) -> str:\n"
            f'    return f"user={{user}}&password={SECRET}&opts={{{{\\"a\\": 1}}}}"\n',
            id="literal-doubled-brace",
        ),
        pytest.param(
            "def build(n: int) -> str:\n"
            f"    return f\"password={SECRET} size={{n:{{'>'}}8}}\"\n",
            id="nested-format-spec",
        ),
    ],
)
def test_inline_key_value_redaction_keeps_an_f_string_parseable(shape: str) -> None:
    """Redacting a sensitive pair inside an f-string must not break its syntax."""
    assert parses(shape), "the fixture itself must parse, or it measures nothing"
    redacted = redact(shape)
    assert SECRET not in redacted
    assert REDACTION_MARKER in redacted
    assert parses(redacted)


def test_inline_key_value_redaction_still_fires_on_a_plain_string() -> None:
    """The narrowed pattern must not switch the shape off for ordinary strings."""
    source = f'def build() -> str:\n    return "password={SECRET}"\n'
    redacted = redact(source)
    assert SECRET not in redacted
    assert REDACTION_MARKER in redacted
    assert parses(redacted)


def test_context_boundary_warns_when_redaction_breaks_the_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A redactor that corrupts a parseable scope is reported to the operator."""
    source = (
        f"def build(d: dict) -> str:\n    return f\"password={SECRET}&k={{d['k']}}\"\n"
    )
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")

    def corrupting_redact(text: str) -> str:
        return text.replace('f"', 'f"{', 1)

    monkeypatch.setattr(
        "omnipatch.codebase.redaction.redact", corrupting_redact, raising=True
    )
    extract_context(make_finding("sample.py", 2), tmp_path)

    message = capsys.readouterr().err
    assert "warning:" in message
    assert "finding-op25" in message
    assert "B608" in message
    assert SECRET not in message
    assert "def build" not in message


def test_context_boundary_is_quiet_when_redaction_keeps_the_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The report is about preservation, so a parse-preserving redactor says nothing."""
    source = "def build() -> str:\n    return 'plain'\n"
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")
    monkeypatch.setattr(
        "omnipatch.codebase.redaction.redact", lambda text: text, raising=True
    )
    context = extract_context(make_finding("sample.py", 2), tmp_path)
    assert parses(context.snippet)
    assert "warning: redaction" not in capsys.readouterr().err


def test_report_is_silent_when_the_scope_did_not_parse_before_redaction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An already-unparseable scope keeps its existing behaviour and is not blamed here."""
    finding = make_finding("sample.py", 1)
    broken = "def build(:\n"
    assert not parses(broken)
    ast_tools._report_redaction_parse_loss(finding, broken, broken + "# tail\n")
    assert capsys.readouterr().err == ""


def test_redacting_a_credential_shaped_import_name_warns_but_still_extracts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Redaction may legitimately destroy syntax; that must warn, never refuse.

    A credential-shaped module name is redacted to a marker that cannot parse. The
    redaction is correct, so extraction proceeds and the operator is told. This is
    the case that made a refusing gate wrong — OP-25 records the design error.
    """
    (tmp_path / "sample.py").write_text(
        "import github_pat_01234567890123456789\nvalue = 1\n", encoding="utf-8"
    )
    context = extract_context(make_finding("sample.py", 2), tmp_path)
    assert REDACTION_MARKER in context.snippet
    assert "github_pat_01234567890123456789" not in context.snippet
    assert "warning: redaction left context" in capsys.readouterr().err


def test_real_f_string_context_survives_the_whole_boundary(tmp_path: Path) -> None:
    """End to end: an f-string carrying a sensitive pair yields a parseable snippet."""
    source = (
        "def build(d: dict) -> str:\n"
        f"    query = f\"password={SECRET}&k={{d['k']}}\"\n"
        "    return query\n"
    )
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")
    context = extract_context(make_finding("sample.py", 2), tmp_path)
    assert SECRET not in context.snippet
    assert parses(context.snippet)

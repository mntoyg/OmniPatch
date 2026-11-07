"""Regression coverage for the context redaction choke point."""

import ast
from pathlib import Path, PurePosixPath

import pytest

from omnipatch.codebase.ast_tools import extract_context
from omnipatch.codebase.redaction import REDACTION_MARKER, redact_b105_literal
from omnipatch.errors import PatchGenerationError
from omnipatch.models import Finding, Severity
from omnipatch.scanners.bandit_scanner import BanditScanner


@pytest.mark.parametrize(
    ("name", "source", "secrets", "disposition"),
    [
        (
            "dict literal value",
            'data = {"password": "SECRET"}\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "auth header dict",
            'headers = {"Authorization": "Bearer SECRET"}\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "equality comparison",
            'if token == "SECRET":\n    pass\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "URL embedded credentials",
            'DB_DSN = "postgres://user:SECRET@host/db"\n',
            ("SECRET",),
            "redacted-url",
        ),
        (
            "subscript assignment",
            'headers["X-Api-Key"] = "SECRET"\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "plain return in sensitive-named function",
            'def get_password():\n    return "SECRET"\n',
            ("SECRET",),
            "redacted-return",
        ),
        (
            "kwarg at call site",
            'connect(password="SECRET")\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "function default",
            'def helper(pwd="SECRET"):\n    pass\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "simple assignment",
            'api_key = "SECRET"\n',
            ("SECRET",),
            "redacted",
        ),
        (
            "implicit concatenation",
            'TOKEN = ("SEC" "RET")\n',
            ("SEC", "RET"),
            "redacted-concatenation",
        ),
        (
            "sensitive tuple pair",
            'values = [("password", "ZZ06")]\n',
            ("ZZ06",),
            "redacted",
        ),
        (
            "unquoted key in multiline literal",
            'blob = """\npassword: ZZ07\n"""\n',
            ("ZZ07",),
            "redacted",
        ),
        (
            "authorization scheme in literal",
            'headers = "Authorization: Bearer ZZ08"\n',
            ("ZZ08",),
            "redacted-scheme",
        ),
        (
            "dotenv assignment in literal",
            'blob = "TOKEN=ZZ09"\n',
            ("ZZ09",),
            "redacted",
        ),
    ],
    ids=[
        "mapping-value",
        "authorization-header",
        "equality",
        "url-password",
        "subscript-assignment",
        "sensitive-return",
        "call-kwarg",
        "function-default",
        "simple-assignment",
        "implicit-concatenation",
        "sensitive-sequence-pair",
        "multiline-unquoted-key",
        "authorization-scheme-literal",
        "dotenv-literal",
    ],
)
def test_fourteen_redaction_shapes_through_extract_context(
    tmp_path: Path,
    name: str,
    source: str,
    secrets: tuple[str, ...],
    disposition: str,
) -> None:
    """The extraction choke point covers fourteen credential source shapes."""
    path = tmp_path / "case.py"
    path.write_text(source, encoding="utf-8")
    line_start = 2 if name == "plain return in sensitive-named function" else 1
    finding = Finding(
        id="redaction-probe",
        rule_id="B105",
        title=name,
        severity=Severity.LOW,
        file=PurePosixPath("case.py"),
        line_start=line_start,
        line_end=line_start,
        message=name,
        source="test",
    )
    context = extract_context(finding, tmp_path)

    if disposition == "redacted-return":
        assert context.symbol == "get_password"
        assert secrets[0] not in context.snippet
        assert REDACTION_MARKER in context.snippet
        assert len(context.snippet.splitlines()) == len(source.splitlines())
        ast.parse(context.snippet)

    for secret in secrets:
        assert secret not in context.snippet
    assert REDACTION_MARKER in context.snippet
    if disposition == "redacted-url":
        assert f"postgres://user:{REDACTION_MARKER}@host/db" in context.snippet
    if disposition == "redacted-concatenation":
        assert context.snippet.count(REDACTION_MARKER) == 2
    if disposition == "redacted-scheme":
        assert f"Authorization: Bearer {REDACTION_MARKER}" in context.snippet


@pytest.mark.parametrize(
    ("source", "visible", "hidden"),
    [
        (
            'def public_message():\n    return "public text"\n',
            "public text",
            (),
        ),
        (
            'def get_password():\n    if True:\n        return f"credential {PASSWORD}"\n    try:\n        return "BACKUP-SECRET" + "-SUFFIX"\n    except ValueError:\n        return "THIRD-SECRET"\n',
            "",
            ("credential", "BACKUP-SECRET", "-SUFFIX", "THIRD-SECRET"),
        ),
        (
            'def get_password():\n    def helper():\n        return "PUBLIC-HELPER"\n    return "PRIVATE-SECRET"\n',
            "PUBLIC-HELPER",
            ("PRIVATE-SECRET",),
        ),
        (
            'def public_outer():\n    def read_secret():\n        return "NESTED-SECRET"\n    return "PUBLIC-OUTER"\n',
            "PUBLIC-OUTER",
            ("NESTED-SECRET",),
        ),
    ],
    ids=[
        "public-return",
        "control-flow-and-literals",
        "nested-public",
        "nested-sensitive",
    ],
)
def test_sensitive_return_redaction_respects_function_ownership(
    tmp_path: Path, source: str, visible: str, hidden: tuple[str, ...]
) -> None:
    """Only returns owned by sensitive-named functions lose their literals."""
    path = tmp_path / "case.py"
    path.write_text(source, encoding="utf-8")
    finding = Finding(
        id="sensitive-return-probe",
        rule_id="B105",
        title="return credential",
        severity=Severity.LOW,
        file=PurePosixPath("case.py"),
        line_start=1,
        line_end=len(source.splitlines()),
        message="return credential",
        source="test",
    )
    context = extract_context(finding, tmp_path)
    for secret in hidden:
        assert secret not in context.snippet
    if visible:
        assert visible in context.snippet
    assert len(context.snippet.splitlines()) == len(source.splitlines())
    ast.parse(context.snippet)


def test_sensitive_return_redaction_is_idempotent(tmp_path: Path) -> None:
    """Repeating context extraction does not change an existing redaction."""
    source = 'def fetch_api_token():\n    return "IDEMPOTENCE-SECRET"\n'
    (tmp_path / "case.py").write_text(source, encoding="utf-8")
    finding = Finding(
        id="idempotent-return-probe",
        rule_id="B105",
        title="return token",
        severity=Severity.LOW,
        file=PurePosixPath("case.py"),
        line_start=2,
        line_end=2,
        message="return token",
        source="test",
    )
    once = extract_context(finding, tmp_path).snippet
    twice = extract_context(finding, tmp_path).snippet
    assert once == twice
    assert "IDEMPOTENCE-SECRET" not in once


@pytest.mark.parametrize(
    ("source", "scheme", "credential"),
    [
        ('header = "Basic dXNlcjpwYXNzd29yZA=="\n', "Basic", "dXNlcjpwYXNzd29yZA=="),
        ('header = "token abc123"\n', "token", "abc123"),
    ],
)
def test_all_inline_http_schemes_keep_scheme_through_context(
    tmp_path: Path, source: str, scheme: str, credential: str
) -> None:
    """Basic and token schemes retain their marker while credentials disappear."""
    (tmp_path / "case.py").write_text(source, encoding="utf-8")
    finding = Finding(
        id="scheme-probe",
        rule_id="B105",
        title="inline credential",
        severity=Severity.LOW,
        file=PurePosixPath("case.py"),
        line_start=1,
        line_end=1,
        message="inline credential",
        source="test",
    )
    context = extract_context(finding, tmp_path)
    assert credential not in context.snippet
    assert f"{scheme} {REDACTION_MARKER}" in context.snippet


@pytest.mark.integration
@pytest.mark.parametrize(
    "target_statement",
    [
        'stored_pass = "SELF_LABELLED_B105_CONTEXT_SENTINEL_DO_NOT_USE"',
        'credentials = {"stored_pass": "SELF_LABELLED_B105_CONTEXT_SENTINEL_DO_NOT_USE"}',
        'if stored_pass == "SELF_LABELLED_B105_CONTEXT_SENTINEL_DO_NOT_USE":\n    pass',
        'settings["pass"] = "SELF_LABELLED_B105_CONTEXT_SENTINEL_DO_NOT_USE"',
    ],
    ids=["assignment", "mapping-value", "comparison", "subscript-value"],
)
def test_bandit_b105_reported_literal_is_removed_from_extracted_context(
    tmp_path: Path, target_statement: str
) -> None:
    """B105's exact synthetic literal is redacted even outside our name list."""
    source = (
        "from os import getenv\n"
        f"{target_statement}\n"
        'public_label = "PUBLIC_CONTEXT_SENTINEL"\n'
    )
    (tmp_path / "case.py").write_text(source, encoding="utf-8")
    findings = BanditScanner().scan(tmp_path)
    finding = next(
        item
        for item in findings
        if item.rule_id == "B105" and item.file == PurePosixPath("case.py")
    )

    context = extract_context(finding, tmp_path)
    secret_leaked = any(
        "SELF_LABELLED_B105_CONTEXT_SENTINEL_DO_NOT_USE" in text
        for text in (context.snippet, *context.imports)
    )
    assert secret_leaked is False
    assert "PUBLIC_CONTEXT_SENTINEL" in context.snippet
    assert len(context.snippet.splitlines()) == len(source.splitlines())
    ast.parse(context.snippet)
    assert context.imports == ("from os import getenv",)


@pytest.mark.integration
def test_bandit_b105_redaction_preserves_unrelated_literal_on_same_line(
    tmp_path: Path,
) -> None:
    """A neighboring non-B105 target remains visible even on the finding line."""
    source = (
        'stored_pass = "SELF_LABELLED_B105_SHARED_LINE_SENTINEL"; '
        'public_label = "PUBLIC_SHARED_LINE_SENTINEL"\n'
    )
    (tmp_path / "case.py").write_text(source, encoding="utf-8")
    findings = BanditScanner().scan(tmp_path)
    finding = next(item for item in findings if item.rule_id == "B105")

    context = extract_context(finding, tmp_path)

    assert "SELF_LABELLED_B105_SHARED_LINE_SENTINEL" not in context.snippet
    assert "PUBLIC_SHARED_LINE_SENTINEL" in context.snippet
    assert len(context.snippet.splitlines()) == len(source.splitlines())
    ast.parse(context.snippet)


def test_b105_redaction_fails_closed_for_unmatched_target_without_echoing_source() -> (
    None
):
    """Unsupported B105 expressions fail with a value-free diagnostic."""
    source = 'stored_pass = load_value("SELF_LABELLED_B105_UNMATCHED_SENTINEL")\n'

    with pytest.raises(PatchGenerationError) as error:
        redact_b105_literal(source, 1)

    assert "SELF_LABELLED_B105_UNMATCHED_SENTINEL" not in str(error.value)

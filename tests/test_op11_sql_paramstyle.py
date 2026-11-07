"""Focused offline controls for explicit B608 parameter-style configuration."""

import json
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

import omnipatch.cli as cli_module
from omnipatch.agents.llm_agent import (
    LLMPatchAgent,
    _validate_b608_paramstyle_candidate,
)
from omnipatch.errors import PatchGenerationError
from omnipatch.models import CodeContext, Finding, Severity


class FakeProvider:
    model = "offline-test-provider"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append(user)
        return "not a valid patch"


def _finding() -> Finding:
    return Finding(
        id="sql-finding",
        rule_id="B608",
        title="SQL injection",
        severity=Severity.HIGH,
        file=PurePosixPath("app.py"),
        line_start=4,
        line_end=4,
        message="unsafe query",
        source="test",
    )


def _candidate(query: str, execute: str = "cursor.execute(query, (value,))") -> str:
    return (
        "def load_user(value, cursor):\n"
        "    query = " + query + "\n"
        "    " + execute + "\n"
        "    return cursor.fetchall()\n"
    )


@pytest.mark.parametrize(
    ("style", "placeholder"),
    [
        ("qmark", "?"),
        ("numeric", ":1"),
        ("named", ":value"),
        ("format", "%s"),
        ("pyformat", "%(value)s"),
    ],
)
def test_all_pep249_styles_accept_bound_static_query(
    style: str, placeholder: str
) -> None:
    _validate_b608_paramstyle_candidate(
        _candidate(f"\"SELECT * FROM users WHERE name = '{placeholder}'\""),
        _finding(),
        style,
    )


def test_qmark_refuses_live_failure_percent_s_candidate() -> None:
    with pytest.raises(PatchGenerationError, match="inconsistent"):
        _validate_b608_paramstyle_candidate(
            _candidate('"SELECT * FROM users WHERE name = %s"'),
            _finding(),
            "qmark",
        )


def test_query_without_bound_parameters_is_refused() -> None:
    with pytest.raises(PatchGenerationError, match="bind parameters"):
        _validate_b608_paramstyle_candidate(
            _candidate('"SELECT * FROM users WHERE name = ?"', "cursor.execute(query)"),
            _finding(),
            "qmark",
        )


@pytest.mark.parametrize(
    "query",
    [
        'f"SELECT * FROM users WHERE name = {value} AND id = ?"',
        '"SELECT * FROM users WHERE name = " + value + " AND id = ?"',
    ],
)
def test_interpolated_or_concatenated_query_is_refused(query: str) -> None:
    with pytest.raises(
        PatchGenerationError, match="not interpolation or concatenation"
    ):
        _validate_b608_paramstyle_candidate(_candidate(query), _finding(), "qmark")


def test_non_static_query_is_refused_for_manual_review() -> None:
    source = (
        "def load_user(value, cursor):\n"
        "    query = build_query(value)\n"
        "    cursor.execute(query, (value,))\n"
    )
    with pytest.raises(PatchGenerationError, match="manual review required"):
        _validate_b608_paramstyle_candidate(source, _finding(), "qmark")


def test_missing_mapping_refuses_before_provider_call() -> None:
    provider = FakeProvider()
    agent = LLMPatchAgent(provider, max_repair_attempts=0)
    context = CodeContext(
        "sql-finding",
        'def load_user(value, cursor):\n    query = "SELECT * FROM users"\n',
        1,
        "load_user",
        (),
    )
    with pytest.raises(PatchGenerationError, match="app.py::load_user") as caught:
        agent.propose(_finding(), context, context.snippet)
    assert "qmark, numeric, named, format, pyformat" in str(caught.value)
    assert provider.calls == []


def test_cli_lists_unmapped_b608_key_before_provider_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "b608-target"
    target.mkdir()
    (target / "app.py").write_text(
        "def lookup_item(connection, item_id):\n"
        "    cursor = connection.cursor()\n"
        "    query = f\"SELECT item_id FROM inventory WHERE item_id = '{item_id}'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    provider = FakeProvider()
    monkeypatch.setenv("OMNIPATCH_SQL_PARAMSTYLE", "{}")
    monkeypatch.setattr(cli_module, "build_llm_client", lambda settings: provider)
    result = CliRunner().invoke(
        cli_module.app,
        ["verify", "--repo", str(target), "--rule", "B608", "--json"],
    )
    assert result.exit_code == 1
    assert "app.py::lookup_item" in result.output
    assert "qmark, numeric, named, format, pyformat" in result.output
    assert provider.calls == []


def test_request_names_required_paramstyle_without_secret_data() -> None:
    provider = FakeProvider()
    agent = LLMPatchAgent(
        provider,
        max_repair_attempts=0,
        sql_paramstyle={"app.py::load_user": "qmark"},
    )
    source = _candidate('"SELECT * FROM users WHERE name = ?"')
    context = CodeContext("sql-finding", source, 1, "load_user", ())
    with pytest.raises(PatchGenerationError):
        agent.propose(_finding(), context, source)
    request = json.loads(provider.calls[0])
    assert request["required_sql_paramstyle"] == "qmark"
    assert request["required_sql_placeholder_example"] == "?"

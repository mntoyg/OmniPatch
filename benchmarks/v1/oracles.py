"""Trusted behavioral oracles for approved v1 development reference fixes."""

import ast
import os
import runpy
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

DEVELOPMENT_CASE_IDS = (
    "dev-b608-static-query",
    "dev-b608-concatenated-query",
    "dev-b105-module-constant",
    "dev-b105-function-local",
    "dev-b602-direct-call",
    "dev-b602-wrapper-call",
)


def _without_docstrings(node: ast.AST) -> None:
    """Remove docstring expressions before comparing reviewed executable ASTs."""
    if (
        isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        )
        and node.body
        and _is_docstring(node.body[0])
    ):
        del node.body[0]
    for child in ast.iter_child_nodes(node):
        _without_docstrings(child)


def _is_docstring(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def candidate_matches_approved_reference(
    candidate_path: Path, reference_path: Path
) -> bool:
    """Allow execution only when executable AST matches the owner-approved source."""
    try:
        candidate_tree = ast.parse(candidate_path.read_text(encoding="utf-8"))
        reference_tree = ast.parse(reference_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return False
    _without_docstrings(candidate_tree)
    _without_docstrings(reference_tree)
    return ast.dump(candidate_tree, include_attributes=False) == ast.dump(
        reference_tree, include_attributes=False
    )


def run_behavioral_oracle(
    case_id: str, candidate_path: Path, approved_reference_path: Path
) -> None:
    """Exercise an AST-matched owner-approved candidate without launching processes."""
    if case_id not in DEVELOPMENT_CASE_IDS:
        raise ValueError(f"Unsupported development case: {case_id}")
    if not candidate_matches_approved_reference(
        candidate_path, approved_reference_path
    ):
        raise ValueError("Candidate differs from its owner-approved executable AST")
    source = candidate_path.read_text(encoding="utf-8")
    if case_id in ("dev-b105-module-constant", "dev-b105-function-local"):
        if "FAKE_BENCHMARK_" in source:
            raise AssertionError("Self-labelled fake password remains in candidate")
        with patch.dict(os.environ, {"APP_PASSWORD": "FAKE_RUNTIME_PASSWORD"}):
            namespace = runpy.run_path(str(candidate_path))
            password = namespace["configured_password"]()
        assert password == "FAKE_RUNTIME_PASSWORD"
        return

    namespace = runpy.run_path(str(candidate_path))

    if case_id == "dev-b608-static-query":
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE accounts (username TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO accounts (username) VALUES (?)", [("alice",), ("bob",)]
        )
        rows = namespace["lookup_username"](connection, "alice' OR '1'='1")
        assert rows == []
        connection.close()
        return

    if case_id == "dev-b608-concatenated-query":
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE inventory (item_id TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO inventory (item_id) VALUES (?)", [("1",), ("2",)]
        )
        rows = namespace["lookup_item"](connection, "1' OR 1=1 -- ")
        assert rows == []
        connection.close()
        return

    captured: list[tuple[object, dict[str, object]]] = []

    def fake_run(args: object, **kwargs: object) -> SimpleNamespace:
        captured.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    function_name = (
        "search_sample" if case_id == "dev-b602-direct-call" else "print_user_value"
    )
    patterns = (
        ("green", 'green"; echo UNTRUSTED; "')
        if case_id == "dev-b602-direct-call"
        else ("ordinary-value", "value; touch SHOULD_NOT_EXIST")
    )
    with patch.object(subprocess, "run", fake_run):
        for value in patterns:
            namespace[function_name](value)
            args, kwargs = captured[-1]
            assert isinstance(args, list)
            assert args[0] == sys.executable
            assert args[-1] == value
            assert kwargs.get("shell") is False

"""Offline regression checks for proposed synthetic benchmark development fixes."""

import ast
import json
import runpy
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
CASE_ROOT = ROOT / "benchmarks" / "v1" / "development"
SQL_CASES = (
    (
        "dev-b608-static-query",
        "lookup_username",
        "accounts",
        "username",
        "alice' OR '1'='1",
    ),
    (
        "dev-b608-concatenated-query",
        "lookup_item",
        "inventory",
        "item_id",
        "1' OR 1=1 -- ",
    ),
)
PASSWORD_CASES = (
    ("dev-b105-module-constant", "FAKE_BENCHMARK_PASSWORD_DO_NOT_USE"),
    ("dev-b105-function-local", "FAKE_BENCHMARK_LOCAL_PASSWORD_DO_NOT_USE"),
)
COMMAND_CASES = (("dev-b602-wrapper-call", "print_user_value"),)


def _load(case_id: str, source_name: str) -> dict[str, object]:
    """Load one benchmark module by path without creating a package or files."""
    return runpy.run_path(str(CASE_ROOT / case_id / source_name))


@pytest.mark.parametrize(
    ("case_id", "function_name", "table", "column", "payload"), SQL_CASES
)
def test_sqlite_repairs_bind_injected_looking_values(
    case_id: str, function_name: str, table: str, column: str, payload: str
) -> None:
    """Vulnerable SQL returns all rows; qmark binding treats payload as data."""
    connection = sqlite3.connect(":memory:")
    connection.execute(f"CREATE TABLE {table} ({column} TEXT NOT NULL)")
    rows = [("alice",), ("bob",)] if column == "username" else [("1",), ("2",)]
    connection.executemany(f"INSERT INTO {table} ({column}) VALUES (?)", rows)

    vulnerable = _load(case_id, "vulnerable.py")[function_name]
    proposed = _load(case_id, "reference_fix.py")[function_name]
    assert callable(vulnerable)
    assert callable(proposed)
    vulnerable_rows = vulnerable(connection, payload)
    repaired_rows = proposed(connection, payload)
    assert vulnerable_rows == rows
    assert repaired_rows == []
    connection.close()


@pytest.mark.parametrize(("case_id", "sentinel"), PASSWORD_CASES)
def test_environment_repairs_remove_self_labelled_passwords(
    case_id: str, sentinel: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proposed fixes read an explicit environment variable without fake literals."""
    monkeypatch.setenv("APP_PASSWORD", "FAKE_RUNTIME_PASSWORD_FOR_TESTS")
    vulnerable_source = (CASE_ROOT / case_id / "vulnerable.py").read_text(
        encoding="utf-8"
    )
    fixed_path = CASE_ROOT / case_id / "reference_fix.py"
    fixed_source = fixed_path.read_text(encoding="utf-8")
    vulnerable = _load(case_id, "vulnerable.py")["configured_password"]
    proposed = _load(case_id, "reference_fix.py")["configured_password"]
    assert callable(vulnerable)
    assert callable(proposed)
    assert vulnerable() == sentinel
    assert proposed() == "FAKE_RUNTIME_PASSWORD_FOR_TESTS"
    assert sentinel in vulnerable_source
    assert sentinel not in fixed_source
    assert 'os.environ["APP_PASSWORD"]' in fixed_source
    module = ast.parse(fixed_source)
    assert isinstance(module.body[0], ast.Import)
    assert any(alias.name == "os" for alias in module.body[0].names)


@pytest.mark.parametrize(("case_id", "function_name"), COMMAND_CASES)
def test_command_repairs_pass_user_input_as_argv(
    case_id: str, function_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The vulnerable boundary enables shell parsing; the proposed one does not."""
    calls: list[tuple[object, dict[str, object]]] = []

    def fake_run(args: object, **kwargs: object) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    vulnerable = _load(case_id, "vulnerable.py")[function_name]
    proposed = _load(case_id, "reference_fix.py")[function_name]
    assert callable(vulnerable)
    assert callable(proposed)
    for payload in ("ordinary-value", "value; touch SHOULD_NOT_EXIST"):
        vulnerable(payload)
        proposed(payload)

        assert calls[-2][0] == "printf " + payload
        assert calls[-2][1]["shell"] is True
        assert calls[-1][0] == [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            payload,
        ]
        assert calls[-1][1]["shell"] is False


def test_direct_search_preserves_operation_and_argument_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordinary searches keep their operation and metacharacters stay data."""
    calls: list[tuple[object, dict[str, object]]] = []

    def fake_run(args: object, **kwargs: object) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    vulnerable_module = _load("dev-b602-direct-call", "vulnerable.py")
    proposed_module = _load("dev-b602-direct-call", "reference_fix.py")
    vulnerable = vulnerable_module["search_sample"]
    proposed = proposed_module["search_sample"]
    assert callable(vulnerable)
    assert callable(proposed)
    script = proposed_module["SEARCH_SCRIPT"]
    assert script == vulnerable_module["SEARCH_SCRIPT"]
    assert script == "import sys; print(sys.argv[1] in 'red green blue')"

    for pattern in ("green", 'green"; echo UNTRUSTED; "'):
        vulnerable(pattern)
        proposed(pattern)
        assert calls[-2][0] == f'"{sys.executable}" -c "{script}" "{pattern}"'
        assert calls[-2][1]["shell"] is True
        assert calls[-1][0] == [sys.executable, "-c", script, pattern]
        assert calls[-1][1]["shell"] is False


@pytest.mark.integration
def test_case_bandit_json_matches_baseline_and_proposed_fix(tmp_path: Path) -> None:
    """Fresh Bandit JSON scans identify all six targets and clear them in fixes."""
    baseline_root = tmp_path / "baseline"
    fixed_root = tmp_path / "reference-fixes"
    target_by_case = {
        "dev-b608-static-query": "B608",
        "dev-b608-concatenated-query": "B608",
        "dev-b105-module-constant": "B105",
        "dev-b105-function-local": "B105",
        "dev-b602-direct-call": "B602",
        "dev-b602-wrapper-call": "B602",
    }
    for case_id in target_by_case:
        for root, source_name in (
            (baseline_root, "vulnerable.py"),
            (fixed_root, "reference_fix.py"),
        ):
            case_dir = root / case_id
            case_dir.mkdir(parents=True)
            source = (CASE_ROOT / case_id / source_name).read_text(encoding="utf-8")
            (case_dir / "app.py").write_text(source, encoding="utf-8")

    reports: dict[str, dict[str, object]] = {}
    for label, scan_root in (("baseline", baseline_root), ("fixed", fixed_root)):
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", str(scan_root), "-f", "json", "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode in (0, 1), result.stderr
        report = json.loads(result.stdout)
        assert report["errors"] == []
        reports[label] = report

    baseline_pairs = {
        (finding["test_id"], Path(finding["filename"]).parent.name)
        for finding in reports["baseline"]["results"]
    }
    fixed_pairs = {
        (finding["test_id"], Path(finding["filename"]).parent.name)
        for finding in reports["fixed"]["results"]
    }
    for case_id, rule_id in target_by_case.items():
        assert (rule_id, case_id) in baseline_pairs
        assert (rule_id, case_id) not in fixed_pairs

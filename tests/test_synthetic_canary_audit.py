"""Offline tests for the opt-in canary gate in a real CLI child process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path
from uuid import uuid4

import pytest

from omnipatch.agents.ollama_client import OllamaCompletionClient, UrlResponse
from omnipatch.agents.request_audit import SyntheticCanaryAuditor
from omnipatch.config import Settings
from omnipatch.errors import PatchGenerationError
from omnipatch.scanners.bandit_scanner import BanditScanner

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
CANARY_ENV = "OP_SYNTHETIC_CANARY_AUDIT_VALUE"
RECORD_ENV = "OP_SYNTHETIC_CANARY_AUDIT_RECORD"
TRIAL_ENV = "OP_SYNTHETIC_CANARY_AUDIT_TRIAL_ID"

_CHILD_HARNESS = r"""
import difflib
import json
import os
import sys
import tempfile
import urllib.request
from dataclasses import replace
from pathlib import Path

mode = os.environ["OP_TEST_MODE"]
scope = os.environ["OP_TEST_SCOPE"]
canary = os.environ["OP_SYNTHETIC_CANARY_AUDIT_VALUE"]
target = Path(os.environ["OP_TEST_TARGET"])
call_count_path = Path(os.environ["OP_TEST_CALL_COUNT"])
request_flags_path = Path(os.environ["OP_TEST_REQUEST_FLAGS"])
public_flags_path = Path(os.environ["OP_TEST_PUBLIC_FLAGS"])
expected_child_temp = Path(__file__).parent / "child-temp"
if (
    Path(tempfile.gettempdir()).resolve() != expected_child_temp.resolve()
    or Path(os.environ["TEMP"]).resolve() != expected_child_temp.resolve()
    or Path(os.environ["TMP"]).resolve() != expected_child_temp.resolve()
):
    raise SystemExit("test-owned temp configuration mismatch")
call_count = 0
request_canary_flags = []
request_public_flags = []


class FakeResponse:
    def __init__(self, content):
        self.body = json.dumps({
            "done_reason": "stop",
            "message": {"content": content},
        }).encode("utf-8")

    def read(self):
        return self.body

    def close(self):
        pass


class FakeOpener:
    def open(self, request, timeout):
        global call_count, request_canary_flags, request_public_flags
        call_count += 1
        serialized_request = request.data or b""
        request_canary_flags.append(canary.encode("utf-8") in serialized_request)
        request_public_flags.append(
            b"PUBLIC_CONTEXT_CONTROL_REMAINS" in serialized_request
        )
        original = (target / "app.py").read_text(encoding="utf-8")
        if scope == "module-constant":
            vulnerable_assignment = f'password_value = "{canary}"'
            fixed_assignment = 'password_value = os.environ["APP_PASSWORD"]'
            mismatched_assignment = 'password_value = os.environ["WRONG_PASSWORD"]'
        else:
            vulnerable_assignment = f'password = "{canary}"'
            fixed_assignment = 'password = os.environ["APP_PASSWORD"]'
            mismatched_assignment = 'password = os.environ["WRONG_PASSWORD"]'
        candidate = original.replace(
            vulnerable_assignment,
            fixed_assignment,
        )
        mismatched_candidate = original.replace(
            vulnerable_assignment,
            mismatched_assignment,
        )
        valid_diff = "".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            candidate.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        ))
        mismatch_diff = "".join(difflib.unified_diff(
            original.splitlines(keepends=True),
            mismatched_candidate.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        ))
        if mode == "positive" and call_count == 1:
            content = mismatch_diff
        else:
            content = valid_diff
        return FakeResponse(content)


urllib.request.build_opener = lambda *args, **kwargs: FakeOpener()

import omnipatch.cli as cli
import omnipatch.agents.llm_agent as llm_agent
from omnipatch.errors import PatchGenerationError

if mode == "auditor_error":
    original_open = Path.open

    def fail_audit_record_write(self, *args, **kwargs):
        if self == Path(os.environ["OP_SYNTHETIC_CANARY_AUDIT_RECORD"]):
            raise OSError(f"synthetic writer diagnostic {canary}")
        return original_open(self, *args, **kwargs)

    Path.open = fail_audit_record_write

if mode == "initial_leak":
    original_prepare = cli._prepare_finding_contexts

    def leak_initial_context(findings, repo_root, settings):
        contexts = original_prepare(findings, repo_root, settings)
        return {
            finding_id: replace(context, snippet=f"{context.snippet}\n{canary}")
            for finding_id, context in contexts.items()
        }

    cli._prepare_finding_contexts = leak_initial_context

if mode == "repair_leak":
    def leak_repair_diagnostic(*args, **kwargs):
        raise PatchGenerationError(canary)

    llm_agent.validate_patch = leak_repair_diagnostic

sys.argv = ["omnipatch", *sys.argv[1:]]
exit_code = 0
try:
    cli.app()
except SystemExit as exc:
    exit_code = int(exc.code or 0)
finally:
    call_count_path.write_text(str(call_count), encoding="utf-8")
    request_flags_path.write_text(
        ",".join("1" if found else "0" for found in request_canary_flags),
        encoding="utf-8",
    )
    public_flags_path.write_text(
        ",".join("1" if found else "0" for found in request_public_flags),
        encoding="utf-8",
    )
raise SystemExit(exit_code)
"""


def _run_child_cli(
    tmp_path: Path,
    *,
    mode: str,
    scope: str = "function-local",
    audit_path: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], str, Path, str, str, str]:
    """Run the actual CLI app in a child with only a fake Ollama opener."""
    canary = f"OMNIPATCH_SYNTHETIC_CANARY_{uuid4().hex}"
    target = tmp_path / "target"
    target.mkdir()
    if scope == "module-constant":
        source = (
            "import os\n"
            f'password_value = "{canary}"\n'
            'public_label = "PUBLIC_CONTEXT_CONTROL_REMAINS"\n'
        )
        mapping = {"app.py::<module>": "APP_PASSWORD"}
    elif scope == "function-local":
        source = (
            "import os\n"
            "def configured_password():\n"
            f'    password = "{canary}"\n'
            '    public_label = "PUBLIC_CONTEXT_CONTROL_REMAINS"\n'
            "    return password, public_label\n"
        )
        mapping = {"app.py::configured_password": "APP_PASSWORD"}
    else:
        raise AssertionError("unsupported synthetic test scope")
    (target / "app.py").write_text(source, encoding="utf-8")
    baseline = BanditScanner().scan(target)
    if not any(
        finding.rule_id == "B105" and finding.file.as_posix() == "app.py"
        for finding in baseline
    ):
        pytest.fail(
            "synthetic scope target lacked B105 before provider request", pytrace=False
        )
    harness = tmp_path / "child_cli.py"
    harness.write_text(_CHILD_HARNESS, encoding="utf-8")
    call_count_path = tmp_path / "fake-opener-count.txt"
    request_flags_path = tmp_path / "fake-opener-canary-flags.txt"
    public_flags_path = tmp_path / "fake-opener-public-flags.txt"
    record_path = audit_path or tmp_path / "audit.jsonl"
    child_temp = tmp_path / "child-temp"
    child_temp.mkdir()
    record_path.parent.mkdir(parents=True, exist_ok=True)
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "WINDIR")
        if key in os.environ
    }
    environment.update(
        {
            "TEMP": str(child_temp),
            "TMP": str(child_temp),
            "PYTHONPATH": str(SOURCE_ROOT),
            "PYTHONIOENCODING": "utf-8",
            "OMNIPATCH_LLM_PROVIDER": "ollama",
            "OMNIPATCH_LLM_OUTPUT": "diff",
            "OMNIPATCH_LLM_MODEL": "synthetic-fake-model",
            "OMNIPATCH_SECRET_ENVIRONMENT": json.dumps(mapping),
            CANARY_ENV: canary,
            RECORD_ENV: str(record_path.resolve()),
            TRIAL_ENV: "synthetic-child-trial",
            "OP_TEST_MODE": mode,
            "OP_TEST_SCOPE": scope,
            "OP_TEST_TARGET": str(target),
            "OP_TEST_CALL_COUNT": str(call_count_path),
            "OP_TEST_REQUEST_FLAGS": str(request_flags_path),
            "OP_TEST_PUBLIC_FLAGS": str(public_flags_path),
        }
    )
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(harness),
                "verify",
                "--repo",
                str(target),
                "--rule",
                "B105",
                "--json",
            ],
            cwd=target,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.fail("child CLI process could not complete", pytrace=False)
    opener_calls = call_count_path.read_text(encoding="utf-8")
    request_flags = request_flags_path.read_text(encoding="utf-8")
    public_flags = public_flags_path.read_text(encoding="utf-8")
    return result, canary, record_path, opener_calls, request_flags, public_flags


def _assert_no_canary(canary: str, **surfaces: str) -> None:
    """Fail with the surface identifier only; never print a captured payload."""
    for surface, value in surfaces.items():
        if canary in value:
            pytest.fail(
                f"synthetic canary detected at surface: {surface}", pytrace=False
            )


def _read_records(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


@pytest.mark.integration
@pytest.mark.parametrize("scope", ["module-constant", "function-local"])
def test_child_cli_audits_initial_and_repair_before_fake_transport(
    tmp_path: Path, scope: str
) -> None:
    result, canary, record_path, call_count, request_flags, public_flags = (
        _run_child_cli(tmp_path, mode="positive", scope=scope)
    )

    _assert_no_canary(canary, stdout=result.stdout, stderr=result.stderr)
    if (
        result.returncode != 0
        or call_count != "2"
        or request_flags != "0,0"
        or public_flags != "1,1"
    ):
        pytest.fail(
            "positive child CLI control did not complete two fake calls", pytrace=False
        )
    records = _read_records(record_path)
    _assert_no_canary(canary, audit_record=json.dumps(records))
    expected_keys = {"schema_version", "trial_id", "phase", "surface", "outcome"}
    if len(records) != 2:
        pytest.fail("positive child CLI did not record both phases", pytrace=False)
    for record, phase in zip(records, ("initial", "repair"), strict=True):
        if set(record) != expected_keys or record != {
            "schema_version": 1,
            "trial_id": "synthetic-child-trial",
            "phase": phase,
            "surface": "serialized_ollama_request_body",
            "outcome": "pass",
        }:
            pytest.fail("audit record violated its allowlist", pytrace=False)


@pytest.mark.integration
@pytest.mark.parametrize(
    ("mode", "expected_calls", "expected_phase", "scope"),
    [
        ("initial_leak", "0", "initial", "module-constant"),
        ("initial_leak", "0", "initial", "function-local"),
        ("repair_leak", "1", "repair", "module-constant"),
        ("repair_leak", "1", "repair", "function-local"),
    ],
)
def test_child_cli_blocks_canary_in_initial_or_repair_request(
    tmp_path: Path, mode: str, expected_calls: str, expected_phase: str, scope: str
) -> None:
    result, canary, record_path, call_count, request_flags, _ = _run_child_cli(
        tmp_path, mode=mode, scope=scope
    )

    _assert_no_canary(canary, stdout=result.stdout, stderr=result.stderr)
    if result.returncode == 0 or call_count != expected_calls:
        pytest.fail(
            f"{mode} did not stop before the unsafe transport call", pytrace=False
        )
    if request_flags != ("0" if mode == "repair_leak" else ""):
        pytest.fail(
            f"{mode} fake transport observed unexpected request content",
            pytrace=False,
        )
    records = _read_records(record_path)
    _assert_no_canary(canary, audit_record=json.dumps(records))
    expected_outcomes = (
        [("initial", "pass"), ("repair", "fail")]
        if mode == "repair_leak"
        else [("initial", "fail")]
    )
    observed = [(record.get("phase"), record.get("outcome")) for record in records]
    if observed != expected_outcomes:
        pytest.fail(f"{mode} audit phase attribution was incorrect", pytrace=False)
    failed = records[-1]
    if (
        failed.get("phase") != expected_phase
        or failed.get("failure_category") != "canary_match"
        or set(failed)
        != {
            "schema_version",
            "trial_id",
            "phase",
            "surface",
            "outcome",
            "failure_category",
        }
    ):
        pytest.fail(f"{mode} failure record violated its allowlist", pytrace=False)


@pytest.mark.integration
def test_child_cli_auditor_failure_is_value_free_and_fails_closed(
    tmp_path: Path,
) -> None:
    result, canary, record_path, call_count, request_flags, _ = _run_child_cli(
        tmp_path, mode="auditor_error"
    )

    _assert_no_canary(canary, stdout=result.stdout, stderr=result.stderr)
    if result.returncode == 0 or call_count != "0":
        pytest.fail("auditor failure did not block the fake transport", pytrace=False)
    if request_flags:
        pytest.fail(
            "auditor failure allowed a request to reach transport", pytrace=False
        )
    if "auditor_error" not in result.stderr:
        pytest.fail("auditor failure category was not reported", pytrace=False)
    if str(record_path) in result.stderr:
        pytest.fail("auditor exception details escaped to CLI output", pytrace=False)
    if record_path.exists():
        pytest.fail(
            "failed audit record unexpectedly created an artifact", pytrace=False
        )


def test_unobserved_phase_is_recorded_as_not_observed_and_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = f"OMNIPATCH_SYNTHETIC_CANARY_{uuid4().hex}"
    record_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(CANARY_ENV, canary)
    monkeypatch.setenv(RECORD_ENV, str(record_path))
    monkeypatch.setenv(TRIAL_ENV, "unobserved-phase-test")
    auditor = SyntheticCanaryAuditor.from_environment()
    if auditor is None:
        pytest.fail("opt-in auditor was not constructed", pytrace=False)
    opener_calls: list[urllib.request.Request] = []

    def opener(request: urllib.request.Request, *, timeout: float) -> UrlResponse:
        opener_calls.append(request)
        pytest.fail("unobserved phase reached the transport", pytrace=False)

    client = OllamaCompletionClient(
        "synthetic-fake-model", opener=opener, request_auditor=auditor
    )
    with pytest.raises(PatchGenerationError) as error:
        client.complete("synthetic system", "synthetic user")
    if "phase_not_observed" not in str(error.value):
        pytest.fail(
            "unobserved phase did not produce its allowlisted category", pytrace=False
        )
    if opener_calls:
        pytest.fail("unobserved phase called the transport", pytrace=False)
    records = _read_records(record_path)
    if records != [
        {
            "schema_version": 1,
            "trial_id": "unobserved-phase-test",
            "phase": "not_observed",
            "surface": "serialized_ollama_request_body",
            "outcome": "fail",
            "failure_category": "phase_not_observed",
        }
    ]:
        pytest.fail("unobserved phase was not recorded explicitly", pytrace=False)


def test_canary_is_not_part_of_settings_configuration_dump(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = f"OMNIPATCH_SYNTHETIC_CANARY_{uuid4().hex}"
    monkeypatch.setenv(CANARY_ENV, canary)
    monkeypatch.setenv(RECORD_ENV, str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv(TRIAL_ENV, "config-dump-test")
    settings = Settings(_env_file=None, llm_provider="ollama")
    _assert_no_canary(
        canary,
        settings_repr=repr(settings),
        settings_dump=settings.model_dump_json(),
    )

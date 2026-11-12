"""Offline checks for the one-case Windows B105 canary runner."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPOSITORY_ROOT / "scripts" / "run-b105-canary-smoke.ps1"


def test_powershell_runner_preflight_and_audit_classification_are_offline() -> None:
    powershell = shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell 7 is unavailable for the runner's offline self-test")

    result = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(RUNNER),
            "-OfflineSelfTest",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if result.returncode != 0:
        pytest.fail("PowerShell runner offline self-test failed", pytrace=False)
    if result.stderr or "OMNIPATCH_SYNTHETIC_CANARY_" in result.stdout:
        pytest.fail("PowerShell self-test exposed a synthetic canary", pytrace=False)

    report = json.loads(result.stdout)
    assert report["preflight"] == {
        "connection_error": "connection_error",
        "connection_error_detail": "transport_error",
        "timeout": "connection_error",
        "timeout_detail": "timeout",
        "connection_refused": "connection_error",
        "connection_refused_detail": "connection_refused",
        "transport_error": "connection_error",
        "transport_error_detail": "transport_error",
        "other_error": "connection_error",
        "other_error_detail": "other_error",
        "http_status": "http_status",
        "invalid_json": "invalid_json",
        "model_missing": "model_missing",
        "digest_mismatch": "digest_mismatch",
        "passed": "passed",
    }
    assert report["scopes"] == {
        "module-constant": {
            "mapping_key": "app.py::<module>",
            "mapping_value": "APP_PASSWORD",
            "canary_embedded": True,
            "expected_shape": True,
            "baseline_b105": True,
            "scanner_errors_empty": True,
        },
        "function-local": {
            "mapping_key": "app.py::configured_password",
            "mapping_value": "APP_PASSWORD",
            "canary_embedded": True,
            "expected_shape": True,
            "baseline_b105": True,
            "scanner_errors_empty": True,
        },
    }
    # Each fake sender is called once: transport failures are classified without retry.
    assert report["fake_request_count"] == 10
    assert report["audit"] == {
        "no_record": "no_audit_record",
        "no_record_initial": "not_observed",
        "repair_only": "initial_not_observed",
        "repair_only_initial": "not_observed",
        "repair_only_repair": "pass",
        "initial_only": "audit_incomplete",
        "initial_only_initial": "pass",
        "initial_only_repair": "not_observed",
        "initial_only_record_count": 1,
        "valid_initial_and_repair": "audit_pass",
        "valid_initial": "pass",
        "valid_repair": "pass",
        "wrong_trial_id": "audit_failed",
        "wrong_schema": "audit_failed",
        "failed_record": "audit_failed",
        "failed_repair": "audit_failed",
    }
    assert report["runner"] == {
        "cli_failure_initial_only_exit": 1,
        "cli_failure_initial_only_category": "audit_incomplete",
        "cli_success_no_record_exit": 1,
        "cli_success_failed_audit_exit": 1,
        "cli_success_initial_only_exit": 1,
        "cli_success_initial_only_category": "audit_incomplete",
        "cli_success_failed_repair_exit": 1,
        "cli_success_audit_pass_exit": 0,
    }

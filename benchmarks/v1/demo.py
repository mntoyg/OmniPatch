"""Safe, single-case local Ollama demo for the synthetic B608 SQLite case."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from benchmarks.v1 import evaluate
from omnipatch.config import validate_local_ollama_endpoint
from omnipatch.defaults import DEFAULT_OLLAMA_ENDPOINT

CASE_ID = "dev-b608-static-query"
MODEL_TAG = "qwen-ctx8k:latest"
DEFAULT_ENDPOINT = DEFAULT_OLLAMA_ENDPOINT
_DIGEST_PATTERN = re.compile(r"(?:sha256:)?[0-9a-fA-F]{64}\Z")
TAGS_FIRST_TIMEOUT_SECONDS = 5
TAGS_RETRY_TIMEOUT_SECONDS = 30
TagsFetcher = Callable[[str, float], Mapping[str, object]]
Evaluator = Callable[[list[str]], int]


@dataclass(frozen=True)
class Preflight:
    """Non-secret identity of the local Ollama model selected for this demo."""

    endpoint: str
    model_digest: str


@dataclass(frozen=True)
class DemoOutcome:
    """Sanitized outcome displayed to the operator."""

    verifier: bool
    oracle: str
    target_finding: bool
    scan_errors: int
    post_findings: int
    introduced_findings: int
    latency_seconds: float | None


def _local_tags_url(endpoint: str) -> str:
    """Accept only the configured loopback Ollama API endpoint."""
    validated = validate_local_ollama_endpoint(endpoint)
    return validated.removesuffix("/api/chat") + "/api/tags"


class _NoRedirect(HTTPRedirectHandler):
    """Prevent a local preflight request from following a remote redirect."""

    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _fetch_tags(url: str, timeout_seconds: float) -> Mapping[str, object]:
    """Fetch the loopback tags document without redirects or credential headers."""
    request = Request(url, headers={"Accept": "application/json"})
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=timeout_seconds) as response:
        raw_payload = response.read(1_048_577)
    if len(raw_payload) > 1_048_576:
        raise ValueError("Local Ollama tags response is too large")
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        raise TypeError("invalid tags response")
    return cast(Mapping[str, object], payload)


def _is_transient_tags_failure(exc: Exception) -> bool:
    """Retry only connection and timeout failures from the loopback API."""
    if isinstance(exc, HTTPError):
        return False
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    # A non-HTTP URLError is urllib's transport-level failure for this validated URL.
    return isinstance(exc, URLError)


def preflight(
    environ: Mapping[str, str], tags_fetcher: TagsFetcher = _fetch_tags
) -> Preflight:
    """Validate exact local settings and resolve the installed tag digest."""
    if environ.get("OMNIPATCH_LLM_PROVIDER") != "ollama":
        raise ValueError("Demo requires OMNIPATCH_LLM_PROVIDER=ollama")
    if environ.get("OMNIPATCH_LLM_OUTPUT") != "function":
        raise ValueError("Demo requires OMNIPATCH_LLM_OUTPUT=function")
    if environ.get("OMNIPATCH_LLM_MODEL") != MODEL_TAG:
        raise ValueError(f"Demo requires OMNIPATCH_LLM_MODEL={MODEL_TAG}")
    endpoint = environ.get("OMNIPATCH_OLLAMA_ENDPOINT", DEFAULT_ENDPOINT)
    tags_url = _local_tags_url(endpoint)
    try:
        payload = tags_fetcher(tags_url, TAGS_FIRST_TIMEOUT_SECONDS)
    except json.JSONDecodeError:
        raise ValueError("Local Ollama tags response is invalid") from None
    except TypeError:
        raise TypeError("Local Ollama tags response is invalid") from None
    except (OSError, ValueError) as exc:
        if not _is_transient_tags_failure(exc):
            raise ValueError("Local Ollama tags API request failed") from None
        try:
            payload = tags_fetcher(tags_url, TAGS_RETRY_TIMEOUT_SECONDS)
        except json.JSONDecodeError:
            raise ValueError("Local Ollama tags response is invalid") from None
        except TypeError:
            raise TypeError("Local Ollama tags response is invalid") from None
        except (OSError, ValueError) as retry_exc:
            if _is_transient_tags_failure(retry_exc):
                raise ValueError(
                    "Local Ollama tags API is unavailable after one retry"
                ) from None
            raise ValueError("Local Ollama tags API request failed") from None
    models = payload.get("models")
    if not isinstance(models, list):
        raise TypeError("Local Ollama tags response is invalid")
    for item in models:
        if not isinstance(item, dict) or item.get("name") != MODEL_TAG:
            continue
        digest = item.get("digest")
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            raise ValueError("Local Ollama model digest is missing or invalid")
        return Preflight(endpoint=endpoint, model_digest=digest)
    raise ValueError(f"Local Ollama model tag {MODEL_TAG} is not installed")


def _validate_output_location(output_dir: Path, cwd: Path) -> Path:
    """Reject project dotenv loading, existing output, and Git repository paths."""
    working = cwd.resolve()
    if (working / ".env").exists():
        raise ValueError("Demo working directory must not contain a .env file")
    output = output_dir.resolve()
    if output.exists():
        raise ValueError("Demo output directory already exists")
    if any(
        (parent / ".git").exists() or (parent / ".git").is_symlink()
        for parent in (output, *output.parents)
    ):
        raise ValueError("Demo output directory must be outside every Git repository")
    return output


def _safe_child_environment(
    environ: Mapping[str, str], endpoint: str
) -> dict[str, str]:
    """Build a minimal child environment with provider and Git credentials removed."""
    safe_names = {
        "PATH",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "HOME",
        "PYTHONPATH",
    }
    child = {key: value for key, value in environ.items() if key.upper() in safe_names}
    child.update(
        {
            "OMNIPATCH_LLM_PROVIDER": "ollama",
            "OMNIPATCH_LLM_OUTPUT": "function",
            "OMNIPATCH_LLM_MODEL": MODEL_TAG,
            "OMNIPATCH_OLLAMA_ENDPOINT": endpoint,
        }
    )
    return child


@contextmanager
def _temporary_environment(values: Mapping[str, str]) -> Iterator[None]:
    """Run the evaluator with only an allowlisted, credential-free environment."""
    original = dict(os.environ)
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def _outcome(output_dir: Path) -> DemoOutcome:
    """Read only bounded status fields; never echo raw evaluator artifacts."""
    result_path = output_dir / "cases" / CASE_ID / "result.json"
    post_path = output_dir / "cases" / CASE_ID / "post-bandit-meta.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    post = (
        json.loads(post_path.read_text(encoding="utf-8")) if post_path.exists() else {}
    )
    errors = post.get("errors", [])
    findings = post.get("findings", [])
    introduced = result.get("introduced_findings_by_severity", {})
    introduced_count = (
        sum(len(values) for values in introduced.values() if isinstance(values, list))
        if isinstance(introduced, dict)
        else 0
    )
    return DemoOutcome(
        verifier=result.get("verification_passed") is True,
        oracle=(
            cast(str, result.get("regression_test", {}).get("status", "not_run"))
            if isinstance(result.get("regression_test"), dict)
            else "not_run"
        ),
        target_finding=any(
            isinstance(item, dict)
            and item.get("rule_id") == "B608"
            and item.get("file") == "app.py"
            for item in findings
        ),
        scan_errors=len(errors) if isinstance(errors, list) else 1,
        post_findings=len(findings) if isinstance(findings, list) else 0,
        introduced_findings=introduced_count,
        latency_seconds=(
            float(result["latency_seconds"])
            if isinstance(result.get("latency_seconds"), (int, float))
            else None
        ),
    )


def run_demo(
    output_dir: Path,
    *,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    tags_fetcher: TagsFetcher = _fetch_tags,
    evaluator: Evaluator = evaluate.main,
) -> DemoOutcome:
    """Preflight and run exactly one existing development evaluator case."""
    source_env = dict(os.environ if environ is None else environ)
    working = Path.cwd() if cwd is None else cwd
    output = _validate_output_location(output_dir, working)
    checked = preflight(source_env, tags_fetcher)
    started = time.perf_counter()
    stdout, stderr = StringIO(), StringIO()
    args = [
        "--live",
        "--allow-dirty",
        "--case",
        CASE_ID,
        "--output-dir",
        str(output),
    ]
    with (
        _temporary_environment(_safe_child_environment(source_env, checked.endpoint)),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        exit_code = evaluator(args)
    elapsed = round(time.perf_counter() - started, 4)
    if not (output / "run.json").is_file():
        raise ValueError("Demo evaluation did not produce a run record")
    run_record = json.loads((output / "run.json").read_text(encoding="utf-8"))
    outcome = _outcome(output)
    metadata = {
        "kind": "live_local_ollama_demo",
        "case_id": CASE_ID,
        "provider": "ollama",
        "output_mode": "function",
        "model": MODEL_TAG,
        "model_digest": checked.model_digest,
        "ollama_endpoint": checked.endpoint,
        "source_revision": run_record.get(
            "source_revision", {"head": "unknown", "dirty": True}
        ),
        "elapsed_seconds": elapsed,
        "verifier_passed": outcome.verifier,
        "oracle_status": outcome.oracle,
        "target_b608_remaining": outcome.target_finding,
        "post_scan_errors": outcome.scan_errors,
        "post_scan_findings": outcome.post_findings,
        "introduced_findings": outcome.introduced_findings,
        "evaluator_exit_code": exit_code,
    }
    metadata_path = output / "demo-metadata.json"
    with metadata_path.open("x", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2, sort_keys=True)
        file.write("\n")
    print(
        "Demo result: "
        f"verifier={'passed' if outcome.verifier else 'failed'}, "
        f"oracle={outcome.oracle}, "
        f"B608={'remaining' if outcome.target_finding else 'absent'}, "
        f"post_scan_findings={outcome.post_findings}, "
        f"post_scan_errors={outcome.scan_errors}, "
        f"introduced_findings={outcome.introduced_findings}, "
        f"latency_seconds={outcome.latency_seconds}"
    )
    if (
        exit_code != 0
        or not outcome.verifier
        or outcome.oracle != "passed"
        or outcome.target_finding
        or outcome.scan_errors != 0
        or outcome.post_findings != 0
        or outcome.introduced_findings != 0
    ):
        raise ValueError("Demo did not produce a verified oracle-scored repair")
    return outcome


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Query only local Ollama tags and print the selected model digest.",
    )
    args = parser.parse_args(argv)
    try:
        if args.preflight_only:
            checked = preflight(os.environ)
            print(
                "Local Ollama preflight passed: provider=ollama, output=function, "
                f"model={MODEL_TAG}, digest={checked.model_digest}"
            )
            return 0
        if args.output_dir is None:
            parser.error("--output-dir is required unless --preflight-only is used")
        run_demo(args.output_dir)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Demo stopped: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

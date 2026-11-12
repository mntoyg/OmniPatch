# OmniPatch

OmniPatch is an experimental command-line tool that uses Bandit findings and a configured language model to propose Python security repairs. It validates proposed changes in an isolated workspace and rescans the candidate before reporting verification results.

This public-preview candidate is not a production security product. Current evidence is limited to synthetic benchmark cases. Results do not establish performance on arbitrary customer repositories, and verification cannot prove that a patch is correct for every application. Review every proposed diff and run your own tests before applying it.

## Current scope

- Python repositories scanned with Bandit.
- Model providers: Anthropic or a local Ollama server.
- CLI commands: `scan`, `context`, `patch`, `verify`, `run`, and `version`.
- `run` performs a dry run by default. GitHub publication requires the explicit `--apply` option and creates draft pull requests; OmniPatch does not auto-merge.
- B105 and B608 repairs may require explicit environment-variable or SQL parameter-style mappings. The tool must not invent application-specific configuration.

The supported behavior is intentionally narrow and may change during the preview. OmniPatch is not a general vulnerability scanner, autonomous deployment tool, or substitute for a security review.

## Requirements

- Python 3.11 or newer.
- Bandit is installed as a project dependency and runs locally against the selected repository.
- `uv` for installing the project from source.
- For model-backed commands, either an Anthropic API key or a local Ollama installation with a compatible model.
- GitHub credentials and repository permissions only when explicitly using `run --apply`.

## Install from a checkout

```powershell
uv sync --locked
uv run omnipatch version
uv run omnipatch --help
```

For a released wheel, use the accompanying hash-pinned `requirements-runtime.txt`
from the same release to keep installed dependency versions aligned with the lock
and bundled third-party notice inventory. Install the requirements first, then
install the wheel without resolving a second dependency set:

```powershell
uv venv
uv pip sync --python .venv/Scripts/python.exe --require-hashes requirements-runtime.txt
uv pip install --python .venv/Scripts/python.exe --no-deps dist/omnipatch-0.1.0-py3-none-any.whl
```

On Linux, use `.venv/bin/python` in place of `.venv/Scripts/python.exe`. The wheel
metadata allows compatible dependency versions; installing the wheel alone with
an unconstrained resolver may select versions outside the lock snapshot.

## Quick start

Run a scan without contacting a model:

```powershell
uv run omnipatch scan --repo . --json
```

Inspect the redacted, bounded context for findings:

```powershell
uv run omnipatch context --repo . --json
```

Generate and verify a candidate for a specific Bandit rule; this does not publish a pull request:

```powershell
uv run omnipatch verify --repo . --rule B608 --json
```

Use `uv run omnipatch <command> --help` for command options. Start with a disposable test repository and inspect the complete candidate diff and verification report.

## Configuration and data flow

Settings use the `OMNIPATCH_` environment-variable prefix and can also be loaded from a `.env` file in the process working directory. Keep `.env` files out of version control. Secret settings are represented as secret values internally; this does not replace host-level secret management.

The default provider is Anthropic. Model-backed commands send finding metadata and bounded, redacted source context to the selected model provider. Redaction reduces accidental disclosure but cannot guarantee that every secret or sensitive datum is identified. Do not process code you are not authorized to send to that provider. Anthropic requests leave the local machine and are subject to the provider's current terms and retention settings.

For local inference, set `OMNIPATCH_LLM_PROVIDER=ollama` and install/run Ollama yourself. OmniPatch restricts the configured Ollama endpoint to HTTP loopback `/api/chat`; model requests remain on the machine hosting OmniPatch and Ollama, subject to that machine's own logging and model configuration. Confirm that the model is present before running model-backed commands.

Example for local Ollama:

```powershell
$env:OMNIPATCH_LLM_PROVIDER = 'ollama'
$env:OMNIPATCH_LLM_MODEL = 'your-installed-model'
uv run omnipatch verify --repo . --rule B608 --json
```

GitHub API access is only needed for `run --apply`. Without `--apply`, `run` remains a dry run and does not call GitHub. With it, OmniPatch requests creation of draft pull requests for verified repairs. Review the requested permissions and every draft before any merge.

## Security and privacy

- Use a clean, disposable checkout for first evaluation.
- Inspect the proposed diff and verification report; run repository-specific tests and review the change before applying it.
- Treat model output as untrusted. Verification checks are not a proof of correctness.
- Do not submit proprietary or personal data to a remote provider unless your organization has approved that data flow.
- Never put API tokens or GitHub tokens in command-line arguments, source files, reports, or issues. Use environment variables or a protected `.env` file.
- Report security issues privately using the process in [`SECURITY.md`](SECURITY.md).

## Development

```powershell
uv sync --locked
uv run python -m pytest -q
uv run python -m pytest -q -o addopts= -m "integration and not protected"
uv run mypy --strict src/
uv run ruff check .
uv run ruff format --check .
uv run bandit -q -r src/
```

Live-provider and protected holdout tests are intentionally excluded from routine CI. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution workflow and required review.

## License

OmniPatch is distributed under the Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Third-party dependencies have their own licenses and notices; review their distributions before redistribution.

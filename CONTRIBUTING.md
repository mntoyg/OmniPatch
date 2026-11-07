# Contributing

Thanks for helping improve OmniPatch. The project is an experimental preview, so changes should be narrow, evidence-based, and safe for untrusted repositories.

## Before opening a change

1. Check existing issues and documentation to avoid duplicating work.
2. For a significant change, open an issue first and describe the user problem, scope, and security implications.
3. Use synthetic fixtures. Never add real credentials, customer source, or personal data.
4. Keep holdout cases, prompts, and expected outcomes private. Do not add provider-dependent or holdout cases to routine CI.

## Local setup

Requirements: Python 3.11 or newer and `uv`.

```powershell
uv sync --locked
```

## Required checks

Run checks through the project environment:

```powershell
uv run python -m pytest -q
uv run python -m pytest -q -o addopts= -m "integration and not protected"
uv run mypy --strict src/
uv run ruff check .
uv run ruff format --check .
uv run bandit -q -r src/
```

Do not run protected holdout or live-provider tests in routine contributions. If a change requires one of those checks, document the need and obtain maintainer direction first. Include actual command results in the pull request; state clearly which checks were skipped.

## Security expectations

- Treat scanner input, repository files, and model output as untrusted.
- Keep path checks, patch isolation, redaction, and post-patch scanning intact. Do not weaken a security control to make a test pass.
- Never execute generated model text. Invoke subprocesses with argument arrays and explicit timeouts.
- Do not log secrets, raw model requests, unredacted source snippets, or sensitive test values.
- Draft pull requests only; no auto-merge. Human review is required for every proposed patch.
- Add a regression test that demonstrates the defect before the fix and confirms the behavior after it.
- Add a same-line explanation for any security suppression and include the suppression audit result.

## Pull requests

Keep changes focused. Explain the problem, approach, security impact, tests run, and known limitations. Use sanitized output and synthetic examples. Do not include customer repository names, source excerpts, credentials, or private benchmark material. A maintainer must review and approve changes before merge.

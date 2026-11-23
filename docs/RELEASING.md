# Releasing a Public Preview

This guide describes a manual GitHub release containing the source archive and wheel. The current
CI validates a wheel and clean installation; it does not publish release artifacts or validate the
source archive. Do not treat a CI green run as release approval.

## Release gates

Before preparing a release candidate:


- Confirm all P0 readiness items in `TASK.md` are closed before versioning the release candidate.
- Confirm branch protection and required checks with a repository administrator.
- Record the scoped third-party license and notice review for both source and wheel distribution.
- Record TL/SE review and the authorized pilot results, including limitations.
- Keep the PR as a draft until those approvals are recorded. A maintainer must approve the final
  versioned Public Preview separately.

## Build and verify artifacts

1. Choose the intended version, update `project.version` in `pyproject.toml`, and refresh
   `uv.lock`. The CI wheel smoke steps currently name `omnipatch-0.1.0-py3-none-any.whl`; make that
   reference version-independent before changing the package version. The README install example
   already uses `omnipatch-VERSION-py3-none-any.whl`; replace `VERSION` with the shipped version.
2. Treat the versioned commit as a new release candidate. Before tagging it, rerun the full required
   CI matrix, Gitleaks, and dependency audit on that exact commit. Reconfirm that third-party
   sign-off, TL/SE review, and pilot evidence cover the exact source and wheel candidate being
   released; obtain updated approvals if the versioning change affects their scope.
3. From the reviewed release commit, install the locked development dependencies and build both
   the Python source distribution (sdist, `*.tar.gz`) and wheel artifacts. GitHub's automatically
   generated source ZIP/tarball for a tag is separate from the Python sdist:

   ```sh
   uv sync --locked --all-groups
   uv build --sdist --wheel --out-dir dist
   ```

4. Check that generated notices match the lock and verify the wheel includes the project and
   third-party notices:

   ```sh
   uv run --frozen python scripts/generate-third-party-notices.py --check
   uv run --frozen python scripts/verify-wheel-notices.py dist
   ```

5. Export and verify the hash-pinned runtime dependency set from the same lock:

   ```sh
   uv export --locked --no-dev --no-emit-project --format requirements.txt --no-header --no-annotate --output-file dist/requirements-runtime.txt
   uv run --frozen python scripts/verify-runtime-requirements.py dist/requirements-runtime.txt
   ```

6. Inspect the Python sdist (`*.tar.gz`) against the approved public file boundary. Confirm it contains the
   project license, notice, documentation, and required source files, and excludes holdout data,
   private history, credentials, and internal-only instructions. Record the artifact filenames and
   SHA-256 digests.
7. Install the wheel in clean Windows and Linux environments using
   `dist/requirements-runtime.txt` with hash checking, install the wheel with `--no-deps`, run
   `uv pip check --python <venv-python>`, and run `scripts/smoke-installed-wheel.py` against the
   synthetic fixture. Use the platform's venv interpreter path shown in the CI workflow. Run the
   same default and safe integration CI gates on the exact release-candidate commit.

## Publish and preserve evidence

Create a **draft GitHub Release** from the reviewed tag. Attach the source archive, wheel,
hash-pinned runtime requirements file, and SHA-256 checksums. Include the candidate commit, CI and
Gitleaks run links, supported-platform limits, known product limitations, and security-reporting
route in the release notes. Have the owner approve and publish the release only after verifying the
draft and attached files.

Do not publish to PyPI or another package index unless the owner separately chooses and approves
that distribution channel. Preserve the exact release artifacts and verification results so users
can reproduce what was distributed.

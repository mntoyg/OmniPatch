"""Tests for temporary materialization of patched source."""

from pathlib import Path, PurePosixPath

import pytest

from omnipatch import codebase
from omnipatch.codebase.repo_io import patched_sandbox
from omnipatch.errors import PatchApplyError


def test_patched_sandbox_writes_nested_path_and_cleans_up() -> None:
    """The requested relative layout exists only during the context."""
    with patched_sandbox(PurePosixPath("pkg/nested/app.py"), "value = 2\n") as root:
        file_path = root / "pkg" / "nested" / "app.py"
        assert file_path.read_text(encoding="utf-8") == "value = 2\n"
        assert set(root.rglob("*")) == {
            root / "pkg",
            root / "pkg/nested",
            file_path,
        }
    assert not root.exists()


def test_patched_sandbox_cleans_up_when_body_raises() -> None:
    """The temporary tree is removed even if its consumer fails."""
    roots: list[Path] = []
    with (
        pytest.raises(RuntimeError, match="consumer failed"),
        patched_sandbox(PurePosixPath("app.py"), "x = 1\n") as root,
    ):
        roots.append(root)
        raise RuntimeError("consumer failed")
    assert roots
    assert not roots[0].exists()


def test_cleanup_failure_does_not_replace_body_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cleanup failure is warned about while the original error propagates."""
    roots: list[Path] = []

    def fail_cleanup(_temporary: object) -> None:
        """Simulate Windows refusing to remove an open temporary file."""
        raise OSError("file is in use")

    monkeypatch.setattr(codebase.repo_io.TemporaryDirectory, "cleanup", fail_cleanup)
    with (
        pytest.raises(RuntimeError, match="Patch introduced new findings: B602"),
        patched_sandbox(PurePosixPath("app.py"), "x = 1\n") as root,
    ):
        roots.append(root)
        raise RuntimeError("Patch introduced new findings: B602")

    assert (
        "warning: unable to remove temporary patch sandbox" in capsys.readouterr().err
    )
    assert roots


def test_cleanup_failure_on_normal_exit_raises_patch_apply_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cleanup failure remains an error when the body succeeded."""

    def fail_cleanup(_temporary: object) -> None:
        """Simulate an operating-system cleanup failure."""
        raise OSError("file is in use")

    monkeypatch.setattr(codebase.repo_io.TemporaryDirectory, "cleanup", fail_cleanup)
    with (
        pytest.raises(
            PatchApplyError, match="Unable to remove temporary patch sandbox"
        ),
        patched_sandbox(PurePosixPath("app.py"), "x = 1\n"),
    ):
        pass


@pytest.mark.parametrize(
    "path",
    [
        PurePosixPath("/absolute/app.py"),
        PurePosixPath("../outside.py"),
        PurePosixPath("pkg/../outside.py"),
        PurePosixPath("C:/absolute/app.py"),
        PurePosixPath(r"pkg\..\outside.py"),
    ],
)
def test_patched_sandbox_rejects_absolute_and_traversal_paths(
    path: PurePosixPath,
) -> None:
    """POSIX and Windows absolute or traversal forms cannot escape."""
    with (
        pytest.raises(PatchApplyError, match="relative and confined"),
        patched_sandbox(path, "x = 1\n"),
    ):
        pytest.fail("unsafe path unexpectedly entered a sandbox")


def test_patched_sandbox_stays_outside_forbidden_repository(tmp_path: Path) -> None:
    """A sandbox's root never resolves under the source repository."""
    with patched_sandbox(
        PurePosixPath("app.py"), "x = 1\n", forbidden_root=tmp_path
    ) as root:
        assert not root.resolve().is_relative_to(tmp_path.resolve())

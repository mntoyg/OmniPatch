"""Confined source reads used by patch workflows."""

from pathlib import Path, PurePosixPath

import pytest

import omnipatch.codebase.source as source_module
from omnipatch.codebase.source import read_finding_source
from omnipatch.errors import PatchGenerationError
from omnipatch.models import Finding, Severity


def make_finding(file: str) -> Finding:
    """Build a minimal finding for a repository-relative source path."""
    return Finding(
        id="source-test-finding",
        rule_id="B999",
        title="Test finding",
        severity=Severity.LOW,
        file=PurePosixPath(file),
        line_start=1,
        line_end=1,
        message="Synthetic finding",
        source="test",
    )


def test_read_finding_source_reads_inside_repository(tmp_path: Path) -> None:
    """A repository-relative source file is returned unchanged."""
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")

    assert read_finding_source(make_finding("app.py"), tmp_path) == "value = 1\n"


@pytest.mark.skipif(source_module.sys.platform != "linux", reason="Linux openat2")
def test_linux_source_read_fails_closed_on_mount_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mount crossing rejected by openat2 never falls back to component opens."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("inside content\n", encoding="utf-8")
    opened: list[tuple[int, bytes, int]] = []

    def reject_mount(root_fd: int, relative_path: bytes, flags: int) -> int:
        opened.append((root_fd, relative_path, flags))
        raise OSError(source_module.errno.EXDEV, "mount boundary")

    monkeypatch.setattr(source_module, "_openat2_source", reject_mount)
    with pytest.raises(PatchGenerationError, match="outside the repository"):
        read_finding_source(make_finding("app.py"), root)
    assert len(opened) == 1
    assert opened[0][1] == b"app.py"


def test_read_finding_source_rejects_symlink_outside_repository(
    tmp_path: Path,
) -> None:
    """An escaping source symlink is rejected before its target is read."""
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("value = 2\n", encoding="utf-8")
    link = root / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(PatchGenerationError, match="outside the repository"):
        read_finding_source(make_finding("escape.py"), root)


def test_read_finding_source_rejects_symlink_swapped_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path swap after root resolution cannot redirect the source read."""
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "app.py"
    target.write_text("inside content\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("synthetic outside content\n", encoding="utf-8")
    swapped = False
    content_read = False

    if source_module.os.name == "nt":
        real_read = source_module.os.fdopen

        def track_windows_read(*args: object, **kwargs: object) -> object:
            nonlocal content_read
            content_read = True
            return real_read(*args, **kwargs)

        monkeypatch.setattr(source_module.os, "fdopen", track_windows_read)
    else:
        real_read = source_module.os.read

        def track_posix_read(descriptor: int, size: int) -> bytes:
            nonlocal content_read
            content_read = True
            return real_read(descriptor, size)

        monkeypatch.setattr(source_module.os, "read", track_posix_read)

    def swap_target() -> None:
        nonlocal swapped
        target.unlink()
        try:
            target.symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")
        swapped = True

    if source_module.os.name == "nt":
        real_open = source_module._open_windows_handle

        def swap_windows_open(path: str, *, directory: bool) -> int:
            if not directory and path.casefold().endswith("\\app.py"):
                swap_target()
            return real_open(path, directory=directory)

        monkeypatch.setattr(source_module, "_open_windows_handle", swap_windows_open)
    else:
        real_open = source_module._open_posix

        def swap_posix_open(
            path: str | Path, flags: int, *, dir_fd: int | None = None
        ) -> int:
            if path == "app.py" and dir_fd is not None:
                swap_target()
            return real_open(path, flags, dir_fd=dir_fd)

        monkeypatch.setattr(source_module, "_open_posix", swap_posix_open)

    with pytest.raises(PatchGenerationError):
        read_finding_source(make_finding("app.py"), root)
    assert swapped
    assert not content_read


@pytest.mark.skipif(source_module.os.name == "nt", reason="POSIX dir-fd behavior")
def test_read_finding_source_rejects_swapped_root_ancestor_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replaced root ancestor cannot redirect the POSIX root descriptor."""
    parent = tmp_path / "parent"
    root = parent / "repo"
    outside = tmp_path / "outside"
    external_root = outside / "repo"
    root.mkdir(parents=True)
    external_root.mkdir(parents=True)
    (root / "app.py").write_text("inside content\n", encoding="utf-8")
    (external_root / "app.py").write_text(
        "synthetic outside content\n", encoding="utf-8"
    )
    swapped = False
    content_read = False
    real_read = source_module._read_posix
    real_os_read = source_module.os.read

    def track_content_read(descriptor: int, size: int) -> bytes:
        nonlocal content_read
        content_read = True
        return real_os_read(descriptor, size)

    monkeypatch.setattr(source_module.os, "read", track_content_read)

    def swap_ancestor(
        resolved_root: Path,
        parts: tuple[str, ...],
        expected_identity: tuple[int, int],
    ) -> bytes:
        nonlocal swapped
        parent.rename(tmp_path / "moved-parent")
        parent.symlink_to(outside, target_is_directory=True)
        swapped = True
        return real_read(resolved_root, parts, expected_identity)

    monkeypatch.setattr(source_module, "_read_posix", swap_ancestor)

    with pytest.raises(PatchGenerationError, match="Repository root changed"):
        read_finding_source(make_finding("app.py"), root)
    assert swapped
    assert not content_read


@pytest.mark.skipif(source_module.os.name != "nt", reason="Windows handle behavior")
def test_windows_parent_swap_is_blocked_or_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parent swap is blocked or rejected before the source content is read."""
    root = tmp_path / "repo"
    parent = root / "subdir"
    parent.mkdir(parents=True)
    (parent / "app.py").write_text("inside content\n", encoding="utf-8")
    moved = tmp_path / "moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("synthetic outside content\n", encoding="utf-8")
    rename_blocked = False
    rename_succeeded = False
    content_read = False
    real_handle_path = source_module._windows_handle_path
    real_fdopen = source_module.os.fdopen

    def track_content_read(*args: object, **kwargs: object) -> object:
        nonlocal content_read
        content_read = True
        return real_fdopen(*args, **kwargs)

    monkeypatch.setattr(source_module.os, "fdopen", track_content_read)

    def attempt_parent_swap(handle: int) -> str:
        nonlocal rename_blocked, rename_succeeded
        final_path = real_handle_path(handle)
        normalized = source_module._normalize_windows_path(final_path)
        if Path(normalized).name.casefold() == "subdir":
            try:
                parent.rename(moved)
            except OSError as exc:
                if getattr(exc, "winerror", None) != 32:
                    raise
                rename_blocked = True
            else:
                rename_succeeded = True
                try:
                    parent.symlink_to(outside, target_is_directory=True)
                except OSError as exc:
                    pytest.skip(f"directory symlink creation is unavailable: {exc}")
        return final_path

    monkeypatch.setattr(source_module, "_windows_handle_path", attempt_parent_swap)

    result: str | None = None
    rejected = False
    try:
        result = read_finding_source(make_finding("subdir/app.py"), root)
    except PatchGenerationError:
        rejected = True

    if rename_succeeded:
        assert rejected
        assert not content_read
    else:
        assert rename_blocked
        assert result == "inside content\n"


@pytest.mark.skipif(source_module.os.name != "nt", reason="Windows handle behavior")
def test_windows_root_replacement_is_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replacing the root directory at the same path cannot redirect a read."""
    root = tmp_path / "repo"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "original"
    root.mkdir()
    replacement.mkdir()
    (root / "app.py").write_text("inside content\n", encoding="utf-8")
    (replacement / "app.py").write_text("synthetic outside content\n", encoding="utf-8")
    swapped = False
    content_read = False
    real_open = source_module._open_windows_handle
    real_fdopen = source_module.os.fdopen

    def track_content_read(*args: object, **kwargs: object) -> object:
        nonlocal content_read
        content_read = True
        return real_fdopen(*args, **kwargs)

    monkeypatch.setattr(source_module.os, "fdopen", track_content_read)

    def replace_root(path: str, *, directory: bool) -> int:
        nonlocal swapped
        if directory and not swapped:
            root.rename(moved)
            replacement.rename(root)
            swapped = True
        return real_open(path, directory=directory)

    monkeypatch.setattr(source_module, "_open_windows_handle", replace_root)

    with pytest.raises(PatchGenerationError, match="Repository root changed"):
        read_finding_source(make_finding("app.py"), root)
    assert swapped
    assert not content_read


def test_read_finding_source_translates_symlink_loop(tmp_path: Path) -> None:
    """A symlink loop is reported through the project error boundary."""
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    try:
        first.symlink_to(second)
        second.symlink_to(first)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(PatchGenerationError):
        read_finding_source(make_finding("first.py"), tmp_path)


def test_read_finding_source_rejects_nul_path(tmp_path: Path) -> None:
    """Invalid OS path values do not escape as raw ValueError exceptions."""
    with pytest.raises(PatchGenerationError):
        read_finding_source(make_finding("bad\x00.py"), tmp_path)


def test_read_finding_source_translates_missing_file(tmp_path: Path) -> None:
    """Filesystem errors cross the source boundary as a project error."""
    with pytest.raises(PatchGenerationError, match="Unable to read finding source"):
        read_finding_source(make_finding("missing.py"), tmp_path)

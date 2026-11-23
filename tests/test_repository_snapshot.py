"""Offline tests for bounded repository snapshot capture."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from omnipatch.codebase import snapshot as snapshot_module
from omnipatch.codebase.snapshot import RepositorySnapshot
from omnipatch.errors import PatchGenerationError


def _snapshot(
    root: Path,
    *,
    max_bytes: int = 1024,
    max_file_bytes: int = 1024,
    max_entries: int = 20,
    max_metadata_entries: int = 20,
    timeout_seconds: int = 10,
    clock=lambda: 0.0,
    operation_hook=None,
) -> RepositorySnapshot:
    return RepositorySnapshot(
        root,
        excluded_dirs=("node_modules", ".git"),
        max_bytes=max_bytes,
        max_file_bytes=max_file_bytes,
        max_entries=max_entries,
        max_metadata_entries=max_metadata_entries,
        timeout_seconds=timeout_seconds,
        clock=clock,
        operation_hook=operation_hook,
    )


def test_snapshot_copies_source_excludes_configured_trees_and_cleans_up(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    excluded = source / "node_modules"
    excluded.mkdir(parents=True)
    file = source / "app.py"
    original = b"public_value = 1\n"
    file.write_bytes(original)
    (excluded / "ignored.py").write_text("ignored = True\n", encoding="utf-8")

    with _snapshot(source) as snapshot:
        assert snapshot.root is not None
        captured = snapshot.root
        assert captured != source
        assert not captured.is_relative_to(source)
        assert (captured / "app.py").read_bytes() == original
        assert not (captured / "node_modules").exists()
        assert any(item.category == "excluded" for item in snapshot.report.notices)
        assert snapshot.report.entries_copied == 1
    assert not captured.exists()
    assert file.read_bytes() == original
    assert (excluded / "ignored.py").exists()


def test_snapshot_root_identity_is_cleared_after_cleanup(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n", encoding="utf-8")

    with _snapshot(source) as snapshot:
        assert snapshot.root is not None
        assert snapshot.root_identity is not None

    assert snapshot.root is None
    assert snapshot.root_identity is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_file_bytes": 3}, "file limit"),
        ({"max_bytes": 3}, "byte limit"),
        ({"max_entries": 1}, "entry limit"),
    ],
)
def test_included_limits_fail_closed(
    tmp_path: Path, kwargs: dict[str, int], message: str
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "a.py").write_bytes(b"1234")
    if kwargs.get("max_entries") == 1:
        (source / "b.py").write_bytes(b"5678")

    with (
        pytest.raises(PatchGenerationError, match=message),
        _snapshot(source, **kwargs),
    ):
        pytest.fail("over-limit snapshot was exposed")


def test_exact_file_and_total_byte_limits_are_accepted(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "a.py").write_bytes(b"1234")

    with _snapshot(source, max_file_bytes=4, max_bytes=4, max_entries=1) as snapshot:
        assert snapshot.root is not None
        assert (snapshot.root / "a.py").read_bytes() == b"1234"
        assert snapshot.report.bytes_copied == 4


def test_excluded_metadata_budget_reports_unavailable_and_keeps_capture(
    tmp_path: Path,
) -> None:
    source = tmp_path / "repository"
    nested = source / "node_modules" / "package"
    nested.mkdir(parents=True)
    (nested / "entry.py").write_text("value = 1\n", encoding="utf-8")
    (source / "app.py").write_text("value = 2\n", encoding="utf-8")

    with _snapshot(source, max_metadata_entries=1) as snapshot:
        assert snapshot.root is not None
        assert (snapshot.root / "app.py").is_file()
        assert not (snapshot.root / "node_modules").exists()
        assert any(
            item.category == "count_unavailable" for item in snapshot.report.notices
        )


def test_injected_clock_deadline_aborts_capture(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n", encoding="utf-8")
    ticks = iter((0.0, 0.0, 2.0))

    with (
        pytest.raises(PatchGenerationError, match="deadline"),
        _snapshot(source, timeout_seconds=1, clock=lambda: next(ticks)),
    ):
        pytest.fail("expired snapshot was exposed")


def test_capture_failure_cleans_partial_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed copy removes the private partial tree before returning."""
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("synthetic = True\n", encoding="utf-8")
    roots: list[Path] = []
    create_root = (
        RepositorySnapshot._make_windows_private_root
        if os.name == "nt"
        else RepositorySnapshot._make_private_root
    )
    method = "_make_windows_private_root" if os.name == "nt" else "_make_private_root"

    def tracked_root(snapshot: RepositorySnapshot) -> Path:
        root = create_root(snapshot)
        roots.append(root)
        return root

    def fail_copy(*args: object, **kwargs: object) -> None:
        raise PatchGenerationError("synthetic capture failure")

    monkeypatch.setattr(RepositorySnapshot, method, tracked_root)
    copy_method = (
        "_copy_windows_directory" if os.name == "nt" else "_copy_linux_directory"
    )
    monkeypatch.setattr(RepositorySnapshot, copy_method, fail_copy)

    with (
        pytest.raises(PatchGenerationError, match="synthetic capture failure"),
        _snapshot(source),
    ):
        pytest.fail("failed capture was exposed")
    assert len(roots) == 1
    assert not roots[0].exists()


def test_primary_error_survives_and_reports_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cleanup failure is disclosed without replacing the primary domain error."""
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("synthetic = True\n", encoding="utf-8")
    roots: list[Path] = []
    remove_tree = snapshot_module._remove_tree_no_follow

    def fail_cleanup(path: Path) -> None:
        roots.append(path)
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(snapshot_module, "_remove_tree_no_follow", fail_cleanup)
    with (
        pytest.raises(PatchGenerationError, match="primary synthetic error.*cleanup"),
        _snapshot(source),
    ):
        raise PatchGenerationError("primary synthetic error")
    assert len(roots) == 1
    monkeypatch.setattr(snapshot_module, "_remove_tree_no_follow", remove_tree)
    remove_tree(roots[0])


def test_hard_linked_file_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    file = source / "app.py"
    file.write_text("value = 1\n", encoding="utf-8")
    alias = source / "alias.py"
    try:
        os.link(file, alias)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hard links are unavailable: {type(exc).__name__}")

    with pytest.raises(PatchGenerationError, match="hard-linked"), _snapshot(source):
        pytest.fail("hard-linked source was exposed")


def test_symbolic_link_is_rejected_without_reading_target(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("synthetic = True\n", encoding="utf-8")
    link = source / "linked.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links are unavailable: {type(exc).__name__}")

    with (
        pytest.raises(PatchGenerationError, match="symbolic links|reparse points"),
        _snapshot(source),
    ):
        pytest.fail("linked source was exposed")


def test_cleanup_unlinks_snapshot_links_without_following_targets(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private-snapshot"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic outside target\n", encoding="utf-8")
    try:
        (root / "link").symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links are unavailable: {type(exc).__name__}")

    snapshot_module._remove_tree_no_follow(root)
    assert not root.exists()
    assert outside.read_text(encoding="utf-8") == "synthetic outside target\n"


@pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX-only")
def test_special_file_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    os.mkfifo(source / "pipe")

    with (
        pytest.raises(PatchGenerationError, match="symbolic links|special files"),
        _snapshot(source),
    ):
        pytest.fail("special entry was exposed")


@pytest.mark.skipif(
    sys.platform == "win32", reason="Case-fold collisions are Windows-only"
)
def test_case_fold_collision_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "a.py").write_text("a = 1\n", encoding="utf-8")
    (source / "A.py").write_text("b = 2\n", encoding="utf-8")

    with (
        pytest.raises(PatchGenerationError, match="unsafe path component"),
        _snapshot(source),
    ):
        pytest.fail("colliding names were exposed")


@pytest.mark.parametrize("mutation", ["add", "remove", "rename"])
def test_directory_inventory_mutation_aborts_snapshot(
    tmp_path: Path, mutation: str
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n", encoding="utf-8")
    fired = False

    def mutate(operation: str, parts: tuple[str, ...]) -> None:
        nonlocal fired
        if operation != "directory_before_final_inventory" or parts or fired:
            return
        fired = True
        extra = source / "extra.py"
        if mutation == "add":
            extra.write_text("extra = 1\n", encoding="utf-8")
        elif mutation == "remove":
            (source / "app.py").unlink()
        else:
            (source / "app.py").rename(extra)

    with pytest.raises(PatchGenerationError), _snapshot(source, operation_hook=mutate):
        pytest.fail("mutated snapshot was exposed")
    assert fired


def test_file_content_mutation_aborts_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    file = source / "app.py"
    file.write_text("value = 1\n", encoding="utf-8")
    fired = False

    def mutate(operation: str, parts: tuple[str, ...]) -> None:
        nonlocal fired
        if (
            operation == "file_before_final_check"
            and parts == ("app.py",)
            and not fired
        ):
            fired = True
            file.write_text("value = 2\n", encoding="utf-8")

    with pytest.raises(PatchGenerationError), _snapshot(source, operation_hook=mutate):
        pytest.fail("mutated file snapshot was exposed")
    assert fired


@pytest.mark.skipif(os.name != "nt", reason="Windows handle/path race control")
def test_windows_root_replacement_during_capture_never_copies_replacement(
    tmp_path: Path,
) -> None:
    """A source-root path swap is either denied by handles or rejected before scan."""
    source = tmp_path / "repository"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "original"
    source.mkdir()
    replacement.mkdir()
    (source / "app.py").write_text("original_value = 1\n", encoding="utf-8")
    (replacement / "app.py").write_text("replacement_value = 2\n", encoding="utf-8")
    attempted = False
    moved_original = False

    def swap_during_capture(operation: str, parts: tuple[str, ...]) -> None:
        nonlocal attempted, moved_original
        if operation != "directory_before_inventory" or parts or attempted:
            return
        attempted = True
        try:
            source.rename(moved)
            moved_original = True
        except OSError:
            return
        try:
            replacement.rename(source)
        except OSError:
            pass

    try:
        with _snapshot(source, operation_hook=swap_during_capture) as snapshot:
            assert snapshot.root is not None
            assert (snapshot.root / "app.py").read_text(encoding="utf-8") == (
                "original_value = 1\n"
            )
        assert not moved_original
    except PatchGenerationError:
        assert moved_original
    assert attempted


@pytest.mark.skipif(sys.platform != "linux", reason="openat2 is Linux-specific")
def test_bind_mount_crossing_is_rejected_without_copying_mounted_content(
    tmp_path: Path,
) -> None:
    unshare = shutil.which("unshare")
    mount = shutil.which("mount")
    if unshare is None or mount is None:
        pytest.skip("Linux mount namespace tools are unavailable")
    probe = subprocess.run(
        [
            unshare,
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "true",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("Unprivileged private mount namespaces are unavailable")

    root = tmp_path / "repository"
    mountpoint = root / "mounted"
    outside = tmp_path / "outside"
    mountpoint.mkdir(parents=True)
    outside.mkdir()
    (outside / "outside.py").write_text("synthetic = True\n", encoding="utf-8")
    script = """
import ctypes
import os
import errno
import sys
from pathlib import Path
from pathlib import PurePosixPath
from omnipatch.codebase import source as source_module
from omnipatch.codebase.snapshot import RepositorySnapshot
from omnipatch.models import Finding, Severity
from omnipatch.errors import PatchGenerationError
root, mountpoint, outside = map(Path, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(os.fsencode(outside), os.fsencode(mountpoint), None, 4096, None) != 0:
    raise SystemExit(20)
original = RepositorySnapshot._openat2_path
saw_mount_boundary = False
def observe_mount_boundary(self, dir_fd, path, flags):
    global saw_mount_boundary
    try:
        return original(self, dir_fd, path, flags)
    except OSError as exc:
        saw_mount_boundary = exc.errno == errno.EXDEV
        raise
RepositorySnapshot._openat2_path = observe_mount_boundary
try:
    with RepositorySnapshot(root, excluded_dirs=(), max_bytes=1024, max_file_bytes=1024, max_entries=20, max_metadata_entries=20, timeout_seconds=10):
        raise SystemExit(21)
except PatchGenerationError:
    if not saw_mount_boundary:
        raise SystemExit(22)

original_source_open = source_module._openat2_source
saw_source_mount_boundary = False
def observe_source_mount_boundary(root_fd, relative_path, flags):
    global saw_source_mount_boundary
    try:
        return original_source_open(root_fd, relative_path, flags)
    except OSError as exc:
        saw_source_mount_boundary = exc.errno == errno.EXDEV
        raise
source_module._openat2_source = observe_source_mount_boundary
finding = Finding(
    id="mount-boundary-test",
    rule_id="B999",
    title="Synthetic mount-boundary test",
    severity=Severity.LOW,
    file=PurePosixPath("mounted/outside.py"),
    line_start=1,
    line_end=1,
    message="Synthetic test finding",
    source="test",
)
try:
    source_module.read_finding_source(finding, root)
except PatchGenerationError:
    raise SystemExit(0 if saw_source_mount_boundary else 23)
raise SystemExit(24)
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(snapshot_module.__file__).parents[2])
    completed = subprocess.run(
        [
            unshare,
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            sys.executable,
            "-c",
            script,
            str(root),
            str(mountpoint),
            str(outside),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert completed.returncode == 0


@pytest.mark.skipif(
    sys.platform != "linux", reason="process termination case is Linux-only"
)
def test_terminated_child_leaves_private_identifiable_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "app.py").write_text("synthetic = True\n", encoding="utf-8")
    script = """
import sys, time
from pathlib import Path
from omnipatch.codebase.snapshot import RepositorySnapshot
root = Path(sys.argv[1])
snapshot = RepositorySnapshot(root, excluded_dirs=(), max_bytes=1024, max_file_bytes=1024, max_entries=20, max_metadata_entries=20, timeout_seconds=10)
snapshot.__enter__()
print(snapshot.root, flush=True)
time.sleep(30)
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(snapshot_module.__file__).parents[2])
    child = subprocess.Popen(
        [sys.executable, "-c", script, str(source)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    stale: Path | None = None
    try:
        assert child.stdout is not None
        line = child.stdout.readline().strip()
        assert line
        stale = Path(line)
        assert stale.name.startswith("omnipatch-snapshot-")
        assert stale.stat().st_mode & 0o777 == 0o700
    finally:
        child.terminate()
        child.wait(timeout=10)
        if stale is not None:
            snapshot_module._remove_tree_no_follow(stale)

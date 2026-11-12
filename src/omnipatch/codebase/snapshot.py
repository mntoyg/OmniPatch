"""Bounded, private copies of repository inputs for a single CLI operation.

The POSIX backend requires Linux ``openat2`` with BENEATH, NO_SYMLINKS, and
NO_XDEV resolution. The Windows backend uses held, non-delete-shared handles
and a protected current-user/SYSTEM DACL. No path-only fallback is permitted.
"""

from __future__ import annotations

import errno
import os
import platform
import re
import secrets
import stat
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from omnipatch.codebase.source import (
    _close_windows_handle,
    _extended_path,
    _is_windows_directory,
    _is_windows_reparse_point,
    _normalize_windows_path,
    _open_windows_handle,
    _windows_file_identity,
    _windows_file_info,
    _windows_handle_path,
    _windows_is_disk_file,
    _windows_path_is_within,
    capture_source_root,
)
from omnipatch.errors import OmniPatchError, PatchGenerationError

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _windows_library(name: str) -> Any:
    """Load a Windows DLL without requiring Windows-only typing stubs."""
    import ctypes

    loader = getattr(ctypes, "WinDLL")  # noqa: B009 -- Available only on Windows.
    return loader(name, use_last_error=True)


@dataclass(frozen=True, slots=True)
class SnapshotNotice:
    """One bounded, value-free inventory item for CLI scope reporting."""

    path: str
    category: str
    count: int | None = None


@dataclass(frozen=True, slots=True)
class SnapshotReport:
    """Metadata-only result of exclusions and nested checkout inspection."""

    notices: tuple[SnapshotNotice, ...]
    entries_copied: int
    bytes_copied: int


class RepositorySnapshot:
    """Capture a repository once and expose its private, bounded working tree."""

    def __init__(
        self,
        repo_root: Path,
        *,
        excluded_dirs: tuple[str, ...],
        max_bytes: int,
        max_file_bytes: int,
        max_entries: int,
        max_metadata_entries: int,
        timeout_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        operation_hook: Callable[[str, tuple[str, ...]], None] | None = None,
    ) -> None:
        self.source_root = repo_root
        self.excluded_dirs = tuple(
            tuple(PurePosixPath(item.replace("\\", "/")).parts)
            for item in excluded_dirs
            if item
        )
        self.max_bytes = max_bytes
        self.max_file_bytes = max_file_bytes
        self.max_entries = max_entries
        self.max_metadata_entries = max_metadata_entries
        self.timeout_seconds = timeout_seconds
        self._clock = clock
        self._operation_hook = operation_hook or (lambda _operation, _parts: None)
        self._deadline = 0.0
        self.root: Path | None = None
        self.root_identity: tuple[int, int] | None = None
        self.report = SnapshotReport((), 0, 0)
        self._notices: list[SnapshotNotice] = []
        self._entries = 0
        self._metadata_entries = 0
        self._metadata_exhausted = False
        self._bytes = 0
        self._source_identity: tuple[int, int] | None = None
        self._source_device: int | None = None
        self._windows_root_path = ""

    def __enter__(self) -> Self:
        if (
            min(
                self.max_bytes,
                self.max_file_bytes,
                self.max_entries,
                self.max_metadata_entries,
                self.timeout_seconds,
            )
            < 1
        ):
            raise PatchGenerationError("Repository snapshot limits must be positive")
        self._deadline = self._clock() + self.timeout_seconds
        try:
            source, identity = capture_source_root(self.source_root)
            self.source_root = source
            self._source_identity = identity
            if os.name == "nt":
                self._capture_windows()
            elif sys.platform == "linux":
                self._capture_linux()
            else:
                raise PatchGenerationError(
                    "Secure repository snapshots are supported only on Windows and Linux"
                )
            if self.root is None:
                raise PatchGenerationError("Repository snapshot was not created")
            if os.name == "nt":
                _, self.root_identity = capture_source_root(self.root)
            else:
                info = self.root.stat()
                self.root_identity = (info.st_dev, info.st_ino)
            self.report = SnapshotReport(
                tuple(self._notices), self._entries, self._bytes
            )
            return self
        except BaseException as exc:
            cleanup_failed = self._cleanup_after_error(exc)
            if not isinstance(exc, Exception):
                raise
            if isinstance(exc, PatchGenerationError):
                raise
            message = "Unable to create a safe repository snapshot"
            if cleanup_failed:
                message += "; snapshot cleanup also failed"
            raise PatchGenerationError(message) from exc

    def __exit__(self, exc_type: object, exc: object, tb: object) -> Literal[False]:
        cleanup_error = self._cleanup()
        if cleanup_error is not None:
            if isinstance(exc, BaseException):
                exc.add_note("Repository snapshot cleanup also failed")
                if isinstance(exc, OmniPatchError):
                    exc.args = (f"{exc}; repository snapshot cleanup also failed",)
                return False
            raise PatchGenerationError(
                "Unable to clean up repository snapshot"
            ) from cleanup_error
        return False

    def _check_deadline(self) -> None:
        if self._clock() > self._deadline:
            raise PatchGenerationError("Repository snapshot capture deadline exceeded")

    def _operation(self, name: str, parts: tuple[str, ...]) -> None:
        self._check_deadline()
        self._operation_hook(name, parts)
        self._check_deadline()

    def _count_entry(self, *, metadata: bool = False) -> None:
        self._check_deadline()
        if metadata:
            if self._metadata_exhausted:
                raise _MetadataLimit
            self._metadata_entries += 1
            if self._metadata_entries > self.max_metadata_entries:
                self._metadata_exhausted = True
                raise _MetadataLimit
            return
        self._entries += 1
        if self._entries > self.max_entries:
            raise PatchGenerationError(
                f"Repository snapshot entry limit exceeded ({self.max_entries})"
            )

    def _is_excluded(self, parts: tuple[str, ...]) -> bool:
        return any(
            len(parts) >= len(rule) and parts[-len(rule) :] == rule
            for rule in self.excluded_dirs
            if rule
        )

    def _capture_linux(self) -> None:
        if platform.machine() not in {"x86_64", "aarch64", "riscv64"}:
            raise PatchGenerationError(
                "Secure Linux snapshots are unavailable on this architecture"
            )
        filesystem = _linux_filesystem_type(self.source_root)
        if filesystem not in {"ext4", "xfs", "btrfs", "tmpfs"}:
            raise PatchGenerationError(
                "Repository snapshots require a supported local Linux filesystem"
            )
        self.root = self._make_private_root()
        source_fd = os.open(
            self.source_root,
            os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
        )
        try:
            source_info = os.fstat(source_fd)
            if (source_info.st_dev, source_info.st_ino) != self._source_identity:
                raise PatchGenerationError("Repository root changed before snapshot")
            self._source_device = source_info.st_dev
            target_fd = os.open(self.root, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
            try:
                self._copy_linux_directory(source_fd, target_fd, ())
            finally:
                os.close(target_fd)
        finally:
            os.close(source_fd)

    def _openat2_path(self, dir_fd: int, path: bytes, flags: int) -> int:
        import ctypes

        class OpenHow(ctypes.Structure):
            _fields_ = [
                ("flags", ctypes.c_uint64),
                ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64),
            ]

        how = OpenHow(flags, 0, 0x08 | 0x04 | 0x01)
        libc = ctypes.CDLL(None, use_errno=True)
        syscall = 437
        result = libc.syscall(
            syscall,
            dir_fd,
            ctypes.c_char_p(path),
            ctypes.byref(how),
            ctypes.sizeof(how),
        )
        if result < 0:
            error = ctypes.get_errno()
            if error in {errno.ENOSYS, errno.EINVAL, errno.E2BIG}:
                raise PatchGenerationError(
                    "Linux openat2 with required resolution flags is unavailable"
                )
            raise OSError(error, "openat2 failed")
        return int(result)

    def _copy_linux_directory(
        self, source_fd: int, target_fd: int, parts: tuple[str, ...]
    ) -> None:
        self._operation("directory_before_inventory", parts)
        before = os.fstat(source_fd)
        if not stat.S_ISDIR(before.st_mode) or before.st_dev != self._source_device:
            raise PatchGenerationError(
                "Repository snapshot encountered an unsafe directory"
            )
        inventory_before = self._linux_inventory(source_fd)
        folded: set[str] = set()
        with os.scandir(source_fd) as entries:
            for entry in entries:
                name = self._validate_component(entry.name, folded)
                child_parts = (*parts, name)
                meta = entry.stat(follow_symlinks=False)
                if self._is_excluded(child_parts):
                    try:
                        self._count_entry(metadata=True)
                        self._inventory_excluded_linux(
                            source_fd, entry, child_parts, meta
                        )
                    except _MetadataLimit:
                        self._notices.append(
                            SnapshotNotice(
                                PurePosixPath(*child_parts).as_posix(),
                                "count_unavailable",
                            )
                        )
                    continue
                self._count_entry()
                if stat.S_ISLNK(meta.st_mode):
                    raise PatchGenerationError(
                        "Repository snapshot rejects symbolic links"
                    )
                if stat.S_ISDIR(meta.st_mode):
                    if name == ".git" and parts:
                        self._notices.append(
                            SnapshotNotice(
                                PurePosixPath(*parts).as_posix(), "nested_checkout"
                            )
                        )
                    child_fd = self._openat2_path(
                        source_fd,
                        os.fsencode(name),
                        os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC,
                    )
                    try:
                        child_stat = os.fstat(child_fd)
                        if child_stat.st_dev != self._source_device or (
                            child_stat.st_dev,
                            child_stat.st_ino,
                        ) != (meta.st_dev, meta.st_ino):
                            raise PatchGenerationError(
                                "Repository snapshot rejects mount crossings"
                            )
                        os.mkdir(name, 0o700, dir_fd=target_fd)
                        target_child = os.open(
                            name,
                            os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW,
                            dir_fd=target_fd,
                        )
                        try:
                            self._copy_linux_directory(
                                child_fd, target_child, child_parts
                            )
                        finally:
                            os.close(target_child)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(meta.st_mode):
                    self._copy_linux_file(source_fd, target_fd, name, meta, child_parts)
                else:
                    raise PatchGenerationError(
                        "Repository snapshot rejects special files"
                    )
        self._operation("directory_before_final_inventory", parts)
        inventory_after = self._linux_inventory(source_fd)
        after = os.fstat(source_fd)
        if self._directory_signature(before) != self._directory_signature(after):
            raise PatchGenerationError(
                "Repository snapshot detected directory mutation"
            )
        if inventory_before != inventory_after:
            raise PatchGenerationError(
                "Repository snapshot detected directory inventory change"
            )

    def _copy_linux_file(
        self,
        source_dir_fd: int,
        target_dir_fd: int,
        name: str,
        initial: os.stat_result,
        parts: tuple[str, ...],
    ) -> None:
        source_fd = self._openat2_path(
            source_dir_fd, os.fsencode(name), os.O_RDONLY | _O_CLOEXEC
        )
        target_fd: int | None = None
        try:
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise PatchGenerationError(
                    "Repository snapshot rejects non-regular or hard-linked files"
                )
            if (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
                raise PatchGenerationError(
                    "Repository snapshot detected file replacement"
                )
            if before.st_size > self.max_file_bytes:
                raise PatchGenerationError(
                    f"Repository snapshot file limit exceeded ({self.max_file_bytes})"
                )
            target_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                0o600,
                dir_fd=target_dir_fd,
            )
            copied = 0
            while True:
                self._check_deadline()
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                self._bytes += len(chunk)
                if copied > self.max_file_bytes or self._bytes > self.max_bytes:
                    raise PatchGenerationError(
                        f"Repository snapshot byte limit exceeded ({self.max_bytes})"
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(target_fd, view)
                    view = view[written:]
            self._operation("file_before_final_check", parts)
            after = os.fstat(source_fd)
            if (
                copied != before.st_size
                or self._file_signature(before) != self._file_signature(after)
                or after.st_nlink != 1
            ):
                raise PatchGenerationError("Repository snapshot detected file mutation")
        finally:
            if target_fd is not None:
                os.close(target_fd)
            os.close(source_fd)

    def _linux_inventory(self, directory_fd: int) -> tuple[tuple[object, ...], ...]:
        inventory: list[tuple[object, ...]] = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                self._check_deadline()
                if len(inventory) >= self.max_entries + self.max_metadata_entries:
                    raise PatchGenerationError(
                        "Repository snapshot directory inventory limit exceeded"
                    )
                info = entry.stat(follow_symlinks=False)
                inventory.append(
                    (
                        entry.name,
                        info.st_mode,
                        info.st_dev,
                        info.st_ino,
                        info.st_size,
                        info.st_mtime_ns,
                        info.st_nlink,
                    )
                )
        return tuple(sorted(inventory))

    def _inventory_excluded_linux(
        self,
        parent_fd: int,
        entry: os.DirEntry[str],
        parts: tuple[str, ...],
        info: os.stat_result,
    ) -> None:
        if stat.S_ISLNK(info.st_mode):
            self._notices.append(
                SnapshotNotice(PurePosixPath(*parts).as_posix(), "excluded_link")
            )
            return
        if stat.S_ISDIR(info.st_mode):
            path = PurePosixPath(*parts).as_posix()
            fd: int | None = None
            try:
                if entry.name == ".git" and len(parts) > 1:
                    self._notices.append(
                        SnapshotNotice(
                            PurePosixPath(*parts[:-1]).as_posix(), "nested_checkout"
                        )
                    )
                fd = self._openat2_path(
                    parent_fd,
                    os.fsencode(entry.name),
                    os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC,
                )
            except (OSError, PatchGenerationError):
                self._notices.append(SnapshotNotice(path, "count_unavailable"))
                return
            try:
                count = self._count_excluded_linux(fd, parts)
                self._notices.append(SnapshotNotice(path, "excluded", count))
            except _MetadataLimit:
                self._notices.append(SnapshotNotice(path, "count_unavailable"))
            finally:
                if fd is not None:
                    os.close(fd)

    def _count_excluded_linux(self, directory_fd: int, parts: tuple[str, ...]) -> int:
        count = 0
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                self._count_entry(metadata=True)
                info = entry.stat(follow_symlinks=False)
                child = (*parts, entry.name)
                if stat.S_ISLNK(info.st_mode):
                    self._notices.append(
                        SnapshotNotice(
                            PurePosixPath(*child).as_posix(), "excluded_link"
                        )
                    )
                elif stat.S_ISDIR(info.st_mode):
                    if entry.name == ".git":
                        self._notices.append(
                            SnapshotNotice(
                                PurePosixPath(*parts).as_posix(), "nested_checkout"
                            )
                        )
                    fd = self._openat2_path(
                        directory_fd,
                        os.fsencode(entry.name),
                        os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC,
                    )
                    try:
                        count += self._count_excluded_linux(fd, child)
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(info.st_mode) and entry.name.endswith(".py"):
                    count += 1
        return count

    def _capture_windows(self) -> None:
        # Windows snapshots require the native protected-ACL constructor below.
        self.root = self._make_windows_private_root()
        from ctypes import wintypes

        get_drive_type = _windows_library("kernel32").GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
        source_drive = self.source_root.drive + "\\"
        if int(get_drive_type(source_drive)) != 3:
            raise PatchGenerationError(
                "Repository snapshots require a local fixed filesystem"
            )
        source_handle = _open_windows_handle(
            _extended_path(str(self.source_root)),
            directory=True,
            stable_snapshot=True,
        )
        handles = [source_handle]
        try:
            info = _windows_file_info(source_handle)
            if (
                not _is_windows_directory(info)
                or _is_windows_reparse_point(info)
                or _windows_file_identity(info) != self._source_identity
                or not _same_windows_path(
                    _windows_handle_path(source_handle), str(self.source_root)
                )
            ):
                raise PatchGenerationError("Repository root changed before snapshot")
            self._source_device = int(info.volume)
            self._windows_root_path = _normalize_windows_path(
                _windows_handle_path(source_handle)
            )
            self._copy_windows_directory(source_handle, self.source_root, self.root, ())
        finally:
            for handle in reversed(handles):
                _close_windows_handle(handle)

    def _copy_windows_directory(
        self,
        source_handle: int,
        source_path: Path,
        target_path: Path,
        parts: tuple[str, ...],
    ) -> None:
        self._operation("directory_before_inventory", parts)
        if not _same_windows_path(
            _windows_handle_path(source_handle), str(source_path)
        ):
            raise PatchGenerationError(
                "Repository directory path changed during snapshot capture"
            )
        before = _windows_file_info(source_handle)
        inventory_before = self._windows_inventory(source_path)
        folded: set[str] = set()
        with os.scandir(source_path) as entries:
            for entry in entries:
                name = self._validate_component(entry.name, folded)
                child_parts = (*parts, name)
                child_path = source_path / name
                metadata = entry.stat(follow_symlinks=False)
                if self._is_excluded(child_parts):
                    try:
                        self._count_entry(metadata=True)
                        self._inventory_excluded_windows(
                            child_path, child_parts, metadata
                        )
                    except _MetadataLimit:
                        self._notices.append(
                            SnapshotNotice(
                                PurePosixPath(*child_parts).as_posix(),
                                "count_unavailable",
                            )
                        )
                    continue
                self._count_entry()
                entry_handle = _open_windows_handle(
                    _extended_path(str(child_path)),
                    directory=stat.S_ISDIR(metadata.st_mode),
                    stable_snapshot=True,
                )
                try:
                    entry_info = _windows_file_info(entry_handle)
                    entry_display = _windows_handle_path(entry_handle)
                    if (
                        _is_windows_reparse_point(entry_info)
                        or int(entry_info.volume) != self._source_device
                        or (
                            stat.S_ISDIR(metadata.st_mode)
                            and not _is_windows_directory(entry_info)
                        )
                        or (
                            stat.S_ISREG(metadata.st_mode)
                            and (
                                _is_windows_directory(entry_info)
                                or not _windows_is_disk_file(entry_handle)
                            )
                        )
                        or not _windows_path_is_within(
                            self._windows_root_path, entry_display
                        )
                    ):
                        raise PatchGenerationError(
                            "Repository snapshot rejects reparse points"
                        )
                    if stat.S_ISDIR(metadata.st_mode):
                        target_child = target_path / name
                        target_child.mkdir(mode=0o700)
                        self._copy_windows_directory(
                            entry_handle, child_path, target_child, child_parts
                        )
                    elif stat.S_ISREG(metadata.st_mode):
                        file_handle = entry_handle
                        entry_handle = -1
                        self._copy_windows_file(
                            file_handle, target_path / name, metadata, child_parts
                        )
                    else:
                        raise PatchGenerationError(
                            "Repository snapshot rejects special files"
                        )
                finally:
                    if entry_handle not in {-1, None}:
                        _close_windows_handle(entry_handle)
        self._operation("directory_before_final_inventory", parts)
        if not _same_windows_path(
            _windows_handle_path(source_handle), str(source_path)
        ):
            raise PatchGenerationError(
                "Repository directory path changed during snapshot capture"
            )
        after = _windows_file_info(source_handle)
        if _windows_directory_signature(before) != _windows_directory_signature(after):
            raise PatchGenerationError(
                "Repository snapshot detected directory mutation"
            )
        if inventory_before != self._windows_inventory(source_path):
            raise PatchGenerationError(
                "Repository snapshot detected directory inventory change"
            )

    def _copy_windows_file(
        self,
        source_handle: int,
        target_path: Path,
        initial: os.stat_result,
        parts: tuple[str, ...],
    ) -> None:
        import msvcrt

        descriptor: int | None = None
        target_fd: int | None = None
        try:
            info = _windows_file_info(source_handle)
            identity = _windows_file_identity(info)
            size = int(info.size_high) * (1 << 32) + int(info.size_low)
            if (
                int(info.links) != 1
                or not _windows_is_disk_file(source_handle)
                or int(info.volume) != self._source_device
                or not _windows_path_is_within(
                    self._windows_root_path, _windows_handle_path(source_handle)
                )
            ):
                raise PatchGenerationError(
                    "Repository snapshot rejects hard-linked or special files"
                )
            if size > self.max_file_bytes:
                raise PatchGenerationError("Repository snapshot file limit exceeded")
            open_osfhandle = getattr(msvcrt, "open_osfhandle")  # noqa: B009 -- Windows only.
            get_osfhandle = getattr(msvcrt, "get_osfhandle")  # noqa: B009 -- Windows only.
            binary_mode = getattr(os, "O_BINARY", 0)
            descriptor = open_osfhandle(source_handle, os.O_RDONLY | binary_mode)
            target_fd = os.open(
                target_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_mode,
                0o600,
            )
            copied = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                self._check_deadline()
                copied += len(chunk)
                self._bytes += len(chunk)
                if copied > self.max_file_bytes or self._bytes > self.max_bytes:
                    raise PatchGenerationError(
                        "Repository snapshot byte limit exceeded"
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(target_fd, view)
                    view = view[written:]
            self._operation("file_before_final_check", parts)
            if descriptor is None:
                raise PatchGenerationError(
                    "Repository snapshot file handle is unavailable"
                )
            after = _windows_file_info(get_osfhandle(descriptor))
            if copied != size or _windows_file_signature(
                info
            ) != _windows_file_signature(after):
                raise PatchGenerationError(
                    "Repository snapshot file changed during capture"
                )
            if _windows_file_identity(after) != identity or int(after.links) != 1:
                raise PatchGenerationError("Repository snapshot detected file mutation")
        finally:
            if target_fd is not None:
                os.close(target_fd)
            if descriptor is not None:
                os.close(descriptor)
            else:
                _close_windows_handle(source_handle)

    def _windows_inventory(self, directory: Path) -> tuple[tuple[object, ...], ...]:
        result: list[tuple[object, ...]] = []
        with os.scandir(directory) as entries:
            for entry in entries:
                self._check_deadline()
                if len(result) >= self.max_entries + self.max_metadata_entries:
                    raise PatchGenerationError(
                        "Repository snapshot directory inventory limit exceeded"
                    )
                info = entry.stat(follow_symlinks=False)
                result.append(
                    (
                        entry.name,
                        info.st_mode,
                        info.st_size,
                        None if stat.S_ISDIR(info.st_mode) else info.st_mtime_ns,
                    )
                )
        return tuple(sorted(result))

    def _inventory_excluded_windows(
        self, path: Path, parts: tuple[str, ...], info: os.stat_result
    ) -> None:
        relative = PurePosixPath(*parts).as_posix()
        if getattr(info, "st_file_attributes", 0) & 0x400:
            self._notices.append(SnapshotNotice(relative, "excluded_link"))
        elif stat.S_ISDIR(info.st_mode):
            if path.name == ".git" and len(parts) > 1:
                self._notices.append(
                    SnapshotNotice(
                        PurePosixPath(*parts[:-1]).as_posix(), "nested_checkout"
                    )
                )
            try:
                handle = _open_windows_handle(
                    _extended_path(str(path)), directory=True, stable_snapshot=True
                )
                try:
                    handle_info = _windows_file_info(handle)
                    if _is_windows_reparse_point(
                        handle_info
                    ) or not _is_windows_directory(handle_info):
                        raise PatchGenerationError("Excluded inventory changed")
                    count = self._count_excluded_windows(path, parts, handle)
                finally:
                    _close_windows_handle(handle)
                self._notices.append(SnapshotNotice(relative, "excluded", count))
            except (_MetadataLimit, OSError, PatchGenerationError):
                self._notices.append(SnapshotNotice(relative, "count_unavailable"))
        elif stat.S_ISREG(info.st_mode) and path.name.endswith(".py"):
            self._metadata_entries += 1
            if self._metadata_entries > self.max_metadata_entries:
                self._notices.append(SnapshotNotice(relative, "count_unavailable"))

    def _count_excluded_windows(
        self, root: Path, parts: tuple[str, ...], directory_handle: int
    ) -> int:
        count = 0
        self._check_deadline()
        with os.scandir(root) as entries:
            for entry in entries:
                self._count_entry(metadata=True)
                info = entry.stat(follow_symlinks=False)
                child = Path(entry.path)
                child_parts = (*parts, child.name)
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    self._notices.append(
                        SnapshotNotice(
                            PurePosixPath(*child_parts).as_posix(), "excluded_link"
                        )
                    )
                elif stat.S_ISDIR(info.st_mode):
                    if child.name == ".git":
                        self._notices.append(
                            SnapshotNotice(
                                PurePosixPath(*child_parts[:-1]).as_posix(),
                                "nested_checkout",
                            )
                        )
                    child_handle = _open_windows_handle(
                        _extended_path(str(child)),
                        directory=True,
                        stable_snapshot=True,
                    )
                    try:
                        child_info = _windows_file_info(child_handle)
                        if _is_windows_reparse_point(
                            child_info
                        ) or not _is_windows_directory(child_info):
                            self._notices.append(
                                SnapshotNotice(
                                    PurePosixPath(*child_parts).as_posix(),
                                    "count_unavailable",
                                )
                            )
                            continue
                        count += self._count_excluded_windows(
                            child, child_parts, child_handle
                        )
                    finally:
                        _close_windows_handle(child_handle)
                elif stat.S_ISREG(info.st_mode) and child.name.endswith(".py"):
                    count += 1
        return count

    def _make_private_root(self) -> Path:
        parent = Path(tempfile.gettempdir()).resolve()
        if parent == self.source_root or parent.is_relative_to(self.source_root):
            raise PatchGenerationError(
                "System temporary directory is inside the repository"
            )
        if sys.platform == "linux" and _linux_filesystem_type(parent) not in {
            "ext4",
            "xfs",
            "btrfs",
            "tmpfs",
        }:
            raise PatchGenerationError(
                "Repository snapshots require a supported local temporary filesystem"
            )
        root = Path(tempfile.mkdtemp(prefix="omnipatch-snapshot-", dir=parent))
        self.root = root
        os.chmod(root, 0o700)
        return root

    def _make_windows_private_root(self) -> Path:
        import ctypes
        from ctypes import wintypes

        # Restrict temporary snapshots to their owner and SYSTEM at creation.
        parent = Path(tempfile.gettempdir()).resolve()
        if parent == self.source_root or parent.is_relative_to(self.source_root):
            raise PatchGenerationError(
                "System temporary directory is inside the repository"
            )
        drive = parent.drive + "\\"
        get_drive_type = _windows_library("kernel32").GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
        if int(get_drive_type(drive)) != 3:
            raise PatchGenerationError(
                "Repository snapshots require a local fixed filesystem"
            )
        name = parent / f"omnipatch-snapshot-{secrets.token_hex(12)}"
        advapi = _windows_library("advapi32")
        descriptor = wintypes.LPVOID()
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.DWORD),
        ]
        convert.restype = wintypes.BOOL
        # OWNER RIGHTS is the current directory owner's SID; SYSTEM is explicit.
        if not convert(
            "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)", 1, ctypes.byref(descriptor), None
        ):
            raise PatchGenerationError("Unable to build private snapshot ACL")

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [
                ("length", wintypes.DWORD),
                ("descriptor", wintypes.LPVOID),
                ("inherit", wintypes.BOOL),
            ]

        attributes = SecurityAttributes(
            ctypes.sizeof(SecurityAttributes), descriptor, False
        )
        create = _windows_library("kernel32").CreateDirectoryW
        create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
        create.restype = wintypes.BOOL
        try:
            if not create(_extended_path(str(name)), ctypes.byref(attributes)):
                raise PatchGenerationError(
                    "Unable to create private repository snapshot"
                )
        finally:
            _windows_library("kernel32").LocalFree(descriptor)
        self.root = name
        self._verify_windows_acl(name)
        return name

    def _verify_windows_acl(self, path: Path) -> None:
        import ctypes
        from ctypes import wintypes

        advapi = _windows_library("advapi32")
        dacl = wintypes.LPVOID()
        descriptor = wintypes.LPVOID()
        get_info = advapi.GetNamedSecurityInfoW
        get_info.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.LPVOID),
        ]
        get_info.restype = wintypes.DWORD
        result = get_info(
            str(path),
            1,
            4,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if result != 0 or not dacl.value:
            raise PatchGenerationError("Unable to verify private snapshot ACL")
        try:

            class AclInformation(ctypes.Structure):
                _fields_ = [
                    ("ace_count", wintypes.DWORD),
                    ("bytes_in_use", wintypes.DWORD),
                    ("bytes_free", wintypes.DWORD),
                ]

            info = AclInformation()
            if not advapi.GetAclInformation(
                dacl, ctypes.byref(info), ctypes.sizeof(info), 2
            ):
                raise PatchGenerationError("Unable to verify private snapshot ACL")
            if info.ace_count != 2:
                raise PatchGenerationError(
                    "Snapshot ACL is not restricted to owner and SYSTEM"
                )

            class AceHeader(ctypes.Structure):
                _fields_ = [
                    ("ace_type", ctypes.c_byte),
                    ("ace_flags", ctypes.c_byte),
                    ("ace_size", wintypes.WORD),
                ]

            class AccessAllowedAce(ctypes.Structure):
                _fields_ = [
                    ("header", AceHeader),
                    ("mask", wintypes.DWORD),
                    ("sid_start", wintypes.DWORD),
                ]

            expected_allocations: list[int] = []
            convert_sid = advapi.ConvertStringSidToSidW
            convert_sid.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
            convert_sid.restype = wintypes.BOOL
            free_local = _windows_library("kernel32").LocalFree
            free_local.argtypes = [wintypes.LPVOID]
            free_local.restype = wintypes.LPVOID
            equal_sid = advapi.EqualSid
            equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
            equal_sid.restype = wintypes.BOOL
            try:
                for sid_text in ("S-1-3-4", "S-1-5-18"):
                    sid_pointer = wintypes.LPVOID()
                    if not convert_sid(sid_text, ctypes.byref(sid_pointer)):
                        raise PatchGenerationError(
                            "Unable to verify private snapshot ACL identities"
                        )
                    if sid_pointer.value is None:
                        raise PatchGenerationError(
                            "Unable to verify private snapshot ACL identities"
                        )
                    expected_allocations.append(int(sid_pointer.value))
                matched_sids: set[int] = set()
                for index in range(info.ace_count):
                    ace_pointer = wintypes.LPVOID()
                    if not advapi.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                        raise PatchGenerationError(
                            "Unable to verify private snapshot ACL entries"
                        )
                    if ace_pointer.value is None:
                        raise PatchGenerationError(
                            "Unable to verify private snapshot ACL entries"
                        )
                    ace = ctypes.cast(
                        ace_pointer, ctypes.POINTER(AccessAllowedAce)
                    ).contents
                    sid_address = (
                        int(ace_pointer.value) + AccessAllowedAce.sid_start.offset
                    )
                    sid_pointer = wintypes.LPVOID(sid_address)
                    matching_indices = {
                        expected_index
                        for expected_index, expected in enumerate(expected_allocations)
                        if equal_sid(sid_pointer, expected)
                    }
                    if (
                        ace.header.ace_type != 0
                        or ace.header.ace_flags != 0x03
                        or int(ace.mask) != 0x1F01FF
                        or len(matching_indices) != 1
                        or bool(matched_sids & matching_indices)
                    ):
                        raise PatchGenerationError(
                            "Snapshot ACL is not restricted to owner and SYSTEM"
                        )
                    matched_sids.update(matching_indices)
                if matched_sids != {0, 1}:
                    raise PatchGenerationError(
                        "Snapshot ACL is not restricted to owner and SYSTEM"
                    )
            finally:
                for allocation in expected_allocations:
                    free_local(wintypes.LPVOID(allocation))
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            get_control = advapi.GetSecurityDescriptorControl
            get_control.argtypes = [
                wintypes.LPVOID,
                ctypes.POINTER(wintypes.WORD),
                ctypes.POINTER(wintypes.DWORD),
            ]
            get_control.restype = wintypes.BOOL
            if (
                not get_control(
                    descriptor, ctypes.byref(control), ctypes.byref(revision)
                )
                or not control.value & 0x1000
            ):
                raise PatchGenerationError("Snapshot ACL is not protected")
        finally:
            _windows_library("kernel32").LocalFree(descriptor)

    def _cleanup_after_error(self, primary: BaseException) -> bool:
        error = self._cleanup()
        if error is not None:
            if isinstance(primary, PatchGenerationError):
                primary.args = (f"{primary}; repository snapshot cleanup also failed",)
            else:
                primary.add_note("Repository snapshot cleanup also failed")
            return True
        return False

    def _cleanup(self) -> OSError | None:
        root = self.root
        if root is None:
            return None
        try:
            _remove_tree_no_follow(root)
            self.root = None
            self.root_identity = None
            return None
        except OSError as exc:
            return exc

    @staticmethod
    def _validate_component(name: str, folded: set[str]) -> str:
        normalized = unicodedata.normalize("NFC", name)
        key = normalized.casefold()
        if (
            not name
            or name in {".", ".."}
            or normalized != name
            or any(char in name for char in ":/\\\x00")
            or name.endswith((".", " "))
            or key in folded
        ):
            raise PatchGenerationError(
                "Repository snapshot found an unsafe path component"
            )
        folded.add(key)
        return name

    @staticmethod
    def _file_signature(info: os.stat_result) -> tuple[int, ...]:
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            info.st_nlink,
        )

    @staticmethod
    def _directory_signature(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


class _MetadataLimit(Exception):
    """Internal signal: omitted metadata counts become explicitly unavailable."""


def _remove_tree_no_follow(path: Path) -> None:
    """Remove the private snapshot without traversing symlinks/reparse points."""
    if sys.platform == "linux":
        _remove_linux_tree_no_follow(path)
        return
    if not path.exists() and not path.is_symlink():
        return
    info = path.lstat()
    is_reparse = bool(getattr(info, "st_file_attributes", 0) & 0x400)
    if stat.S_ISDIR(info.st_mode) and not is_reparse:
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
        for child in children:
            _remove_tree_no_follow(child)
        path.rmdir()
    else:
        path.unlink()


def _remove_linux_tree_no_follow(path: Path) -> None:
    """Remove a Linux snapshot by held directory descriptors and unlinkat."""
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
    )
    try:
        try:
            root_fd = os.open(
                path.name,
                os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return
        try:
            root_identity = os.fstat(root_fd)
            _remove_linux_contents(root_fd)
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (
                root_identity.st_dev,
                root_identity.st_ino,
            ):
                raise OSError(errno.ESTALE, "snapshot root changed during cleanup")
        finally:
            os.close(root_fd)
        os.rmdir(path.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _remove_linux_contents(directory_fd: int) -> None:
    """Remove immediate entries without following links or path re-resolution."""
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                child_fd = os.open(
                    entry.name,
                    os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                try:
                    child_identity = os.fstat(child_fd)
                    _remove_linux_contents(child_fd)
                    current = os.stat(
                        entry.name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (current.st_dev, current.st_ino) != (
                        child_identity.st_dev,
                        child_identity.st_ino,
                    ):
                        raise OSError(
                            errno.ESTALE, "snapshot entry changed during cleanup"
                        )
                finally:
                    os.close(child_fd)
                os.rmdir(entry.name, dir_fd=directory_fd)
            else:
                os.unlink(entry.name, dir_fd=directory_fd)


def _linux_filesystem_type(path: Path) -> str | None:
    """Identify the mount type containing path without exposing mount metadata."""
    try:
        candidates: list[tuple[int, str]] = []
        resolved = str(path.resolve(strict=True))
        with Path("/proc/self/mountinfo").open(encoding="utf-8") as mountinfo:
            for line in mountinfo:
                fields = line.rstrip("\n").split(" ")
                separator = fields.index("-")
                mountpoint = fields[4]
                mountpoint = re.sub(
                    r"\\([0-7]{3})",
                    lambda match: chr(int(match.group(1), 8)),
                    mountpoint,
                )
                if resolved == mountpoint or resolved.startswith(
                    mountpoint.rstrip("/") + "/"
                ):
                    candidates.append((len(mountpoint), fields[separator + 1]))
        return max(candidates)[1] if candidates else None
    except (OSError, ValueError, IndexError):
        return None


def _windows_directory_signature(info: Any) -> tuple[object, ...]:
    return (
        _windows_file_identity(info),
        int(info.attributes),
        int(info.size_high),
        int(info.size_low),
        int(info.index_high),
        int(info.index_low),
    )


def _windows_file_signature(info: Any) -> tuple[object, ...]:
    return (
        _windows_file_identity(info),
        int(info.attributes),
        int(info.size_high),
        int(info.size_low),
        int(info.links),
        int(info.write.low),
        int(info.write.high),
    )


def _same_windows_path(left: str, right: str) -> bool:
    return os.path.normcase(_normalize_windows_path(left)) == os.path.normcase(
        _normalize_windows_path(right)
    )

"""Confined, race-resistant reads from the target repository."""

from __future__ import annotations

import errno
import os
import platform
import stat
import sys
from pathlib import Path, PureWindowsPath
from typing import Any

from omnipatch.errors import PatchGenerationError
from omnipatch.models import Finding


def capture_source_root(repo_root: Path) -> tuple[Path, tuple[int, int]]:
    """Resolve a repository path and bind its identity before scanning begins."""
    try:
        before = repo_root.stat()
        root = repo_root.resolve(strict=True)
        after = root.stat()
    except OSError as exc:
        raise PatchGenerationError("Unable to resolve repository root") from exc
    except (RuntimeError, ValueError) as exc:
        raise PatchGenerationError("Unable to safely resolve repository root") from exc

    identity = (before.st_dev, before.st_ino)
    if identity != (after.st_dev, after.st_ino) or not stat.S_ISDIR(after.st_mode):
        raise PatchGenerationError("Repository root changed while resolving")
    return root, identity


def read_finding_source(
    finding: Finding,
    repo_root: Path,
    *,
    root_identity: tuple[int, int] | None = None,
) -> str:
    """Read one regular source file through handles confined to the repository."""
    parts = _validated_parts(finding)
    try:
        if root_identity is None:
            root, root_identity = capture_source_root(repo_root)
        else:
            root = repo_root
        if os.name == "nt":
            content = _read_windows(root, parts, root_identity)
        else:
            content = _read_posix(root, parts, root_identity)
        text = content.decode("utf-8", errors="strict")
        return text.replace("\r\n", "\n").replace("\r", "\n")
    except PatchGenerationError:
        raise
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EXDEV}:
            raise PatchGenerationError(
                "Finding source is outside the repository or uses a link"
            ) from exc
        raise PatchGenerationError("Unable to read finding source") from exc
    except UnicodeError as exc:
        raise PatchGenerationError("Unable to read finding source as UTF-8") from exc
    except (RuntimeError, ValueError) as exc:
        raise PatchGenerationError("Unable to safely read finding source") from exc


def _validated_parts(finding: Finding) -> tuple[str, ...]:
    """Reject path forms whose meaning differs across supported platforms."""
    path = finding.file
    parts = path.parts
    windows_path = PureWindowsPath(path.as_posix())
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or not parts
        or any(
            not part
            or part in {".", ".."}
            or "/" in part
            or "\\" in part
            or ":" in part
            or "\x00" in part
            for part in parts
        )
    ):
        raise PatchGenerationError(
            "Finding source path is not a safe repository-relative path"
        )
    return parts


def _read_posix(
    root: Path, parts: tuple[str, ...], expected_identity: tuple[int, int]
) -> bytes:
    """Walk by directory descriptors without following symlinks."""
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory or os.open not in os.supports_dir_fd:
        raise PatchGenerationError(
            "This platform cannot safely open repository-relative source files"
        )

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | directory | no_follow | close_on_exec
    file_flags = os.O_RDONLY | no_follow | getattr(os, "O_NONBLOCK", 0) | close_on_exec
    descriptors: list[int] = []
    try:
        root_fd = _open_posix(root, directory_flags)
        descriptors.append(root_fd)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise PatchGenerationError("Repository root is not a directory")
        if (root_stat.st_dev, root_stat.st_ino) != expected_identity:
            raise PatchGenerationError("Repository root changed while opening source")

        if sys.platform == "linux":
            if platform.machine() not in {"x86_64", "aarch64", "riscv64"}:
                raise PatchGenerationError(
                    "Secure Linux source reads are unavailable on this architecture"
                )
            source_fd = _openat2_source(
                root_fd,
                "/".join(parts).encode("utf-8"),
                file_flags,
            )
            descriptors.append(source_fd)
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise PatchGenerationError("Finding source is not a regular file")
            chunks: list[bytes] = []
            while chunk := os.read(source_fd, 65536):
                chunks.append(chunk)
            return b"".join(chunks)

        parent_fd = root_fd
        for part in parts[:-1]:
            child_fd = _open_posix(part, directory_flags, dir_fd=parent_fd)
            descriptors.append(child_fd)
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                raise PatchGenerationError(
                    "Finding source path contains a non-directory component"
                )
            parent_fd = child_fd

        source_fd = _open_posix(parts[-1], file_flags, dir_fd=parent_fd)
        descriptors.append(source_fd)
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise PatchGenerationError("Finding source is not a regular file")

        chunks: list[bytes] = []
        while chunk := os.read(source_fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _openat2_source(root_fd: int, relative_path: bytes, flags: int) -> int:
    """Open a Linux source path beneath root without symlink or mount traversal."""
    import ctypes

    class OpenHow(ctypes.Structure):
        _fields_ = [
            ("flags", ctypes.c_uint64),
            ("mode", ctypes.c_uint64),
            ("resolve", ctypes.c_uint64),
        ]

    # openat2 is syscall 437 on the explicitly supported Linux architectures.
    how = OpenHow(flags, 0, 0x08 | 0x04 | 0x01)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        437,
        root_fd,
        ctypes.c_char_p(relative_path),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if result < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL, errno.E2BIG}:
            raise PatchGenerationError(
                "Linux openat2 with required resolution flags is unavailable"
            )
        raise OSError(error, "openat2 source read failed")
    return int(result)


def _open_posix(
    path: str | Path,
    flags: int,
    *,
    dir_fd: int | None = None,
) -> int:
    """Open one path component; kept separate as the descriptor boundary."""
    if dir_fd is None:
        return os.open(path, flags)
    return os.open(path, flags, dir_fd=dir_fd)


def _read_windows(
    root: Path, parts: tuple[str, ...], expected_identity: tuple[int, int]
) -> bytes:
    """Open each Windows component without following reparse points.

    Directory and file handles deny delete sharing while in use. That keeps the
    verified handle chain stable until the bytes have been read.
    """
    import msvcrt
    import ntpath

    directory_handles: list[int] = []
    file_handle: int | None = None
    descriptor: int | None = None
    try:
        root_handle = _open_windows_handle(_extended_path(str(root)), directory=True)
        directory_handles.append(root_handle)
        root_info = _windows_file_info(root_handle)
        root_display = _windows_handle_path(root_handle)
        if not _is_windows_directory(root_info) or _is_windows_reparse_point(root_info):
            raise PatchGenerationError("Repository root is not a safe directory")
        if _windows_file_identity(root_info) != expected_identity:
            raise PatchGenerationError("Repository root changed while opening source")
        if not _same_windows_path(root_display, str(root)):
            raise PatchGenerationError("Repository root changed while opening source")

        parent_display = root_display
        root_normalized = _normalize_windows_path(root_display)
        for part in parts[:-1]:
            candidate = ntpath.join(parent_display, part)
            child_handle = _open_windows_handle(
                _extended_path(candidate), directory=True
            )
            directory_handles.append(child_handle)
            child_info = _windows_file_info(child_handle)
            child_display = _windows_handle_path(child_handle)
            if (
                not _is_windows_directory(child_info)
                or _is_windows_reparse_point(child_info)
                or not _windows_path_is_within(root_normalized, child_display)
            ):
                raise PatchGenerationError(
                    "Finding source path contains an unsafe directory component"
                )
            parent_display = child_display

        candidate = ntpath.join(parent_display, parts[-1])
        file_handle = _open_windows_handle(_extended_path(candidate), directory=False)
        file_info = _windows_file_info(file_handle)
        file_display = _windows_handle_path(file_handle)
        if (
            _is_windows_directory(file_info)
            or _is_windows_reparse_point(file_info)
            or not _windows_is_disk_file(file_handle)
            or not _windows_path_is_within(root_normalized, file_display)
        ):
            raise PatchGenerationError(
                "Finding source is outside the repository or is not a regular file"
            )

        import msvcrt

        open_osfhandle = getattr(msvcrt, "open_osfhandle")  # noqa: B009 -- Windows only.
        descriptor = open_osfhandle(
            file_handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        file_handle = None
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            return source.read()
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if file_handle is not None:
            _close_windows_handle(file_handle)
        for handle in reversed(directory_handles):
            _close_windows_handle(handle)


def _open_windows_handle(
    path: str, *, directory: bool, stable_snapshot: bool = False
) -> int:
    """Open one Windows path component without following its reparse point."""
    import ctypes
    from ctypes import wintypes

    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    access = 0x00000080 if directory else 0x80000000
    # Snapshot handles deny write/delete sharing so the held path cannot be
    # modified or replaced while its bytes and directory inventory are copied.
    share = 0x00000001 if stable_snapshot else 0x00000001 | 0x00000002
    flags = 0x00200000 | (0x02000000 if directory else 0)
    handle = create_file(path, access, share, None, 3, flags, None)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        raise _windows_error()
    return int(handle)


def _windows_file_info(handle: int) -> Any:
    """Return file attributes queried from an already-open handle."""
    import ctypes
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class FileInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation", FileTime),
            ("access", FileTime),
            ("write", FileTime),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

    get_info = _windows_kernel32().GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInfo)]
    get_info.restype = wintypes.BOOL
    info = FileInfo()
    if not get_info(handle, ctypes.byref(info)):
        raise _windows_error()
    return info


def _windows_file_identity(info: Any) -> tuple[int, int]:
    """Match a Windows handle's volume/file index to ``Path.stat()`` identity."""
    index = (int(info.index_high) << 32) | int(info.index_low)
    return int(info.volume), index


def _windows_handle_path(handle: int) -> str:
    """Return the normalized DOS path for an already-open Windows handle."""
    import ctypes
    from ctypes import wintypes

    get_path = _windows_kernel32().GetFinalPathNameByHandleW
    get_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_path.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_path(handle, buffer, len(buffer), 0)
    if not length or length >= len(buffer):
        raise _windows_error()
    return buffer.value


def _close_windows_handle(handle: int) -> None:
    """Close a native handle and surface cleanup failures."""
    from ctypes import wintypes

    close_handle = _windows_kernel32().CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise _windows_error()


def _windows_is_disk_file(handle: int) -> bool:
    """Reject device handles even when their names appear beneath the root."""
    from ctypes import wintypes

    get_type = _windows_kernel32().GetFileType
    get_type.argtypes = [wintypes.HANDLE]
    get_type.restype = wintypes.DWORD
    return int(get_type(handle)) == 1  # FILE_TYPE_DISK


def _windows_kernel32() -> Any:
    """Load the Windows API only on the Windows source-reading path."""
    import ctypes

    loader = getattr(ctypes, "WinDLL")  # noqa: B009 -- Available only on Windows.
    return loader("kernel32", use_last_error=True)


def _windows_error() -> OSError:
    """Build a Windows OS error without including an untrusted path."""
    return OSError("Windows source handle operation failed")


def _windows_path_is_within(root: str, candidate: str) -> bool:
    """Check final handle paths using Windows path and case rules."""
    import ntpath

    try:
        common = ntpath.commonpath((root, _normalize_windows_path(candidate)))
    except ValueError:
        return False
    return ntpath.normcase(common) == ntpath.normcase(root)


def _same_windows_path(left: str, right: str) -> bool:
    """Compare DOS paths after removing the extended-path prefix."""
    import ntpath

    return ntpath.normcase(_normalize_windows_path(left)) == ntpath.normcase(
        _normalize_windows_path(right)
    )


def _normalize_windows_path(path: str) -> str:
    """Normalize a Win32 extended path for containment comparisons."""
    import ntpath

    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return ntpath.normpath(path)


def _extended_path(path: str) -> str:
    """Add the Win32 extended prefix without changing UNC path meaning."""
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def _is_windows_directory(info: Any) -> bool:
    return bool(info.attributes & 0x00000010)


def _is_windows_reparse_point(info: Any) -> bool:
    return bool(info.attributes & 0x00000400)

"""Materialize validated source in temporary directories outside a repository."""

import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory

from omnipatch.errors import PatchApplyError


@contextmanager
def patched_sandbox(
    relative_path: PurePosixPath,
    patched_source: str,
    *,
    forbidden_root: Path | None = None,
) -> Iterator[Path]:
    """Yield a temporary root containing only the patched file at its relative path."""
    relative_text = str(relative_path).replace("\\", "/")
    safe_relative_path = PurePosixPath(relative_text)
    windows_path = PureWindowsPath(str(relative_path))
    if (
        safe_relative_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or ".." in safe_relative_path.parts
        or ".." in windows_path.parts
        or not safe_relative_path.parts
    ):
        raise PatchApplyError(
            f"Sandbox path must be relative and confined: {relative_text}"
        )

    try:
        resolved_forbidden = (
            forbidden_root.resolve() if forbidden_root is not None else None
        )
        candidate_parent = Path(tempfile.gettempdir()).resolve()
    except (OSError, RuntimeError) as exc:
        raise PatchApplyError("Unable to resolve a safe temporary directory") from exc
    # Query the platform temp root without retaining or creating a temporary directory.
    if resolved_forbidden is not None and candidate_parent.is_relative_to(
        resolved_forbidden
    ):
        candidate_parent = resolved_forbidden.parent
        if candidate_parent == resolved_forbidden:
            raise PatchApplyError("No temporary parent exists outside the repository")

    temporary: TemporaryDirectory[str] | None = None
    try:
        temporary = TemporaryDirectory(prefix="omnipatch-", dir=candidate_parent)
        sandbox_root = Path(temporary.name).resolve()
        if resolved_forbidden is not None and sandbox_root.is_relative_to(
            resolved_forbidden
        ):
            raise PatchApplyError(
                "Temporary sandbox resolved inside the source repository"
            )
        destination = sandbox_root.joinpath(*safe_relative_path.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(patched_source.encode("utf-8"))
    except PatchApplyError:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError as exc:
                raise PatchApplyError(
                    "Unable to remove temporary patch sandbox"
                ) from exc
        raise
    except (OSError, UnicodeError) as exc:
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError as cleanup_error:
                raise PatchApplyError(
                    "Unable to remove temporary patch sandbox"
                ) from cleanup_error
        raise PatchApplyError(
            f"Unable to materialize sandbox file {relative_text}"
        ) from exc

    try:
        yield sandbox_root
    finally:
        if temporary is not None:
            active_exception = sys.exc_info()[0]
            try:
                temporary.cleanup()
            except OSError as exc:
                if active_exception is None:
                    raise PatchApplyError(
                        "Unable to remove temporary patch sandbox"
                    ) from exc
                print(
                    "warning: unable to remove temporary patch sandbox",
                    file=sys.stderr,
                )

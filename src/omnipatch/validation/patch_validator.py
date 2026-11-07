"""Parse and validate unified diffs without writing to disk."""

import ast
import re
from pathlib import PurePosixPath, PureWindowsPath

from omnipatch.errors import PatchGenerationError
from omnipatch.models import Finding, Patch

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")


def strip_fence(text: str) -> str:
    """Remove an optional code fence; a single-space line is content, not whitespace."""
    lines = _outer_lines(text)
    if lines and lines[0].startswith("```"):
        if len(lines) < 2 or lines[-1] != "```":
            raise PatchGenerationError("Code fence is incomplete")
        inner = _outer_lines("\n".join(lines[1:-1]))
        if not inner:
            raise PatchGenerationError("Code fence contains no content")
        return "\n".join(inner)
    return "\n".join(lines)


def _outer_lines(text: str) -> list[str]:
    """Trim newline delimiters and only wholly empty outer lines."""
    lines = text.strip("\n\r").splitlines()
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _path(header: str, prefix: str, finding: Finding) -> PurePosixPath:
    """Validate and normalize one diff header path."""
    raw = header[len(prefix) :].split("\t", 1)[0].strip()
    if raw == "/dev/null":
        raise PatchGenerationError("Diff cannot create or delete files (/dev/null)")
    normalized = raw.replace("\\", "/")
    windows_path = PureWindowsPath(raw)
    path = PurePosixPath(normalized)
    if path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise PatchGenerationError(f"Diff path must be relative: {raw}")
    if ".." in path.parts:
        raise PatchGenerationError(f"Diff path contains traversal: {raw}")
    if path.parts and path.parts[0] in {"a", "b"}:
        path = PurePosixPath(*path.parts[1:])
    if path != finding.file:
        raise PatchGenerationError(
            f"Diff path {path.as_posix()} does not match finding file "
            f"{finding.file.as_posix()}"
        )
    return path


def _apply_hunks(diff: str, source: str) -> str:
    """Apply validated hunk lines to source text in memory."""
    lines = source.splitlines(keepends=True)
    diff_lines = diff.splitlines()
    index = 0
    hunks: list[tuple[int, int, list[tuple[str, str]]]] = []
    while index < len(diff_lines):
        if not diff_lines[index].startswith("@@"):
            index += 1
            continue
        header = diff_lines[index]
        parsed = _HUNK_RE.match(header)
        if parsed is None:
            raise PatchGenerationError(f"Malformed hunk header: {header}")
        old_start = int(parsed.group(1))
        old_count = int(parsed.group(2) or "1")
        new_count = int(parsed.group(4) or "1")
        index += 1
        body: list[tuple[str, str]] = []
        old_seen = new_seen = 0
        while index < len(diff_lines) and not diff_lines[index].startswith("@@"):
            line = diff_lines[index]
            if line == "\\ No newline at end of file":
                index += 1
                continue
            if not line or line[0] not in " +-":
                break
            marker, content = line[0], line[1:]
            body.append((marker, content))
            old_seen += marker in " -"
            new_seen += marker in " +"
            index += 1
        if old_seen != old_count or new_seen != new_count:
            raise PatchGenerationError(
                f"Hunk {header!r} declares -{old_count}/+{new_count} lines "
                f"but contains -{old_seen}/+{new_seen}"
            )
        hunks.append((old_start, old_count, body))
        if index < len(diff_lines) and not diff_lines[index].startswith("@@"):
            index += 1
    if not hunks:
        raise PatchGenerationError("Diff must contain at least one hunk")

    offset = 0
    for old_start, old_count, body in hunks:
        position = old_start if old_count == 0 else old_start - 1
        position += offset
        replacement: list[str] = []
        consumed = 0
        for marker, content in body:
            if marker == "+":
                replacement.append(content + "\n")
                continue
            if position + consumed >= len(lines):
                raise PatchGenerationError(
                    "Hunk context extends beyond original source"
                )
            original_line = lines[position + consumed].rstrip("\r\n")
            if original_line != content:
                raise PatchGenerationError(
                    f"Hunk context mismatch at original line {position + consumed + 1}; "
                    "match the supplied source context exactly"
                )
            if marker == " ":
                replacement.append(lines[position + consumed])
            consumed += 1
        lines[position : position + consumed] = replacement
        offset += len(replacement) - consumed
    result = "".join(lines)
    if source and not source.endswith(("\n", "\r")) and result.endswith("\n"):
        result = result[:-1]
    return result


def validate_patch(
    diff_text: str,
    finding: Finding,
    original_source: str,
    model: str,
) -> Patch:
    """Return a validated, one-file Python patch without modifying files."""
    diff, _ = _validate_and_apply(diff_text, finding, original_source)
    return Patch(
        finding_id=finding.id,
        unified_diff=diff,
        explanation=f"{finding.rule_id}: {finding.title} "
        f"({finding.file.as_posix()}:{finding.line_start})",
        touched_files=(finding.file,),
        model=model,
    )


def materialize_patch_source(
    diff_text: str, finding: Finding, original_source: str
) -> str:
    """Return the validator-checked patched text without writing it to disk."""
    _, patched = _validate_and_apply(diff_text, finding, original_source)
    return patched


def _validate_and_apply(
    diff_text: str, finding: Finding, original_source: str
) -> tuple[str, str]:
    """Validate file boundaries and hunks, then return normalized diff and text."""
    diff = strip_fence(diff_text)
    if not diff:
        raise PatchGenerationError("Diff is empty")
    lines = diff.splitlines()
    headers = [(i, line) for i, line in enumerate(lines) if line.startswith("--- ")]
    if not headers:
        raise PatchGenerationError("Diff must contain a --- / +++ file header pair")
    if len(headers) != 1:
        extra_path = headers[1][1][4:].split("\t", 1)[0].strip()
        raise PatchGenerationError(
            f"Diff must touch exactly one file; additional path: {extra_path}"
        )
    old_index, old_header = headers[0]
    if old_index + 1 >= len(lines) or not lines[old_index + 1].startswith("+++ "):
        raise PatchGenerationError("Diff must contain a --- / +++ file header pair")
    old_path = _path(old_header, "--- ", finding)
    new_path = _path(lines[old_index + 1], "+++ ", finding)
    if old_path != new_path:
        raise PatchGenerationError("Diff old and new paths do not match")
    if not any(line.startswith("@@") for line in lines):
        raise PatchGenerationError("Diff must contain at least one @@ hunk")
    patched = _apply_hunks(diff, original_source)
    if patched == original_source:
        raise PatchGenerationError("Patch does not change the original source")
    try:
        ast.parse(patched, filename=finding.file.as_posix())
    except SyntaxError as exc:
        raise PatchGenerationError(
            f"Patched Python is invalid at line {exc.lineno}: {exc.msg}"
        ) from exc
    return diff, patched

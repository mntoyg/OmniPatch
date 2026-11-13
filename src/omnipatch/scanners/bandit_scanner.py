"""Bandit subprocess adapter."""

import json
import os
import re
import stat
import subprocess  # nosec B404  # Required to invoke Bandit through argv.
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import cast

from omnipatch.defaults import DEFAULT_SCAN_TIMEOUT_SECONDS, EXCLUDED_DIRS
from omnipatch.errors import ScannerError
from omnipatch.models import Finding, Severity, make_finding_id

DEFAULT_COMMAND: tuple[str, ...] = (sys.executable, "-m", "bandit")

_SEVERITY_BY_BANDIT: Mapping[str, Severity] = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "UNDEFINED": Severity.LOW,
}


def _excluded_at_any_depth(
    directories: tuple[str, ...], excluded: tuple[str, ...]
) -> bool:
    """Report whether an exclusion's path segments appear anywhere in a file's directories."""
    span = len(excluded)
    if not span or span > len(directories):
        return False
    return any(
        directories[index : index + span] == excluded
        for index in range(len(directories) - span + 1)
    )


def _is_link_entry(path: Path) -> bool:
    """Report whether an entry is a symlink or a Windows junction.

    OP-33/OP-34. `Path.is_symlink()` is **false** for a Windows directory junction,
    whose reparse tag is `IO_REPARSE_TAG_MOUNT_POINT`, so a symlink check alone lets a
    walk both escape the scan root and loop. An unreadable entry returns True so it is
    left alone rather than descended.
    """
    try:
        info = path.lstat()
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _count_python_files(directory: Path) -> int:
    """Count `.py` files under a directory without following a link out of it.

    OP-33. The previous `rglob("*.py")` descended junctions, so the count could include
    files outside the repository — a number nobody measured, and a read outside the
    target root (OWASP A01). No link is followed *below* `directory`, so no child escapes.

    **OP-37/RT-0013 corrects what this docstring used to claim.** It said containment
    held "by construction" and needs no check. That is false at this function's own
    boundary: handed a junction as `directory`, it reads straight through it — measured,
    five files all resolving outside the scan root. The property is an invariant of the
    single caller, `_report_scope`, which guards its argument; it is not a property of
    this function. The control still owed is to give this function the scan root and have
    it enforce containment itself, which is what RT-0009 asked for and what was wrongly
    dropped. Non-symlink detection also depends on `st_file_attributes`, which a
    non-Windows platform may not provide, so the guard can degrade to symlinks alone.
    """
    total = 0
    pending = [directory]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    child = Path(entry.path)
                    if not _is_link_entry(child):
                        pending.append(child)
                elif entry.name.endswith(".py") and entry.is_file(
                    follow_symlinks=False
                ):
                    total += 1
    return total


class BanditScanner:
    """Run bandit over a repository and translate its JSON report."""

    name = "bandit"

    def __init__(
        self,
        command: Sequence[str] = DEFAULT_COMMAND,
        timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
        excluded_dirs: Sequence[str] = EXCLUDED_DIRS,
        report_scope: bool = True,
    ) -> None:
        """Configure command, timeout, and excluded repository directories."""
        self._command = tuple(command)
        self._timeout_seconds = timeout_seconds
        self._excluded_dirs = tuple(excluded_dirs)
        self._report_scope_enabled = report_scope

    def is_available(self) -> bool:
        """True when the configured command's version check succeeds."""
        try:
            # argv is fixed by the adapter and is never interpreted by a shell.
            result = subprocess.run(  # nosec B603  # argv prevents shell interpretation.
                [*self._command, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return False
        return result.returncode == 0

    def _report_scope(
        self,
        root: Path,
        excluded_parts: tuple[tuple[str, tuple[str, ...]], ...],
    ) -> None:
        """Tell the operator what an exclusion kept out, and what is still in scope.

        OP-27. Exclusions used to be silent in the ordinary case: Bandit's `-x` glob
        removes findings before the finding-level backstop can count them, so the
        operator warning never fired. This walk prunes at every exclusion, so an
        excluded tree is counted but never descended into for its own sake.

        The count is **Python files**, not findings: a finding count for files nobody
        scanned would be a number nobody measured. A directory carrying its own `.git`
        is reported and deliberately not excluded — the operator decides, and dropping
        it here would be the OP-1 constant-special-case mistake with a better excuse.

        Only exclusions **outside** the documented default set are reported. The default
        set in `ARCHITECTURE.md` section 8 is the published baseline, so a reader of a
        report already assumes it; a per-target addition is a decision this run made and
        has to appear. Reporting the baseline on every run is noise, not information,
        which is the contract `test_scan_excludes_virtualenv_without_warning_or_slowdown`
        holds this module to.
        """
        skipped: dict[str, int] = {}
        uncounted: list[str] = []
        uncounted_links: list[str] = []
        nested_checkouts: list[str] = []
        for current, dirnames, _filenames in os.walk(root):
            current_path = Path(current)
            relative_parts = current_path.relative_to(root).parts
            if relative_parts and (current_path / ".git").exists():
                nested_checkouts.append(PurePosixPath(*relative_parts).as_posix())
            retained_dirnames: list[str] = []
            for name in dirnames:
                child = current_path / name
                candidate = (*relative_parts, name)
                matched = [
                    directory
                    for directory, parts in excluded_parts
                    if candidate[-len(parts) :] == parts
                ]
                # Match exclusions before pruning links: Bandit's -x glob can still
                # drop a linked subtree, so omitting its scope warning would hide a
                # deliberate exclusion. Never count through the link, because its
                # target may be outside the scan root.
                if _is_link_entry(child):
                    if matched:
                        uncounted_links.append(PurePosixPath(*candidate).as_posix())
                    continue
                if not matched:
                    retained_dirnames.append(name)
                    continue
                relative = PurePosixPath(*candidate).as_posix()
                try:
                    count = _count_python_files(child)
                except OSError:
                    # The walk is advisory. A scan that succeeded must not be thrown
                    # away because a count failed, and the operator must still be told
                    # the count is missing rather than shown a wrong one (A09).
                    uncounted.append(relative)
                    continue
                for directory in matched:
                    skipped[directory] = skipped.get(directory, 0) + count
            dirnames[:] = retained_dirnames
        reportable = {
            directory: count
            for directory, count in skipped.items()
            if directory not in EXCLUDED_DIRS
        }
        total = sum(reportable.values())
        if total:
            names = ", ".join(
                directory
                for directory in self._excluded_dirs
                if reportable.get(directory)
            )
            print(
                f"warning: {total} python file(s) under scan-exclude ({names}) "
                "were not scanned",
                file=sys.stderr,
            )
        for relative in uncounted:
            print(
                f"warning: python file count unavailable under {relative}; "
                "the scan itself was not affected",
                file=sys.stderr,
            )
        for relative in uncounted_links:
            print(
                f"warning: scan-exclude path {relative} was not traversed; "
                "python file count unavailable (link or inspection failure)",
                file=sys.stderr,
            )
        for relative in nested_checkouts:
            print(
                f"warning: {relative} is a nested checkout still in scope; its "
                "findings are reported as this repository's",
                file=sys.stderr,
            )

    def scan(self, repo_root: Path) -> list[Finding]:
        """Raise ScannerError on any scanner-level failure."""
        resolved_root = repo_root.resolve()
        args = [
            *self._command,
            "-r",
            str(resolved_root),
            "-f",
            "json",
            "-q",
        ]
        if self._excluded_dirs:
            # Bandit's -x glob is primary; post-filtering is a root-level backstop.
            patterns = ",".join(
                f"*/{directory.strip('/')}/*" for directory in self._excluded_dirs
            )
            args.extend(("-x", patterns))
        try:
            # argv is fixed by the adapter and is never interpreted by a shell.
            completed = subprocess.run(  # nosec B603  # argv prevents shell interpretation.
                args,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"Bandit scan timed out after {self._timeout_seconds} seconds"
            ) from exc
        except (OSError, UnicodeError, subprocess.SubprocessError, ValueError):
            raise ScannerError("Unable to run Bandit scanner") from None

        if completed.returncode not in (0, 1):
            raise ScannerError(
                f"Bandit exited with status {completed.returncode}; diagnostics omitted"
            ) from None
        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"Bandit returned malformed JSON: {exc}") from exc
        findings = _parse_report(report, resolved_root)
        excluded_parts = tuple(
            (directory, PurePosixPath(directory.replace("\\", "/")).parts)
            for directory in self._excluded_dirs
        )
        if self._report_scope_enabled:
            self._report_scope(resolved_root, excluded_parts)
        retained: list[Finding] = []
        matched_directories: set[str] = set()
        excluded_count = 0
        for finding in findings:
            # OP-27: match at any depth, as Bandit's own -x glob already does, so the
            # backstop actually backs up the primary layer instead of disagreeing with it.
            matching_directories = [
                directory
                for directory, parts in excluded_parts
                if _excluded_at_any_depth(finding.file.parts[:-1], parts)
            ]
            if not matching_directories:
                retained.append(finding)
            else:
                excluded_count += 1
                matched_directories.update(matching_directories)
        if excluded_count:
            matched_names = [
                directory
                for directory in self._excluded_dirs
                if directory in matched_directories
            ]
            print(
                f"warning: {excluded_count} finding(s) excluded by scan-exclude "
                f"({', '.join(matched_names)})",
                file=sys.stderr,
            )
        return retained


def _relative_posix(filename: str, repo_root: Path) -> PurePosixPath:
    """Convert a bandit filename into a repo-relative POSIX path."""
    root = repo_root.resolve()
    normalized = filename.replace("\\", os.sep).replace("/", os.sep)
    given_path = Path(normalized)
    candidate = given_path if given_path.is_absolute() else root / given_path
    try:
        relative = candidate.resolve().relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ScannerError(
            f"Bandit reported a path outside the repository: {filename}"
        ) from exc
    return PurePosixPath(relative.as_posix())


def _parse_report(report: object, repo_root: Path) -> list[Finding]:
    """Translate a validated Bandit JSON report into findings."""
    if not isinstance(report, dict):
        raise ScannerError("Bandit returned a malformed JSON report")
    raw_report = cast(dict[str, object], report)
    errors = raw_report.get("errors")
    results = raw_report.get("results")
    if not isinstance(errors, list):
        raise ScannerError("Bandit JSON report has no valid errors list")
    if not isinstance(results, list):
        raise ScannerError("Bandit JSON report has no valid results list")

    for raw_error in errors:
        if not isinstance(raw_error, dict):
            raise ScannerError("Bandit JSON report contains a malformed error")
        error = cast(dict[str, object], raw_error)
        filename = error.get("filename")
        reason = error.get("reason")
        if not isinstance(filename, str) or not isinstance(reason, str):
            raise ScannerError("Bandit JSON report contains a malformed error")
        relative = _relative_posix(filename, repo_root)
        if relative == PurePosixPath("."):
            raise ScannerError("Bandit could not scan the repository root")
        print(
            f"warning: bandit skipped {relative}: scanner reported an error",
            file=sys.stderr,
        )

    findings: list[Finding] = []
    for raw_result in results:
        if not isinstance(raw_result, dict):
            raise ScannerError("Bandit JSON report contains a malformed result")
        result = cast(dict[str, object], raw_result)
        filename = result.get("filename")
        rule_id = result.get("test_id")
        issue_text = result.get("issue_text")
        severity_name = result.get("issue_severity")
        line_number = result.get("line_number")
        if not isinstance(filename, str):
            raise ScannerError("Bandit JSON report contains an invalid filename")
        if not isinstance(rule_id, str):
            raise ScannerError("Bandit JSON report contains an invalid test_id")
        if not isinstance(issue_text, str):
            raise ScannerError("Bandit JSON report contains an invalid issue_text")
        if not isinstance(severity_name, str):
            raise ScannerError("Bandit JSON report contains an invalid result field")
        if isinstance(line_number, bool) or not isinstance(
            line_number, (int, float, str)
        ):
            raise ScannerError("Bandit JSON report contains an invalid line_number")
        if isinstance(line_number, float) and not line_number.is_integer():
            raise ScannerError("Bandit JSON report contains a fractional line_number")
        try:
            line_start = int(line_number)
        except (ValueError, OverflowError) as exc:
            raise ScannerError(
                "Bandit JSON report contains an invalid line_number"
            ) from exc
        try:
            severity = _SEVERITY_BY_BANDIT[severity_name]
        except KeyError as exc:
            raise ScannerError(
                f"Bandit returned unknown severity: {severity_name}"
            ) from exc

        line_range = result.get("line_range", [])
        if line_range is None:
            line_range = []
        if not isinstance(line_range, list) or any(
            isinstance(line, bool) or not isinstance(line, int) for line in line_range
        ):
            raise ScannerError("Bandit JSON report contains an invalid line_range")
        line_end: object = max(line_range) if line_range else line_start
        file_path = _relative_posix(filename, repo_root)
        more_info = result.get("more_info")
        if more_info is not None and not isinstance(more_info, str):
            raise ScannerError("Bandit JSON report contains invalid more_info")
        message = "Hardcoded credential finding" if rule_id == "B105" else issue_text
        if more_info is not None and rule_id != "B105":
            message = f"{message} ({more_info})"
        issue_cwe = result.get("issue_cwe")
        cwe: str | None = None
        if issue_cwe is not None:
            if not isinstance(issue_cwe, dict):
                raise ScannerError("Bandit JSON report contains invalid issue_cwe")
            cwe_id = issue_cwe.get("id")
            if isinstance(cwe_id, bool) or not isinstance(cwe_id, (int, str)):
                raise ScannerError("Bandit JSON report contains invalid CWE id")
            cwe = f"CWE-{cwe_id}"
        title = (
            "Hardcoded credential finding"
            if rule_id == "B105"
            else re.split(r"(?<=[.!?])\s+", issue_text.strip(), maxsplit=1)[0][:120]
        )
        try:
            findings.append(
                Finding.from_json_dict(
                    {
                        "id": make_finding_id(rule_id, file_path, line_start),
                        "rule_id": rule_id,
                        "title": title,
                        "severity": severity.value,
                        "file": file_path.as_posix(),
                        "line_start": line_number,
                        "line_end": line_end,
                        "message": message,
                        "source": "bandit",
                        "cwe": cwe,
                    }
                )
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise ScannerError(f"Bandit returned an invalid result: {exc}") from exc
    return findings

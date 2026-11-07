"""RT-0004 round two — regression tests for the scope-walk findings.

Written by the red team seat; a PM seat owns whether any of this is committed
(`RED_TEAM.md` §2). Nothing here edits `src/`, and nothing here touches
`tests/test_rt0004_redaction_terminators_and_scope_walk.py`, which a PM seat now owns.

OP-35 has both an injected link-detection test and a real Windows-junction regression.
OP-36 and OP-37 remain `xfail(strict=True)` until their defects are fixed.

Link fixtures are built inside `tmp_path` and every junction is removed with `rmdir`,
which unlinks without following.
"""

import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from omnipatch.scanners import bandit_scanner
from omnipatch.scanners.bandit_scanner import BanditScanner


def excluded_parts(*directories: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Mirror the tuple `BanditScanner.scan` builds before calling `_report_scope`."""
    return tuple(
        (directory, PurePosixPath(directory.replace("\\", "/")).parts)
        for directory in directories
    )


def make_junction(link: Path, target: Path) -> None:
    """Create a Windows directory junction, skipping the test where unavailable."""
    if sys.platform != "win32":
        pytest.skip("directory junctions are a Windows reparse point")
    completed = subprocess.run(  # nosec B603  # argv list, no shell, fixed program.
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or not link.exists():
        pytest.skip(f"could not create a junction: {completed.stdout.strip()}")


def test_an_excluded_directory_that_is_itself_a_link_is_still_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Report an excluded link without traversing or counting its target.

    Before the OP-35 fix, `_report_scope` skipped a link before checking whether the
    directory matched an exclusion, so the operator received no scope warning. The
    current code reports the path and an unavailable count while still pruning it. This
    test covers the injected link-detection seam; the following test exercises a real
    Windows junction.
    """
    root = tmp_path / "target"
    (root / "ok").mkdir(parents=True)
    (root / "ok" / "visible.py").write_text("x = 1\n", encoding="utf-8")
    vendored = tmp_path / "outside"
    vendored.mkdir()
    for index in range(5):
        (vendored / f"vend{index}.py").write_text("y = 1\n", encoding="utf-8")

    excluded_link = root / "vendorlib"
    excluded_link.mkdir()
    for index in range(5):
        (excluded_link / f"local{index}.py").write_text("y = 1\n", encoding="utf-8")

    monkeypatch.setattr(
        bandit_scanner,
        "_is_link_entry",
        lambda path: path == excluded_link,
    )
    scanner = BanditScanner(excluded_dirs=("vendorlib",))
    scanner._report_scope(root, excluded_parts("vendorlib"))

    err = capsys.readouterr().err
    assert "scan-exclude path vendorlib was not traversed" in err
    assert "count unavailable (link or inspection failure)" in err
    assert "5 python file(s)" not in err


def test_real_excluded_junction_is_reported_without_reading_its_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A real excluded junction warns with unavailable count and is never descended.

    Tripwires fail before any directory enumeration or file counting at the junction
    or its outside target. This proves the scope report does not read the target merely
    to produce an exclusion count.
    """
    root = tmp_path / "target"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    for index in range(5):
        (outside / f"outside_{index}.py").write_text("x = 1\n", encoding="utf-8")

    excluded_link = root / "vendorlib"
    try:
        make_junction(excluded_link, outside)
        assert bandit_scanner._is_link_entry(excluded_link)

        def normalized(path: str | bytes | Path) -> str:
            return os.path.normcase(os.path.abspath(os.fsdecode(path)))

        forbidden = {normalized(excluded_link), normalized(outside)}
        original_scandir = bandit_scanner.os.scandir

        def guarded_scandir(path: str | bytes | Path) -> object:
            assert normalized(path) not in forbidden, (
                "excluded junction target was enumerated"
            )
            return original_scandir(path)

        original_count = bandit_scanner._count_python_files

        def guarded_count(directory: Path) -> int:
            assert normalized(directory) not in forbidden, (
                "excluded junction target was counted"
            )
            return original_count(directory)

        monkeypatch.setattr(bandit_scanner.os, "scandir", guarded_scandir)
        monkeypatch.setattr(bandit_scanner, "_count_python_files", guarded_count)

        scanner = BanditScanner(excluded_dirs=("vendorlib",))
        scanner._report_scope(root, excluded_parts("vendorlib"))

        err = capsys.readouterr().err
        assert "scan-exclude path vendorlib was not traversed" in err
        assert "count unavailable (link or inspection failure)" in err
        assert "5 python file(s)" not in err
    finally:
        if os.path.lexists(excluded_link):
            excluded_link.rmdir()


@pytest.mark.xfail(
    strict=True,
    reason=(
        "OP-36 / RT-0012 open: a partial file count is reported as an exclusion's total"
    ),
)
def test_a_partial_count_is_never_reported_as_the_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """When one location of an exclusion fails to count, the total must not read as whole.

    `_report_scope` sums a count per exclusion *name* across every location that
    matched, and on `OSError` it drops that location and records it as unavailable. The
    exclusion's warning then prints the sum of the locations that succeeded, with no
    sign that it is partial, while the unavailable line names a path rather than the
    exclusion. An operator cannot reconstruct the real total from the two lines.
    """
    for location, count in (("a", 7), ("b", 3)):
        directory = tmp_path / location / "vendorlib"
        directory.mkdir(parents=True)
        for index in range(count):
            (directory / f"f{index}.py").write_text("x = 1\n", encoding="utf-8")

    original = bandit_scanner._count_python_files

    def fail_under_a(directory: Path) -> int:
        if directory.parent.name == "a":
            raise OSError(5, "Access is denied")
        return original(directory)

    monkeypatch.setattr(bandit_scanner, "_count_python_files", fail_under_a)
    scanner = BanditScanner(excluded_dirs=("vendorlib",))
    scanner._report_scope(tmp_path, excluded_parts("vendorlib"))

    err = capsys.readouterr().err
    assert "count unavailable under a/vendorlib" in err
    # The true total is ten. Printing three as the total for `vendorlib` is a partial
    # presented as complete, so the exclusion's own line must say it is incomplete.
    assert "3 python file(s) under scan-exclude (vendorlib)" not in err


@pytest.mark.xfail(
    strict=True,
    reason=(
        "OP-37 / RT-0013 open: _count_python_files does not enforce containment itself"
    ),
)
def test_the_counter_does_not_read_through_a_link_it_is_handed(
    tmp_path: Path,
) -> None:
    """`_count_python_files` must enforce its own containment claim, not inherit it.

    Its docstring states that because no link is followed, "every path reached is a real
    descendant of `directory` and containment needs no second check". That is false for
    its own argument: handed a junction, it reads straight through it and counts files
    outside the scan root. The property holds only as an invariant of the single caller,
    which is the fragility the explicit `is_relative_to(scan_root)` check would have
    covered (`RED_TEAM.md` §7 RT-0009).
    """
    root = tmp_path / "target"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    for index in range(5):
        (outside / f"vend{index}.py").write_text("y = 1\n", encoding="utf-8")

    make_junction(root / "vendorlib", outside)
    try:
        counted = bandit_scanner._count_python_files(root / "vendorlib")
    finally:
        (root / "vendorlib").rmdir()

    assert counted == 0

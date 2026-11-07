"""RT-0004 proof tests — one per finding of the red team pass on `bbb1d77` and `09f0ef4`.

Written by the red team seat; committed by a PM seat, which `RED_TEAM.md` section 2 requires.
Each is marked `xfail(strict=True)` by that PM seat so the gate block stays green while the
defects are open **and** the marker cannot outlive its defect: the moment a fix makes one of
these pass, strict xfail turns the pass into a failure and forces the marker's removal. Do not
relax a marker to make a gate pass (`AGENTS.md` section 2, A05).
"""

import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from omnipatch.codebase.ast_tools import extract_context
from omnipatch.models import Finding, Severity
from omnipatch.scanners import bandit_scanner
from omnipatch.scanners.bandit_scanner import BanditScanner

WHOLE_CREDENTIAL = "WHOLEKEY-SYNTHETIC"


def make_finding(file: str, line: int) -> Finding:
    """Build a non-bandit finding so the general snippet redaction path runs."""
    return Finding(
        "finding-rt0004",
        "B608",
        "query built from string",
        Severity.MEDIUM,
        PurePosixPath(file),
        line,
        line,
        "possible SQL injection",
        "redteam",
    )


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


@pytest.mark.parametrize(
    "shape",
    [
        pytest.param(
            'DSN = "DRIVER={ODBC Driver 17};PWD={'
            + WHOLE_CREDENTIAL
            + '};Server=db"\n',
            id="odbc-brace-quoted-value",
        ),
        pytest.param(
            'DSN = "Password=;' + WHOLE_CREDENTIAL + '"\n',
            id="value-opens-with-a-semicolon",
        ),
        pytest.param(
            'DSN = "Password=`' + WHOLE_CREDENTIAL + '`"\n',
            id="backtick-quoted-value",
        ),
        pytest.param(
            "DSN = 'Server=db;Password=\"" + WHOLE_CREDENTIAL + "\"'\n",
            id="quoted-value-shadowed-by-an-outer-assignment",
        ),
        pytest.param(
            'cfg = {"dsn": "PWD={' + WHOLE_CREDENTIAL + '}"}\n',
            id="odbc-under-a-non-sensitive-mapping-key",
        ),
    ],
)
def test_a_whole_credential_never_survives_into_the_model_snippet(
    tmp_path: Path, shape: str
) -> None:
    """A terminator at the start of the value must not leave the credential intact.

    `_INLINE_KEY_VALUE_RE`'s value group is a negated character class requiring one
    or more characters, so when the first character of the value is itself in that
    class the pattern does not match at all and nothing is redacted. The surviving
    text is a complete, usable credential, not a fragment.
    """
    (tmp_path / "config.py").write_text(shape, encoding="utf-8")
    context = extract_context(make_finding("config.py", 1), tmp_path)
    assert WHOLE_CREDENTIAL not in context.snippet


@pytest.mark.xfail(
    strict=True,
    reason="OP-30 / RT-0006 open: a default exclusion name matching a project's own package drops its findings in silence",
)
def test_a_default_exclusion_name_at_depth_is_reported_like_any_other(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A default name matching a project's own package must not vanish in silence.

    `_report_scope` suppresses every exclusion whose name is in `EXCLUDED_DIRS`, so a
    project whose own package is `build` or `dist` at depth loses real findings with
    nothing on stderr, while the identical tree reported under the spelling
    `src/build` does produce a warning.
    """
    own_package = tmp_path / "src" / "build"
    own_package.mkdir(parents=True)
    (own_package / "handler.py").write_text("x = 1\n", encoding="utf-8")

    scanner = BanditScanner(excluded_dirs=("src/build",))
    scanner._report_scope(tmp_path, excluded_parts("src/build"))
    assert "were not scanned" in capsys.readouterr().err

    scanner = BanditScanner(excluded_dirs=("build",))
    scanner._report_scope(tmp_path, excluded_parts("build"))
    assert "were not scanned" in capsys.readouterr().err


def test_the_skipped_file_count_never_includes_files_outside_the_scan_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported count must describe the repository, not whatever a link reaches.

    `rglob` descends a junction, because a junction is a mount-point reparse tag and
    `Path.is_symlink()` is false for it, so the count can include files that are not
    in the repository and that Bandit was never going to scan.
    """
    root = tmp_path / "target"
    vendored = root / "vendorlib"
    vendored.mkdir(parents=True)
    (vendored / "own.py").write_text("y = 1\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    for index in range(3):
        (outside / f"extra{index}.py").write_text("x = 1\n", encoding="utf-8")

    make_junction(vendored / "escape", outside)
    try:
        scanner = BanditScanner(excluded_dirs=("vendorlib",))
        scanner._report_scope(root, excluded_parts("vendorlib"))
    finally:
        (vendored / "escape").rmdir()
    assert "1 python file(s)" in capsys.readouterr().err


def test_a_link_loop_under_an_exclusion_is_neither_followed_nor_fatal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A junction loop must not be descended, must not hang, and must not fail the scan.

    **A PM seat changed this test's contract when it fixed OP-33 and OP-34, and says so
    here rather than quietly.** As the red team wrote it, this asserted
    `pytest.raises(ScannerError)`, because the junction loop made `rglob` recurse until
    Windows refused the path and the resulting `OSError` escaped untranslated. The fix
    stops descending links of either kind, so the loop is never entered and there is no
    `OSError` left to translate — the test's own trigger is gone. Asserting a raise that
    can no longer happen would be asserting the fix had not worked.

    The contract is therefore the stronger property: the loop is not followed, the count
    is the truth, and an advisory count never fails a scan that succeeded. The boundary
    rule the original test defended is covered by
    `test_a_failing_count_is_reported_and_never_escapes` below. This change goes back to
    the red team as part of the RT-0004 round-two review.
    """
    root = tmp_path / "target"
    vendored = root / "vendorlib"
    vendored.mkdir(parents=True)
    (vendored / "own.py").write_text("y = 1\n", encoding="utf-8")

    make_junction(vendored / "loop", root)
    try:
        scanner = BanditScanner(excluded_dirs=("vendorlib",))
        scanner._report_scope(root, excluded_parts("vendorlib"))
    finally:
        (vendored / "loop").rmdir()

    err = capsys.readouterr().err
    assert "1 python file(s)" in err
    assert "count unavailable" not in err


def test_a_failing_count_is_reported_and_never_escapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An `OSError` while counting is reported to the operator, not raised at the caller.

    `AGENTS.md` section 3 requires that no third-party exception escape the module
    boundary, and section 2's A09 requires that anything dropped be reported. The walk
    is advisory, so the honest resolution is to report the missing count and leave the
    scan's own result intact — never a traceback, and never a wrong number.
    """
    vendored = tmp_path / "vendorlib"
    vendored.mkdir()
    (vendored / "own.py").write_text("y = 1\n", encoding="utf-8")

    def refuse(_directory: Path) -> int:
        raise OSError(1921, "The name of the file cannot be resolved by the system")

    monkeypatch.setattr(bandit_scanner, "_count_python_files", refuse, raising=True)
    scanner = BanditScanner(excluded_dirs=("vendorlib",))
    scanner._report_scope(tmp_path, excluded_parts("vendorlib"))

    err = capsys.readouterr().err
    assert "count unavailable under vendorlib" in err
    assert "the scan itself was not affected" in err
    assert "python file(s) under scan-exclude" not in err

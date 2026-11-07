"""Verify validated patches by scanning their materialized file in isolation."""

from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from omnipatch.codebase.repo_io import patched_sandbox
from omnipatch.errors import PatchApplyError
from omnipatch.models import Finding, Patch, PatchResult
from omnipatch.scanners.base import Scanner
from omnipatch.validation.patch_validator import materialize_patch_source


def verify_patch(
    patch: Patch,
    finding: Finding,
    repo_root: Path,
    scanner: Scanner,
    baseline: Sequence[Finding],
    policy: Literal["severity", "strict"] = "severity",
) -> PatchResult:
    """Re-scan the patched file in isolation and judge the patch."""
    if policy not in ("severity", "strict"):
        raise PatchApplyError(f"Unknown verification policy: {policy}")
    root = repo_root.resolve()
    if patch.finding_id != finding.id or patch.touched_files != (finding.file,):
        raise PatchApplyError("Patch metadata does not match the finding")
    source_path = (root / Path(finding.file.as_posix())).resolve()
    if not source_path.is_relative_to(root):
        raise PatchApplyError(
            f"Finding path resolves outside repository: {finding.file}"
        )
    try:
        original_source = source_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise PatchApplyError(f"Unable to read finding source: {finding.file}") from exc

    patched_source = materialize_patch_source(
        patch.unified_diff, finding, original_source
    )
    with patched_sandbox(
        finding.file, patched_source, forbidden_root=root
    ) as sandbox_root:
        scan_root = sandbox_root.resolve()
        if scan_root.is_relative_to(root):
            raise PatchApplyError("Temporary sandbox is inside the source repository")
        after = scanner.scan(scan_root)

    baseline_counts = Counter(
        (item.rule_id, item.file.as_posix())
        for item in baseline
        if item.file == finding.file
    )
    after_counts = Counter(
        (item.rule_id, item.file.as_posix())
        for item in after
        if item.file == finding.file
    )
    target = (finding.rule_id, finding.file.as_posix())
    introduced_pairs = sorted(
        pair for pair, count in after_counts.items() if count > baseline_counts[pair]
    )
    severity_by_pair = {
        pair: max(
            item.severity.rank
            for item in after
            if item.rule_id == pair[0] and item.file.as_posix() == pair[1]
        )
        for pair in introduced_pairs
    }
    blocking: list[tuple[str, str]] = []
    tolerated: list[str] = []
    for pair in introduced_pairs:
        label = f"{pair[0]} in {pair[1]}"
        if policy == "strict" or severity_by_pair[pair] >= finding.severity.rank:
            blocking.append(pair)
        else:
            tolerated.append(label)
    reasons: list[str] = []
    if not baseline_counts[target]:
        reasons.append(
            f"Target finding {finding.rule_id} in {finding.file.as_posix()} "
            "was absent from the baseline scan."
        )
    if after_counts[target]:
        reasons.append(
            f"Target finding {finding.rule_id} in {finding.file.as_posix()} survived."
        )
    if blocking:
        labels = ", ".join(f"{rule} in {file}" for rule, file in blocking)
        reasons.append(f"Patch introduced new findings: {labels}.")
    error = " ".join(reasons) if reasons else None
    return PatchResult(
        patch=patch,
        applied=True,
        verified=error is None,
        error=error,
        introduced=tuple(tolerated),
    )

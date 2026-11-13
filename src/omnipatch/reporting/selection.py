"""Shared bounded selection for scanner findings."""

from collections.abc import Sequence

from omnipatch.models import Finding


def select_findings(
    findings: Sequence[Finding], maximum: int
) -> tuple[list[Finding], int]:
    """Return at most ``maximum`` findings and the number omitted."""
    if maximum < 1:
        raise ValueError("maximum must be at least one")
    selected = list(findings[:maximum])
    return selected, max(0, len(findings) - len(selected))

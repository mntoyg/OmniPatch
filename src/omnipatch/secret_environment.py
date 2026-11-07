"""Stable keys and fail-closed lookup for B105 environment mappings."""

from omnipatch.models import CodeContext, Finding


def secret_environment_key(finding: Finding, context: CodeContext) -> str:
    """Return the public mapping key for a repository-relative B105 target."""
    return f"{finding.file.as_posix()}::{context.symbol or '<module>'}"


def missing_secret_environment_keys(
    findings: list[Finding],
    contexts: dict[str, CodeContext],
    mappings: dict[str, str],
) -> list[str]:
    """Return every B105 target key that lacks an explicit variable mapping."""
    return [
        secret_environment_key(finding, contexts[finding.id])
        for finding in findings
        if finding.rule_id == "B105"
        and secret_environment_key(finding, contexts[finding.id]) not in mappings
    ]


def sql_paramstyle_key(finding: Finding, context: CodeContext) -> str:
    """Return the stable repository-relative mapping key for a B608 target."""
    return f"{finding.file.as_posix()}::{context.symbol or '<module>'}"


def missing_sql_paramstyle_keys(
    findings: list[Finding],
    contexts: dict[str, CodeContext],
    mappings: dict[str, str],
) -> list[str]:
    """Return every B608 target key that lacks an explicit parameter style."""
    return [
        sql_paramstyle_key(finding, contexts[finding.id])
        for finding in findings
        if finding.rule_id == "B608"
        and sql_paramstyle_key(finding, contexts[finding.id]) not in mappings
    ]

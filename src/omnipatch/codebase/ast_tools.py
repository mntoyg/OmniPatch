"""Extract bounded, redacted Python context for a finding."""

import ast
import sys
from pathlib import Path
from textwrap import dedent
from typing import TypeGuard, cast

from omnipatch.defaults import (
    DEFAULT_CONTEXT_MAX_LINES,
    DEFAULT_MODULE_WINDOW_LINES,
)
from omnipatch.errors import PatchGenerationError
from omnipatch.models import CodeContext, Finding

ScopeNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


def _is_scope(node: ast.AST) -> TypeGuard[ScopeNode]:
    """Return whether a node represents a supported lexical scope."""
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))


def _scope_start(node: ScopeNode) -> int:
    """Return the first decorator or definition line for a scope node."""
    line_numbers = [node.lineno]
    line_numbers.extend(decorator.lineno for decorator in node.decorator_list)
    return min(line_numbers)


def _scope_end(node: ScopeNode) -> int:
    """Return a parsed scope node's last source line."""
    return cast(int, node.end_lineno)


def _statement_start(node: ast.stmt) -> int:
    """Return the first decorator or statement line for a top-level statement."""
    line_numbers = [node.lineno]
    if _is_scope(node):
        line_numbers.extend(decorator.lineno for decorator in node.decorator_list)
    return min(line_numbers)


def _module_window(
    tree: ast.Module, lines: list[str], line_number: int, budget: int
) -> tuple[int, int]:
    """Return a contiguous line range covering whole module statements."""
    spans = [(_statement_start(node), cast(int, node.end_lineno)) for node in tree.body]
    if not spans:
        return 1, len(lines)
    anchor = next(
        (
            index
            for index, (start, end) in enumerate(spans)
            if start <= line_number <= end
        ),
        None,
    )
    if anchor is None:
        following = [
            index for index, (start, _) in enumerate(spans) if start > line_number
        ]
        anchor = following[0] if following else len(spans) - 1
    low = high = anchor
    total = spans[anchor][1] - spans[anchor][0] + 1
    while True:
        grew = False
        if low > 0 and total + (spans[low][0] - spans[low - 1][0]) <= budget:
            total += spans[low][0] - spans[low - 1][0]
            low -= 1
            grew = True
        if (
            high < len(spans) - 1
            and total + (spans[high + 1][1] - spans[high][1]) <= budget
        ):
            total += spans[high + 1][1] - spans[high][1]
            high += 1
            grew = True
        if not grew:
            break
    return spans[low][0], min(spans[high][1], len(lines))


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map each AST child to its parent node."""
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _enclosing_scope(
    tree: ast.Module, line_number: int, parents: dict[ast.AST, ast.AST]
) -> ScopeNode | None:
    """Return the narrowest function or class containing a source line."""
    candidates = [
        node
        for node in ast.walk(tree)
        if _is_scope(node) and _scope_start(node) <= line_number <= _scope_end(node)
    ]
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda node: _scope_end(node) - _scope_start(node),
    )


def _scope_symbol(node: ScopeNode, parents: dict[ast.AST, ast.AST]) -> str:
    """Build a dotted name from enclosing class and function scopes."""
    names: list[str] = []
    current: ast.AST | None = node
    while current is not None:
        if _is_scope(current):
            names.append(current.name)
        current = parents.get(current)
    return ".".join(reversed(names))


def _snippet_lines(
    tree: ast.Module,
    lines: list[str],
    line_number: int,
    parents: dict[ast.AST, ast.AST],
    module_window_lines: int,
) -> tuple[str, int, str | None]:
    """Select the decorated scope or a bounded module-level window."""
    scope = _enclosing_scope(tree, line_number, parents)
    if scope is None:
        start, end = _module_window(tree, lines, line_number, module_window_lines)
        snippet = "\n".join(lines[start - 1 : end])
        return snippet, start, None
    start = _scope_start(scope)
    end = _scope_end(scope)
    return "\n".join(lines[start - 1 : end]), start, _scope_symbol(scope, parents)


def _scope_parses(source: str) -> bool:
    """Report whether a scope parses once dedented, as `rewrite_scope_to_diff` parses it."""
    try:
        ast.parse(dedent(source))
    except (SyntaxError, ValueError):
        return False
    return True


def _report_redaction_parse_loss(finding: Finding, before: str, after: str) -> None:
    """Tell the operator when redaction left a once-parseable scope unparseable.

    This reports and does not refuse, and OP-25 records why. Redaction legitimately
    destroys syntax when the secret *is* a syntactic element — a credential-shaped
    module name in an `import` statement is redacted to a marker that cannot parse,
    and that is the correct outcome. A refusal here would reject correct answers,
    and a gate no correct answer can pass is not a gate. What was wrong before was
    the silence: the model received a corrupted scope and nothing said so.

    The comparison is preservation, not parseability, so a scope that already failed
    to parse is never reported as a redaction fault. The message carries the finding
    and rule id only — no literal, no source (OWASP A02/A09).
    """
    if _scope_parses(before) and not _scope_parses(after):
        print(
            f"warning: redaction left context for {finding.id} "
            f"({finding.rule_id}) unparseable; the model receives a degraded scope",
            file=sys.stderr,
        )


def extract_context(
    finding: Finding,
    repo_root: Path,
    max_snippet_lines: int = DEFAULT_CONTEXT_MAX_LINES,
    *,
    module_window_lines: int = DEFAULT_MODULE_WINDOW_LINES,
) -> CodeContext:
    """Build the redacted code context surrounding a finding."""
    from omnipatch.codebase.redaction import (
        redact,
        redact_b105_literal,
        redact_sensitive_returns,
    )

    if max_snippet_lines < 1:
        raise PatchGenerationError("Context line limit must be at least 1")
    if module_window_lines < 1:
        raise PatchGenerationError(
            "Module context window line limit must be at least 1"
        )
    try:
        root = repo_root.resolve()
        source_path = (root / Path(finding.file.as_posix())).resolve()
        source_path.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PatchGenerationError(
            f"Context source is outside the repository: {finding.file}"
        ) from exc
    try:
        source = source_path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise PatchGenerationError(
            f"Unable to read context source: {finding.file}"
        ) from exc
    # Bandit B105 locations identify the statement used by the target resolver;
    # synthetic/non-Bandit findings keep the general redaction behavior below.
    if finding.rule_id == "B105" and finding.source == "bandit":
        source = redact_b105_literal(source, finding.line_start)
    try:
        tree = ast.parse(source, filename=str(finding.file))
    except SyntaxError as exc:
        raise PatchGenerationError(
            f"Unable to parse context source: {finding.file}"
        ) from exc

    lines = source.splitlines()
    parents = _parent_map(tree)
    snippet, snippet_line_start, symbol = _snippet_lines(
        tree,
        lines,
        finding.line_start,
        parents,
        min(module_window_lines, max_snippet_lines),
    )
    scope_before_redaction = snippet
    snippet = redact(redact_sensitive_returns(snippet))
    _report_redaction_parse_loss(finding, scope_before_redaction, snippet)
    snippet_lines = snippet.splitlines()
    if len(snippet_lines) > max_snippet_lines:
        remaining = len(snippet_lines) - max_snippet_lines
        snippet = "\n".join(
            [
                *snippet_lines[:max_snippet_lines],
                f"# ... truncated by omnipatch: {remaining} more line(s)",
            ]
        )

    rendered_imports: list[str] = []
    seen_imports: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            rendered = ast.get_source_segment(source, node)
            if rendered is None:
                raise PatchGenerationError(
                    f"Unable to render module import in context source: {finding.file}"
                )
            if rendered not in seen_imports:
                redacted_import = redact(rendered)
                if redacted_import not in seen_imports:
                    seen_imports.add(redacted_import)
                    rendered_imports.append(redacted_import)
    return CodeContext(
        finding_id=finding.id,
        snippet=snippet,
        snippet_line_start=snippet_line_start,
        symbol=symbol,
        imports=tuple(rendered_imports),
    )

"""Convert rewritten, redacted-context scopes into validator-ready diffs."""

import ast
from collections import Counter
from difflib import unified_diff
from textwrap import dedent
from typing import cast

from omnipatch.errors import PatchGenerationError
from omnipatch.models import CodeContext, Finding
from omnipatch.validation.patch_validator import strip_fence

_TRUNCATION_PREFIX = "# ... truncated by omnipatch:"


def _import_lines(scope: str) -> Counter[str]:
    """Count import statements by their dedented, trimmed source lines."""
    # Line matching intentionally rejects reformatted parenthesized imports.
    return Counter(
        normalized
        for line in scope.splitlines()
        if (normalized := dedent(line).strip()).startswith(("import ", "from "))
    )


def _is_import(node: ast.stmt) -> bool:
    return isinstance(node, (ast.Import, ast.ImportFrom))


def _leading_import_end(module: ast.Module) -> int:
    """Return the last line of the module docstring and consecutive imports."""
    body = module.body
    index = 0
    end_line = 0
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            end_line = cast(int, body[0].end_lineno)
            index = 1
    while index < len(body) and _is_import(body[index]):
        end_line = cast(int, body[index].end_lineno)
        index += 1
    return end_line


def _leading_import_lines(source: str, module: ast.Module) -> Counter[str]:
    """Return source-line imports that are direct children in the leading region."""
    result: Counter[str] = Counter()
    body = module.body
    index = 0
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            index = 1
    while index < len(body) and _is_import(body[index]):
        segment = ast.get_source_segment(source, body[index])
        if segment is None:
            raise PatchGenerationError("Cannot inspect a module import statement")
        result.update(_import_lines(segment))
        index += 1
    return result


def _top_level_import_buckets(source: str, module: ast.Module) -> dict[int, list[str]]:
    """Group direct imports by preceding non-import statements and preserve order."""
    buckets: dict[int, list[str]] = {}
    non_imports = 0
    for node in module.body:
        if _is_import(node):
            segment = ast.get_source_segment(source, node)
            if segment is None:
                raise PatchGenerationError("Cannot inspect a module import statement")
            buckets.setdefault(non_imports, []).extend(_import_lines(segment))
        else:
            non_imports += 1
    return buckets


def _import_placements(
    source: str, module: ast.Module
) -> Counter[tuple[str, tuple[str, ...]]]:
    """Record exact import lines and their enclosing AST scope types."""
    result: Counter[tuple[str, tuple[str, ...]]] = Counter()

    def visit(node: ast.AST, parents: tuple[str, ...]) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            segment = ast.get_source_segment(source, node)
            if segment is None:
                raise PatchGenerationError(
                    "Cannot inspect an existing import statement"
                )
            for statement in _import_lines(segment):
                result[(statement, parents)] += 1
        child_parents = (
            parents if isinstance(node, ast.Module) else (*parents, type(node).__name__)
        )
        for field_name, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                visit(value, child_parents)
            elif isinstance(value, list):
                statements = [child for child in value if isinstance(child, ast.stmt)]
                if statements and len(statements) == len(value):
                    suite = (*child_parents, f"{type(node).__name__}.{field_name}")
                    bucket = 0
                    for child in statements:
                        visit(child, (*suite, f"slot:{bucket}"))
                        if not _is_import(child):
                            bucket += 1
                else:
                    for child in value:
                        if isinstance(child, ast.AST):
                            visit(child, child_parents)

    visit(module, ())
    return result


def _is_submultiset(
    required: Counter[tuple[str, tuple[str, ...]]],
    available: Counter[tuple[str, tuple[str, ...]]],
) -> bool:
    return not (required - available)


def _is_subsequence(required: list[str], available: list[str]) -> bool:
    """Check that existing imports retain their relative order."""
    iterator = iter(available)
    return all(any(candidate == item for candidate in iterator) for item in required)


def rewrite_scope_to_diff(
    rewritten_scope: str,
    context: CodeContext,
    original_source: str,
    finding: Finding,
) -> str:
    """Splice rewritten scope into real source and generate a unified diff."""
    snippet_lines = context.snippet.splitlines()
    if snippet_lines and snippet_lines[-1].startswith(_TRUNCATION_PREFIX):
        raise PatchGenerationError(
            "Cannot rewrite a truncated context snippet; increase the context line limit"
        )
    if not snippet_lines:
        raise PatchGenerationError("Cannot rewrite an empty context snippet")

    cleaned_scope = strip_fence(rewritten_scope)
    if not cleaned_scope:
        raise PatchGenerationError("Rewritten scope is empty")
    try:
        ast.parse(dedent(cleaned_scope), filename=finding.file.as_posix())
    except SyntaxError as exc:
        raise PatchGenerationError(
            f"Rewritten scope is not valid Python at line {exc.lineno}: {exc.msg}"
        ) from exc
    original_lines = original_source.splitlines()
    start = context.snippet_line_start - 1
    end = start + len(snippet_lines)
    if start < 0 or end > len(original_lines):
        raise PatchGenerationError(
            "Context scope line range is outside the original source"
        )
    original_scope = "\n".join(original_lines[start:end])
    original_import_lines = _import_lines(original_scope)
    rewritten_import_lines = _import_lines(cleaned_scope)
    added_imports = sorted((rewritten_import_lines - original_import_lines).elements())
    removed_imports = sorted(
        (_import_lines(original_scope) - _import_lines(cleaned_scope)).elements()
    )
    changes = [
        *(f"Added import statement {statement!r}" for statement in added_imports),
        *(f"Removed import statement {statement!r}" for statement in removed_imports),
    ]
    if removed_imports:
        raise PatchGenerationError(
            "; ".join(changes)
            + "; imports are supplied separately in the request and must be left exactly as they are."
        )
    original_module_scope: ast.Module | None = None
    rewritten_module_scope: ast.Module | None = None
    if context.symbol is None:
        original_module: ast.Module | None = None
        if added_imports:
            try:
                original_module = ast.parse(
                    original_source, filename=finding.file.as_posix()
                )
            except SyntaxError as exc:
                raise PatchGenerationError(
                    f"Cannot authorize an import addition from an invalid original module: {exc.msg}"
                ) from exc
            if start != 0 or end < _leading_import_end(original_module):
                raise PatchGenerationError(
                    "Cannot add imports unless the module context contains the complete leading import region"
                )
        try:
            original_module_scope = ast.parse(original_scope)
            rewritten_module_scope = ast.parse(cleaned_scope)
        except SyntaxError as exc:
            raise PatchGenerationError(
                f"Cannot inspect imports in an invalid module context: {exc.msg}"
            ) from exc
        original_placements = _import_placements(original_scope, original_module_scope)
        rewritten_placements = _import_placements(cleaned_scope, rewritten_module_scope)
        if not _is_submultiset(original_placements, rewritten_placements):
            raise PatchGenerationError(
                "Existing imports must remain unchanged and in their original scope."
            )
        original_buckets = _top_level_import_buckets(
            original_scope, original_module_scope
        )
        rewritten_buckets = _top_level_import_buckets(
            cleaned_scope, rewritten_module_scope
        )
        if any(
            not _is_subsequence(imports, rewritten_buckets.get(bucket, []))
            for bucket, imports in original_buckets.items()
        ):
            raise PatchGenerationError(
                "Existing imports must remain in their original module region and order."
            )
        added_placements = rewritten_placements - original_placements
    if added_imports:
        if context.symbol is not None:
            raise PatchGenerationError(
                "; ".join(changes)
                + "; imports are supplied separately in the request and must be left exactly as they are."
            )
        if original_module_scope is None or rewritten_module_scope is None:
            raise PatchGenerationError("Cannot inspect module-level import placement")
        leading_additions = _leading_import_lines(cleaned_scope, rewritten_module_scope)
        if (
            original_module is not None
            and ast.get_docstring(original_module, clean=False) is not None
            and ast.get_docstring(rewritten_module_scope, clean=False) is None
        ):
            raise PatchGenerationError(
                "The module docstring must remain before the leading import region"
            )
        direct_additions = Counter(
            {
                statement: count
                for (statement, parents), count in added_placements.items()
                if len(parents) == 2 and parents[0] == "Module.body"
            }
        )
        if (
            any(
                not (len(parents) == 2 and parents[0] == "Module.body")
                for _, parents in added_placements
            )
            or not direct_additions
            or direct_additions - leading_additions
        ):
            raise PatchGenerationError(
                "Added imports must be direct top-level statements in the leading module import region"
            )
    rewritten_lines = cleaned_scope.splitlines()
    patched_lines = [*original_lines[:start], *rewritten_lines, *original_lines[end:]]
    patched_source = "\n".join(patched_lines)
    if original_source.endswith(("\n", "\r")):
        patched_source += "\n"
    generated = unified_diff(
        original_source.splitlines(),
        patched_source.splitlines(),
        fromfile=f"a/{finding.file.as_posix()}",
        tofile=f"b/{finding.file.as_posix()}",
        lineterm="",
    )
    return "\n".join(generated)

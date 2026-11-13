"""Deterministic redaction for credential-shaped source values."""

import ast
import io
import re
import textwrap
import tokenize

from omnipatch.errors import PatchGenerationError

REDACTION_MARKER = "<redacted by omnipatch>"

_SENSITIVE_NAMES = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
    "passphrase",
    "client_secret",
    "access_key",
    "secret_key",
)
_B105_NAME = re.compile(
    r"(?i)(?:^|_)(?:pas+wo?r?d|pass(?:phrase)?|pwd|token|secrete?)(?:_|$)"
)
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_PREFIX = r"(?P<prefix>(?i:br|rb|fr|rf|r|u|b|f)?)"
_QUOTE = r"(?P<quote>'''|\"\"\"|'|\")"
_STRING_VALUE = r"(?P<value>(?:\\.|(?!(?P=quote)).)*?)(?P=quote)"
_ASSIGNMENT_RE = re.compile(
    rf"(?P<lhs>(?P<name>{_IDENTIFIER})[ \t]*(?::[^=\r\n]+)?[ \t]*=[ \t]*)"
    rf"{_PREFIX}{_QUOTE}{_STRING_VALUE}",
    re.DOTALL,
)
_STRING_LITERAL_RE = re.compile(rf"{_PREFIX}{_QUOTE}{_STRING_VALUE}", re.DOTALL)
_STRING_PART_PATTERN = (
    r"(?:(?i:br|rb|fr|rf|r|u|b|f))?"
    r"(?:'''(?:\\.|(?!(?:''')).)*?'''|"
    r"\"\"\"(?:\\.|(?!(?:\"\"\")).)*?\"\"\"|"
    r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
_CONCAT_ASSIGNMENT_RE = re.compile(
    rf"(?P<lhs>(?P<name>{_IDENTIFIER})[ \t]*(?::[^=\r\n]+)?[ \t]*=[ \t]*)"
    rf"(?P<before>\([ \t]*)"
    rf"(?P<parts>(?:{_STRING_PART_PATTERN}\s*){{2,}})"
    rf"(?P<after>\))",
    re.DOTALL,
)
_MAPPING_RE = re.compile(
    rf"(?P<key_quote>['\"])(?P<key>(?:\\.|(?!(?P=key_quote)).)*)(?P=key_quote)"
    rf"(?P<separator>\s*:\s*){_PREFIX}{_QUOTE}{_STRING_VALUE}",
    re.DOTALL,
)
_SUBSCRIPT_ASSIGNMENT_RE = re.compile(
    rf"(?P<target>{_IDENTIFIER})\[\s*(?P<key_quote>['\"])(?P<key>.*?)"
    rf"(?P=key_quote)\s*\](?P<separator>\s*=\s*){_PREFIX}{_QUOTE}{_STRING_VALUE}",
    re.DOTALL,
)
_COMPARISON_RE = re.compile(
    rf"(?P<name>{_IDENTIFIER})(?P<operator>\s*(?:==|!=)\s*)"
    rf"{_PREFIX}{_QUOTE}{_STRING_VALUE}",
    re.DOTALL,
)
_URL_CREDENTIAL_RE = re.compile(
    r"(?P<prefix>[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)"
    r"(?P<password>[^@/\s?#]+)(?P<suffix>@)"
)
# OP-28. This pattern matches a sensitive key and its separator and **nothing else**.
# It deliberately has no value group: the previous one ended the value at a negated
# character class, and every character in that class was a point where redaction
# stopped. RT-0004 measured the consequence — with a terminator inside the value a
# fragment survived, and with one *first* in the value the group could not match at
# all, so the whole credential survived. The value's extent is now the string token's
# own boundary, which `_redact_embedded_literal` holds.
_LEADING_SCHEME_RE = re.compile(r"(?i)^(bearer|basic|token)(\s+)")
_INLINE_SENSITIVE_KEY_RE = re.compile(
    rf"(?i)(?P<key>[A-Za-z0-9_.-]*(?:{'|'.join(map(re.escape, _SENSITIVE_NAMES))})"
    r"[A-Za-z0-9_.-]*)(?P<sep>\s*[:=]\s*)"
)
_INLINE_SCHEME_RE = re.compile(
    r"(?i)(?P<scheme>\b(?:bearer|basic|token))(?P<space>\s+)"
    r"(?P<secret>[^\s\"'`,;}]+)"
)
_SEQUENCE_PAIR_RE = re.compile(
    rf"(?P<key_quote>['\"])(?P<key>(?:\\.|(?!(?P=key_quote)).)*)(?P=key_quote)"
    rf"(?P<separator>\s*,\s*){_PREFIX}{_QUOTE}{_STRING_VALUE}",
    re.DOTALL,
)
_PEM_RE = re.compile(
    r"(?ms)^[^\r\n]*-----BEGIN [^\r\n]*PRIVATE KEY-----[^\r\n]*"
    r"(?:\r?\n|$).*?^[^\r\n]*-----END [^\r\n]*-----[^\r\n]*(?=\r?$)"
)
_SHAPE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"sk-[A-Za-z0-9_-]{8,}",
        r"ghp_[A-Za-z0-9_]{8,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"xox[baprs]-[A-Za-z0-9-]{10,}",
    )
)


def _redact_pem(match: re.Match[str]) -> str:
    """Replace PEM block lines individually and preserve line endings."""
    lines = match.group().splitlines(keepends=True)
    return "".join(
        REDACTION_MARKER
        + (
            "\r\n"
            if line.endswith("\r\n")
            else "\n"
            if line.endswith("\n")
            else "\r"
            if line.endswith("\r")
            else ""
        )
        for line in lines
    )


def _redact_assignment(match: re.Match[str]) -> str:
    """Replace a sensitive-name literal while retaining its quote style."""
    if REDACTION_MARKER in match.group("value"):
        return match.group()
    name = match.group("name")
    if not _is_sensitive_name(name) and not _B105_NAME.search(name):
        return match.group()
    return f"{match.group('lhs')}{_redact_literal(match)}"


def _is_sensitive_name(name: str) -> bool:
    """Match configured credential fragments after normalizing separators."""
    folded = name.casefold()
    normalized = re.sub(r"[^a-z0-9]", "", folded)
    return any(
        sensitive in folded or re.sub(r"[^a-z0-9]", "", sensitive) in normalized
        for sensitive in _SENSITIVE_NAMES
    )


def _sensitive_return_ranges(
    source: str,
) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """Find return expressions owned by functions with credential-like names."""
    source = textwrap.dedent(source)
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise PatchGenerationError(
            "Unable to analyze context for sensitive return values"
        ) from exc

    ranges: list[tuple[tuple[int, int], tuple[int, int]]] = []

    class ReturnVisitor(ast.NodeVisitor):
        """Track the function that directly owns each return statement."""

        sensitive: bool

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            previous = self.sensitive
            self.sensitive = _is_sensitive_name(node.name)
            for child in node.body:
                self.visit(child)
            self.sensitive = previous

        def __init__(self) -> None:
            self.sensitive = False

        def visit_Return(self, node: ast.Return) -> None:
            if self.sensitive and node.value is not None:
                start = (node.value.lineno, node.value.col_offset)
                end = (
                    node.value.end_lineno or node.value.lineno,
                    node.value.end_col_offset or 0,
                )
                ranges.append((start, end))
            self.generic_visit(node)

    visitor = ReturnVisitor()
    visitor.visit(tree)
    return ranges


def _redact_return_token(token: tokenize.TokenInfo) -> str:
    """Replace a return-expression string token without changing its line count."""
    if tokenize.tok_name.get(token.type) == "FSTRING_MIDDLE":
        newlines = "".join(re.findall(r"\r\n|\r|\n", token.string))
        if token.string == f"{REDACTION_MARKER}{newlines}":
            return token.string
        return f"{REDACTION_MARKER}{newlines}"
    match = re.match(r"(?i)([rubf]*)(\"\"\"|'''|\"|')", token.string)
    if match is None:
        raise PatchGenerationError("Unable to safely redact a sensitive return value")
    prefix, quote = match.groups()
    if not token.string.endswith(quote):
        raise PatchGenerationError("Unable to safely redact a sensitive return value")
    body = token.string[match.end() : -len(quote)]
    newlines = "".join(re.findall(r"\r\n|\r|\n", body))
    if body == f"{REDACTION_MARKER}{newlines}":
        return token.string
    return f"{prefix}{quote}{REDACTION_MARKER}{newlines}{quote}"


def redact_sensitive_returns(source: str) -> str:
    """Redact string tokens in return expressions owned by sensitive functions."""
    dedented_source = textwrap.dedent(source)
    ranges = _sensitive_return_ranges(dedented_source)
    if not ranges:
        return source
    source_lines = source.splitlines(keepends=True)
    dedented_lines = dedented_source.splitlines(keepends=True)
    removed_columns = [
        max(0, len(original) - len(dedented))
        for original, dedented in zip(source_lines, dedented_lines, strict=True)
    ]
    offsets = [0]
    for line in source_lines:
        offsets.append(offsets[-1] + len(line))

    def ast_char_position(position: tuple[int, int]) -> tuple[int, int]:
        line_number, byte_column = position
        line = dedented_lines[line_number - 1]
        column = len(line.encode("utf-8")[:byte_column].decode("utf-8"))
        return line_number, column

    normalized = [
        (ast_char_position(start), ast_char_position(end)) for start, end in ranges
    ]
    replacements: list[tuple[int, int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.STRING and (
                tokenize.tok_name.get(token.type) != "FSTRING_MIDDLE"
            ):
                continue
            token_start = (
                token.start[0],
                max(0, token.start[1] - removed_columns[token.start[0] - 1]),
            )
            token_end = (
                token.end[0],
                max(0, token.end[1] - removed_columns[token.end[0] - 1]),
            )
            if any(
                start <= token_start and token_end <= end for start, end in normalized
            ):
                start_offset = offsets[token.start[0] - 1] + token.start[1]
                end_offset = offsets[token.end[0] - 1] + token.end[1]
                replacement = _redact_return_token(token)
                if replacement != token.string:
                    replacements.append((start_offset, end_offset, replacement))
    except (tokenize.TokenError, IndentationError, UnicodeError) as exc:
        raise PatchGenerationError(
            "Unable to safely analyze context for sensitive return values"
        ) from exc
    for start, end, replacement in reversed(replacements):
        source = source[:start] + replacement + source[end:]
    return source


def redact_b105_literal(source: str, finding_line: int) -> str:
    """Redact literals bound to the B105-sensitive target at a finding line.

    Bandit reports a line but not a literal span. Associate its recognized
    credential name with the owning AST expression, then replace only string
    tokens in that expression. Unsupported shapes fail closed.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        raise PatchGenerationError("Unable to analyze B105 context safely") from None

    def sensitive(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        else:
            return False
        return _B105_NAME.search(name) is not None

    ranges: list[tuple[int, int, int, int]] = []

    def add_string_constants(node: ast.AST) -> None:
        if (
            isinstance(node, ast.Constant) and isinstance(node.value, str)
        ) or isinstance(node, ast.JoinedStr):
            ranges.append(
                (
                    node.lineno,
                    node.col_offset,
                    node.end_lineno or node.lineno,
                    node.end_col_offset or node.col_offset,
                )
            )
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            add_string_constants(node.left)
            add_string_constants(node.right)

    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt):
            continue
        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        if not start <= finding_line <= end:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            if any(sensitive(target) for target in targets):
                add_string_constants(value)
            for child in ast.walk(value):
                if isinstance(child, ast.Dict):
                    for key, item in zip(child.keys, child.values, strict=True):
                        if key is not None and sensitive(key):
                            add_string_constants(item)
            for target in targets:
                if isinstance(target, ast.Subscript) and sensitive(target.slice):
                    add_string_constants(value)
        for comparison in ast.walk(node):
            if (
                isinstance(comparison, ast.Compare)
                and sensitive(comparison.left)
                and comparison.comparators
            ):
                add_string_constants(comparison.comparators[0])

    if not ranges:
        raise PatchGenerationError("Unable to safely redact B105 context target")

    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def char_column(line_number: int, byte_column: int) -> int:
        return len(lines[line_number - 1].encode("utf-8")[:byte_column].decode("utf-8"))

    normalized = [
        (
            (start_line, char_column(start_line, start_col)),
            (end_line, char_column(end_line, end_col)),
        )
        for start_line, start_col, end_line, end_col in ranges
    ]
    replacements: list[tuple[int, int, str]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.STRING and (
                tokenize.tok_name.get(token.type) != "FSTRING_MIDDLE"
            ):
                continue
            if not any(
                start <= token.start and token.end <= end for start, end in normalized
            ):
                continue
            replacement = _redact_return_token(token)
            if replacement != token.string:
                replacements.append(
                    (
                        offsets[token.start[0] - 1] + token.start[1],
                        offsets[token.end[0] - 1] + token.end[1],
                        replacement,
                    )
                )
    except (tokenize.TokenError, IndentationError, UnicodeError):
        raise PatchGenerationError(
            "Unable to safely redact B105 context target"
        ) from None
    if not replacements:
        raise PatchGenerationError("Unable to safely redact B105 context target")
    for start, end, replacement in reversed(replacements):
        source = source[:start] + replacement + source[end:]
    return source


def _redact_literal(match: re.Match[str]) -> str:
    """Replace a captured string literal and preserve its syntax and newlines."""
    if REDACTION_MARKER in match.group("value"):
        return match.group()
    newlines = re.findall(r"\r\n|\r|\n", match.group("value"))
    return (
        f"{match.group('prefix')}{match.group('quote')}"
        f"{REDACTION_MARKER}{''.join(newlines)}{match.group('quote')}"
    )


def _redact_mapping_value(match: re.Match[str]) -> str:
    """Redact a literal value whose quoted mapping key is sensitive."""
    if not _is_sensitive_name(match.group("key")):
        return match.group()
    key_end = match.start("separator")
    return (
        f"{match.string[match.start() : key_end]}"
        f"{match.group('separator')}{_redact_literal(match)}"
    )


def _redact_subscript_value(match: re.Match[str]) -> str:
    """Redact a literal assigned through a sensitive subscript key."""
    if not _is_sensitive_name(match.group("key")):
        return match.group()
    return (
        f"{match.group('target')}[{match.group('key_quote')}{match.group('key')}"
        f"{match.group('key_quote')}]{match.group('separator')}{_redact_literal(match)}"
    )


def _redact_comparison_value(match: re.Match[str]) -> str:
    """Redact a literal compared against a sensitive identifier."""
    if not _is_sensitive_name(match.group("name")):
        return match.group()
    return f"{match.group('name')}{match.group('operator')}{_redact_literal(match)}"


def _redact_concatenation(match: re.Match[str]) -> str:
    """Redact every literal in a sensitive parenthesized concatenation."""
    if not _is_sensitive_name(match.group("name")):
        return match.group()
    parts = _STRING_LITERAL_RE.sub(_redact_literal, match.group("parts"))
    return f"{match.group('lhs')}{match.group('before')}{parts}{match.group('after')}"


def _redact_url_password(match: re.Match[str]) -> str:
    """Replace only the password between URL user and host."""
    if REDACTION_MARKER in match.group("password"):
        return match.group()
    return f"{match.group('prefix')}{REDACTION_MARKER}{match.group('suffix')}"


def _redact_sequence_pair(match: re.Match[str]) -> str:
    """Redact the value literal paired with a sensitive string key."""
    if not _is_sensitive_name(match.group("key")):
        return match.group()
    prefix = match.group(0)[: match.start("prefix") - match.start()]
    return f"{prefix}{_redact_literal(match)}"


def _token_contents_parse(match: re.Match[str], candidate: str) -> bool:
    """Report whether one string token still parses with candidate contents.

    OP-28. This is the only check needed to keep a replacement safe inside an
    f-string: the token's prefix and quotes are already in hand here, so the question
    is answered locally without a second tokenize pass over the file.
    """
    literal = (
        f"{match.group('prefix')}{match.group('quote')}"
        f"{candidate}{match.group('quote')}"
    )
    try:
        ast.parse(literal, mode="eval")
    except (SyntaxError, ValueError):
        return False
    return True


def _redact_embedded_literal(match: re.Match[str]) -> str:
    """Redact credential assignments and schemes inside literal text.

    OP-28. On a sensitive key inside a string literal, the credential's extent is the
    **token**, not a character class: everything from the separator to the end of the
    token's contents is replaced. A negated class can always be ended early by one of
    its own members, which is how a complete credential survived into the snippet sent
    to the model.

    This over-redacts by design — a connection string keeps `PWD=` and loses what
    follows it, and a `B608` query carrying a sensitive key loses the query. That cost
    was weighed against sending a working database password to a provider, and it is
    bounded: `CodeContext.snippet` goes only to the model, while
    `materialize_patch_source(...)` supplies the real source for anything written.
    """
    original = match.group("value")
    value = _INLINE_SCHEME_RE.sub(
        lambda item: f"{item.group('scheme')}{item.group('space')}{REDACTION_MARKER}",
        original,
    )
    hit = _INLINE_SENSITIVE_KEY_RE.search(value)
    if hit is not None and hit.end() < len(value):
        # Keep the line span: a truncated triple-quoted scope must still occupy the
        # same number of lines, or `snippet_line_start` plus the snippet's length no
        # longer describes the region it came from.
        removed = value[hit.end() :]
        # Keep a leading HTTP scheme word, as the previous inline replacement
        # did: the model needs to know a header is Bearer or Basic, and the
        # scheme is not the secret. What follows it is still cut to the token end.
        scheme = _LEADING_SCHEME_RE.match(removed)
        kept = f"{scheme.group(1)}{scheme.group(2)}" if scheme is not None else ""
        tail = kept + REDACTION_MARKER + "\n" * removed.count("\n")
        bounded = value[: hit.end()] + tail
        if _token_contents_parse(match, bounded):
            value = bounded
        else:
            # Cutting inside a replacement field or a format spec would leave its
            # braces unbalanced. Replacing the whole contents cannot: nothing of the
            # original structure is left to dangle.
            value = tail
    if value == original:
        return match.group()
    return f"{match.group('prefix')}{match.group('quote')}{value}{match.group('quote')}"


def redact(text: str) -> str:
    """Replace credential-shaped values in source text."""
    redacted = _PEM_RE.sub(_redact_pem, text)
    redacted = _MAPPING_RE.sub(_redact_mapping_value, redacted)
    redacted = _SUBSCRIPT_ASSIGNMENT_RE.sub(_redact_subscript_value, redacted)
    redacted = _COMPARISON_RE.sub(_redact_comparison_value, redacted)
    redacted = _CONCAT_ASSIGNMENT_RE.sub(_redact_concatenation, redacted)
    redacted = _ASSIGNMENT_RE.sub(_redact_assignment, redacted)
    redacted = _URL_CREDENTIAL_RE.sub(_redact_url_password, redacted)
    redacted = _SEQUENCE_PAIR_RE.sub(_redact_sequence_pair, redacted)
    redacted = _STRING_LITERAL_RE.sub(_redact_embedded_literal, redacted)
    for pattern in _SHAPE_PATTERNS:
        redacted = pattern.sub(REDACTION_MARKER, redacted)
    return redacted

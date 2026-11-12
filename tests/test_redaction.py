"""Tests for deterministic source-secret redaction."""

import base64
import secrets

import pytest

from omnipatch.codebase.redaction import REDACTION_MARKER, redact


@pytest.mark.parametrize(
    "secret",
    [
        "sk-0123456789abcdef",
        "sk-ant-SENTINEL_DO_NOT_LOG",
        "ghp_01234567890123456789",
        "ghp_SENTINEL_DO_NOT_LOG",
        "github_pat_0123456789abcdefghijklmn",
        "AKIA1234567890ABCDEF",
        "xoxb-1234567890-abcd",
    ],
)
def test_redact_credential_shapes(secret: str) -> None:
    """Known provider credential shapes are replaced anywhere in text."""
    assert secret not in redact(f"value = {secret}")


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('PASSWORD = "hunter2"', f'PASSWORD = "{REDACTION_MARKER}"'),
        ("api_key: str = 'secret-value'", f"api_key: str = '{REDACTION_MARKER}'"),
        ("self.private_key = 'private'", f"self.private_key = '{REDACTION_MARKER}'"),
        (
            'PASSWORD = f"secret {variable}"',
            f'PASSWORD = f"{REDACTION_MARKER}"',
        ),
        (
            'TOKEN = b"secret-bytes"',
            f'TOKEN = b"{REDACTION_MARKER}"',
        ),
    ],
)
def test_redact_sensitive_name_assignments(source: str, expected: str) -> None:
    """Sensitive assignment names redact literals and retain quote style."""
    assert redact(source) == expected


@pytest.mark.parametrize(
    "name",
    [
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
    ],
)
def test_redact_every_sensitive_name_fragment(name: str) -> None:
    """Every configured sensitive-name fragment is matched case-insensitively."""
    secret = "name-based-secret-value"
    result = redact(f"{name.upper()} = '{secret}'")
    assert secret not in result
    assert result == f"{name.upper()} = '{REDACTION_MARKER}'"


def test_redact_pem_preserves_line_count_and_is_idempotent() -> None:
    """PEM material is replaced line by line and repeated redaction is stable."""
    key_body = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    source = f'KEY = """{begin}\n{key_body}\n{end}\n"""'
    result = redact(source)
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" not in result
    assert result.count("\n") == source.count("\n")
    assert redact(result) == result


def test_redaction_preserves_line_count_and_is_idempotent() -> None:
    """Redacting tokens does not alter source line numbers."""
    source = "first sk-0123456789abcdef\nsecond line\n"
    result = redact(source)
    assert result.count("\n") == source.count("\n")
    assert redact(result) == result


def test_multiline_sensitive_assignment_preserves_line_count() -> None:
    """Triple-quoted sensitive values are redacted without shifting lines."""
    source = 'PRIVATE_KEY = """first-line\nsecond-line\nthird-line"""\n'
    result = redact(source)
    assert "first-line" not in result
    assert "second-line" not in result
    assert "third-line" not in result
    assert result.count("\n") == source.count("\n")
    assert redact(result) == result


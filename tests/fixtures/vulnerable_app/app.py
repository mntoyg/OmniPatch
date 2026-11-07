"""Small intentionally vulnerable application for scanner integration tests."""

import subprocess
from typing import Any

PASSWORD = "changeme-not-a-real-secret"


def load_user(cursor: Any, user_id: str) -> Any:
    """Load one user using an intentionally unsafe SQL query."""
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()


def run_command(command: str) -> int:
    """Run an intentionally unsafe shell command."""
    return subprocess.call(command, shell=True)

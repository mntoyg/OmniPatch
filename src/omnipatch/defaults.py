"""Shared configuration defaults without implementation dependencies."""

from typing import Literal

EXCLUDED_DIRS: tuple[str, ...] = (
    ".venv",
    ".git",
    "node_modules",
    "__pycache__",
    ".tox",
    "dist",
    "build",
)
DEFAULT_SCAN_TIMEOUT_SECONDS = 120
DEFAULT_SNAPSHOT_MAX_BYTES = 1024 * 1024 * 1024
DEFAULT_SNAPSHOT_MAX_FILE_BYTES = 128 * 1024 * 1024
DEFAULT_SNAPSHOT_MAX_ENTRIES = 100_000
DEFAULT_SNAPSHOT_MAX_METADATA_ENTRIES = 100_000
DEFAULT_SNAPSHOT_TIMEOUT_SECONDS = 120
DEFAULT_CONTEXT_MAX_LINES = 120
DEFAULT_MODULE_WINDOW_LINES = 21
DEFAULT_LLM_MODEL = "claude-opus-5-5"
DEFAULT_LLM_MAX_TOKENS = 16000
DEFAULT_LLM_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "high"
DEFAULT_LLM_TIMEOUT_SECONDS = 120
DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434/api/chat"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 300

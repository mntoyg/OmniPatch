import subprocess
import sys

SAMPLE_TEXT = "red green blue"
SEARCH_SCRIPT = f"import sys; print(sys.argv[1] in {SAMPLE_TEXT!r})"


def search_sample(pattern):
    """Search the same fixed sample text without invoking a shell."""
    return subprocess.run(
        [sys.executable, "-c", SEARCH_SCRIPT, pattern],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
    )

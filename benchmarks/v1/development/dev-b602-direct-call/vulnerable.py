import subprocess
import sys

SAMPLE_TEXT = "red green blue"
SEARCH_SCRIPT = f"import sys; print(sys.argv[1] in {SAMPLE_TEXT!r})"


def search_sample(pattern):
    """Search fixed sample text by constructing a shell command unsafely."""
    command = f'"{sys.executable}" -c "{SEARCH_SCRIPT}" "{pattern}"'
    return subprocess.run(
        command, shell=True, check=False, capture_output=True, text=True
    )

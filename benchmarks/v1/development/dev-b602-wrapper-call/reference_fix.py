import subprocess
import sys


def print_user_value(user_input):
    """Pass user data as one argv element without invoking a shell."""
    command = [
        sys.executable,
        "-c",
        "import sys; print(sys.argv[1])",
        user_input,
    ]
    return subprocess.run(
        command,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
    )

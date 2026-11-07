import subprocess


def print_user_value(user_input):
    """Build a shell command from user data (intentionally vulnerable)."""
    command = "printf " + user_input
    return subprocess.run(
        command, shell=True, check=False, capture_output=True, text=True
    )

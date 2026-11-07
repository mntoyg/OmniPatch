import os


def configured_password():
    """Return the password supplied by the runtime environment."""
    password = os.environ["APP_PASSWORD"]
    return password

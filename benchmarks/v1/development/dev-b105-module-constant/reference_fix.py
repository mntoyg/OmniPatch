import os

APP_PASSWORD = os.environ["APP_PASSWORD"]


def configured_password():
    """Return the password supplied by the runtime environment."""
    return APP_PASSWORD

"""A fixture used by the standards checker tests."""

# Imports
import os

# Constants
NAME = os.name


def one() -> int:
    value = 1
    # No blank line above this comment
    return value

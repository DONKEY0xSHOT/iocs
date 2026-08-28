"""A fixture used by the standards checker tests."""

# Imports
import os

# Constants
NAME = os.name


# This comment has a semicolon; which is banned
def one() -> int:
    return 1


# This comment has an em dash — which is banned too
def two() -> int:
    return 2

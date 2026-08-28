"""A fixture used by the standards checker tests."""

# Imports
import os

# Constants
LIMIT = 10


# Return the doubled value
def double(value: int) -> int:
    """Double an integer."""

    # Multiplication is clearer than addition here
    return value * 2


# Report whether the value is over the limit
def over_limit(value: int) -> bool:
    """Check a value against the module limit."""

    return value > LIMIT and os.name != ""

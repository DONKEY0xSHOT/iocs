"""Checks a commit message is short, plain ascii, and carries no indicator."""

# Imports
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.rules import IOC_PATTERNS, TRAILER

# Constants
MAX_LINES = 2
MAX_ASCII = 126


def problems(message: str) -> list[str]:
    """List everything wrong with a proposed commit message."""

    prose = [line for line in message.rstrip().splitlines() if not TRAILER.match(line)]
    found = []
    if len(prose) > MAX_LINES:
        found.append("over two lines")
    if any(ord(char) > MAX_ASCII for char in message):
        found.append("non ascii character")
    if any(pattern.search(message) for pattern in IOC_PATTERNS):
        found.append("looks like an indicator")
    return found


def main() -> int:
    """Read the message git is about to use and report on it."""

    found = problems(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    for item in found:
        print(f"commit message: {item}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())

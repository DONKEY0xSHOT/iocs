"""Draws one indicator as a small coloured table for the terminal."""

# Imports
import ctypes
import os
from typing import Any, TextIO

# Constants
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
STRONG_SCORE = 70
FAIR_SCORE = 40
WINDOWS_ANSI_MODE = 0x0004
STDOUT_HANDLE = -11


def supports_colour(stream: TextIO) -> bool:
    """Report whether colour would reach a person rather than a pipe or a file."""

    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", bool)())


def enable_windows_colour() -> None:
    """Switch on escape sequences, which windows consoles start with turned off."""

    # there is nothing to switch on outside a windows console
    if os.name != "nt":
        return
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return
    kernel = windll.kernel32
    handle = kernel.GetStdHandle(STDOUT_HANDLE)
    mode = ctypes.c_ulong()
    if kernel.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel.SetConsoleMode(handle, mode.value | WINDOWS_ANSI_MODE)


# Pick the colour that says how much weight to give a score
def _score_colour(score: int) -> str:
    if score >= STRONG_SCORE:
        return GREEN
    return YELLOW if score >= FAIR_SCORE else RED


# Turn one record into the label and value pairs the table shows, with a colour
# for each value. Padding is measured on the plain text, so codes never shift it.
def _rows(record: dict[str, Any], value: str) -> list[tuple[str, str, str]]:
    origins = [str(name) for name in record.get("origins", [])]
    first, last = str(record.get("first_seen")), str(record.get("last_seen"))
    score = int(record.get("score", 0))
    shareable = bool(record.get("redistributable"))
    return [
        ("value", value, BOLD),
        ("type", str(record.get("type")), CYAN),
        ("score", f"{score} of 100", _score_colour(score)),
        ("origins", f"{len(origins)}  {', '.join(origins)}", ""),
        ("seen", first if first == last else f"{first} to {last}", ""),
        ("shareable", "yes" if shareable else "no", GREEN if shareable else YELLOW),
    ]


# Pad a cell to the column width, then colour it, so the border stays aligned
def _cell(text: str, width: int, colour: str, wanted: bool) -> str:
    padded = text.ljust(width)
    return f"{colour}{padded}{RESET}" if colour and wanted else padded


def render_record(record: dict[str, Any], value: str, colour: bool) -> str:
    """Draw the table for one indicator, using the already defanged value."""

    rows = _rows(record, value)
    labels = max(len(label) for label, _, _ in rows)
    values = max(len(text) for _, text, _ in rows)
    rule = f"  +{'-' * (labels + 2)}+{'-' * (values + 2)}+"
    lines = [rule]
    for label, text, tint in rows:
        left = _cell(label, labels, DIM, colour)
        right = _cell(text, values, tint, colour)
        lines.append(f"  | {left} | {right} |")
    lines.append(rule)
    return "\n".join(lines)

"""Draws one indicator as a small coloured table for the terminal."""

# Imports
import ctypes
import os
from collections.abc import Mapping, Sequence
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
Cell = tuple[str, str]
BAR_WIDTH = 24


def is_terminal(stream: TextIO) -> bool:
    """Report whether this stream can redraw a line in place."""

    return bool(getattr(stream, "isatty", bool)())


def supports_colour(stream: TextIO) -> bool:
    """Report whether colour would reach a person rather than a pipe or a file."""

    if os.environ.get("NO_COLOR"):
        return False
    return is_terminal(stream)


def colour_ready(stream: TextIO) -> bool:
    """Report whether to tint, switching the console on when it is wanted."""

    wanted = supports_colour(stream)
    if wanted:
        enable_windows_colour()
    return wanted


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


# Draw one row of already measured cells between the table borders
def _line(cells: Sequence[Cell], widths: Sequence[int], colour: bool) -> str:
    drawn = (
        _cell(text, width, tint, colour) for (text, tint), width in zip(cells, widths, strict=True)
    )
    return "  | " + " | ".join(drawn) + " |"


def render_table(rows: Sequence[Sequence[Cell]], colour: bool, headers: Sequence[str] = ()) -> str:
    """Draw an aligned table, tinting cells only when colour is wanted."""

    measured = [*rows, [(text, "") for text in headers]] if headers else list(rows)
    widths = [max(len(row[index][0]) for row in measured) for index in range(len(measured[0]))]
    rule = "  +" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [rule]
    if headers:
        lines.append(_line([(text, DIM) for text in headers], widths, colour))
        lines.append(rule)
    lines.extend(_line(row, widths, colour) for row in rows)
    lines.append(rule)
    return "\n".join(lines)


def render_record(record: dict[str, Any], value: str, colour: bool) -> str:
    """Draw the table for one indicator, using the already defanged value."""

    rows = [[(label, DIM), (text, tint)] for label, text, tint in _rows(record, value)]
    return render_table(rows, colour)


def render_sources(entries: Sequence[tuple[str, str, bool]], colour: bool) -> str:
    """Draw every source, saying whether its data may be passed on."""

    rows = [
        [
            (name, ""),
            (licence, CYAN),
            ("yes", GREEN) if shareable else ("no", YELLOW),
        ]
        for name, licence, shareable in entries
    ]
    return render_table(rows, colour, headers=("source", "license", "shareable"))


def progress_bar(done: int, total: int, label: str, colour: bool) -> str:
    """Draw the one line that reports how far a collection has got."""

    filled = round(BAR_WIDTH * done / total) if total else BAR_WIDTH
    bar = f"{'#' * filled}{'-' * (BAR_WIDTH - filled)}"
    if colour:
        bar = f"{GREEN}{'#' * filled}{RESET}{DIM}{'-' * (BAR_WIDTH - filled)}{RESET}"
    return f"  [{bar}]  {done}/{total}  {label}"


class Progress:
    """Keeps one bar on a single line, rewriting it rather than scrolling."""

    def __init__(self, total: int, stream: TextIO, live: bool, colour: bool) -> None:
        self.total = total
        self.stream = stream
        self.live = live
        self.colour = colour
        self.done = 0
        self.width = 0

    # Overwrite whatever the last bar left behind, so a shorter line cannot
    # leave the tail of a longer one on screen
    def _wipe(self) -> None:
        self.stream.write("\r" + " " * self.width + "\r")

    def step(self, label: str, finished: bool) -> None:
        """Redraw the bar, counting one more source when it has finished."""

        if finished:
            self.done += 1
        if not self.live:
            return
        self._wipe()
        self.width = len(progress_bar(self.done, self.total, label, colour=False))
        self.stream.write(progress_bar(self.done, self.total, label, self.colour))
        self.stream.flush()

    def close(self, summary: str) -> None:
        """Clear the bar and leave one line saying how the run went."""

        if self.live:
            self._wipe()
        self.stream.write(f"[*] {summary}\n")
        self.stream.flush()


def run_summary(outcomes: Mapping[str, str], troubled_prefixes: Sequence[str]) -> str:
    """Say how a run went in one line, naming whatever needs a look."""

    troubled = sorted(
        name for name, outcome in outcomes.items() if outcome.startswith(tuple(troubled_prefixes))
    )
    line = f"{len(outcomes)} sources done, {len(outcomes) - len(troubled)} fetched"
    return line if not troubled else f"{line}, needs a look: {', '.join(troubled)}"

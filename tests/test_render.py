"""Tests for render."""

# Imports
import io
import pytest
from iocs.render import GREEN, RED, RESET, YELLOW, render_record, supports_colour

# Constants
RECORD = {
    "value": "45.155.205.233",
    "type": "ipv4",
    "first_seen": "2026-08-01",
    "last_seen": "2026-08-20",
    "origins": ["circl", "etopen"],
    "score": 74,
    "redistributable": False,
}
SHOWN = "45[.]155[.]205[.]233"


# A stream that claims to be a terminal, which is what turns colour on
class Terminal(io.StringIO):
    """Stands in for a console so colour decisions can be tested."""

    def isatty(self) -> bool:
        """Report that this stream is a terminal."""

        return True


# Verify a real terminal gets colour
def test_terminal_supports_colour() -> None:
    assert supports_colour(Terminal())


# Verify a pipe or a file does not, so redirected output stays plain
def test_plain_stream_gets_no_colour() -> None:
    assert not supports_colour(io.StringIO())


# Verify the standard opt out is honoured
def test_no_color_environment_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert not supports_colour(Terminal())


# Verify every field reaches the table
def test_table_shows_every_field() -> None:
    table = render_record(RECORD, SHOWN, colour=False)
    for expected in (SHOWN, "ipv4", "74 of 100", "circl", "etopen", "2026-08-01", "no"):
        assert expected in table


# Verify the value shown is the defanged one the caller passed, never the raw one
def test_table_uses_the_defanged_value() -> None:
    table = render_record(RECORD, SHOWN, colour=False)
    assert "45.155.205.233" not in table


# Verify a single day is written once rather than as a range
def test_one_day_is_not_shown_as_a_range() -> None:
    same = {**RECORD, "first_seen": "2026-08-20", "last_seen": "2026-08-20"}
    table = render_record(same, SHOWN, colour=False)
    assert "2026-08-20 to" not in table


# Verify plain output carries no escape sequences at all
def test_plain_table_has_no_escapes() -> None:
    assert "\033" not in render_record(RECORD, SHOWN, colour=False)


# Verify every row lines up, which is the thing colour codes most easily break
@pytest.mark.parametrize("colour", [False, True])
def test_borders_line_up(colour: bool) -> None:
    lines = render_record(RECORD, SHOWN, colour=colour).splitlines()
    widths = {len(_strip(line)) for line in lines}
    assert len(widths) == 1


# Remove escape sequences so a line can be measured as a person would see it
def _strip(line: str) -> str:
    for code in (RESET, GREEN, YELLOW, RED, "\033[2m", "\033[1m", "\033[36m"):
        line = line.replace(code, "")
    return line


# Verify a confident score reads as good and a weak one as poor
@pytest.mark.parametrize(
    ("score", "expected"),
    [(90, GREEN), (74, GREEN), (50, YELLOW), (10, RED)],
)
def test_score_colour_matches_confidence(score: int, expected: str) -> None:
    table = render_record({**RECORD, "score": score}, SHOWN, colour=True)
    assert f"{expected}{score} of 100" in table


# Verify shareability is obvious at a glance
def test_shareable_is_coloured() -> None:
    shareable = render_record({**RECORD, "redistributable": True}, SHOWN, colour=True)
    assert f"{GREEN}yes" in shareable
    assert f"{YELLOW}no" in render_record(RECORD, SHOWN, colour=True)

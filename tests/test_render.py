"""Tests for render."""

# Imports
import io
import pytest
from iocs.render import (
    BAR_WIDTH,
    GREEN,
    RED,
    RESET,
    YELLOW,
    Progress,
    progress_bar,
    render_record,
    run_summary,
    supports_colour,
)

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


# Verify the bar fills in proportion to the sources finished
@pytest.mark.parametrize(
    ("done", "total", "filled"), [(0, 10, 0), (5, 10, 12), (10, 10, 24), (0, 0, 24)]
)
def test_bar_fills_proportionally(done: int, total: int, filled: int) -> None:
    bar = progress_bar(done, total, "some_feed", colour=False)
    assert bar.count("#") == filled
    assert bar.count("#") + bar.count("-") == BAR_WIDTH


# Verify the bar names where it is and what it is working on
def test_bar_states_its_position() -> None:
    assert "9/24" in progress_bar(9, 24, "abusech_threatfox", colour=False)
    assert "abusech_threatfox" in progress_bar(9, 24, "abusech_threatfox", colour=False)


# Verify colour reaches the filled part without changing what the line says
def test_bar_colour_does_not_change_the_words() -> None:
    plain = progress_bar(5, 10, "feed", colour=False)
    tinted = progress_bar(5, 10, "feed", colour=True)
    assert GREEN in tinted
    assert _strip(tinted) == plain


# Verify a redirected stream gets no bar at all, only the closing line, which is
# what keeps piped output and ci logs readable
def test_progress_without_a_terminal_writes_one_line() -> None:
    buffer = io.StringIO()
    progress = Progress(2, buffer, live=False, colour=False)
    progress.step("alpha_feed", True)
    progress.step("beta_feed", True)
    progress.close("2 sources done, 2 fetched")
    assert buffer.getvalue() == "[*] 2 sources done, 2 fetched\n"


# Verify a terminal redraws one line rather than scrolling a bar per step
def test_progress_redraws_a_single_line() -> None:
    buffer = io.StringIO()
    progress = Progress(2, buffer, live=True, colour=False)
    progress.step("alpha_feed", True)
    progress.step("beta_feed", True)
    written = buffer.getvalue()
    assert "\n" not in written
    assert written.count("\r") >= 2


# Verify a step that has not finished still redraws, so a slow source keeps moving
def test_progress_moves_without_finishing_a_source() -> None:
    buffer = io.StringIO()
    progress = Progress(4, buffer, live=True, colour=False)
    progress.step("virusshare_md5 12/500", False)
    assert "0/4" in buffer.getvalue()
    assert "virusshare_md5 12/500" in buffer.getvalue()


# Verify a healthy run says so in one line
def test_summary_when_everything_worked() -> None:
    outcomes = {"alpha": "fetched", "beta": "not_modified"}
    assert run_summary(outcomes, ("failed", "empty")) == "2 sources done, 2 fetched"


# Verify anything needing attention is named, since no per source line reports it
def test_summary_names_what_needs_a_look() -> None:
    outcomes = {"alpha": "fetched", "beta": "failed: http 403", "gamma": "empty: nothing"}
    summary = run_summary(outcomes, ("failed", "empty"))
    assert "needs a look: beta, gamma" in summary

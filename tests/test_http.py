"""Tests for http."""

# Imports
import hashlib
import random
from datetime import UTC, datetime
import httpx
import pytest
from iocs.http import (
    BACKOFF_CAP_SECONDS,
    HOST_GAP_SECONDS,
    MAX_ATTEMPTS,
    MAX_BODY_BYTES,
    CacheEntry,
    Clock,
    Failed,
    Fetched,
    Fetcher,
    NotModified,
    ResponseKind,
    Skipped,
    Unchanged,
    UrlGuard,
    backoff_delay,
    build_conditional_headers,
    classify_status,
    fetch_once,
    parse_retry_after,
)
from iocs.version import USER_AGENT
from strategies import make_source

# Constants
FEED = "https://probe.example/list.txt"
BODY = b"45.155.205.233\n5.6.7.8\n"
GUARD = UrlGuard(frozenset({FEED}))
SOURCE = make_source("probe_feed", "probe")


class FakeClock(Clock):
    """A clock that records sleeps instead of performing them."""

    def __init__(self) -> None:
        self.seconds = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        """Report the current virtual time."""

        return self.seconds

    async def sleep(self, seconds: float) -> None:
        """Record a sleep and jump the virtual clock forward."""

        self.sleeps.append(seconds)
        self.seconds += seconds


class ScriptedClient(httpx.AsyncClient):
    """A client that replies from a scripted queue and logs what it sent."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.requests: list[httpx.Request] = []
        queue = list(responses)

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return queue.pop(0) if queue else httpx.Response(500)

        super().__init__(transport=httpx.MockTransport(handler))


# Build a fetcher whose transport replays a fixed list of responses
def fetcher_for(*replies: httpx.Response) -> tuple[Fetcher, FakeClock, ScriptedClient]:
    client = ScriptedClient(*replies)
    clock = FakeClock()
    guard = UrlGuard(frozenset({SOURCE.url}))
    return Fetcher(client, guard, clock=clock, rng=random.Random(1)), clock, client


# Verify the guard refuses everything that is not a declared feed
def test_guard_default_is_refusal() -> None:
    assert not UrlGuard(frozenset()).permits("https://evil.example/payload")


# Verify our own forge stays reachable so index sources keep working
def test_guard_permits_infrastructure() -> None:
    assert UrlGuard(frozenset()).permits("https://api.github.com/repos/x/y")


# Verify a known etag is sent alone, since if modified since would be ignored
def test_conditional_headers_prefer_etag() -> None:
    entry = CacheEntry(etag='"v1"', last_modified="Wed, 26 Aug 2026 10:00:00 GMT")
    assert build_conditional_headers(entry) == {"If-None-Match": '"v1"'}


# Verify the modification date is used only when no etag is known
def test_conditional_headers_fall_back_to_date() -> None:
    entry = CacheEntry(last_modified="Wed, 26 Aug 2026 10:00:00 GMT")
    assert build_conditional_headers(entry) == {"If-Modified-Since": entry.last_modified}


# Verify a status is sorted into retry, wait, or give up
@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (200, ResponseKind.SUCCESS),
        (304, ResponseKind.SUCCESS),
        (429, ResponseKind.RATE_LIMITED),
        (404, ResponseKind.FEED_BROKEN),
        (403, ResponseKind.FEED_BROKEN),
        (500, ResponseKind.SERVER_ERROR),
        (503, ResponseKind.SERVER_ERROR),
    ],
)
def test_status_classification(status: int, kind: ResponseKind) -> None:
    assert classify_status(status) is kind


# Verify a plain number of seconds is read straight from the header
def test_retry_after_seconds() -> None:
    now = datetime.now(tz=UTC)
    assert parse_retry_after("120", None, now) == 120.0


# Verify a date is measured against the server clock, not ours
def test_retry_after_date_uses_the_server_clock() -> None:
    sent = datetime(2026, 8, 26, 10, 0, 0, tzinfo=UTC)
    header = "Wed, 26 Aug 2026 10:02:00 GMT"
    assert parse_retry_after(header, sent, datetime.now(tz=UTC)) == 120.0


# Verify nonsense in the header is ignored rather than crashing the run
@pytest.mark.parametrize("header", [None, "", "soon", "12.5", "²"])
def test_retry_after_rejects_nonsense(header: str | None) -> None:
    assert parse_retry_after(header, None, datetime.now(tz=UTC)) is None


# Verify backoff never exceeds its cap however many attempts have failed
@pytest.mark.parametrize("attempt", range(8))
def test_backoff_stays_under_the_cap(attempt: int) -> None:
    delay = backoff_delay(attempt, random.Random(attempt))
    assert 0.0 <= delay <= BACKOFF_CAP_SECONDS


# Verify a first fetch returns the body and remembers the validators
async def test_first_fetch_returns_body() -> None:
    reply = httpx.Response(200, content=BODY, headers={"etag": '"v1"'})
    outcome = await fetch_once(ScriptedClient(reply), GUARD, FEED, CacheEntry())
    assert isinstance(outcome, Fetched)
    assert outcome.body == BODY
    assert outcome.entry.etag == '"v1"'


# Verify a 304 is reported without a body
async def test_not_modified() -> None:
    outcome = await fetch_once(ScriptedClient(httpx.Response(304)), GUARD, FEED, CacheEntry())
    assert isinstance(outcome, NotModified)


# Verify identical bytes are recognised even when the server sends them again
async def test_identical_body_is_unchanged() -> None:
    entry = CacheEntry(body_sha256=hashlib.sha256(BODY).hexdigest())
    client = ScriptedClient(httpx.Response(200, content=BODY))
    assert isinstance(await fetch_once(client, GUARD, FEED, entry), Unchanged)


# Verify every request says who we are
async def test_user_agent_identifies_project() -> None:
    client = ScriptedClient(httpx.Response(200, content=BODY))
    await fetch_once(client, GUARD, FEED, CacheEntry())
    assert client.requests[0].headers["user-agent"] == USER_AGENT


# Verify a url outside the allowlist is never requested
async def test_guard_blocks_unknown_url() -> None:
    client = ScriptedClient(httpx.Response(200, content=BODY))
    outcome = await fetch_once(client, GUARD, "https://evil.example/c2", CacheEntry())
    assert isinstance(outcome, Skipped)
    assert client.requests == []


# Verify an oversized body is refused rather than loaded
async def test_body_size_cap() -> None:
    huge = httpx.Response(200, content=b"a", headers={"content-length": str(MAX_BODY_BYTES + 1)})
    huge.headers["content-length"] = "1"
    client = ScriptedClient(huge)
    outcome = await fetch_once(client, GUARD, FEED, CacheEntry())
    assert isinstance(outcome, Fetched | Failed)


# Verify a redirect is never followed off the allowlist
async def test_redirect_off_the_allowlist_is_refused() -> None:
    moved = httpx.Response(302, headers={"location": "https://evil.example/c2"})
    outcome = await fetch_once(ScriptedClient(moved), GUARD, FEED, CacheEntry())
    assert isinstance(outcome, Skipped)


# Verify a transient server error is retried and can then succeed
async def test_server_error_is_retried() -> None:
    fetcher, clock, _ = fetcher_for(httpx.Response(500), httpx.Response(200, content=BODY))
    assert isinstance(await fetcher(SOURCE, CacheEntry()), Fetched)
    assert clock.sleeps


# Verify a source that is gone is abandoned at once rather than retried
async def test_broken_feed_is_not_retried() -> None:
    fetcher, _, client = fetcher_for(httpx.Response(404))
    outcome = await fetcher(SOURCE, CacheEntry())
    assert isinstance(outcome, Failed)
    assert outcome.kind is ResponseKind.FEED_BROKEN
    assert len(client.requests) == 1


# Verify we give up after the attempt limit rather than hammering a sick server
async def test_attempts_are_bounded() -> None:
    fetcher, _, client = fetcher_for(*[httpx.Response(500)] * (MAX_ATTEMPTS + 2))
    assert isinstance(await fetcher(SOURCE, CacheEntry()), Failed)
    assert len(client.requests) == MAX_ATTEMPTS


# Verify a server asking us to wait is obeyed exactly
async def test_retry_after_is_obeyed() -> None:
    limited = httpx.Response(429, headers={"retry-after": "30"})
    fetcher, clock, _ = fetcher_for(limited, httpx.Response(200, content=BODY))
    assert isinstance(await fetcher(SOURCE, CacheEntry()), Fetched)
    assert 30.0 in clock.sleeps


# Verify an unreasonable wait makes us give up instead of sleeping for hours
async def test_absurd_wait_is_refused() -> None:
    limited = httpx.Response(429, headers={"retry-after": "99999"})
    fetcher, clock, client = fetcher_for(limited, httpx.Response(200, content=BODY))
    assert isinstance(await fetcher(SOURCE, CacheEntry()), Failed)
    assert clock.sleeps == []
    assert len(client.requests) == 1


# Verify two requests to one host are spaced out rather than sent together
async def test_requests_to_one_host_are_spaced() -> None:
    fetcher, clock, _ = fetcher_for(
        httpx.Response(200, content=BODY), httpx.Response(200, content=b"other\n")
    )
    await fetcher(SOURCE, CacheEntry())
    await fetcher(SOURCE, CacheEntry())
    assert HOST_GAP_SECONDS in clock.sleeps


# Verify a different host does not have to wait behind the first
async def test_other_hosts_do_not_queue() -> None:
    fetcher, clock, _ = fetcher_for(
        httpx.Response(200, content=BODY), httpx.Response(200, content=b"other\n")
    )
    await fetcher(SOURCE, CacheEntry())
    await fetcher(make_source("second", "other"), CacheEntry())
    assert clock.sleeps == []

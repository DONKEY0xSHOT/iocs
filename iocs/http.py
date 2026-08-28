"""One guarded, polite http request, and the loop that retries it."""

# Imports
import asyncio
import hashlib
import random
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from urllib.parse import urlsplit
import httpx
from iocs.sources import Source
from iocs.version import USER_AGENT

# Constants
MAX_BODY_BYTES = 512 * 1024 * 1024
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
HOST_GAP_SECONDS = 1.0
MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 2.0
BACKOFF_CAP_SECONDS = 60.0
MAX_WAIT_SECONDS = 300.0
MAX_REDIRECTS = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RATE_LIMIT_STATUSES = frozenset({429})
BROKEN_FEED_STATUSES = frozenset({401, 403, 404, 410})
SUCCESS_STATUSES = frozenset({200, 203, 206, 304})
DELAY_SECONDS = re.compile(r"\A-?[0-9]+\Z")
INFRA_HOSTS = frozenset(
    {
        "api.github.com",
        "uploads.github.com",
        "objects.githubusercontent.com",
        "codeload.github.com",
    }
)


class ResponseKind(StrEnum):
    """What one http status means for whether to try again."""

    SUCCESS = "success"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    FEED_BROKEN = "feed_broken"


@dataclass(frozen=True)
class CacheEntry:
    """Validators remembered from the last fetch of one url."""

    etag: str | None = None
    last_modified: str | None = None
    body_sha256: str | None = None


@dataclass(frozen=True)
class Fetched:
    """New content arrived and should be parsed."""

    body: bytes
    entry: CacheEntry


@dataclass(frozen=True)
class NotModified:
    """The server confirmed the cached copy is still current."""


@dataclass(frozen=True)
class Unchanged:
    """New bytes arrived but they are identical to the cached copy."""


@dataclass(frozen=True)
class Skipped:
    """We decided not to send this request at all."""

    reason: str


@dataclass(frozen=True)
class Failed:
    """The request completed unsuccessfully."""

    kind: ResponseKind
    detail: str
    retry_after: float | None = None


Outcome = Fetched | NotModified | Unchanged | Skipped | Failed


class Clock:
    """The real clock. Tests subclass this to control time instead."""

    def now(self) -> float:
        """Report seconds on a clock that only moves forward."""

        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        """Pause for the given number of seconds."""

        await asyncio.sleep(seconds)


class UrlGuard:
    """Allows only the feed urls we listed, plus our own github."""

    def __init__(self, allowed: frozenset[str], prefixes: frozenset[str] = frozenset()) -> None:
        self.allowed = allowed
        self.prefixes = prefixes

    def permits(self, url: str) -> bool:
        """Report whether this exact url may be requested."""

        if url in self.allowed or any(url.startswith(prefix) for prefix in self.prefixes):
            return True
        return (urlsplit(url).hostname or "") in INFRA_HOSTS


def classify_status(status: int) -> ResponseKind:
    """Say whether a status means success, wait, retry later, or give up."""

    if status in SUCCESS_STATUSES:
        return ResponseKind.SUCCESS
    if status in RATE_LIMIT_STATUSES:
        return ResponseKind.RATE_LIMITED
    if status in BROKEN_FEED_STATUSES:
        return ResponseKind.FEED_BROKEN
    return ResponseKind.SERVER_ERROR


def parse_retry_after(header: str | None, sent: datetime | None, now: datetime) -> float | None:
    """Read a retry after header, which is either seconds or an http date."""

    if not header:
        return None
    text = header.strip()
    if DELAY_SECONDS.match(text):
        return max(0.0, float(text))
    try:
        target = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    return max(0.0, (target - (sent or now)).total_seconds())


def backoff_delay(attempt: int, rng: random.Random) -> float:
    """Wait a random time up to an exponential cap, so retries do not sync up."""

    return rng.uniform(0.0, min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * (2.0**attempt)))


def build_conditional_headers(entry: CacheEntry) -> dict[str, str]:
    """Build revalidation headers, preferring the etag as the standard requires."""

    if entry.etag:
        return {"If-None-Match": entry.etag}
    if entry.last_modified:
        return {"If-Modified-Since": entry.last_modified}
    return {}


def build_client() -> httpx.AsyncClient:
    """Create the single project client with verification and timeouts fixed on."""

    timeout = httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=10.0, pool=5.0)
    return httpx.AsyncClient(
        verify=True,
        follow_redirects=False,
        http2=False,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    )


# Turn a successful response into either fresh content or an unchanged marker
def _content_outcome(response: httpx.Response, entry: CacheEntry) -> Outcome:
    body = response.content
    if len(body) > MAX_BODY_BYTES:
        return Failed(ResponseKind.SERVER_ERROR, "response body too large")
    digest = hashlib.sha256(body).hexdigest()
    if entry.body_sha256 and digest == entry.body_sha256:
        return Unchanged()
    fresh = CacheEntry(
        etag=response.headers.get("etag"),
        last_modified=response.headers.get("last-modified"),
        body_sha256=digest,
    )
    return Fetched(body, fresh)


# Decide what one completed response means for this source
def _classify(response: httpx.Response, entry: CacheEntry) -> Outcome:
    if response.status_code in REDIRECT_STATUSES:
        moved = str(response.headers.get("location", ""))
        return Skipped(f"redirect not followed: {moved}")
    if response.status_code == httpx.codes.NOT_MODIFIED:
        return NotModified()
    kind = classify_status(response.status_code)
    if kind is not ResponseKind.SUCCESS:
        sent = _server_time(response.headers.get("date"))
        wait = parse_retry_after(response.headers.get("retry-after"), sent, datetime.now(tz=UTC))
        return Failed(kind, f"http {response.status_code}", wait)
    return _content_outcome(response, entry)


# Read the server clock from its date header, so skew cannot mislead us
def _server_time(header: str | None) -> datetime | None:
    if not header:
        return None
    try:
        return parsedate_to_datetime(header)
    except (TypeError, ValueError):
        return None


async def fetch_once(
    client: httpx.AsyncClient, guard: UrlGuard, url: str, entry: CacheEntry
) -> Outcome:
    """Perform one guarded conditional request and classify the result."""

    target = url
    for _ in range(MAX_REDIRECTS):
        if not guard.permits(target):
            return Skipped(f"url is not on the egress allowlist: {target}")
        headers = {"User-Agent": USER_AGENT, **build_conditional_headers(entry)}
        try:
            response = await client.get(target, headers=headers)
        except httpx.HTTPError as error:
            return Failed(ResponseKind.SERVER_ERROR, f"transport error: {type(error).__name__}")
        if response.status_code not in REDIRECT_STATUSES:
            return _classify(response, entry)

        # a redirect is only followed to somewhere the guard already allows
        moved = str(response.headers.get("location", ""))
        if not moved or not guard.permits(moved):
            return Skipped(f"redirect not followed: {moved}")
        target = moved
    return Skipped(f"too many redirects starting at {url}")


class Fetcher:
    """Fetches feeds, leaving a gap between requests to the same host."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        guard: UrlGuard,
        clock: Clock | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.client = client
        self.guard = guard
        self.clock = clock or Clock()
        self.rng = rng or random.Random()  # noqa: S311
        self.last_request: dict[str, float] = {}

    # Space requests to one host apart, so a run never arrives as a burst
    async def _wait_turn(self, host: str) -> None:
        previous = self.last_request.get(host)
        if previous is not None:
            gap = HOST_GAP_SECONDS - (self.clock.now() - previous)
            if gap > 0:
                await self.clock.sleep(gap)
        self.last_request[host] = self.clock.now()

    # Report whether to try again, waiting as long as the server asked us to
    async def _pause(self, outcome: Failed, attempt: int) -> bool:
        if outcome.kind is ResponseKind.FEED_BROKEN:
            return False
        wait = outcome.retry_after
        if wait is not None and wait > MAX_WAIT_SECONDS:
            return False
        await self.clock.sleep(wait if wait is not None else backoff_delay(attempt, self.rng))
        return True

    async def __call__(self, source: Source, entry: CacheEntry) -> Outcome:
        """Fetch one source, retrying transient failures and pacing every request."""

        last: Outcome = Skipped("no attempt was made")
        for attempt in range(MAX_ATTEMPTS):
            await self._wait_turn(source.host)
            last = await fetch_once(self.client, self.guard, source.url, entry)
            if not isinstance(last, Failed) or not await self._pause(last, attempt):
                return last
        return last

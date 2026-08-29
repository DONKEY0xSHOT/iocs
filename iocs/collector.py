"""The collection run, from fetching each source to the written corpus."""

# Imports
import dataclasses
import datetime
import json
import pathlib
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Sequence
from iocs.allowlist import Allowlist, apply_layers, load_warninglist_archive
from iocs.corpus import Stats, build, write_sorted_chunks
from iocs.http import (
    CacheEntry,
    Fetched,
    Fetcher,
    NotModified,
    Outcome,
    Unchanged,
    load_cache,
    save_cache,
)
from iocs.indicators import Canonical, IocType, Observation, Record, classify, encode
from iocs.parsers import ParserOptions, parse
from iocs.sources import Source, traits_by_origin
from iocs.version import VERSION

# Constants
WORK_DIR = "work"
EXCLUDED_NAME = "excluded.json"
REPORT_NAME = "sources.json"
MERGING_NOTE = "merging and scoring, this is the slow part"
Typed = tuple[IocType, Observation]
Report = Callable[[str, bool], None]


# Ignore progress, which is what a test or a piped run wants
def _silent(*_: object) -> None:
    return


def today() -> str:
    """Report the current date, which is the resolution the corpus stores."""

    return datetime.datetime.now(tz=datetime.UTC).date().isoformat()


# Say what a source did, and why, since a bare skipped tells nobody anything
def _outcome_detail(outcome: Outcome) -> str:
    name = type(outcome).__name__.lower().replace("notmodified", "not_modified")
    reason = getattr(outcome, "reason", None) or getattr(outcome, "detail", None)
    return f"{name}: {reason}" if reason else name


# Fetch one url, sending what we cached last time and saving what comes back
async def _fetch(source: Source, fetcher: Fetcher, cache: dict[str, CacheEntry]) -> Outcome:
    outcome = await fetcher(source, cache.get(source.url, CacheEntry()))
    if isinstance(outcome, Fetched):
        cache[source.url] = outcome.entry
    return outcome


# Some publishers post a tiny revision file, so we can tell nothing changed cheaply
async def _sentinel_unchanged(
    source: Source, fetcher: Fetcher, cache: dict[str, CacheEntry]
) -> bool:
    if not source.sentinel_url:
        return False
    probe = dataclasses.replace(source, url=source.sentinel_url)
    return isinstance(await _fetch(probe, fetcher, cache), NotModified | Unchanged)


# Collect the settings a parser needs from the source declaration
def _options_for(source: Source) -> ParserOptions:
    return ParserOptions(
        follow_suffixes=source.follow_suffixes,
        csv_columns=source.csv_columns,
        csv_skip_rows=source.csv_skip_rows,
        archive=source.archive,
    )


# Turn one feed body into observations of the types the source declares
def _observations(source: Source, body: bytes, today: str) -> Iterator[Typed]:
    for raw in parse(source.parser, body, _options_for(source)):
        result = classify(raw)
        if isinstance(result, Canonical) and result.type in source.produces:
            yield result.type, Observation(result.value, source.origin, today, source.credibility)


# Fetch each document an index source points at, capped so one feed cannot run
# away. One batch is yielded per document, so a large feed is never held whole.
async def _follow(
    source: Source,
    body: bytes,
    fetcher: Fetcher,
    today: str,
    cache: dict[str, CacheEntry],
    report: Report,
) -> AsyncIterator[Iterator[Typed]]:
    if not source.follow_template or not source.follow_parser:
        yield _observations(source, body, today)
        return
    items = list(parse(source.parser, body, _options_for(source)))[: source.follow_limit]
    reader = dataclasses.replace(source, parser=source.follow_parser, archive="")
    for index, item in enumerate(items, start=1):
        report(f"{source.name} {index}/{len(items)}", False)
        target = source.follow_template.format(item=item)
        outcome = await _fetch(dataclasses.replace(source, url=target), fetcher, cache)
        if isinstance(outcome, Fetched):
            yield _observations(reader, outcome.body, today)


# Group fresh observations into one staged chunk file per indicator type
def _stage(observations: Iterable[Typed], work: pathlib.Path) -> int:
    lines: dict[IocType, list[str]] = {}
    staged = 0
    for kind, item in observations:
        lines.setdefault(kind, []).append(encode(Record.from_observation(item)))
        staged += 1
    for kind, batch in lines.items():
        write_sorted_chunks(iter(batch), work / kind.value)
    return staged


# Build the allowlist from any source that supplies exclusions rather than indicators
async def _load_allowlist(
    sources: Sequence[Source],
    fetcher: Fetcher,
    outcomes: dict[str, str],
    report: Report,
) -> Allowlist:
    built = Allowlist()
    for source in sources:
        # exclusions are needed in full every run, so a 304 would leave us with
        # no layers at all and silently drop the filtering
        outcome = await fetcher(source, CacheEntry())
        outcomes[source.name] = _outcome_detail(outcome)
        if isinstance(outcome, Fetched):
            built = apply_layers(built, load_warninglist_archive(outcome.body))
        report(source.name, True)
    return built


async def collect(
    sources: Sequence[Source],
    out: pathlib.Path,
    state: pathlib.Path,
    fetcher: Fetcher,
    today: str,
    report: Report = _silent,
) -> tuple[list[Stats], dict[str, str]]:
    """Run one full collection, from fetch through to the written corpus."""

    work = out / WORK_DIR
    outcomes: dict[str, str] = {}
    cache = load_cache(state)

    # a source producing no indicators is here to supply exclusions instead
    allowlist = await _load_allowlist(
        [item for item in sources if not item.produces], fetcher, outcomes, report
    )
    for source in (item for item in sources if item.produces):
        report(source.name, False)
        if await _sentinel_unchanged(source, fetcher, cache):
            outcomes[source.name] = "not_modified"
            report(source.name, True)
            continue
        outcome = await _fetch(source, fetcher, cache)
        outcomes[source.name] = _outcome_detail(outcome)
        if not isinstance(outcome, Fetched):
            report(source.name, True)
            continue
        produced = 0
        async for found in _follow(source, outcome.body, fetcher, today, cache, report):
            produced += _stage(found, work)

        # a feed that answers but parses to nothing is how a format change looks,
        # and a 200 on its own would let that pass as a healthy run
        if not produced:
            outcomes[source.name] = "empty: fetched but produced no indicators"
        report(source.name, True)
    save_cache(state, cache)

    # the merge is the long tail of a big run, so keep the bar saying so
    report(MERGING_NOTE, False)
    stats, excluded = build(out, state, work, today, allowlist, traits_by_origin())
    (out / EXCLUDED_NAME).write_text(json.dumps(excluded, indent=2), encoding="utf-8")
    (out / REPORT_NAME).write_text(
        json.dumps({"tool": VERSION, "sources": outcomes}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return stats, outcomes

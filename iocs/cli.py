"""The commands people type, and the collection run behind them."""

# Imports
import argparse
import asyncio
import dataclasses
import datetime
import json
import pathlib
import sys
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from typing import Any
from iocs.allowlist import Allowlist, apply_layers, load_warninglist_archive
from iocs.corpus import OUTPUT_NAME, Stats, build, lookup, write_sorted_chunks
from iocs.http import (
    CacheEntry,
    Fetched,
    Fetcher,
    NotModified,
    Outcome,
    Unchanged,
    UrlGuard,
    build_client,
    load_cache,
    save_cache,
)
from iocs.indicators import Canonical, IocType, Observation, Record, classify, defang, encode
from iocs.parsers import ParserOptions, parse
from iocs.render import (
    Progress,
    enable_windows_colour,
    is_terminal,
    render_record,
    render_sources,
    run_summary,
    supports_colour,
)
from iocs.sources import REGISTRY, LicenseClass, Source, follow_prefixes, traits_by_origin
from iocs.version import VERSION

# Constants
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PARTIAL = 3
DEFAULT_OUT = "out"
DEFAULT_STATE = "state"
WORK_DIR = "work"
EXCLUDED_NAME = "excluded.json"
REPORT_NAME = "sources.json"
MERGING_NOTE = "merging and scoring, this is the slow part"
EXIT_PARTIAL_PREFIXES = ("failed", "skipped", "empty")
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
def _observations(source: Source, body: bytes, today: str) -> list[Typed]:
    kept: list[Typed] = []
    for raw in parse(source.parser, body, _options_for(source)):
        result = classify(raw)
        if isinstance(result, Canonical) and result.type in source.produces:
            seen = Observation(result.value, source.origin, today, source.credibility)
            kept.append((result.type, seen))
    return kept


# Fetch each document an index source points at, capped so one feed cannot run
# away. One batch is yielded per document, so a large feed is never held whole.
async def _follow(
    source: Source,
    body: bytes,
    fetcher: Fetcher,
    today: str,
    cache: dict[str, CacheEntry],
    report: Report,
) -> AsyncIterator[list[Typed]]:
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
def _stage(observations: Iterable[Typed], work: pathlib.Path) -> None:
    lines: dict[IocType, list[str]] = {}
    for kind, item in observations:
        lines.setdefault(kind, []).append(encode(Record.from_observation(item)))
    for kind, batch in lines.items():
        write_sorted_chunks(iter(batch), work / kind.value)


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
            produced += len(found)
            _stage(found, work)

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


def select_sources(names: str) -> tuple[Source, ...]:
    """Pick the named feeds, or every source when nothing is named."""

    if not names:
        return REGISTRY
    wanted = set(names.split(","))

    # a source producing nothing supplies exclusions, and every run refilters the
    # whole stored corpus, so dropping one would let old false positives back in
    return tuple(item for item in REGISTRY if item.name in wanted or not item.produces)


async def run_collect(args: argparse.Namespace) -> int:
    """Run a full collection and report what happened to each kind of indicator."""

    sources = select_sources(args.sources)
    guard = UrlGuard(frozenset(source.url for source in sources), follow_prefixes(sources))
    colour = supports_colour(sys.stdout)
    if colour:
        enable_windows_colour()
    progress = Progress(len(sources), sys.stdout, is_terminal(sys.stdout), colour)
    async with build_client() as client:
        fetcher = Fetcher(client, guard)
        stats, outcomes = await collect(
            sources,
            pathlib.Path(args.out),
            pathlib.Path(args.state),
            fetcher,
            today(),
            progress.step,
        )
    progress.close(run_summary(outcomes, EXIT_PARTIAL_PREFIXES))
    for item in stats:
        print(f"    {item.kind.value:8} {item.total:>12,}   confirmed {item.confirmed:>9,}")
    print()
    failed = sum(1 for text in outcomes.values() if text.startswith(EXIT_PARTIAL_PREFIXES))
    return EXIT_PARTIAL if failed else EXIT_OK


def run_sources() -> int:
    """List every source, its license, and whether its data may be passed on."""

    colour = supports_colour(sys.stdout)
    if colour:
        enable_windows_colour()
    entries = [
        (source.name, source.license_id, source.license_class is LicenseClass.PERMISSIVE)
        for source in sorted(REGISTRY, key=lambda item: item.name)
    ]
    print()
    print(render_sources(entries, colour))
    print()
    return EXIT_OK


def show_record(record: dict[str, Any]) -> None:
    """Print what we know about one indicator, defanged so it cannot be clicked."""

    colour = supports_colour(sys.stdout)
    if colour:
        enable_windows_colour()
    print()
    print(render_record(record, defang(str(record["value"])), colour))
    print()


def run_lookup(args: argparse.Namespace) -> int:
    """Answer one offline lookup from the collected corpus."""

    parsed = classify(args.value)
    if not isinstance(parsed, Canonical):
        print(f"not a recognised indicator: {defang(args.value)}", file=sys.stderr)
        return EXIT_USAGE
    store = pathlib.Path(args.data) / OUTPUT_NAME
    if not store.exists():
        print(f"no corpus at {store}", file=sys.stderr)
        print("run: python -m iocs collect", file=sys.stderr)
        return EXIT_USAGE
    record = lookup(store, parsed.value)
    if record is None:
        print(f"not found: {defang(parsed.value)}")
        return EXIT_OK
    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
        return EXIT_OK
    show_record(record)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Describe every command the tool accepts."""

    parser = argparse.ArgumentParser(prog="iocs", description="Collect public malware indicators.")
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    gather = commands.add_parser("collect", help="fetch every accepted source and write the corpus")
    gather.add_argument("--out", default=DEFAULT_OUT)
    gather.add_argument("--state", default=DEFAULT_STATE)
    gather.add_argument("--sources", default="")
    commands.add_parser("sources", help="show every source and its terms")
    find = commands.add_parser("lookup", help="answer offline from the collected corpus")
    find.add_argument("value")
    find.add_argument("--data", default=DEFAULT_OUT)
    find.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and dispatch to the requested command."""

    args = build_parser().parse_args(argv)
    if args.command == "collect":
        return asyncio.run(run_collect(args))
    if args.command == "sources":
        return run_sources()
    return run_lookup(args)


if __name__ == "__main__":
    sys.exit(main())

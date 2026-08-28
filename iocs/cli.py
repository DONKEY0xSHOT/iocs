"""The commands people type, and the collection run behind them."""

# Imports
import argparse
import asyncio
import dataclasses
import datetime
import json
import pathlib
import sys
from collections.abc import AsyncIterator, Iterable, Sequence
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
)
from iocs.indicators import Canonical, IocType, Observation, Record, classify, defang, encode
from iocs.parsers import ParserOptions, parse
from iocs.sources import REGISTRY, LicenseClass, Source, follow_prefixes, traits_by_origin
from iocs.version import VERSION

# Constants
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PARTIAL = 3
DEFAULT_OUT = "out"
DEFAULT_STATE = "state"
WORK_DIR = "work"
CACHE_NAME = "http_cache.json"
EXCLUDED_NAME = "excluded.json"
REPORT_NAME = "sources.json"
EXIT_PARTIAL_PREFIXES = ("failed", "skipped", "empty")
Typed = tuple[IocType, Observation]


def today() -> str:
    """Report the current date, which is the resolution the corpus stores."""

    return datetime.datetime.now(tz=datetime.UTC).date().isoformat()


# Say what a source did, and why, since a bare skipped tells nobody anything
def _outcome_detail(outcome: Outcome) -> str:
    name = type(outcome).__name__.lower().replace("notmodified", "not_modified")
    reason = getattr(outcome, "reason", None) or getattr(outcome, "detail", None)
    return f"{name}: {reason}" if reason else name


# Remember the validators each url returned so the next run can revalidate cheaply
def _load_cache(state: pathlib.Path) -> dict[str, CacheEntry]:
    target = state / CACHE_NAME
    if not target.exists():
        return {}
    try:
        stored = json.loads(target.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    return {url: CacheEntry(**fields) for url, fields in stored.items()}


# Write the validator cache back in a form a person can read
def _save_cache(state: pathlib.Path, cache: dict[str, CacheEntry]) -> None:
    state.mkdir(parents=True, exist_ok=True)
    payload = {url: dataclasses.asdict(entry) for url, entry in sorted(cache.items())}
    (state / CACHE_NAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")


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
    source: Source, body: bytes, fetcher: Fetcher, today: str, cache: dict[str, CacheEntry]
) -> AsyncIterator[list[Typed]]:
    if not source.follow_template or not source.follow_parser:
        yield _observations(source, body, today)
        return
    items = list(parse(source.parser, body, _options_for(source)))[: source.follow_limit]
    reader = dataclasses.replace(source, parser=source.follow_parser, archive="")
    for item in items:
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
    sources: Sequence[Source], fetcher: Fetcher, outcomes: dict[str, str]
) -> Allowlist:
    built = Allowlist()
    for source in sources:
        # exclusions are needed in full every run, so a 304 would leave us with
        # no layers at all and silently drop the filtering
        outcome = await fetcher(source, CacheEntry())
        outcomes[source.name] = _outcome_detail(outcome)
        if isinstance(outcome, Fetched):
            built = apply_layers(built, load_warninglist_archive(outcome.body))
    return built


async def collect(
    sources: Sequence[Source], out: pathlib.Path, state: pathlib.Path, fetcher: Fetcher, today: str
) -> tuple[list[Stats], dict[str, str]]:
    """Run one full collection, from fetch through to the written corpus."""

    work = out / WORK_DIR
    outcomes: dict[str, str] = {}
    cache = _load_cache(state)

    # a source producing no indicators is here to supply exclusions instead
    allowlist = await _load_allowlist(
        [item for item in sources if not item.produces], fetcher, outcomes
    )
    for source in (item for item in sources if item.produces):
        if await _sentinel_unchanged(source, fetcher, cache):
            outcomes[source.name] = "not_modified"
            continue
        outcome = await _fetch(source, fetcher, cache)
        outcomes[source.name] = _outcome_detail(outcome)
        if not isinstance(outcome, Fetched):
            continue
        produced = 0
        async for found in _follow(source, outcome.body, fetcher, today, cache):
            produced += len(found)
            _stage(found, work)

        # a feed that answers but parses to nothing is how a format change looks,
        # and a 200 on its own would let that pass as a healthy run
        if not produced:
            outcomes[source.name] = "empty: fetched but produced no indicators"
    _save_cache(state, cache)
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
    async with build_client() as client:
        fetcher = Fetcher(client, guard)
        stats, outcomes = await collect(
            sources, pathlib.Path(args.out), pathlib.Path(args.state), fetcher, today()
        )
    for item in stats:
        print(f"{item.kind.value:7} total={item.total:<10} confirmed={item.confirmed}")
    failed = sum(1 for text in outcomes.values() if text.startswith(EXIT_PARTIAL_PREFIXES))
    return EXIT_PARTIAL if failed else EXIT_OK


def run_sources() -> int:
    """List every source, its license, and whether its data may be passed on."""

    for source in REGISTRY:
        shareable = (
            "may be shared" if source.license_class is LicenseClass.PERMISSIVE else "local use only"
        )
        print(f"{source.name:28} {source.license_id:16} {shareable:15} {source.license_url}")
    return EXIT_OK


def show_record(record: dict[str, Any]) -> None:
    """Print what we know about one indicator, defanged so it cannot be clicked."""

    origins = [str(name) for name in record.get("origins", [])]
    first, last = str(record.get("first_seen")), str(record.get("last_seen"))
    rows = (
        ("type", str(record.get("type"))),
        ("score", f"{record.get('score')} of 100"),
        ("origins", f"{len(origins)}  ({', '.join(origins)})"),
        ("seen", first if first == last else f"{first} to {last}"),
        ("shareable", "yes" if record.get("redistributable") else "no"),
    )
    print(f"\n  {defang(str(record['value']))}\n")
    for label, value in rows:
        print(f"  {label:<10} {value}")
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

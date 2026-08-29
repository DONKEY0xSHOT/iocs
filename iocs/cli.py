"""The commands people type."""

# Imports
import argparse
import asyncio
import json
import pathlib
import sys
from collections.abc import Sequence
from typing import Any
from iocs.collector import collect, today
from iocs.corpus import OUTPUT_NAME, lookup
from iocs.http import Fetcher, UrlGuard, build_client
from iocs.indicators import Canonical, classify, defang
from iocs.render import (
    Progress,
    colour_ready,
    is_terminal,
    render_record,
    render_sources,
    run_summary,
)
from iocs.sources import REGISTRY, LicenseClass, Source, follow_prefixes
from iocs.version import VERSION

# Constants
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PARTIAL = 3
DEFAULT_OUT = "out"
DEFAULT_STATE = "state"
EXIT_PARTIAL_PREFIXES = ("failed", "skipped", "empty")


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
    colour = colour_ready(sys.stdout)
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

    colour = colour_ready(sys.stdout)
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

    colour = colour_ready(sys.stdout)
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

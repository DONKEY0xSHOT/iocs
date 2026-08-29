"""Tests for cli."""

# Imports
import dataclasses
import datetime
import json
import pathlib
import random
from collections.abc import Callable
import httpx
import pytest
from test_http import FakeClock
from iocs.cli import (
    EXIT_OK,
    EXIT_PARTIAL_PREFIXES,
    EXIT_USAGE,
    build_parser,
    collect,
    main,
    select_sources,
    today,
)
from iocs.http import Fetcher, UrlGuard
from iocs.indicators import IocType
from iocs.sources import REGISTRY, Source, follow_prefixes
from strategies import RECORD, make_source

# Constants
TODAY = "2026-08-28"
Handler = Callable[[httpx.Request], httpx.Response]
VALUE = str(RECORD["value"])


# Write a small corpus for the lookup tests
def seed_corpus(root: pathlib.Path) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "iocs.jsonl").write_text(json.dumps(RECORD) + "\n", encoding="utf-8", newline="\n")
    return root


# Wrap a request handler in a fetcher that paces against a fake clock
def _fetcher(handler: Handler, sources: list[Source]) -> Fetcher:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    guard = UrlGuard(frozenset(item.url for item in sources), follow_prefixes(sources))
    return Fetcher(client, guard, clock=FakeClock(), rng=random.Random(1))


# Build a fetcher that answers each url from a fixed table of bodies
def fetcher_for(bodies: dict[str, bytes], sources: list[Source]) -> Fetcher:
    def handler(request: httpx.Request) -> httpx.Response:
        body = bodies.get(str(request.url))
        return httpx.Response(200, content=body) if body is not None else httpx.Response(404)

    return _fetcher(handler, sources)


# Read the corpus one collection produced
def corpus_lines(out: pathlib.Path) -> list[dict[str, object]]:
    text = (out / "iocs.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


# Verify the parser exposes every documented command
@pytest.mark.parametrize("command", ["collect", "lookup", "sources"])
def test_commands_exist(command: str) -> None:
    assert command in build_parser().format_help()


# Verify a missing command is a usage error rather than a crash
def test_missing_command_is_usage_error() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main([])
    assert exit_info.value.code == EXIT_USAGE


# Verify the run stamps records with a real calendar date
def test_today_is_a_date() -> None:
    assert datetime.date.fromisoformat(today()) == datetime.datetime.now(tz=datetime.UTC).date()


# Verify a stored indicator is found and shown defanged
def test_lookup_reports_a_hit(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = seed_corpus(tmp_path / "out")
    code = main(["lookup", VALUE, "--data", str(data)])
    output = capsys.readouterr().out
    assert code == EXIT_OK
    assert "45[.]155[.]205[.]233" in output
    assert VALUE not in output


# Verify the origin count is shown so a reader can judge confidence themselves
def test_lookup_shows_the_origins(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = seed_corpus(tmp_path / "out")
    main(["lookup", VALUE, "--data", str(data)])
    output = capsys.readouterr().out
    assert "circl, etopen" in output
    assert "origins" in output


# Verify the json surface stays undefanged and hands back the whole record
def test_lookup_json_is_raw(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = seed_corpus(tmp_path / "out")
    main(["lookup", VALUE, "--data", str(data), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["value"] == VALUE
    assert payload["origins"] == ["circl", "etopen"]


# Verify an absent indicator reports cleanly rather than failing
def test_lookup_reports_a_miss(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = seed_corpus(tmp_path / "out")
    assert main(["lookup", "203.0.113.7", "--data", str(data)]) == EXIT_OK
    assert "not found" in capsys.readouterr().out


# Verify a value that is not an indicator is rejected
def test_lookup_rejects_nonsense(tmp_path: pathlib.Path) -> None:
    assert main(["lookup", "not an ioc", "--data", str(tmp_path)]) == EXIT_USAGE


# Verify the source listing names every source, its license and where to read it
def test_sources_command_lists_feeds(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["sources"]) == EXIT_OK
    output = capsys.readouterr().out
    assert all(source.name in output for source in REGISTRY)
    for heading in ("source", "license", "shareable"):
        assert heading in output


# Verify the listing says which sources may be passed on and which may not
def test_sources_command_marks_shareability(capsys: pytest.CaptureFixture[str]) -> None:
    main(["sources"])
    rows = [line for line in capsys.readouterr().out.splitlines() if line.startswith("  |")]
    cells = [[part.strip() for part in row.split("|")[1:-1]] for row in rows]
    assert {row[-1] for row in cells[1:]} == {"yes", "no"}


# Verify the listing reads alphabetically, so a source is easy to find by eye
def test_sources_command_is_sorted(capsys: pytest.CaptureFixture[str]) -> None:
    main(["sources"])
    rows = [line for line in capsys.readouterr().out.splitlines() if line.startswith("  | ")]
    names = [line.split("|")[1].strip() for line in rows][1:]
    assert names == sorted(names)


# Verify one collection turns a feed into the written corpus
async def test_collect_writes_the_corpus(tmp_path: pathlib.Path) -> None:
    source = make_source("alpha_feed", "alpha")
    fetcher = fetcher_for({source.url: b"45.155.205.233\n5.6.7.8\n"}, [source])
    stats, outcomes = await collect([source], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    assert outcomes["alpha_feed"] == "fetched"
    assert len(corpus_lines(tmp_path / "out")) == 2
    assert next(item for item in stats if item.kind is IocType.IPV4).total == 2


# Verify two feeds agreeing on a value produce one confirmed record
async def test_collect_merges_two_origins(tmp_path: pathlib.Path) -> None:
    first = make_source("alpha_feed", "alpha")
    second = make_source("beta_feed", "beta")
    bodies = {first.url: b"45.155.205.233\n", second.url: b"45.155.205.233\n"}
    fetcher = fetcher_for(bodies, [first, second])
    stats, _ = await collect([first, second], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    record = corpus_lines(tmp_path / "out")[0]
    assert record["origins"] == ["alpha", "beta"]
    assert next(item for item in stats if item.kind is IocType.IPV4).confirmed == 1


# Verify a value the source did not declare is not collected from it
async def test_collect_drops_undeclared_types(tmp_path: pathlib.Path) -> None:
    source = make_source("alpha_feed", "alpha", IocType.IPV4)
    fetcher = fetcher_for({source.url: b"45.155.205.233\nevil.example\n"}, [source])
    await collect([source], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    lines = corpus_lines(tmp_path / "out")
    assert len(lines) == 1
    assert lines[0]["type"] == "ipv4"


# Verify an index source fetches each document it points at, and only those
async def test_collect_follows_an_index(tmp_path: pathlib.Path) -> None:
    source = dataclasses.replace(
        make_source("index_feed", "alpha"),
        url="https://alpha.example/index.json",
        parser="github_tree",
        follow_parser="plaintext",
        follow_template="https://alpha.example/blob/{item}",
        follow_suffixes=(".txt",),
    )
    index = b'{"tree":[{"type":"blob","path":"one.txt"},{"type":"blob","path":"skip.md"}]}'
    bodies = {
        source.url: index,
        "https://alpha.example/blob/one.txt": b"45.155.205.233\n",
        "https://alpha.example/blob/skip.md": b"5.6.7.8\n",
    }
    fetcher = fetcher_for(bodies, [source])
    await collect([source], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    lines = corpus_lines(tmp_path / "out")
    assert len(lines) == 1
    assert lines[0]["value"] == "45.155.205.233"


# Verify every run records what each source did, so nothing fails silently
async def test_collect_reports_a_failure(tmp_path: pathlib.Path) -> None:
    source = make_source("gone_feed", "alpha")
    fetcher = fetcher_for({}, [source])
    _, outcomes = await collect([source], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    assert outcomes["gone_feed"].startswith("failed")
    report = json.loads((tmp_path / "out" / "sources.json").read_text(encoding="utf-8"))
    assert "gone_feed" in report["sources"]


# Verify naming one feed collects only that feed
def test_select_sources_filters_feeds() -> None:
    chosen = {source.name for source in select_sources("certpl_phishing")}
    assert "certpl_phishing" in chosen
    assert "ipsum_level3" not in chosen


# Verify an exclusion provider survives the filter. It is infrastructure, not a
# feed, and every run refilters the whole stored corpus with it.
def test_select_sources_keeps_the_allowlist() -> None:
    chosen = {source.name for source in select_sources("certpl_phishing")}
    assert "misp_warninglists" in chosen


# Verify naming nothing selects every source
def test_select_sources_defaults_to_everything() -> None:
    assert len(select_sources("")) == len(REGISTRY)


# Build a fetcher whose server answers 304 to any conditional request
def revalidating_fetcher(bodies: dict[str, bytes], sources: list[Source]) -> Fetcher:
    def handler(request: httpx.Request) -> httpx.Response:
        if "if-none-match" in request.headers:
            return httpx.Response(304)
        body = bodies.get(str(request.url))
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body, headers={"etag": '"v1"'})

    return _fetcher(handler, sources)


# Verify an exclusion source is read in full on every run. A 304 would leave the
# run with no layers at all, silently dropping every false positive filter.
async def test_collect_never_revalidates_exclusions(tmp_path: pathlib.Path) -> None:
    feed = make_source("alpha_feed", "alpha")
    exclusions = dataclasses.replace(
        make_source("exclusions", "misp"), produces=(), parser="warninglist_archive"
    )
    sources = [exclusions, feed]
    bodies = {feed.url: b"45.155.205.233\n", exclusions.url: b"archive-bytes"}
    out, state = tmp_path / "out", tmp_path / "state"
    await collect(sources, out, state, revalidating_fetcher(bodies, sources), TODAY)
    _, outcomes = await collect(sources, out, state, revalidating_fetcher(bodies, sources), TODAY)
    assert outcomes["exclusions"] == "fetched"


# Verify an ordinary feed still revalidates, which is what keeps a rerun cheap
async def test_collect_revalidates_feeds(tmp_path: pathlib.Path) -> None:
    feed = make_source("alpha_feed", "alpha")
    bodies = {feed.url: b"45.155.205.233\n"}
    out, state = tmp_path / "out", tmp_path / "state"
    await collect([feed], out, state, revalidating_fetcher(bodies, [feed]), TODAY)
    _, outcomes = await collect([feed], out, state, revalidating_fetcher(bodies, [feed]), TODAY)
    assert outcomes["alpha_feed"] == "not_modified"


# Verify a feed that still answers but no longer parses is reported, not passed
# over. This is how a publisher changing format shows up, and a 200 alone hides it.
async def test_collect_flags_a_feed_that_yields_nothing(tmp_path: pathlib.Path) -> None:
    source = make_source("alpha_feed", "alpha")
    fetcher = fetcher_for({source.url: b"<html><body>Moved</body></html>"}, [source])
    _, outcomes = await collect([source], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    assert outcomes["alpha_feed"].startswith("empty")


# Verify a feed that does parse is not flagged
async def test_collect_does_not_flag_a_working_feed(tmp_path: pathlib.Path) -> None:
    source = make_source("alpha_feed", "alpha")
    fetcher = fetcher_for({source.url: b"45.155.205.233\n"}, [source])
    _, outcomes = await collect([source], tmp_path / "out", tmp_path / "state", fetcher, TODAY)
    assert outcomes["alpha_feed"] == "fetched"


# Verify an empty feed makes the run report a partial result rather than success
def test_empty_feed_is_a_partial_run() -> None:
    assert "empty" in EXIT_PARTIAL_PREFIXES


# Verify a missing corpus is reported as such, not as a miss. Saying "not found"
# when nothing has been collected sends the reader looking for the wrong problem.
def test_lookup_without_a_corpus_says_so(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["lookup", "evil.example", "--data", str(tmp_path / "empty")])
    captured = capsys.readouterr()
    assert code == EXIT_USAGE
    assert "no corpus" in captured.err
    assert "collect" in captured.err


# Verify a real miss against a real corpus still reads as a miss
def test_lookup_miss_is_distinct_from_a_missing_corpus(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data = seed_corpus(tmp_path / "out")
    code = main(["lookup", "203.0.113.7", "--data", str(data)])
    assert code == EXIT_OK
    assert "not found" in capsys.readouterr().out

"""Tests for corpus."""

# Imports
import datetime
import json
import pathlib
import pytest
from hypothesis import given
from hypothesis import strategies as st
from iocs.allowlist import Allowlist, RangeSet
from iocs.corpus import (
    LIFETIMES,
    Stats,
    base_score,
    build,
    decay_score,
    lookup,
    merge_duplicate_lines,
    merge_sorted_chunks,
    score_record,
    write_sorted_chunks,
)
from iocs.indicators import IocType, Record, Sighting, encode
from iocs.sources import LicenseClass, Reliability

# Constants
TODAY = "2026-08-28"
WHEN = datetime.date.fromisoformat(TODAY)
PERMISSIVE = (Reliability.B, LicenseClass.PERMISSIVE)
RESTRICTED = (Reliability.B, LicenseClass.RESTRICTED)
TRAITS = {"alpha": PERMISSIVE, "beta": PERMISSIVE, "vendor": RESTRICTED}


# Build a record seen by the named origins on the given day
def make_record(value: str, origins: list[str], day: str = TODAY) -> Record:
    seen = tuple(Sighting(name, day, day, 2, 1) for name in origins)
    return Record(value, day, day, seen)


# Stage records of one type so the merge has something to join
def stage(work: pathlib.Path, kind: IocType, records: list[Record]) -> None:
    write_sorted_chunks(iter([encode(item) for item in records]), work / kind.value)


# Verify sorted chunks merge back into one ordered stream
def test_chunks_merge_in_order(tmp_path: pathlib.Path) -> None:
    chunks = write_sorted_chunks(iter(["c", "a", "b"]), tmp_path, limit=2)
    assert sorted(line for line in merge_sorted_chunks(chunks)) == ["a", "b", "c"]


# Verify a second batch adds to a work directory rather than replacing the first,
# which is what lets one run stage each source as it arrives
def test_chunks_from_a_second_call_are_kept(tmp_path: pathlib.Path) -> None:
    write_sorted_chunks(iter(["b", "a"]), tmp_path, limit=1)
    write_sorted_chunks(iter(["d", "c"]), tmp_path, limit=1)
    chunks = sorted(tmp_path.glob("*"))
    assert len(chunks) == 4
    assert sorted(line.strip() for line in merge_sorted_chunks(chunks)) == ["a", "b", "c", "d"]


# Verify two sightings of one value become a single record
def test_duplicate_lines_merge_into_one_record() -> None:
    lines = [
        encode(make_record("a.example", ["alpha"])),
        encode(make_record("a.example", ["beta"])),
    ]
    merged = list(merge_duplicate_lines(sorted(lines)))
    assert len(merged) == 1
    assert {seen.origin for seen in merged[0].sightings} == {"alpha", "beta"}


# Verify an address loses confidence with age and a hash never does
def test_decay_applies_only_to_types_with_a_lifetime() -> None:
    assert decay_score(80.0, 15, LIFETIMES[IocType.IPV4]) < 80.0
    assert decay_score(80.0, 9999, LIFETIMES[IocType.MD5]) == 80.0


# Verify an indicator past its lifetime scores nothing at all
def test_decay_reaches_zero_at_the_lifetime() -> None:
    assert decay_score(80.0, 30, 30) == 0.0


# Verify decay never leaves the range it started in, at any age
@given(
    base=st.floats(min_value=0.0, max_value=100.0),
    age=st.integers(min_value=0, max_value=5000),
    lifetime=st.integers(min_value=1, max_value=365),
)
def test_decay_stays_within_bounds(base: float, age: int, lifetime: int) -> None:
    assert 0.0 <= decay_score(base, age, lifetime) <= base


# Verify a better rated source starts an indicator higher than a worse one
def test_reliability_orders_the_starting_score() -> None:
    assert base_score(Reliability.A, 2) > base_score(Reliability.E, 2)


# Verify an unrated source is treated as neutral rather than worthless
def test_unrated_sources_are_neutral() -> None:
    assert base_score(Reliability.F, 2) > base_score(Reliability.E, 2)


# Verify a score never leaves the range a reader can rely on
@given(
    reliability=st.sampled_from(list(Reliability)),
    credibility=st.integers(min_value=1, max_value=6),
)
def test_base_score_stays_within_bounds(reliability: Reliability, credibility: int) -> None:
    assert 0.0 <= base_score(reliability, credibility) <= 100.0


# Verify a second independent origin raises confidence
def test_confirmation_raises_the_score() -> None:
    alone = score_record(make_record("a.example", ["alpha"]), IocType.DOMAIN, WHEN, TRAITS)
    both = score_record(make_record("a.example", ["alpha", "beta"]), IocType.DOMAIN, WHEN, TRAITS)
    assert both > alone


# Verify a score never exceeds one hundred however many origins agree
def test_score_is_capped() -> None:
    many = make_record("a.example", [f"origin{index}" for index in range(20)])
    assert score_record(many, IocType.DOMAIN, WHEN, TRAITS) <= 100


# Verify the corpus is written as one sorted file covering every type
def test_build_writes_one_sorted_file(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.DOMAIN, [make_record("b.example", ["alpha"])])
    stage(work, IocType.MD5, [make_record("0" * 32, ["beta"])])
    stats, excluded = build(out, state, work, TODAY, Allowlist(), TRAITS)
    lines = (out / "iocs.jsonl").read_text(encoding="utf-8").splitlines()
    values = [json.loads(line)["value"] for line in lines]
    assert values == sorted(values)
    assert {json.loads(line)["type"] for line in lines} == {"domain", "md5"}
    assert excluded == []
    assert sum(item.total for item in stats) == 2


# Verify a value both origins report is counted as confirmed
def test_build_counts_confirmation(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.DOMAIN, [make_record("a.example", ["alpha"])])
    stage(work, IocType.DOMAIN, [make_record("a.example", ["beta"])])
    stats, _ = build(out, state, work, TODAY, Allowlist(), TRAITS)
    found = next(item for item in stats if item.kind is IocType.DOMAIN)
    assert found.total == 1
    assert found.confirmed == 1


# Verify one restricted origin is enough to mark an indicator unshareable
def test_build_marks_restricted_records(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.DOMAIN, [make_record("a.example", ["alpha", "vendor"])])
    build(out, state, work, TODAY, Allowlist(), TRAITS)
    record = json.loads((out / "iocs.jsonl").read_text(encoding="utf-8"))
    assert record["redistributable"] is False


# Verify an indicator seen only through permissive sources may be shared
def test_build_marks_permissive_records(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.DOMAIN, [make_record("a.example", ["alpha", "beta"])])
    build(out, state, work, TODAY, Allowlist(), TRAITS)
    record = json.loads((out / "iocs.jsonl").read_text(encoding="utf-8"))
    assert record["redistributable"] is True
    assert record["origins"] == ["alpha", "beta"]


# Verify an added layer holds a value back and records which layer did it
def test_build_excludes_allowlisted_values(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.IPV4, [make_record("45.155.205.233", ["alpha"])])
    allowlist = Allowlist(ranges={"vendor cdn": RangeSet(["45.155.205.0/24"])})
    stats, excluded = build(out, state, work, TODAY, allowlist, TRAITS)
    assert (out / "iocs.jsonl").read_text(encoding="utf-8") == ""
    assert excluded[0]["value"] == "45.155.205.233"
    assert excluded[0]["layer"] == "vendor cdn"
    assert stats == []


# Verify the built in layers hold back a well known resolver with no setup
def test_build_excludes_known_infrastructure(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.IPV4, [make_record("8.8.8.8", ["alpha"])])
    _, excluded = build(out, state, work, TODAY, Allowlist(), TRAITS)
    assert excluded[0]["layer"] == "public_resolver"


# Verify a second run merges into what the first run stored
def test_build_merges_with_previous_state(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.DOMAIN, [make_record("a.example", ["alpha"])])
    build(out, state, work, TODAY, Allowlist(), TRAITS)
    later = tmp_path / "work2"
    stage(later, IocType.DOMAIN, [make_record("a.example", ["beta"])])
    build(out, state, later, TODAY, Allowlist(), TRAITS)
    record = json.loads((out / "iocs.jsonl").read_text(encoding="utf-8"))
    assert record["origins"] == ["alpha", "beta"]


# Verify a stored indicator is found by value
def test_lookup_finds_a_record(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "iocs.jsonl"
    target.write_text('{"value":"a.example"}\n{"value":"b.example"}\n', encoding="utf-8")
    found = lookup(target, "b.example")
    assert found is not None
    assert found["value"] == "b.example"


# Verify an absent indicator reports nothing rather than failing
def test_lookup_misses_cleanly(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "iocs.jsonl"
    target.write_text('{"value":"a.example"}\n{"value":"z.example"}\n', encoding="utf-8")
    assert lookup(target, "m.example") is None
    assert lookup(tmp_path / "absent.jsonl", "a.example") is None


# Verify a corrupt line is stepped over rather than crashing the lookup
def test_lookup_survives_a_bad_line(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "iocs.jsonl"
    target.write_text('{not json\n{"value":"a.example"}\n', encoding="utf-8")
    assert lookup(target, "a.example") is not None


# Verify the stats record carries the type it counts
def test_stats_name_their_type() -> None:
    assert Stats(IocType.DOMAIN).kind is IocType.DOMAIN


# Build a sorted corpus file the way build() writes one
def write_corpus(path: pathlib.Path, values: list[str]) -> pathlib.Path:
    target = path / "iocs.jsonl"
    body = "".join(
        json.dumps({"value": value, "type": "domain"}, separators=(",", ":")) + "\n"
        for value in sorted(values)
    )
    target.write_text(body, encoding="utf-8", newline="\n")
    return target


# Verify every stored value is found, whatever its position in the file
def test_lookup_finds_every_value(tmp_path: pathlib.Path) -> None:
    values = [f"{index:06d}.example" for index in range(500)]
    target = write_corpus(tmp_path, values)
    for value in values:
        found = lookup(target, value)
        assert found is not None, value
        assert found["value"] == value


# Verify a value that is not stored is reported missing wherever it would sort
@pytest.mark.parametrize("absent", ["000000a.example", "aaa.example", "zzz.example", ""])
def test_lookup_misses_absent_values(tmp_path: pathlib.Path, absent: str) -> None:
    target = write_corpus(tmp_path, [f"{index:06d}.example" for index in range(200)])
    assert lookup(target, absent) is None


# Verify lookup agrees with a plain scan on any sorted corpus, which is the
# property a binary search is easy to get subtly wrong on
@given(
    values=st.lists(st.text(alphabet="abc0123456789.", min_size=1, max_size=8), unique=True),
    wanted=st.text(alphabet="abc0123456789.", min_size=0, max_size=8),
)
def test_lookup_matches_a_linear_scan(
    tmp_path_factory: pytest.TempPathFactory, values: list[str], wanted: str
) -> None:
    target = write_corpus(tmp_path_factory.mktemp("corpus"), values)
    expected = wanted if wanted in values else None
    found = lookup(target, wanted)
    assert (found["value"] if found else None) == expected


# Verify a one line corpus works, since a binary search can skip the only line
def test_lookup_on_a_single_record(tmp_path: pathlib.Path) -> None:
    target = write_corpus(tmp_path, ["only.example"])
    assert lookup(target, "only.example") is not None
    assert lookup(target, "other.example") is None


# Verify an empty corpus is a miss rather than a crash
def test_lookup_on_an_empty_corpus(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "iocs.jsonl"
    target.write_text("", encoding="utf-8")
    assert lookup(target, "anything.example") is None


# Verify the corpus is renamed into place, so a lookup during a collection reads
# the last complete file instead of a half written one
def test_build_leaves_no_temporary_file(tmp_path: pathlib.Path) -> None:
    work, state, out = tmp_path / "work", tmp_path / "state", tmp_path / "out"
    stage(work, IocType.DOMAIN, [make_record("a.example", ["alpha"])])
    build(out, state, work, TODAY, Allowlist(), TRAITS)
    assert (out / "iocs.jsonl").exists()
    assert list(out.glob("*.new")) == []

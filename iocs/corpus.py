"""Keeps the collected records on disk, sorted, in files too large for memory."""

# Imports
import datetime
import heapq
import itertools
import json
import math
import pathlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import BinaryIO
from iocs.allowlist import Allowlist
from iocs.indicators import IocType, Record, decode, encode, merge_records
from iocs.sources import LicenseClass, Reliability

# Constants
CHUNK_RECORD_LIMIT = 1_000_000
CHUNK_SUFFIX = ".run"
STATE_SUFFIX = ".tsv"
OUTPUT_NAME = "iocs.jsonl"
MAX_PROBE_LINES = 64
ENCODING = "utf-8"
REFERENCE_BASE = 80.0
DECAY_SPEED = 2.0
CONFIRMED_ORIGINS = 2
CONFIRMATION_BONUS = 5.0
NEUTRAL_WEIGHT = 0.55
LIFETIMES = {
    IocType.IPV4: 30,
    IocType.IPV6: 30,
    IocType.DOMAIN: 90,
    IocType.URL: 60,
    IocType.MD5: None,
    IocType.SHA1: None,
    IocType.SHA256: None,
}
RELIABILITY_WEIGHT = {
    Reliability.A: 1.00,
    Reliability.B: 0.90,
    Reliability.C: 0.75,
    Reliability.D: 0.55,
    Reliability.E: 0.30,
    Reliability.F: NEUTRAL_WEIGHT,
}
CREDIBILITY_WEIGHT = {1: 1.00, 2: 0.90, 3: 0.75, 4: 0.55, 5: 0.30, 6: NEUTRAL_WEIGHT}
Traits = Mapping[str, tuple[Reliability, LicenseClass]]


@dataclass
class Stats:
    """How many indicators of one type we hold, and how many are confirmed."""

    kind: IocType
    total: int = 0
    confirmed: int = 0
    excluded: int = 0


# Read the value field that every record line starts with
def _key(line: str) -> str:
    return line.split("\t", 1)[0]


# These three functions are one algorithm used in this order. The corpus is too
# big to sort in memory, so we sort it in pieces and then merge the pieces.
def write_sorted_chunks(
    lines: Iterator[str], workdir: pathlib.Path, limit: int = CHUNK_RECORD_LIMIT
) -> list[pathlib.Path]:
    """Sort lines in bounded batches, writing each batch to its own file."""

    workdir.mkdir(parents=True, exist_ok=True)
    chunks: list[pathlib.Path] = []

    # keep any chunks already staged, so each source can be written as it arrives
    written = len(list(workdir.glob(f"*{CHUNK_SUFFIX}")))
    while True:
        # islice takes the next batch from the same iterator each time round
        batch = sorted(itertools.islice(lines, limit), key=_key)
        if not batch:
            break
        chunk = workdir / f"{written + len(chunks):06d}{CHUNK_SUFFIX}"
        chunk.write_text("\n".join(batch) + "\n", encoding=ENCODING)
        chunks.append(chunk)
    return chunks


def merge_sorted_chunks(chunks: Iterable[pathlib.Path]) -> Iterator[str]:
    """Merge the sorted chunk files into one ordered stream."""

    handles = [path.open(encoding=ENCODING) for path in chunks]
    try:
        streams = ((line.rstrip("\n") for line in handle) for handle in handles)
        yield from heapq.merge(*streams, key=_key)
    finally:
        for handle in handles:
            handle.close()


def merge_duplicate_lines(lines: Iterable[str]) -> Iterator[Record]:
    """Join every group of lines about the same value into one record."""

    # groupby only gathers neighbours, so the lines must already be sorted
    for _, group in itertools.groupby(lines, key=_key):
        yield merge_records(decode(line) for line in group)


def decay_score(base: float, age_days: int, lifetime: int | None) -> float:
    """Apply the misp polynomial decay, leaving types without a lifetime untouched."""

    if lifetime is None:
        return base
    if age_days >= lifetime:
        return 0.0
    return base * (1.0 - math.pow(float(age_days) / float(lifetime), 1.0 / DECAY_SPEED))


def base_score(reliability: Reliability, credibility: int) -> float:
    """Combine source reliability and claim credibility into a starting score."""

    trust = RELIABILITY_WEIGHT[reliability] / RELIABILITY_WEIGHT[Reliability.B]
    belief = CREDIBILITY_WEIGHT.get(credibility, NEUTRAL_WEIGHT) / CREDIBILITY_WEIGHT[2]
    return min(100.0, max(0.0, REFERENCE_BASE * trust * belief))


def score_record(record: Record, kind: IocType, today: datetime.date, traits: Traits) -> int:
    """Score one indicator from its freshest sighting, with a confirmation bonus."""

    lifetime = LIFETIMES[kind]
    best = 0.0
    for seen in record.sightings:
        reliability = traits.get(seen.origin, (Reliability.F, LicenseClass.UNKNOWN))[0]
        start = base_score(reliability, seen.credibility)
        age = (today - datetime.date.fromisoformat(seen.last_seen)).days
        best = max(best, decay_score(start, max(0, age), lifetime))
    if best <= 0.0:
        return 0
    bonus = CONFIRMATION_BONUS * (len(record.sightings) - 1)
    return round(min(100.0, best + bonus))


# An indicator may be shared onward only when every origin behind it permits it
def _redistributable(record: Record, traits: Traits) -> bool:
    return all(
        traits.get(seen.origin, (Reliability.F, LicenseClass.UNKNOWN))[1] is LicenseClass.PERMISSIVE
        for seen in record.sightings
    )


# Rebuild one type's corpus, writing its state file back as the records stream past
def _restream(
    state: pathlib.Path, work: pathlib.Path, kind: IocType
) -> Iterator[tuple[IocType, Record]]:
    staged = work / kind.value
    chunks = sorted(staged.glob(f"*{CHUNK_SUFFIX}")) if staged.exists() else []
    previous = state / f"{kind.value}{STATE_SUFFIX}"
    if previous.exists():
        chunks = [previous, *chunks]
    if not chunks:
        return
    state.mkdir(parents=True, exist_ok=True)
    fresh = state / f"{kind.value}{STATE_SUFFIX}.new"
    with fresh.open("w", encoding=ENCODING, newline="\n") as handle:
        for record in merge_duplicate_lines(merge_sorted_chunks(chunks)):
            handle.write(f"{encode(record)}\n")
            yield kind, record
    fresh.replace(previous)


# Describe one indicator fully enough that a reader can apply their own threshold
def as_json(kind: IocType, record: Record, score: int, shareable: bool) -> str:
    """Render one indicator as the compact json line the corpus file holds."""

    return json.dumps(
        {
            "value": record.value,
            "type": kind.value,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "origins": sorted(seen.origin for seen in record.sightings),
            "score": score,
            "redistributable": shareable,
        },
        separators=(",", ":"),
    )


def build(
    out: pathlib.Path,
    state: pathlib.Path,
    work: pathlib.Path,
    today: str,
    allowlist: Allowlist,
    traits: Traits,
) -> tuple[list[Stats], list[dict[str, str]]]:
    """Merge, score and write the whole corpus in one pass over sorted streams."""

    out.mkdir(parents=True, exist_ok=True)
    when = datetime.date.fromisoformat(today)
    counts = {kind: Stats(kind) for kind in IocType}
    excluded: list[dict[str, str]] = []

    # every type is already sorted, so merging them gives one ordered stream
    streams = [_restream(state, work, kind) for kind in IocType]

    # rename at the end, so a lookup during a collection reads the last
    # complete file rather than a half written one
    fresh = out / f"{OUTPUT_NAME}.new"
    with fresh.open("w", encoding=ENCODING, newline="\n") as handle:
        for kind, record in heapq.merge(*streams, key=lambda pair: pair[1].value):
            hit = allowlist.check(kind, record.value)
            if hit is not None:
                counts[kind].excluded += 1
                excluded.append(
                    {
                        "value": record.value,
                        "type": kind.value,
                        "layer": hit.layer,
                        "reason": hit.reason,
                    }
                )
                continue
            counts[kind].total += 1
            if len(record.sightings) >= CONFIRMED_ORIGINS:
                counts[kind].confirmed += 1
            score = score_record(record, kind, when, traits)
            handle.write(as_json(kind, record, score, _redistributable(record, traits)) + "\n")
    fresh.replace(out / OUTPUT_NAME)
    return [counts[kind] for kind in IocType if counts[kind].total], excluded


# Read the value out of one stored line, or None if the line is unreadable
def _value_of(line: bytes) -> str | None:
    try:
        record = json.loads(line)
    except ValueError:
        return None
    found = record.get("value") if isinstance(record, dict) else None
    return str(found) if found is not None else None


# Find where the first record at or after a value begins, by halving the byte
# range rather than reading every line before it
def _offset_of(handle: BinaryIO, size: int, value: str) -> int:
    low, high = 0, size
    while low < high:
        middle = (low + high) // 2
        handle.seek(middle)
        if middle:
            handle.readline()
        start = handle.tell()
        line = handle.readline()
        found = _value_of(line) if line else None
        if found is not None and found < value:
            low = start + len(line)
        else:
            high = middle
    return low


def lookup(store: pathlib.Path, value: str) -> dict[str, object] | None:
    """Find one indicator in the sorted corpus with a bounded number of seeks."""

    if not store.exists():
        return None
    with store.open("rb") as handle:
        handle.seek(_offset_of(handle, store.stat().st_size, value))

        # the search lands at or just before the answer, so step over any
        # unreadable lines rather than giving up on the first one
        for _ in range(MAX_PROBE_LINES):
            line = handle.readline()
            if not line:
                return None
            found = _value_of(line)
            if found == value:
                return dict(json.loads(line))
            if found is not None and found > value:
                return None
    return None

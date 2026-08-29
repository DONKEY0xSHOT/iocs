"""The four kinds of indicator, and how one value is checked and stored."""

# Imports
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

# Constants
MAX_VALUE_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
URL_SCHEMES = frozenset({"http", "https"})
IPV4_VERSION = 4
MAX_ORIGINS = 64
DEFAULT_CREDIBILITY = 3
DELIMITERS = "\t\n\r"

# a hex digest such as d41d8cd98f00b204e9800998ecf8427e
HEX = re.compile(r"\A[0-9a-fA-F]+\Z")

# one part of a hostname, such as mail in mail.example.com. The inner group
# stops a label starting or ending with a dash.
LABEL = re.compile(r"\A[a-z0-9]([a-z0-9-]*[a-z0-9])?\Z")
UNSAFE = re.compile(r"[\x00-\x1f\x7f]")
DEFANG = (
    ("https://", "hxxps://"),
    ("http://", "hxxp://"),
    (".", "[.]"),
)
REFANG = (
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("hxxps", "https"),
    ("hxxp", "http"),
)


class IocType(StrEnum):
    """Every kind of indicator this project collects."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"


@dataclass(frozen=True)
class Canonical:
    """An accepted indicator in its normalized form."""

    type: IocType
    value: str


@dataclass(frozen=True)
class Rejection:
    """Marks a value we could not accept."""


def refang(raw: str) -> str:
    """Undo the common defanging conventions used by feeds."""

    text = raw
    for marker, replacement in REFANG:
        text = text.replace(marker, replacement).replace(marker.upper(), replacement)
    return text


# Match a bare hex digest by length
def _as_hash(text: str) -> Canonical | None:
    name = HASH_LENGTHS.get(len(text))
    if name is None or not HEX.match(text):
        return None
    return Canonical(IocType[name], text.lower())


# Feeds publish a command and control endpoint as an address and a port. The
# port is context we do not model, so keep the address it points at
def _without_port(text: str) -> str:
    if text.startswith("[") and "]:" in text:
        return text[1 : text.index("]:")]
    head, separator, tail = text.rpartition(":")
    if separator and "." in head and tail.isascii() and tail.isdigit():
        return head
    return text


# Read an address. Zoned and v4 mapped forms are too unclear to keep
def _as_address(text: str) -> Canonical | Rejection | None:
    candidate = _without_port(text)
    if "%" in candidate:
        return Rejection()
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return Rejection()
    kind = IocType.IPV4 if parsed.version == IPV4_VERSION else IocType.IPV6
    return Canonical(kind, str(parsed))


# Validate a hostname label by label
def _as_domain(text: str) -> Canonical | Rejection | None:
    host = text.rstrip(".").lower()
    if "." not in host or len(host) > MAX_DOMAIN_LENGTH:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return Rejection()
    labels = host.split(".")
    if any(len(item) > MAX_LABEL_LENGTH or not LABEL.match(item) for item in labels):
        return Rejection()
    if labels[-1].isdigit():
        return None
    return Canonical(IocType.DOMAIN, host)


# Rebuild a url with lowercased scheme and host
def _as_url(text: str) -> Canonical | Rejection | None:
    parts = urlsplit(text)
    if parts.scheme.lower() not in URL_SCHEMES:
        return None
    if not parts.hostname:
        return Rejection()
    host = _as_domain(parts.hostname)
    if not isinstance(host, Canonical):
        host = _as_address(parts.hostname)
    if not isinstance(host, Canonical):
        return Rejection()
    netloc = host.value if parts.port is None else f"{host.value}:{parts.port}"
    rebuilt = urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
    return Canonical(IocType.URL, rebuilt)


def classify(raw: str) -> Canonical | Rejection:
    """Clean up one raw feed value, or say we cannot use it."""

    text = refang(raw).strip()
    if not text or len(text) > MAX_VALUE_LENGTH:
        return Rejection()
    if UNSAFE.search(text):
        return Rejection()
    digest = _as_hash(text)
    if digest is not None:
        return digest

    # order matters. An address is the most exact and a hostname the loosest,
    # so the loosest has to be tried last.
    for probe in (_as_address, _as_url, _as_domain):
        result = probe(text)
        if result is not None:
            return result
    return Rejection()


@dataclass(frozen=True)
class Observation:
    """One origin reporting one value on one day."""

    value: str
    origin: str
    seen_on: str
    credibility: int = DEFAULT_CREDIBILITY


@dataclass(frozen=True)
class Sighting:
    """What a single origin has said about a value over time."""

    origin: str
    first_seen: str
    last_seen: str
    credibility: int
    count: int


@dataclass(frozen=True)
class Record:
    """The stored aggregate for one indicator value."""

    value: str
    first_seen: str
    last_seen: str
    sightings: tuple[Sighting, ...]

    @classmethod
    def from_observation(cls, obs: Observation) -> "Record":
        """Build a fresh single sighting record."""

        seen = Sighting(obs.origin, obs.seen_on, obs.seen_on, obs.credibility, 1)
        return cls(obs.value, obs.seen_on, obs.seen_on, (seen,))


# Write one source's sighting as a short piece of text
def _encode_sighting(seen: Sighting) -> str:
    return f"{seen.origin}:{seen.first_seen}:{seen.last_seen}:{seen.credibility}:{seen.count}"


# Parse one origin sighting back from its compact field form
def _decode_sighting(text: str) -> Sighting:
    origin, first, last, cred, count = text.split(":")
    return Sighting(origin, first, last, int(cred), int(count))


def encode(record: Record) -> str:
    """Render a record as one tab separated line."""

    if any(char in record.value for char in DELIMITERS):
        raise ValueError("value contains a delimiter")
    seen = ",".join(_encode_sighting(item) for item in record.sightings)
    fields = (record.value, record.first_seen, record.last_seen, seen)
    return "\t".join(str(item) for item in fields)


def decode(line: str) -> Record:
    """Parse a record from one tab separated line."""

    value, first, last, seen = line.split("\t")
    sightings = tuple(_decode_sighting(item) for item in seen.split(",") if item)
    return Record(value, first, last, sightings)


# Combine two sightings of the same origin into one
def _merge_sighting(left: Sighting, right: Sighting) -> Sighting:
    return Sighting(
        left.origin,
        min(left.first_seen, right.first_seen),
        max(left.last_seen, right.last_seen),
        min(left.credibility, right.credibility),
        left.count + right.count,
    )


def merge_records(records: Iterable[Record]) -> Record:
    """Merge every record for one value into a single aggregate."""

    items = list(records)
    seen: dict[str, Sighting] = {}
    for record in items:
        for sighting in record.sightings:
            previous = seen.get(sighting.origin)
            seen[sighting.origin] = _merge_sighting(previous, sighting) if previous else sighting

    # iso dates sort in date order, so the newest origins survive the cap
    by_name = sorted(seen.values(), key=lambda item: item.origin)
    kept = sorted(by_name, key=lambda item: item.last_seen, reverse=True)[:MAX_ORIGINS]
    return Record(
        items[0].value,
        min(item.first_seen for item in items),
        max(item.last_seen for item in items),
        tuple(sorted(kept, key=lambda item: item.origin)),
    )


def defang(value: str) -> str:
    """Render an indicator unclickable for human facing output."""

    text = value
    for live, safe in DEFANG:
        text = text.replace(live, safe)
    return text

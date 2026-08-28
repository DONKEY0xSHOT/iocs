"""Lists of things that are never malicious, used to hold back false alarms."""

# Imports
import bisect
import io
import ipaddress
import json
import re
import tarfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from iocs.indicators import IocType

# Constants
HASH_TYPES = frozenset({IocType.MD5, IocType.SHA1, IocType.SHA256})
ADDRESS_TYPES = frozenset({IocType.IPV4, IocType.IPV6})
RANGE_MATCH_TYPES = frozenset({"cidr"})
VALUE_MATCH_TYPES = frozenset({"string", "hostname"})
NON_NAME = re.compile(r"[^a-z0-9]+")
LIST_FILE = "list.json"
POPULARITY_NAMES = (
    "popular",
    "tranco",
    "umbrella",
    "alexa",
    "majestic",
    "radar",
    "ranking",
    "most_visited",
)

# a name like top_1m or top_1_000_000_domains means a list ranked by popularity
RANKED_BY_POSITION = re.compile(r"top[_ ]?[0-9]")
PUBLIC_RESOLVERS = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "149.112.112.112",
        "208.67.222.222",
        "208.67.220.220",
        "76.76.2.0",
        "94.140.14.14",
    }
)
BENIGN_HASHES = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "44d88612fea8a8f36de82e1278abb02f",
        "3395856ce81f2b7382dee72602f798b642f14140",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    }
)


@dataclass(frozen=True)
class AllowlistHit:
    """Why one indicator was held back from publication."""

    layer: str
    reason: str


# Join touching ranges together, so a lookup only has to check one of them
def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        # plus one joins ranges that only touch, since 10.0.0.255 sits next to 10.0.1.0
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


class RangeSet:
    """Membership test over a set of network ranges."""

    def __init__(self, cidrs: Iterable[str]) -> None:
        collected: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
        for text in cidrs:
            try:
                net = ipaddress.ip_network(text.strip(), strict=False)
            except ValueError:
                continue
            collected[net.version].append((int(net.network_address), int(net.broadcast_address)))
        self.spans = {version: _merge(items) for version, items in collected.items()}
        self.starts = {
            version: [span[0] for span in spans] for version, spans in self.spans.items()
        }

    def contains(self, address: str) -> bool:
        """Report whether an address falls inside any known range."""

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return False
        target = int(parsed)

        # the range before the first one starting after the address is the only
        # candidate, which is safe because _merge left no overlaps behind
        index = bisect.bisect_right(self.starts[parsed.version], target) - 1
        if index < 0:
            return False
        start, end = self.spans[parsed.version][index]
        return start <= target <= end


# Stop if a layer name suggests it hides things for being popular
def _reject_popularity(layer: str) -> None:
    lowered = layer.lower()
    named = any(word in lowered for word in POPULARITY_NAMES)
    if named or RANKED_BY_POSITION.search(lowered):
        raise ValueError(f"popularity is never grounds for exclusion: {layer}")


@dataclass(frozen=True)
class Allowlist:
    """Lists of things to hold back, each with a reason we can check later."""

    ranges: dict[str, RangeSet] = field(default_factory=dict)
    values: dict[str, frozenset[str]] = field(default_factory=dict)

    def with_ranges(self, layer: str, cidrs: Iterable[str]) -> Allowlist:
        """Return a copy with one more list of address ranges."""

        _reject_popularity(layer)
        return Allowlist({**self.ranges, layer: RangeSet(cidrs)}, self.values)

    def with_values(self, layer: str, items: Iterable[str]) -> Allowlist:
        """Return a copy with one more list of exact values."""

        _reject_popularity(layer)
        merged = {**self.values, layer: frozenset(item.lower() for item in items)}
        return Allowlist(self.ranges, merged)

    # Check the cheap stdlib rules before consulting any loaded list
    def _special_use(self, value: str) -> AllowlistHit | None:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return None
        unusable = parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified
        if not parsed.is_global or unusable:
            return AllowlistHit("special_use", "reserved or unroutable address")
        return None

    def check(self, kind: IocType, value: str) -> AllowlistHit | None:
        """Report the first layer that excludes this indicator, if any."""

        lowered = value.lower()
        if kind in HASH_TYPES and lowered in BENIGN_HASHES:
            return AllowlistHit("benign_hash", "digest of a known harmless file")
        if kind in ADDRESS_TYPES:
            special = self._special_use(value)
            if special is not None:
                return special
            if value in PUBLIC_RESOLVERS:
                return AllowlistHit("public_resolver", "public dns resolver")
        for layer, items in self.values.items():
            if lowered in items:
                return AllowlistHit(layer, f"listed in {layer}")
        if kind in ADDRESS_TYPES:
            for layer, ranges in self.ranges.items():
                if ranges.contains(value):
                    return AllowlistHit(layer, f"inside a {layer} range")
        return None


@dataclass(frozen=True)
class WarningLayer:
    """One misp warninglist reduced to entries this project can match on."""

    name: str
    is_range: bool
    entries: list[str]


def load_warninglist(data: bytes) -> WarningLayer | None:
    """Read one misp warning list, skipping match kinds we cannot do exactly."""

    try:
        payload = json.loads(data.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    kind = str(payload.get("type", ""))
    entries = payload.get("list")
    name = str(payload.get("name", ""))
    if not name or not isinstance(entries, list):
        return None
    if kind not in RANGE_MATCH_TYPES | VALUE_MATCH_TYPES:
        return None
    slug = NON_NAME.sub("_", name.lower()).strip("_")
    return WarningLayer(slug, kind in RANGE_MATCH_TYPES, [str(item) for item in entries])


def load_warninglist_archive(data: bytes) -> list[WarningLayer]:
    """Read every warninglist out of one repository archive."""

    found: list[WarningLayer] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
            for member in bundle.getmembers():
                if not member.isfile() or not member.name.endswith(LIST_FILE):
                    continue
                handle = bundle.extractfile(member)
                if handle is None:
                    continue
                layer = load_warninglist(handle.read())
                if layer is not None:
                    found.append(layer)
    except tarfile.TarError, ValueError, EOFError:
        return []
    return found


def apply_layers(allowlist: Allowlist, layers: Iterable[WarningLayer]) -> Allowlist:
    """Add every layer we can use, and quietly drop any based on popularity."""

    built = allowlist
    for layer in layers:
        try:
            if layer.is_range:
                built = built.with_ranges(layer.name, layer.entries)
            else:
                built = built.with_values(layer.name, layer.entries)
        except ValueError:
            continue
    return built


ALLOWLIST_PARSERS = {"warninglist_archive": load_warninglist_archive}

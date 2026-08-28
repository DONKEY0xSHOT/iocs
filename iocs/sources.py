"""The feeds we read, and the terms that say what may be done with each one."""

# Imports
import pathlib
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit
from iocs.indicators import IocType

# Constants
REGISTRY_PATH = pathlib.Path(__file__).with_name("registry.toml")


class LicenseClass(StrEnum):
    """Whether a source's terms let its data be passed on to anyone else."""

    PERMISSIVE = "permissive"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class Reliability(StrEnum):
    """How much we trust a source, from A for the best down to F for unrated."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


@dataclass(frozen=True)
class Source:
    """One feed we read, and the terms that say how its data may be used."""

    name: str
    origin: str
    url: str
    host: str
    parser: str
    produces: tuple[IocType, ...]
    license_class: LicenseClass
    license_id: str
    license_url: str
    attribution: str | None = None
    reliability: Reliability = Reliability.F
    credibility: int = 3
    sentinel_url: str | None = None
    follow_template: str | None = None
    follow_parser: str | None = None
    follow_limit: int = 500
    follow_suffixes: tuple[str, ...] = ()
    csv_columns: tuple[int, ...] = (0,)
    csv_skip_rows: int = 0
    archive: str = ""


# Build one source from its registry table
def _build(entry: dict[str, Any]) -> Source:
    optional = ("attribution", "sentinel_url", "follow_template", "follow_parser")
    text = {name: str(entry[name]) if entry.get(name) else None for name in optional}
    return Source(
        name=str(entry["name"]),
        origin=str(entry["origin"]),
        url=str(entry["url"]),
        host=str(entry["host"]),
        parser=str(entry["parser"]),
        produces=tuple(IocType(item) for item in entry["produces"]),
        license_class=LicenseClass(entry["license_class"]),
        license_id=str(entry["license_id"]),
        license_url=str(entry["license_url"]),
        reliability=Reliability(entry["reliability"]),
        credibility=int(entry["credibility"]),
        follow_limit=int(entry.get("follow_limit", 500)),
        follow_suffixes=tuple(str(item) for item in entry.get("follow_suffixes", ())),
        csv_columns=tuple(int(item) for item in entry.get("csv_columns", (0,))),
        csv_skip_rows=int(entry.get("csv_skip_rows", 0)),
        archive=str(entry.get("archive", "")),
        **text,
    )


REGISTRY = tuple(
    _build(table) for table in tomllib.loads(REGISTRY_PATH.read_text(encoding="utf-8"))["source"]
)


# Confirm the declared rate limit host really covers the fetch url
def _host_matches(source: Source) -> bool:
    actual = urlsplit(source.url).hostname or ""
    return actual == source.host or actual.endswith(f".{source.host}")


def validate_registry(sources: Iterable[Source] = REGISTRY) -> list[str]:
    """List every consistency problem in a set of source declarations."""

    found: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if source.name in seen:
            found.append(f"{source.name}: duplicate source name")
        seen.add(source.name)
        if not _host_matches(source):
            found.append(f"{source.name}: host does not match the url")
        if source.follow_template and not source.follow_parser:
            found.append(f"{source.name}: follows an index without naming a parser")
    return found


def traits_by_origin(
    sources: Iterable[Source] = REGISTRY,
) -> dict[str, tuple[Reliability, LicenseClass]]:
    """Map every origin to how far we trust it and whether its data may be shared."""

    return {source.origin: (source.reliability, source.license_class) for source in sources}


def follow_prefixes(sources: Iterable[Source]) -> frozenset[str]:
    """Collect the url prefixes that index sources are allowed to expand into."""

    return frozenset(
        source.follow_template.split("{item}")[0] for source in sources if source.follow_template
    )

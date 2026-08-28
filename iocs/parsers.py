"""Readers for each feed file format, written to expect hostile input."""

# Imports
import csv
import io
import json
import re
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

# Constants
MAX_LINE_CHARS = 8192
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
COMMENT_PREFIXES = ("#", ";", "//")

# the addresses a hosts file points blocked names at, never indicators themselves
SINKHOLE_ADDRESSES = frozenset(
    {
        "0.0.0.0",  # noqa: S104
        "127.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1%lo0",
    }
)
LINK_HREF = re.compile(r'href="([^"]+)"')
LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain", "broadcasthost", "local"})
UNSAFE_IN_VALUE = ("\n", "\r", "\t", "\x00")
BOM = "\ufeff"
MISP_TYPES = frozenset(
    {
        "md5",
        "sha1",
        "sha256",
        "domain",
        "hostname",
        "ip-src",
        "ip-dst",
        "url",
        "filename|md5",
        "filename|sha1",
        "filename|sha256",
        "domain|ip",
    }
)


@dataclass(frozen=True)
class ParserOptions:
    """The few settings individual parsers need."""

    follow_suffixes: tuple[str, ...] = ()
    csv_columns: tuple[int, ...] = (0,)
    csv_skip_rows: int = 0
    archive: str = ""


# Decode one chunk of feed bytes without ever raising on bad encoding
def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").lstrip(BOM)


# Read the one file inside a zip a line at a time, so a large export never has
# to sit in memory whole. The cap bounds what a small archive can expand into.
def _zip_lines(data: bytes) -> Iterator[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            names = [item.filename for item in bundle.infolist() if not item.is_dir()]
            if not names:
                return
            read = 0
            with bundle.open(names[0]) as handle:
                for raw in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                    read += len(raw)
                    if read > MAX_ARCHIVE_BYTES:
                        return
                    yield raw
    except zipfile.BadZipFile, ValueError, EOFError, RuntimeError, OSError:
        return


# Yield usable lines, dropping comments, blanks and over long rows
def _lines(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    settings = options or ParserOptions()
    source = _zip_lines(data) if settings.archive == "zip" else iter(_text(data).splitlines())
    for raw in source:
        if len(raw) > MAX_LINE_CHARS:
            continue
        line = raw.replace("\x00", "").strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        yield line


# Parse json defensively, returning an empty result on any malformed input
def _json(data: bytes) -> Any:
    if len(data) > MAX_JSON_BYTES:
        return {}
    try:
        return json.loads(_text(data))
    except ValueError, RecursionError:
        return {}


def parse_plaintext(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Yield one value per line."""

    yield from _lines(data, options)


def parse_csv_rows(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Read the named columns out of a quoted csv feed."""

    settings = options or ParserOptions()
    reader = csv.reader(_lines(data, settings), skipinitialspace=True)
    for index, row in enumerate(reader):
        if index < settings.csv_skip_rows:
            continue
        for column in settings.csv_columns:
            if len(row) > column and row[column].strip():
                yield row[column].strip()


def parse_hosts(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Read a hosts file, or a plain list of names, and yield the names."""

    for line in _lines(data, options):
        # a trailing comment after the name is common in these files
        fields = line.split("#")[0].split()
        if not fields:
            continue
        name = fields[1] if len(fields) > 1 and fields[0] in SINKHOLE_ADDRESSES else fields[0]
        if name in SINKHOLE_ADDRESSES or name.lower() in LOCAL_NAMES:
            continue
        yield name


def parse_dshield(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Yield the network column from the tab separated dshield report."""

    for line in _lines(data, options):
        first = line.split("\t")[0].strip()
        if first:
            yield first


def parse_misp_manifest(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Yield the event identifiers listed in a misp feed manifest."""

    manifest = _json(data)
    if isinstance(manifest, dict):
        yield from (str(key) for key in manifest)


# Yield indicator values from a list of misp attribute mappings
def _attribute_values(items: Any) -> Iterator[str]:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict) or item.get("type") not in MISP_TYPES:
            continue
        value = str(item.get("value", "")).replace("\x00", "").strip()
        for part in value.split("|"):
            if part.strip():
                yield part.strip()


def parse_misp_event(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Yield indicator values from a single misp event document."""

    event = _json(data)
    body = event.get("Event", {}) if isinstance(event, dict) else {}
    if not isinstance(body, dict):
        return
    yield from _attribute_values(body.get("Attribute"))
    objects = body.get("Object")
    if isinstance(objects, list):
        for entry in objects:
            if isinstance(entry, dict):
                yield from _attribute_values(entry.get("Attribute"))


def parse_html_links(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """List the links on an index page that point at the files we want."""

    wanted = (options or ParserOptions()).follow_suffixes
    for href in LINK_HREF.findall(_text(data)):
        # only same site paths, since the follow template supplies the host
        if "://" in href:
            continue
        if not wanted or href.endswith(wanted):
            yield href


def parse_github_tree(data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """List the file paths in a github tree listing that we want to read."""

    wanted = (options or ParserOptions()).follow_suffixes
    listing = _json(data)
    entries = listing.get("tree", []) if isinstance(listing, dict) else []
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        path = str(entry.get("path", ""))
        if path and (not wanted or path.endswith(wanted)):
            yield path


PARSERS: dict[str, Callable[[bytes, ParserOptions | None], Iterator[str]]] = {
    "plaintext": parse_plaintext,
    "hosts": parse_hosts,
    "csv_rows": parse_csv_rows,
    "dshield": parse_dshield,
    "misp_manifest": parse_misp_manifest,
    "misp_event": parse_misp_event,
    "github_tree": parse_github_tree,
    "html_links": parse_html_links,
}


# Drop anything that would break the record format or blow the line budget
def _drop_unsafe(values: Iterator[str]) -> Iterator[str]:
    for value in values:
        if len(value) <= MAX_LINE_CHARS and not any(char in value for char in UNSAFE_IN_VALUE):
            yield value


def parse(kind: str, data: bytes, options: ParserOptions | None = None) -> Iterator[str]:
    """Run the named parser over one fetched feed body."""

    return _drop_unsafe(PARSERS[kind](data, options))

"""Tests for parsers."""

# Imports
import io
import json
import zipfile
import pytest
from iocs.parsers import MAX_ARCHIVE_BYTES, MAX_LINE_CHARS, PARSERS, ParserOptions, parse

# Constants
HOSTILE = [
    b"",
    b"\x00\x00\x00",
    b"\xff\xfe\xfd invalid utf8",
    b"\xef\xbb\xbf1.2.3.4\n",
    b"a" * (MAX_LINE_CHARS * 3),
    b'"unclosed,quote\n1.2.3.4\n',
    b"{" * 500,
    b"[" * 500,
    b"\r\n\r\n\r\n",
    b"1.2.3.4\x00evil.example\n",
]


# Verify plaintext keeps values and drops comments and blanks
def test_plaintext_basic() -> None:
    data = b"# header\n\n1.2.3.4\n  5.6.7.8  \n#trailing\nevil.example\n"
    assert list(parse("plaintext", data)) == ["1.2.3.4", "5.6.7.8", "evil.example"]


# Verify plaintext tolerates crlf endings and a byte order mark
def test_plaintext_crlf_and_bom() -> None:
    data = b"\xef\xbb\xbf1.2.3.4\r\n5.6.7.8\r\n"
    assert list(parse("plaintext", data)) == ["1.2.3.4", "5.6.7.8"]


# Verify an over long line is skipped rather than consuming memory
def test_plaintext_skips_long_lines() -> None:
    data = b"1.2.3.4\n" + b"x" * (MAX_LINE_CHARS + 10) + b"\n5.6.7.8\n"
    assert list(parse("plaintext", data)) == ["1.2.3.4", "5.6.7.8"]


# Verify csv parsing selects the requested column and skips the header
def test_csv_rows_column() -> None:
    data = b'# comment\n"id","url","status"\n"1","http://evil.example/a","online"\n'
    got = list(parse("csv_rows", data, ParserOptions(csv_columns=(1,), csv_skip_rows=1)))
    assert got == ["http://evil.example/a"]


# Verify the dshield tab format yields the first column only
def test_dshield_columns() -> None:
    data = b"# comment\n1.2.3.0\t1.2.3.255\t24\t10\tnet\tXX\tabuse\n"
    assert list(parse("dshield", data)) == ["1.2.3.0"]


# Verify the misp manifest yields event identifiers
def test_misp_manifest() -> None:
    data = json.dumps({"aaa-bbb": {"info": "x"}, "ccc-ddd": {"info": "y"}}).encode()
    assert sorted(parse("misp_manifest", data)) == ["aaa-bbb", "ccc-ddd"]


# Verify a misp event yields only indicator attribute values
def test_misp_event_attributes() -> None:
    event = {
        "Event": {
            "Attribute": [
                {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                {"type": "domain", "value": "evil.example"},
                {"type": "comment", "value": "ignore me"},
                {"type": "filename|md5", "value": "a.exe|d41d8cd98f00b204e9800998ecf8427e"},
            ],
            "Object": [{"Attribute": [{"type": "ip-dst", "value": "1.2.3.4"}]}],
        }
    }
    got = set(parse("misp_event", json.dumps(event).encode()))
    assert "d41d8cd98f00b204e9800998ecf8427e" in got
    assert "evil.example" in got
    assert "1.2.3.4" in got
    assert "ignore me" not in got


# Verify a github tree listing yields only the requested file paths
def test_github_tree_paths() -> None:
    tree = {
        "tree": [
            {"path": "family/samples.sha256", "type": "blob"},
            {"path": "family/README.md", "type": "blob"},
            {"path": "family", "type": "tree"},
        ]
    }
    got = list(
        parse(
            "github_tree",
            json.dumps(tree).encode(),
            ParserOptions(follow_suffixes=("samples.sha256",)),
        )
    )
    assert got == ["family/samples.sha256"]


# Verify every parser survives hostile input without raising
@pytest.mark.parametrize("kind", sorted(PARSERS))
@pytest.mark.parametrize("data", HOSTILE)
def test_parsers_never_raise(kind: str, data: bytes) -> None:
    for value in parse(kind, data):
        assert "\n" not in value
        assert "\x00" not in value


# Verify an unknown parser name is rejected rather than silently ignored
def test_unknown_parser_rejected() -> None:
    with pytest.raises(KeyError):
        list(parse("nope", b"1.2.3.4\n"))


# Verify a hosts file yields the blocked name rather than the sinkhole address
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (b"0.0.0.0 evil.example\n", ["evil.example"]),
        (b"127.0.0.1 bad.example\n", ["bad.example"]),
        (b":: blocked.example\n", ["blocked.example"]),
        (b"0.0.0.0\tevil.example\n", ["evil.example"]),
        (b"0.0.0.0 evil.example # a comment\n", ["evil.example"]),
    ],
)
def test_hosts_yields_the_name(line: bytes, expected: list[str]) -> None:
    assert list(parse("hosts", line)) == expected


# Verify a plain list of names still works through the same parser
def test_hosts_accepts_a_bare_list() -> None:
    data = b"# header\nevil.example\nbad.example\n"
    assert list(parse("hosts", data)) == ["evil.example", "bad.example"]


# Verify the loopback entries every hosts file starts with are dropped
def test_hosts_drops_local_entries() -> None:
    data = (
        b"127.0.0.1 localhost\n::1 localhost\n0.0.0.0 evil.example\n255.255.255.255 broadcasthost\n"
    )
    assert list(parse("hosts", data)) == ["evil.example"]


# Verify a sinkhole address on its own is never mistaken for an indicator
def test_hosts_ignores_a_bare_address() -> None:
    assert list(parse("hosts", b"0.0.0.0\n127.0.0.1\n")) == []


# Build a zip holding one csv member, as the abuse.ch exports are shaped
def make_zip(body: bytes, name: str = "full.csv") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(name, body)
    return buffer.getvalue()


# Verify a zipped feed is unwrapped and parsed like a plain one
def test_zip_archive_is_unwrapped() -> None:
    body = b'"2026-01-01", "1", "evil.example"\n"2026-01-02", "2", "worse.example"\n'
    options = ParserOptions(csv_columns=(2,), archive="zip")
    values = list(parse("csv_rows", make_zip(body), options))
    assert values == ["evil.example", "worse.example"]


# Verify a broken archive yields nothing rather than raising
def test_broken_archive_is_empty() -> None:
    options = ParserOptions(csv_columns=(2,), archive="zip")
    assert list(parse("csv_rows", b"not a zip at all", options)) == []


# Verify an empty archive yields nothing
def test_empty_archive_is_empty() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w"):
        pass
    options = ParserOptions(archive="zip")
    assert list(parse("plaintext", buffer.getvalue(), options)) == []


# Verify an archive that expands far beyond the cap is cut off
def test_oversized_archive_is_capped() -> None:
    body = (b"a" * 999 + b"\n") * 2000
    options = ParserOptions(archive="zip")
    values = list(parse("plaintext", make_zip(body), options))
    assert sum(len(item) for item in values) <= MAX_ARCHIVE_BYTES


# Verify every named column is read, which one sample row with three hashes needs
def test_several_csv_columns_are_read() -> None:
    body = b'"2026-01-01", "aa", "bb", "cc", "reporter"\n'
    values = list(parse("csv_rows", body, ParserOptions(csv_columns=(1, 2, 3))))
    assert values == ["aa", "bb", "cc"]


# Verify a space after the comma does not leave quotes in the value
def test_space_after_comma_is_handled() -> None:
    body = b'"2026-01-01", "evil.example"\n'
    assert list(parse("csv_rows", body, ParserOptions(csv_columns=(1,)))) == ["evil.example"]


# Verify an index page yields the file paths we asked for
def test_html_links_are_extracted() -> None:
    page = b'<a href="files/one.md5">one</a> <a href="files/two.txt">two</a>'
    values = list(parse("html_links", page, ParserOptions(follow_suffixes=(".md5",))))
    assert values == ["files/one.md5"]


# Verify a link to another host is left alone, since the template supplies the host
def test_html_links_skip_absolute_urls() -> None:
    page = b'<a href="files/one.md5">a</a> <a href="https://other.example/two.md5">b</a>'
    values = list(parse("html_links", page, ParserOptions(follow_suffixes=(".md5",))))
    assert values == ["files/one.md5"]


# Verify a page with no links yields nothing rather than failing
def test_html_links_without_matches() -> None:
    assert list(parse("html_links", b"<p>nothing here</p>", ParserOptions())) == []

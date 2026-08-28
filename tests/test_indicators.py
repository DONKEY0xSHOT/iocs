"""Tests for indicators."""

# Imports
import pytest
from hypothesis import event, given
from iocs.indicators import (
    MAX_ORIGINS,
    Canonical,
    IocType,
    Observation,
    Record,
    Rejection,
    Sighting,
    classify,
    decode,
    defang,
    encode,
    merge_records,
    refang,
)
from strategies import IOC_LIKE, RECORDS

# Constants
DELIMITERS = "\t\n\r"
LINE = (
    "evil.example\t2026-08-01\t2026-08-20\ta:2026-08-01:2026-08-10:2:3,b:2026-08-15:2026-08-20:1:1"
)
LIVE_MARKERS = ("http://", "https://")
DAY = "2026-08-28"


# Verify each type normalizes correctly
@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("D41D8CD98F00B204E9800998ECF8427E", IocType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
            IocType.SHA1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            IocType.SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        ("  1.2.3.4  ", IocType.IPV4, "1.2.3.4"),
        ("2001:DB8::0:1", IocType.IPV6, "2001:db8::1"),
        ("Example.COM.", IocType.DOMAIN, "example.com"),
        ("xn--bcher-kva.example", IocType.DOMAIN, "xn--bcher-kva.example"),
        ("HTTP://Evil.Example/Path", IocType.URL, "http://evil.example/Path"),
    ],
)
def test_classify_accepts(raw: str, kind: IocType, value: str) -> None:
    result = classify(raw)
    assert result == Canonical(kind, value)


# Verify malformed and unsafe values are rejected
@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not an ioc",
        "1.2.3.4.5",
        "999.1.1.1",
        "fe80::1%eth0",
        "::ffff:1.2.3.4",
        "deadbeef",
        "ftp://example.com/x",
        "http://",
        "value\twith\ttabs",
        "line\nbreak.example",
        "-bad.example",
        "a" * 300 + ".example",
    ],
)
def test_classify_rejects(raw: str) -> None:
    assert isinstance(classify(raw), Rejection)


# Verify defanged input is refanged first
@pytest.mark.parametrize(
    ("raw", "value"),
    [
        ("1.2.3[.]4", "1.2.3.4"),
        ("evil[.]example", "evil.example"),
        ("hxxp://evil[.]example/a", "http://evil.example/a"),
        ("hxxps://evil(.)example/a", "https://evil.example/a"),
    ],
)
def test_classify_refangs_input(raw: str, value: str) -> None:
    result = classify(raw)
    assert isinstance(result, Canonical)
    assert result.value == value


# Verify output cannot break the record format
@given(IOC_LIKE)
def test_canonical_is_delimiter_safe(raw: str) -> None:
    result = classify(raw)
    if isinstance(result, Canonical):
        assert not any(char in result.value for char in DELIMITERS)
        assert all(ord(char) >= 32 and ord(char) != 127 for char in result.value)


# Verify classify is idempotent
@given(IOC_LIKE)
def test_classify_is_idempotent(raw: str) -> None:
    once = classify(raw)
    if isinstance(once, Canonical):
        assert classify(once.value) == once


# Verify the generator reaches accepted values
@given(IOC_LIKE)
def test_generator_reaches_accepted_values(raw: str) -> None:
    event("accepted" if isinstance(classify(raw), Canonical) else "rejected")


# Verify a url whose host is a bare ipv4 address is accepted
@pytest.mark.parametrize(
    ("raw", "value"),
    [
        ("http://1.2.3.4/c2", "http://1.2.3.4/c2"),
        ("https://45.155.205.233/panel", "https://45.155.205.233/panel"),
        ("http://1.2.3.4:8080/x", "http://1.2.3.4:8080/x"),
        ("http://[2001:db8::1]/x", "http://2001:db8::1/x"),
    ],
)
def test_url_with_address_host_is_accepted(raw: str, value: str) -> None:
    result = classify(raw)
    assert isinstance(result, Canonical)
    assert result.type is IocType.URL
    assert result.value == value


# Verify the indicator type list documents itself accurately
def test_ioc_type_count_matches_its_docstring() -> None:
    text = IocType.__doc__ or ""
    assert "four" not in text.lower()
    assert len(list(IocType)) == 7


# Verify an address and port keeps the address, which is the part we model
def test_ipv4_with_a_port_keeps_the_address() -> None:
    result = classify("45.155.205.233:443")
    assert isinstance(result, Canonical)
    assert result.type is IocType.IPV4
    assert result.value == "45.155.205.233"


# Verify the bracketed form used for a v6 endpoint is handled too
def test_ipv6_with_a_port_keeps_the_address() -> None:
    result = classify("[2001:db8::1]:8443")
    assert isinstance(result, Canonical)
    assert result.type is IocType.IPV6
    assert result.value == "2001:db8::1"


# Verify a bare v6 address is not mistaken for an address and port
def test_bare_ipv6_is_untouched() -> None:
    result = classify("2001:db8::1")
    assert isinstance(result, Canonical)
    assert result.value == "2001:db8::1"


# Verify a name with a port is not turned into an address
def test_hostname_with_a_port_is_not_an_address() -> None:
    result = classify("evil.example:8080")
    assert not (isinstance(result, Canonical) and result.type is IocType.IPV4)


# Verify a record encodes to the documented line format
def test_encode_shape() -> None:
    record = Record(
        value="evil.example",
        first_seen="2026-08-01",
        last_seen="2026-08-20",
        sightings=(
            Sighting("a", "2026-08-01", "2026-08-10", 2, 3),
            Sighting("b", "2026-08-15", "2026-08-20", 1, 1),
        ),
    )
    assert encode(record) == LINE


# Verify decoding restores the same record
def test_decode_shape() -> None:
    assert encode(decode(LINE)) == LINE


# Verify the codec round trips any record
@given(RECORDS)
def test_codec_round_trips(record: Record) -> None:
    assert decode(encode(record)) == record


# Verify encoding rejects values that would break the format
@pytest.mark.parametrize("bad", ["a\tb", "a\nb", "a\rb"])
def test_encode_rejects_delimiters(bad: str) -> None:
    record = Record(bad, DAY, DAY, (Sighting("a", DAY, DAY, 1, 1),))
    with pytest.raises(ValueError, match="delimiter"):
        encode(record)


# Verify merging takes the widest window and unions origins
def test_merge_widens_window() -> None:
    left = Record(
        "x", "2026-08-10", "2026-08-20", (Sighting("a", "2026-08-10", "2026-08-20", 2, 2),)
    )
    right = Record(
        "x",
        "2026-08-05",
        "2026-08-30",
        (Sighting("a", "2026-08-05", "2026-08-30", 1, 1), Sighting("b", DAY, DAY, 3, 1)),
    )
    merged = merge_records([left, right])
    assert merged.first_seen == "2026-08-05"
    assert merged.last_seen == "2026-08-30"
    assert {sighting.origin for sighting in merged.sightings} == {"a", "b"}


# Verify a repeated origin accumulates rather than duplicating
def test_merge_accumulates_one_origin() -> None:
    left = Record(
        "x", "2026-08-10", "2026-08-10", (Sighting("a", "2026-08-10", "2026-08-10", 2, 1),)
    )
    right = Record(
        "x", "2026-08-12", "2026-08-12", (Sighting("a", "2026-08-12", "2026-08-12", 2, 4),)
    )
    merged = merge_records([left, right])
    assert len(merged.sightings) == 1
    assert merged.sightings[0] == Sighting("a", "2026-08-10", "2026-08-12", 2, 5)


# Verify the origin list is capped so one value cannot grow without bound
def test_merge_caps_origins() -> None:
    many = [
        Record("x", DAY, DAY, (Sighting(f"o{index}", DAY, DAY, 2, 1),))
        for index in range(MAX_ORIGINS + 20)
    ]
    merged = merge_records(many)
    assert len(merged.sightings) == MAX_ORIGINS


# Verify an observation becomes a single sighting record
def test_record_from_observation() -> None:
    obs = Observation(value="evil.example", origin="circl", seen_on=DAY, credibility=2)
    record = Record.from_observation(obs)
    assert record.first_seen == record.last_seen == DAY
    assert record.sightings == (Sighting("circl", DAY, DAY, 2, 1),)


# Verify defang output for each type
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3.4", "1[.]2[.]3[.]4"),
        ("evil.example", "evil[.]example"),
        ("http://evil.example/a", "hxxp://evil[.]example/a"),
        ("https://evil.example/a", "hxxps://evil[.]example/a"),
        ("d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
    ],
)
def test_defang_examples(raw: str, expected: str) -> None:
    assert defang(raw) == expected


# Verify the defanging is easily reversible
@given(IOC_LIKE)
def test_defang_round_trips(raw: str) -> None:
    result = classify(raw)
    if isinstance(result, Canonical):
        assert refang(defang(result.value)) == result.value


# Verify no live scheme survives defanging
@given(IOC_LIKE)
def test_defang_removes_live_schemes(raw: str) -> None:
    result = classify(raw)
    if isinstance(result, Canonical):
        assert not any(marker in defang(result.value) for marker in LIVE_MARKERS)

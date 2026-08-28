"""Tests for sources."""

# Imports
import dataclasses
from iocs.sources import (
    REGISTRY,
    LicenseClass,
    Reliability,
    follow_prefixes,
    traits_by_origin,
    validate_registry,
)
from strategies import make_source

# Constants
FEED = make_source("probe_feed", "probe_origin")


# Verify the shipped registry breaks none of its own rules
def test_registry_is_valid() -> None:
    assert validate_registry() == []


# Verify every declared source says what it produces and where it came from
def test_registry_entries_are_complete() -> None:
    for source in REGISTRY:
        assert source.name and source.origin and source.url
        assert source.license_url.startswith("https://")


# Verify a repeated source name is reported
def test_duplicate_names_are_rejected() -> None:
    errors = validate_registry([FEED, FEED])
    assert any("duplicate" in message for message in errors)


# Verify a rate limit host that does not cover the url is reported
def test_host_must_match_the_url() -> None:
    errors = validate_registry([dataclasses.replace(FEED, host="elsewhere.example")])
    assert any("host does not match" in message for message in errors)


# Verify origins carry the trust and terms of the source that declares them
def test_traits_come_from_the_registry() -> None:
    traits = traits_by_origin()
    assert traits["circl"][1] is LicenseClass.PERMISSIVE
    assert traits["abusech"][1] is LicenseClass.RESTRICTED
    assert traits["circl"][0] is not Reliability.F


# Verify an index source contributes the prefix its followed urls start with
def test_follow_prefixes_cover_index_sources() -> None:
    source = dataclasses.replace(FEED, follow_template="https://host.example/files/{item}")
    assert follow_prefixes([source]) == frozenset({"https://host.example/files/"})


# Verify an index source that names no follow parser is reported
def test_follow_without_a_parser_is_rejected() -> None:
    broken = dataclasses.replace(
        FEED, follow_template="https://host.example/{item}", follow_parser=None
    )
    assert any("without naming a parser" in message for message in validate_registry([broken]))

"""Tests for filters."""

# Imports
import io
import ipaddress
import json
import pathlib
import tarfile
import pytest
from hypothesis import given
from hypothesis import strategies as st
from iocs.allowlist import (
    BENIGN_HASHES,
    PUBLIC_RESOLVERS,
    Allowlist,
    RangeSet,
    WarningLayer,
    apply_layers,
    load_warninglist,
    load_warninglist_archive,
)
from iocs.indicators import IocType

# Constants
CLOUD = ["104.16.0.0/13", "13.32.0.0/15"]
ROUTABLE = "93.184.216.34"
POPULAR = ["google.com", "microsoft.com", "cloudflare.com", "amazonaws.com"]


# Verify a range set answers membership for addresses inside and outside
@pytest.mark.parametrize(
    ("address", "inside"),
    [("104.16.0.5", True), ("13.33.255.255", True), ("93.184.216.34", False), ("8.8.8.8", False)],
)
def test_range_membership(address: str, inside: bool) -> None:
    assert RangeSet(CLOUD).contains(address) is inside


# Verify the range set agrees with a plain membership oracle
@given(st.ip_addresses(v=4).map(str))
def test_range_set_matches_oracle(address: str) -> None:
    nets = [ipaddress.ip_network(letter) for letter in CLOUD]
    expected = any(ipaddress.ip_address(address) in net for net in nets)
    assert RangeSet(CLOUD).contains(address) is expected


# Verify an empty range set never matches anything
@given(st.ip_addresses(v=4).map(str))
def test_empty_range_set_never_matches(address: str) -> None:
    assert not RangeSet([]).contains(address)


# Verify adding ranges can never lose a previously matching address
@given(st.ip_addresses(v=4).map(str))
def test_ranges_only_grow_coverage(address: str) -> None:
    small = RangeSet(CLOUD)
    larger = RangeSet([*CLOUD, "0.0.0.0/1"])
    assert not small.contains(address) or larger.contains(address)


# Verify ipv6 ranges are handled alongside ipv4
def test_ipv6_ranges() -> None:
    ranges = RangeSet(["2001:db8::/32"])
    assert ranges.contains("2001:db8::1")
    assert not ranges.contains("2001:dead::1")


# Verify a malformed range is skipped instead of raising
def test_malformed_ranges_are_skipped() -> None:
    ranges = RangeSet(["not-a-cidr", "104.16.0.0/13", "999.0.0.0/8"])
    assert ranges.contains("104.16.0.9")


# Verify reserved and unroutable addresses are always caught
@pytest.mark.parametrize(
    "address",
    ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1"],
)
def test_special_use_addresses_are_flagged(address: str) -> None:
    hit = Allowlist().check(IocType.IPV4, address)
    assert hit is not None
    assert hit.layer == "special_use"


# Verify public resolvers are never published as malicious
@pytest.mark.parametrize("address", sorted(PUBLIC_RESOLVERS))
def test_public_resolvers_are_flagged(address: str) -> None:
    hit = Allowlist().check(IocType.IPV4, address)
    assert hit is not None
    assert hit.layer == "public_resolver"


# Verify the empty file and test file digests are never published
@pytest.mark.parametrize("digest", sorted(BENIGN_HASHES))
def test_benign_hashes_are_flagged(digest: str) -> None:
    kind = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}[len(digest)]
    hit = Allowlist().check(kind, digest)
    assert hit is not None
    assert hit.layer == "benign_hash"


# Verify a routable address with no listing passes through untouched
def test_ordinary_address_passes() -> None:
    assert Allowlist().check(IocType.IPV4, ROUTABLE) is None


# Verify cloud ranges are caught once they are loaded
def test_cloud_ranges_are_flagged() -> None:
    allowlist = Allowlist().with_ranges("cloud", CLOUD)
    hit = allowlist.check(IocType.IPV4, "104.16.0.9")
    assert hit is not None
    assert hit.layer == "cloud"


# Verify popularity is never a reason to exclude a domain
@pytest.mark.parametrize("domain", POPULAR)
def test_popular_domains_are_never_excluded(domain: str) -> None:
    assert Allowlist().check(IocType.DOMAIN, domain) is None


# Verify a popularity layer cannot be registered at all
def test_popularity_layer_is_refused() -> None:
    with pytest.raises(ValueError, match="popularity"):
        Allowlist().with_values("popular_domains", POPULAR)


# Verify an explicitly listed domain is still excluded
def test_listed_domain_is_flagged() -> None:
    allowlist = Allowlist().with_values("sinkhole", ["sinkhole.example"])
    hit = allowlist.check(IocType.DOMAIN, "sinkhole.example")
    assert hit is not None
    assert hit.layer == "sinkhole"


# Verify every hit has a reason a human can audit
@given(st.sampled_from(["10.0.0.1", "8.8.8.8", "127.0.0.1"]))
def test_hits_carry_a_reason(address: str) -> None:
    hit = Allowlist().check(IocType.IPV4, address)
    assert hit is not None
    assert hit.reason
    assert hit.layer


# Verify checking is stable no matter how many times it runs
@given(st.ip_addresses(v=4).map(str))
def test_check_is_deterministic(address: str) -> None:
    allowlist: Allowlist = Allowlist().with_ranges("cloud", CLOUD)
    assert allowlist.check(IocType.IPV4, address) == allowlist.check(IocType.IPV4, address)


# Verify a misp warninglist document is read into a usable layer
def test_warninglist_is_parsed() -> None:
    payload = json.dumps(
        {"name": "Cloudflare IP ranges", "type": "cidr", "list": ["104.16.0.0/13", "1.1.1.0/24"]}
    ).encode()
    layer = load_warninglist(payload)
    assert layer is not None
    assert layer.name == "cloudflare_ip_ranges"
    assert layer.is_range
    assert layer.entries == ["104.16.0.0/13", "1.1.1.0/24"]


# Verify a string warninglist becomes an exact match layer
def test_string_warninglist_is_values() -> None:
    payload = json.dumps({"name": "Public DNS", "type": "string", "list": ["dns.example"]}).encode()
    layer = load_warninglist(payload)
    assert layer is not None
    assert not layer.is_range


# Verify match types we cannot follow are skipped rather than half applied
@pytest.mark.parametrize("kind", ["regex", "substring"])
def test_unsupported_match_types_are_skipped(kind: str) -> None:
    payload = json.dumps({"name": "x", "type": kind, "list": ["a"]}).encode()
    assert load_warninglist(payload) is None


# Verify a malformed warninglist is ignored instead of raising
@pytest.mark.parametrize("payload", [b"", b"{", b"null", b'{"name": "x"}'])
def test_malformed_warninglist_is_ignored(payload: bytes) -> None:
    assert load_warninglist(payload) is None


# Verify a popularity warninglist is rejected like any other popularity layer
def test_popularity_warninglist_is_refused() -> None:
    payload = json.dumps(
        {"name": "Top 1000 website from Alexa", "type": "string", "list": ["a.com"]}
    ).encode()
    layer = load_warninglist(payload)
    assert layer is not None
    with pytest.raises(ValueError, match="popularity"):
        Allowlist().with_values(layer.name, layer.entries)


# Verify every warninglist in a repository archive is loaded in one pass
def test_warninglist_archive_is_read(tmp_path: pathlib.Path) -> None:
    payloads = {
        "repo/lists/cloudflare/list.json": {
            "name": "Cloudflare",
            "type": "cidr",
            "list": ["104.16.0.0/13"],
        },
        "repo/lists/dns/list.json": {
            "name": "Public DNS",
            "type": "string",
            "list": ["dns.example"],
        },
        "repo/README.md": None,
    }
    archive = tmp_path / "lists.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name, body in payloads.items():
            blob = json.dumps(body).encode() if body else b"readme"
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            bundle.addfile(info, io.BytesIO(blob))
    layers = load_warninglist_archive(archive.read_bytes())
    assert {layer.name for layer in layers} == {"cloudflare", "public_dns"}


# Verify a corrupt archive yields nothing rather than raising
@pytest.mark.parametrize("payload", [b"", b"not-a-tarball", b"\x1f\x8b\x08bad"])
def test_corrupt_archive_is_ignored(payload: bytes) -> None:
    assert load_warninglist_archive(payload) == []


# Verify archive layers can be applied to build a working allowlist
def test_layers_build_an_allowlist(tmp_path: pathlib.Path) -> None:
    layer = WarningLayer("cdn_ranges", True, ["104.16.0.0/13"])
    allowlist = apply_layers(Allowlist(), [layer])
    hit = allowlist.check(IocType.IPV4, "104.16.5.5")
    assert hit is not None
    assert hit.layer == "cdn_ranges"


# Verify a popularity layer inside an archive is dropped, not applied
def test_popularity_layers_are_dropped() -> None:
    layers = [
        WarningLayer("top_1000_alexa", False, ["a.com"]),
        WarningLayer("tor_exits", False, ["b.com"]),
    ]
    allowlist = apply_layers(Allowlist(), layers)
    assert allowlist.check(IocType.DOMAIN, "a.com") is None
    assert allowlist.check(IocType.DOMAIN, "b.com") is not None


# Verify real ranking list names are recognised as popularity lists
@pytest.mark.parametrize(
    "name",
    [
        "top_1_000_000_domains_from_cloudflare_radar",
        "top_1000_website_from_alexa",
        "top_1000_websites_from_cisco_umbrella",
        "tranco_top_1m",
        "majestic_million",
        "list_of_most_popular_domains",
        "top_500_sites",
    ],
)
def test_ranking_lists_are_recognised(name: str) -> None:
    with pytest.raises(ValueError, match="popularity"):
        Allowlist().with_values(name, ["example.com"])


# Verify ordinary layer names are still accepted
@pytest.mark.parametrize(
    "name",
    ["cloudflare_ip_ranges", "known_aws_ranges", "tor_exit_nodes", "public_dns_resolvers"],
)
def test_ordinary_layer_names_are_accepted(name: str) -> None:
    assert Allowlist().with_values(name, ["example.com"]).values[name]

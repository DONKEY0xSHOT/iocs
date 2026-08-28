"""Shared builders that tests use to make example data."""

# Imports
import datetime
from hypothesis import strategies as st
from iocs.indicators import IocType, Record, Sighting
from iocs.sources import LicenseClass, Reliability, Source

# Constants
HEX = "0123456789abcdefABCDEF"
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
TLDS = ["com", "example", "net"]
LABELS = st.text(ALNUM, min_size=1, max_size=20)
DIGESTS = st.one_of(*[st.text(HEX, min_size=count, max_size=count) for count in (32, 40, 64)])
ADDRESSES = st.one_of(st.ip_addresses(v=4), st.ip_addresses(v=6)).map(str)
DOMAINS = st.builds(lambda label, tld: f"{label}.{tld}", LABELS, st.sampled_from(TLDS))
SCHEMES = st.sampled_from(["http", "https"])
URLS = st.builds(lambda seen, host, part: f"{seen}://{host}/{part}", SCHEMES, DOMAINS, LABELS)
DEFANGED = DOMAINS.map(lambda host: host.replace(".", "[.]"))
IOC_LIKE = st.one_of(DIGESTS, ADDRESSES, DOMAINS, URLS, DEFANGED, st.text(max_size=120))
ORIGIN_IDS = st.text("abcdefghijklmnopqrstuvwxyz0123456789_", min_size=1, max_size=12)
DAYS = st.dates(min_value=datetime.date(2000, 1, 1), max_value=datetime.date(2035, 1, 1)).map(
    lambda when: when.isoformat()
)
SIGHTINGS = st.builds(
    lambda origin, label, tld, cred, count: Sighting(
        origin, min(label, tld), max(label, tld), cred, count
    ),
    ORIGIN_IDS,
    DAYS,
    DAYS,
    st.integers(min_value=1, max_value=6),
    st.integers(min_value=1, max_value=9999),
)
RECORDS = st.builds(
    lambda value, seen: Record(
        value,
        min(item.first_seen for item in seen),
        max(item.last_seen for item in seen),
        tuple({item.origin: item for item in seen}.values()),
    ),
    DOMAINS,
    st.lists(SIGHTINGS, min_size=1, max_size=6),
)


# Build a small permissive source for tests that need one
def make_source(name: str, origin: str, kind: IocType = IocType.IPV4) -> Source:
    return Source(
        name=name,
        origin=origin,
        url=f"https://{origin}.example/list.txt",
        host=f"{origin}.example",
        parser="plaintext",
        produces=(kind,),
        license_class=LicenseClass.PERMISSIVE,
        license_id="MIT",
        license_url=f"https://{origin}.example/LICENSE",
        attribution=f"{origin} feed",
        reliability=Reliability.B,
    )

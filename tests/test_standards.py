"""Tests for the coding standards checker."""

# Imports
import pathlib
import tomllib
import pytest
from tools import check_standards

# Constants
FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "standards"
ALLOWED_RUNTIME_DEPS = {"httpx"}
DOC = '"""A module used by the checker tests."""'
HEAD = f"{DOC}\n\n# Imports\nimport os\n\n# Constants\nNAME = os.name\n"


# Collect rule codes for one fixture
def codes_for(name: str) -> set[str]:
    violations = check_standards.check_file(FIXTURES / name)
    return {item.code for item in violations}


# Verify a clean file passes
def test_good_fixture_is_clean() -> None:
    assert check_standards.check_file(FIXTURES / "good.py") == []


# Verify each broken fixture fires its rule
@pytest.mark.parametrize(
    ("fixture", "code"),
    [
        ("bad_preamble.py", "preamble"),
        ("bad_charset.py", "charset"),
        ("bad_placement.py", "placement"),
        ("bad_length.py", "length"),
        ("bad_divider.py", "divider"),
        ("bad_pii.py", "pii"),
    ],
)
def test_violating_fixture_fires(fixture: str, code: str) -> None:
    assert code in codes_for(fixture)


# Verify the module size budget
def test_module_size_budget(tmp_path: pathlib.Path) -> None:
    body = "\n".join(f"VALUE_{index} = {index}" for index in range(400))
    target = tmp_path / "big.py"
    target.write_text(f"{HEAD}{body}\n")
    assert "size-module" in {item.code for item in check_standards.check_file(target)}


# Verify inline comments fail but tooling pragmas pass
def test_inline_comment_rules(tmp_path: pathlib.Path) -> None:
    bad = tmp_path / "inline.py"
    bad.write_text(f"{HEAD}OTHER = os.sep  # trailing comment\n")
    assert "placement" in {item.code for item in check_standards.check_file(bad)}
    allowed = tmp_path / "pragma.py"
    allowed.write_text(f"{HEAD}OTHER = os.sep  # noqa: E501\n")
    assert "placement" not in {item.code for item in check_standards.check_file(allowed)}


# Verify preamble headers skip the placement rule
def test_preamble_headers_exempt_from_placement(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "noimports.py"
    target.write_text(f"{DOC}\n\n# Imports\n\n# Constants\nVALUE = 1\n")
    assert check_standards.check_file(target) == []


# Verify the runtime dependency allowlist
def test_runtime_dependency_allowlist() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    names = {item.split(">")[0].split("=")[0].strip() for item in data["project"]["dependencies"]}
    assert names == ALLOWED_RUNTIME_DEPS


# Verify plain comments pass untouched
def test_plain_comments_pass(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "plain.py"
    body = f"{DOC}\n\n# Imports\nimport os\n\n# Constants\n\n# Skip bad ones\nNAME = os.name\n"
    target.write_text(body)
    assert [item for item in check_standards.check_file(target) if item.code == "wording"] == []


# Verify very short names are rejected wherever they are introduced
@pytest.mark.parametrize(
    "body",
    [
        "def run(x: int) -> int:\n    return x",
        "def run() -> int:\n    s = 1\n    return s",
        "def run(items: list[int]) -> None:\n    for o in items:\n        print(o)",
        "def run(items: list[int]) -> list[int]:\n    return [v for v in items]",
    ],
)
def test_short_names_are_rejected(tmp_path: pathlib.Path, body: str) -> None:
    target = tmp_path / "short.py"
    target.write_text(f"{HEAD}\n\n{body}\n")
    assert "short-name" in {item.code for item in check_standards.check_file(target)}


# Verify a counting index and a discard are still allowed
def test_counting_names_are_allowed(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "counting.py"
    body = "def run(items: list[int]) -> None:\n    for i, _ in enumerate(items):\n        print(i)"
    target.write_text(f"{HEAD}\n\n{body}\n")
    assert "short-name" not in {item.code for item in check_standards.check_file(target)}


# Verify upper case constants and enum members may be short
def test_upper_case_short_names_are_allowed(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "consts.py"
    head = f"{DOC}\n\n# Imports\nfrom enum import StrEnum\n\n# Constants\n"
    body = f'CI = "ci"\n\n\nclass Grade(StrEnum):\n    {DOC}\n\n    A = "A"\n'
    target.write_text(head + body)
    assert "short-name" not in {item.code for item in check_standards.check_file(target)}


# Verify a file with no constants may leave that header out
def test_empty_sections_may_be_omitted(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "noconst.py"
    body = f"{DOC}\n\n# Imports\nimport os\n\n\ndef name() -> str:\n    return os.name\n"
    target.write_text(body)
    assert "preamble" not in {item.code for item in check_standards.check_file(target)}


# Verify a comment opening an indented block needs no blank line above it
def test_comment_opening_a_block_is_allowed(tmp_path: pathlib.Path) -> None:
    target = tmp_path / "block.py"
    lines = ["def run(items: list[int]) -> None:", "    for item in items:"]
    lines += ["        # explain it", "        print(item)"]
    body = "\n".join(lines)
    target.write_text(f"{HEAD}\n\n{body}\n")
    assert "placement" not in {item.code for item in check_standards.check_file(target)}


# Verify a name long enough to read as a sentence is rejected in the package
@pytest.mark.parametrize(
    "body",
    [
        "def collect_and_normalise_every_indicator() -> None:\n    return",
        "class TheThingThatHoldsAllOfTheCollectedRecords:\n    value = 1",
    ],
)
def test_long_names_are_rejected(tmp_path: pathlib.Path, body: str) -> None:
    target = tmp_path / "long.py"
    target.write_text(f"{HEAD}\n\n{body}\n")
    assert "long-name" in {item.code for item in check_standards.check_file(target)}


# Verify a name that fits the limit is accepted
def test_names_within_the_limit_pass(tmp_path: pathlib.Path) -> None:
    body = "def build_conditional_headers() -> None:\n    return"
    target = tmp_path / "fine.py"
    target.write_text(f"{HEAD}\n\n{body}\n")
    assert "long-name" not in {item.code for item in check_standards.check_file(target)}


# Verify a test file allows longer names, since a test name describes what it checks
def test_longer_names_allowed_in_tests(tmp_path: pathlib.Path) -> None:
    folder = tmp_path / "tests"
    folder.mkdir()
    body = "def test_collect_flags_a_feed_that_yields_nothing() -> None:\n    return"
    target = folder / "test_probe.py"
    target.write_text(f"{HEAD}\n\n{body}\n")
    assert "long-name" not in {item.code for item in check_standards.check_file(target)}

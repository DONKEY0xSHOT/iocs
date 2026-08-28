"""Tests for guards."""

# Imports
import ast
import pathlib
import re
import pytest
from iocs.allowlist import ALLOWLIST_PARSERS
from iocs.http import UrlGuard
from iocs.parsers import PARSERS
from iocs.sources import REGISTRY, follow_prefixes

# Constants
PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "iocs"
WORKFLOWS = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
NETWORK_MODULES = {
    "httpx",
    "socket",
    "ssl",
    "http",
    "http.client",
    "urllib.request",
    "urllib3",
    "requests",
    "asyncio",
}
DATA_MODULES = ("indicators", "parsers", "corpus", "allowlist", "sources")
NETWORK_ALLOWED = ("http", "cli")
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}
BANNED_IMPORTS = {"pickle", "marshal", "shelve", "subprocess", "os.system"}


# Collect every module name imported by one source file
def imports_of(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


# Verify modules that handle collected indicators cannot open a connection
@pytest.mark.parametrize("name", DATA_MODULES)
def test_data_modules_cannot_reach_the_network(name: str) -> None:
    found = imports_of(PACKAGE / f"{name}.py")
    assert not found & NETWORK_MODULES
    assert "iocs.http" not in found


# Verify only the fetch layer is allowed to import the http client
def test_only_fetch_imports_httpx() -> None:
    for path in PACKAGE.glob("*.py"):
        if path.stem in NETWORK_ALLOWED:
            continue
        assert "httpx" not in imports_of(path)


# Verify tls verification is never switched off anywhere in the package
def test_tls_is_never_disabled() -> None:
    for path in PACKAGE.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "verify=False" not in text
        assert "VERIFY_NONE" not in text
        assert "check_hostname" not in text


# Verify no module can execute arbitrary code or deserialise untrusted data
def test_no_dangerous_calls() -> None:
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in BANNED_CALLS
        assert not imports_of(path) & BANNED_IMPORTS


# Verify the guard rejects everything that is not a declared feed
def test_guard_default_is_refusal() -> None:
    guard = UrlGuard(frozenset())
    assert not guard.permits("https://evil.example/payload")
    assert not guard.permits("https://1.2.3.4/c2")
    assert guard.permits("https://api.github.com/repos/x/y")


# Verify every registry url is reachable and nothing else is
def test_guard_admits_exactly_the_registry() -> None:
    urls = frozenset(source.url for source in REGISTRY)
    guard = UrlGuard(urls)
    for source in REGISTRY:
        assert guard.permits(source.url)
    assert not guard.permits("https://unlisted.example/list.txt")


# Verify the scheduled workflow needs no credential beyond the built in token
def test_workflow_uses_only_the_builtin_token() -> None:
    text = WORKFLOWS.joinpath("collect.yml").read_text(encoding="utf-8")
    referenced = set(re.findall(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", text))
    assert referenced <= {"GITHUB_TOKEN"}


# Verify continuous integration runs the same checks the verify script does
@pytest.mark.parametrize("gate", ["verify.py"])
def test_ci_runs_every_gate(gate: str) -> None:
    assert gate in WORKFLOWS.joinpath("ci.yml").read_text(encoding="utf-8")


# Verify every declared source names a parser that actually exists
def test_every_source_has_a_real_parser() -> None:
    known = set(PARSERS) | set(ALLOWLIST_PARSERS)
    for source in REGISTRY:
        assert source.parser in known, f"{source.name} names a missing parser"


# Verify a source that follows an index also names the parser for what it fetches
def test_follow_sources_declare_both_parsers() -> None:
    for source in REGISTRY:
        if source.follow_template and source.produces:
            assert source.follow_parser in PARSERS, f"{source.name} follows without a parser"
            assert "{item}" in source.follow_template


# Verify every source that produces indicators can be fetched by the guard
def test_follow_targets_are_permitted() -> None:
    guard = UrlGuard(frozenset(source.url for source in REGISTRY), follow_prefixes(REGISTRY))
    for source in REGISTRY:
        if source.follow_template:
            assert guard.permits(source.follow_template.format(item="sample"))


# Verify the verify script itself covers every gate we care about
@pytest.mark.parametrize("gate", ["ruff", "check_standards", "mypy", "pytest"])
def test_verify_script_covers_every_gate(gate: str) -> None:
    text = (PACKAGE.parent / "tools" / "verify.py").read_text(encoding="utf-8")
    assert gate in text

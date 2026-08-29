"""The individual rules the coding standards checker applies."""

# Imports
import ast
import pathlib
import re
import tokenize
from dataclasses import dataclass

# Constants
# One module per concern means each is larger than when the package was split
# across fifteen files, so the budget tracks the shape we actually chose
MAX_MODULE_LINES = 340
MAX_PACKAGE_LINES = 2100
MAX_COMMENT_LINES = 2
PREAMBLE_IMPORTS = "# Imports"
PREAMBLE_CONSTANTS = "# Constants"
PREAMBLE_HEADERS = frozenset({PREAMBLE_IMPORTS, PREAMBLE_CONSTANTS})
BANNED_COMMENT_CHARS = ";"
PRAGMA = re.compile(r"#\s*(noqa|type:|pragma|pylint:|mypy:|ruff:)")
DIVIDER = re.compile(r"#\s*[-=*_#]{3,}")
TRAILER = re.compile(r"^[A-Za-z][A-Za-z-]*: ")
MIN_NAME_LENGTH = 3
MAX_NAME_LENGTH = 30

# A test name describes the behaviour it checks, so it needs more room than
# a name inside the package
MAX_TEST_NAME_LENGTH = 50
ALLOWED_SHORT_NAMES = frozenset({"_", "i"})
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", "fixtures"}
PII_PATTERNS = (
    re.compile(r"[A-Za-z]:[\\/]{1,2}Users[\\/]"),
    re.compile(r"/home/[a-z]"),
    re.compile(r"/Users/[A-Za-z]"),
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
)
IOC_PATTERNS = (
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
    re.compile(r"https?://"),
)


@dataclass(frozen=True)
class Violation:
    """One rule breach at a source location."""

    path: str
    line: int
    code: str
    message: str


# Reject non ascii and banned punctuation
def bad_chars(text: str) -> bool:
    return any(ord(char) < 32 or ord(char) > 126 or char in BANNED_COMMENT_CHARS for char in text)


# Report whether code precedes the comment on its line
def is_inline(tok: tokenize.TokenInfo, lines: list[str]) -> bool:
    return bool(lines[tok.start[0] - 1][: tok.start[1]].strip())


# Group consecutive standalone comments
def group_comments(
    comments: list[tokenize.TokenInfo], lines: list[str]
) -> list[list[tokenize.TokenInfo]]:
    grouped: list[list[tokenize.TokenInfo]] = []
    for tok in comments:
        standalone = not is_inline(tok, lines)
        chains = (
            grouped
            and standalone
            and not is_inline(grouped[-1][-1], lines)
            and tok.start[0] == grouped[-1][-1].start[0] + 1
        )
        if chains:
            grouped[-1].append(tok)
        else:
            grouped.append([tok])
    return grouped


# Check the section headers, which may be left out when the section is empty
def check_preamble(path: pathlib.Path, lines: list[str], tree: ast.Module) -> list[Violation]:
    found = []
    body = getattr(tree, "body", [])
    has_imports = any(isinstance(node, ast.Import | ast.ImportFrom) for node in body)
    has_constants = any(isinstance(node, ast.Assign | ast.AnnAssign) for node in body)
    present = {line.strip() for line in lines}
    if has_imports and PREAMBLE_IMPORTS not in present:
        found.append(Violation(str(path), 1, "preamble", "missing # Imports"))
    if has_constants and PREAMBLE_CONSTANTS not in present:
        found.append(Violation(str(path), 1, "preamble", "missing # Constants"))
    if not ast.get_docstring(tree):
        found.append(Violation(str(path), 1, "module-doc", "missing module docstring"))
    return found


# Every introduced name should say what it holds. Upper case names are constants
# and enum members, where a short name like A or CI is the real world spelling.
def check_names(path: pathlib.Path, tree: ast.Module) -> list[Violation]:
    found = []
    longest = MAX_TEST_NAME_LENGTH if "tests" in path.parts else MAX_NAME_LENGTH
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if len(node.name) > longest:
                found.append(
                    Violation(str(path), node.lineno, "long-name", f"name too long: {node.name}")
                )
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            named = [(node.id, node.lineno)]
        elif isinstance(node, ast.arg):
            named = [(node.arg, node.lineno)]
        else:
            continue
        for name, where in named:
            allowed = name in ALLOWED_SHORT_NAMES or name.isupper()
            short = len(name) < MIN_NAME_LENGTH and not allowed
            if short:
                found.append(Violation(str(path), where, "short-name", f"name too short: {name}"))
    return found


# Check one comment block against every comment rule. A comment opening an indented
# block needs no blank line above, because the formatter would strip it anyway.
def check_block(
    path: pathlib.Path, block: list[tokenize.TokenInfo], lines: list[str]
) -> list[Violation]:
    out = []
    first, last = block[0], block[-1]
    inline = is_inline(first, lines)
    if inline:
        if not PRAGMA.match(first.string):
            out.append(Violation(str(path), first.start[0], "placement", "inline comment"))
        return out
    if first.string.strip() in PREAMBLE_HEADERS:
        return out
    if len(block) > MAX_COMMENT_LINES:
        out.append(Violation(str(path), first.start[0], "length", "comment over two lines"))
    for tok in block:
        if bad_chars(tok.string):
            out.append(Violation(str(path), tok.start[0], "charset", "non ascii or semicolon"))
        if DIVIDER.match(tok.string):
            out.append(Violation(str(path), tok.start[0], "divider", "section divider"))
    above = first.start[0] - 2
    opens_block = above >= 0 and lines[above].rstrip().endswith(":")
    if above >= 0 and lines[above].strip() and not opens_block:
        out.append(Violation(str(path), first.start[0], "placement", "no blank line above"))
    below = last.start[0]
    if below >= len(lines) or not lines[below].strip():
        out.append(Violation(str(path), first.start[0], "placement", "not above code"))
    return out

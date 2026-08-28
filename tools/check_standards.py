"""Checks the code against this project's own writing and naming rules."""

# Imports
import argparse
import ast
import io
import pathlib
import sys
import tokenize

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.rules import (
    MAX_MODULE_LINES,
    MAX_PACKAGE_LINES,
    PII_PATTERNS,
    SKIP_DIRS,
    Violation,
    check_block,
    check_names,
    check_preamble,
    group_comments,
)

# Constants
DEFAULT_ROOTS = ["iocs", "tests", "tools"]


def check_file(path: pathlib.Path) -> list[Violation]:
    """Return all standards violations for one file."""

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    out = []
    if len(lines) > MAX_MODULE_LINES:
        out.append(Violation(str(path), 1, "size-module", f"{len(lines)} lines"))
    for number, line in enumerate(lines, start=1):
        if any(path.search(line) for path in PII_PATTERNS):
            out.append(Violation(str(path), number, "pii", "absolute path or address"))
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        tree = ast.parse(text)
    except (SyntaxError, tokenize.TokenError):
        out.append(Violation(str(path), 1, "parse", "file does not parse"))
        return out
    out.extend(check_preamble(path, lines, tree))
    comments = [token for token in tokens if token.type == tokenize.COMMENT]
    for block in group_comments(comments, lines):
        out.extend(check_block(path, block, lines))
    out.extend(check_names(path, tree))
    return out


def iter_sources(root: pathlib.Path) -> list[pathlib.Path]:
    """List checkable python files under a root."""

    return sorted(path for path in root.rglob("*.py") if not SKIP_DIRS.intersection(path.parts))


def check_paths(roots: list[pathlib.Path], budget_root: pathlib.Path) -> list[Violation]:
    """Return violations across all roots plus the package size budget."""

    out = []
    for root in roots:
        for path in iter_sources(root):
            out.extend(check_file(path))
    sizes = (
        len(path.read_text(encoding="utf-8").splitlines()) for path in iter_sources(budget_root)
    )
    total = sum(sizes)
    if total > MAX_PACKAGE_LINES:
        out.append(Violation(str(budget_root), 1, "size-package", f"{total} lines"))
    return out


def main() -> int:
    """Run the checker over the repository and report violations."""

    parser = argparse.ArgumentParser(description="Check project coding standards.")
    parser.add_argument("roots", nargs="*", default=DEFAULT_ROOTS)
    parser.add_argument("--budget-root", default="iocs")
    args = parser.parse_args()
    roots = [pathlib.Path(root) for root in args.roots if pathlib.Path(root).exists()]
    violations = check_paths(roots, pathlib.Path(args.budget_root))
    for item in violations:
        print(f"{item.path}:{item.line}: {item.code}: {item.message}")
    print(f"{len(violations)} violation(s)")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())

"""Runs every quality gate and reports one overall result."""

# Imports
import subprocess
import sys

# Constants
PYTHON = sys.executable

# Types are checked for this machine and again for linux, which ci runs on
GATES = (
    ("lint", [PYTHON, "-m", "ruff", "check", "."]),
    ("format", [PYTHON, "-m", "ruff", "format", "--check", "."]),
    ("standards", [PYTHON, "tools/check_standards.py", "iocs", "tests", "tools"]),
    ("types", [PYTHON, "-m", "mypy"]),
    ("types linux", [PYTHON, "-m", "mypy", "--platform", "linux"]),
    ("tests", [PYTHON, "-m", "pytest", "-q"]),
)


def main() -> int:
    """Run each gate in turn and report which ones failed."""

    failed = []
    for name, command in GATES:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        status = "ok" if result.returncode == 0 else "FAILED"
        print(f"{name:10} {status}")
        if result.returncode != 0:
            failed.append(name)
            print(result.stdout[-2000:] or result.stderr[-2000:])
    print("all gates passed" if not failed else f"failed: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

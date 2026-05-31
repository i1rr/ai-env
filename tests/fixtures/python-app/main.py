"""Minimal entry point for the Python fixture used by ai-env acceptance
tests.

The module deliberately avoids any third-party imports so the fixture
tree can be checked into the repository without a virtualenv, lockfile,
or network round-trip to PyPI.
"""

from __future__ import annotations

import sys


def greet(name: str | None) -> str:
    """Return a deterministic greeting suitable for assertion in tests."""
    if not name:
        return "hello, world"
    return f"hello, {name}"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    who = args[0] if args else "world"
    print(greet(who))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

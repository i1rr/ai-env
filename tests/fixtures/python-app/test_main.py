"""Tiny self-contained smoke test for the Python fixture.

Uses only the Python standard library so the fixture stays
dependency-free and can be exercised by `python test_main.py` inside a
sandbox that has no network access.
"""

from __future__ import annotations

import unittest

from main import greet


class GreetTest(unittest.TestCase):
    def test_named(self) -> None:
        self.assertEqual(greet("ai"), "hello, ai")

    def test_empty(self) -> None:
        self.assertEqual(greet(""), "hello, world")

    def test_none(self) -> None:
        self.assertEqual(greet(None), "hello, world")


if __name__ == "__main__":
    unittest.main()

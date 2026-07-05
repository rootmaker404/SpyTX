from __future__ import annotations

import unittest

from spytx import inspect_username


class UsernameTests(unittest.TestCase):
    def test_inspect_username_builds_public_links(self) -> None:
        result = inspect_username("@syntx404")
        self.assertEqual(result["username"], "syntx404")
        self.assertTrue(result["links"])
        self.assertIn("public profile", result["scope"])


if __name__ == "__main__":
    unittest.main()

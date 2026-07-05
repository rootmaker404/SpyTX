from __future__ import annotations

import unittest

from spytx import inspect_phone


class PhoneTests(unittest.TestCase):
    def test_inspect_phone_returns_public_metadata(self) -> None:
        result = inspect_phone("081234567890", "ID")
        self.assertEqual(result["e164"], "+6281234567890")
        self.assertTrue(result["possible"])
        self.assertIn("safe public phone metadata", result["scope"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from spytx import inspect_ip


class IpTests(unittest.TestCase):
    def test_inspect_ip_flags_address(self) -> None:
        result = inspect_ip("8.8.8.8")
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["version"], 4)


if __name__ == "__main__":
    unittest.main()

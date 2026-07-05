from __future__ import annotations

import unittest

from spytx import (
    inspect_check_ip,
    inspect_contacts,
    inspect_deep_ip,
    inspect_name,
    inspect_rdap,
    inspect_social,
    inspect_whois,
)


class PublicIntelTests(unittest.TestCase):
    def test_deep_ip_keeps_public_scope(self) -> None:
        result = inspect_deep_ip("8.8.8.8")
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertIn("risk", result)

    def test_check_ip_reports_visible_network_only(self) -> None:
        result = inspect_check_ip("8.8.8.8")
        self.assertIn("check", result)
        self.assertEqual(result["check"]["hidden_origin"], "not available from public metadata")

    def test_review_links(self) -> None:
        self.assertIn("iana", inspect_whois("example.com")["links"])
        self.assertTrue(inspect_contacts("example.com")["links"])
        self.assertIn("arin", inspect_rdap("8.8.8.8")["links"])

    def test_social_and_name(self) -> None:
        self.assertIn("links", inspect_social("syntx404"))
        self.assertIn("search_links", inspect_name("Ada Lovelace"))


if __name__ == "__main__":
    unittest.main()

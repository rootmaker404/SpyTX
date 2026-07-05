from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spytx.geo import (
    copy_geo,
    copy_gmaps,
    inspect_best_geo,
    inspect_geo,
    inspect_geo_sources,
    inspect_precision,
    save_geo_map,
)


def fake_geo_payload(url: str) -> dict[str, object]:
    if "ipwho.is" in url:
        return {
            "success": True,
            "country": "United States",
            "region": "California",
            "city": "Mountain View",
            "postal": "94043",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "timezone": {"id": "America/Los_Angeles"},
            "connection": {"asn": 15169, "isp": "Google", "org": "Google"},
        }
    return {
        "country": "US",
        "region": "California",
        "city": "Mountain View",
        "postal": "94043",
        "loc": "37.4056,-122.0775",
        "timezone": "America/Los_Angeles",
        "org": "AS15169 Google",
    }


class GeoTests(unittest.TestCase):
    @patch("spytx.geo._get_json", side_effect=fake_geo_payload)
    def test_geo_returns_best_source_and_precision(self, _mock_get_json) -> None:
        result = inspect_geo("8.8.8.8")
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["precision"]["grade"], "A")
        self.assertEqual(len(result["sources"]), 2)
        self.assertIn("google.com/maps", result["maps"])

    @patch("spytx.geo._get_json", side_effect=fake_geo_payload)
    def test_geo_helpers_keep_coordinates(self, _mock_get_json) -> None:
        best = inspect_best_geo("8.8.8.8")
        self.assertEqual(best["best"]["city"], "Mountain View")
        self.assertIn(",", copy_geo("8.8.8.8")["value"])
        self.assertIn("google.com/maps", copy_gmaps("8.8.8.8")["value"])
        self.assertEqual(inspect_precision("8.8.8.8")["precision"]["grade"], "A")
        self.assertEqual(len(inspect_geo_sources("8.8.8.8")["sources"]), 2)

    @patch("spytx.geo._get_json", side_effect=fake_geo_payload)
    def test_geo_map_writes_local_report(self, _mock_get_json) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            result = save_geo_map("8.8.8.8", output_dir=tmp)
            self.assertTrue(Path(result["file"]).exists())


if __name__ == "__main__":
    unittest.main()

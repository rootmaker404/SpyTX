from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spytx.reports import export_record, list_records, show_record, write_record


class ReportTests(unittest.TestCase):
    def test_records_can_be_listed_shown_and_exported(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            record_id = write_record("ip", {"ip": "8.8.8.8"}, output_dir=tmp)
            listing = list_records(output_dir=tmp)
            shown = show_record(record_id, output_dir=tmp)
            exported = export_record(record_id, "json", output_dir=tmp)

            self.assertEqual(listing["count"], 1)
            self.assertEqual(shown["id"], record_id)
            self.assertTrue(Path(exported["file"]).exists())


if __name__ == "__main__":
    unittest.main()

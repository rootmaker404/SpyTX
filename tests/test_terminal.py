from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from spytx.terminal import run_terminal


class TerminalTests(unittest.TestCase):
    def test_terminal_boots_without_arguments(self) -> None:
        output = io.StringIO()
        with patch("builtins.input", side_effect=["exit"]):
            with redirect_stdout(output):
                run_terminal()
        value = output.getvalue()
        self.assertIn("SpyTX terminal loaded", value)
        self.assertIn("[01] IP", value)


if __name__ == "__main__":
    unittest.main()

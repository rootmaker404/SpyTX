from __future__ import annotations

import sys

from spytx.cli import run as run_cli
from spytx.terminal import run_terminal


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(run_cli(sys.argv[1:]))
    run_terminal()

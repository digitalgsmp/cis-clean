"""Test package. Puts ``src`` on the path so the suite runs from a clean
checkout with no install step and no dependency."""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

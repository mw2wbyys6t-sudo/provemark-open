"""Test isolation without adding a dependency.

The progress ledger is appended by every full scan — useful in production, and
exactly what a test run must not do. ``conftest.py`` is imported by the test
runner before any test module, so pointing the ledger at a throwaway temp file
here is enough; no fixture (and no extra dependency) is required.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_SCRATCH = Path(tempfile.mkdtemp(prefix="provemark-tests-"))
os.environ["PROVEMARK_HISTORY_FILE"] = str(_SCRATCH / "history.jsonl")
os.environ.pop("PROVEMARK_QUIET_HISTORY", None)

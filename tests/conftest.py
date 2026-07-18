"""Shared pytest configuration.

Bootstraps sys.path so:
- `gate_fuzz` is importable from `src/`
- `gate` (gate-python) is importable per `GATE_PYTHON_SRC` env var or
  the workstream-5 sibling path default.

Also provides ``rust_cli_binary`` as a session fixture. Property test
files consume it; when the binary is absent, the fixture calls
``pytest.skip`` at collection time and produces skipped-not-errored
results in the pytest summary (per Item 19b: the six property test
files previously raised ``FileNotFoundError`` at import time when the
CLI binary was absent, producing 19 ERRORs instead of skips).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

_GP = os.environ.get(
    "GATE_PYTHON_SRC",
    str(HERE.parent.parent.parent / "workstream-5" / "gate-python"),
)
if _GP and _GP not in sys.path:
    sys.path.insert(0, _GP)


@pytest.fixture(scope="session")
def rust_cli_binary() -> Path:
    """Session fixture returning the built gate-rust-cli binary path.

    Skips the calling test at collection time (not at ERROR time) when
    the binary is absent. Property test files that require the binary
    take this fixture instead of calling ``default_binary_path()``
    themselves; the shared skip message is the single source of truth
    for how operators enable the differential-fuzz surface.
    """
    from gate_fuzz.protocol import default_binary_path
    binary = default_binary_path()
    if not binary.exists():
        pytest.skip(
            f"gate-rust-cli binary not found at {binary}; run "
            "`cargo build --release` in tools/gate-rust-cli/ first, "
            "or set GATE_RUST_CLI_BIN to an absolute path."
        )
    return binary

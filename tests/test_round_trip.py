"""L1 gate: round-trip subprocess sanity test.

Verifies the subprocess spawns, accepts one canonical_json request for
an empty object, and returns the expected `b'{}'` canonical bytes that
gate-python's `gate.hashing.canonical_json({})` produces. Subprocess
exits cleanly on stdin close.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make src/ importable when running pytest from the package root.
HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gate_fuzz.protocol import RustCliClient


def _gate_python_canonical_json_empty() -> bytes:
    """Reference oracle: gate-python's canonical_json({}) result.

    If gate-python is importable on sys.path (via GATE_PYTHON_SRC env
    var pointing at v1.4/workstream-5/gate-python/src), use it. Otherwise
    fall back to the literal expected value b"{}", which the W5
    canonical-JSON v001 vector confirms.
    """
    gate_python_src = os.environ.get("GATE_PYTHON_SRC")
    if gate_python_src and gate_python_src not in sys.path:
        sys.path.insert(0, gate_python_src)
    try:
        from gate.hashing import canonical_json  # type: ignore[import-not-found]
        return canonical_json({})
    except ImportError:
        # gate-python not on path; use the contract-asserted literal.
        return b"{}"


def test_round_trip_canonical_json_empty_object(rust_cli_binary):
    """L1 acceptance: subprocess spawns, exchanges one message, exits cleanly.

    Consumes the ``rust_cli_binary`` session fixture from conftest.py,
    which skips (not errors) this test when the binary is absent - so
    the skip message stays the single source of truth for operators.
    """
    expected = _gate_python_canonical_json_empty()

    with RustCliClient(rust_cli_binary) as client:
        actual = client.canonical_json({})

    assert actual == expected, (
        f"canonical_json({{}}) mismatch: rust returned {actual!r}, "
        f"gate-python (or contract literal) expects {expected!r}"
    )

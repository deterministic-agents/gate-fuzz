"""Shared property-test harness (L3.1).

Provides:

- `RustCli` fixture-like context manager: one long-lived `gate-rust-cli`
  subprocess per property test (SO1.2 path).
- `Check15EvidenceWriter`: emits JSON artifacts to
  `output/check15-evidence/<timestamp>.json` matching the SO1.4 shape
  (Section 5 of PHASE-1.md).
- Path resolution helpers for the gate-rust-cli binary and gate-python
  source tree.

Per the R2 mitigation, callers do NOT spawn a subprocess per example;
they reuse the per-test subprocess across many Hypothesis examples.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gate_fuzz import __version__ as GATE_FUZZ_VERSION
from gate_fuzz.protocol import RustCliClient, default_binary_path


# ----------------------------------------------------------------------
# gate-python import bootstrap
# ----------------------------------------------------------------------

DEFAULT_GATE_PYTHON_ENV_VAR = "GATE_PYTHON_SRC"


def ensure_gate_python_on_path() -> bool:
    """Add gate-python's package root to sys.path if needed.

    Resolves the path in this order:
    1. `GATE_PYTHON_SRC` env var.
    2. `../../workstream-5/gate-python/` relative to this file.

    Returns True if gate-python is importable after the bootstrap.
    """
    env_override = os.environ.get(DEFAULT_GATE_PYTHON_ENV_VAR)
    if env_override:
        candidate = Path(env_override)
    else:
        here = Path(__file__).resolve().parent
        candidate = here.parent.parent.parent / "workstream-5" / "gate-python"
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
    try:
        import gate.hashing  # noqa: F401
        return True
    except ImportError:
        return False


# ----------------------------------------------------------------------
# Per-property subprocess client
# ----------------------------------------------------------------------

class RustCli:
    """Context manager wrapping `RustCliClient` with binary auto-resolve.

    Use as:

        with RustCli() as cli:
            for example in hypothesis_draws:
                rust_result = cli.canonical_json(example)
                ...
    """

    def __init__(self, binary_path: Path | str | None = None) -> None:
        self._binary_path = Path(binary_path) if binary_path else default_binary_path()
        self._client: RustCliClient | None = None

    def __enter__(self) -> RustCliClient:
        self._client = RustCliClient(self._binary_path)
        self._client.start()
        return self._client

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        if self._client is not None:
            self._client.close()
            self._client = None


# ----------------------------------------------------------------------
# Check15 evidence artifact writer (SO1.4 shape)
# ----------------------------------------------------------------------

class Check15EvidenceWriter:
    """Emit Check15 evidence artifacts per the SO1.4-locked schema.

    Output directory: `output/check15-evidence/` relative to the
    gate-fuzz package root, or override via `output_dir`. One artifact
    per property test run aggregates all four case types
    (spoofed_sender, nonce_replay, invalid_signature, expired_envelope).
    """

    SCHEMA_VERSION = "v1.0"

    def __init__(
        self,
        property_name: str,
        output_dir: Path | str | None = None,
    ) -> None:
        self.property_name = property_name
        if output_dir is None:
            here = Path(__file__).resolve().parent
            output_dir = here.parent.parent / "output" / "check15-evidence"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._cases: list[dict[str, Any]] = []
        self._started_at = datetime.now(timezone.utc)

    def record_case(self, case: dict[str, Any]) -> None:
        """Append a case dict. Caller is responsible for the case shape;
        see PHASE-1.md Section 5 for the canonical examples.
        """
        self._cases.append(case)

    def flush(self) -> Path:
        """Write the artifact and return its path."""
        summary = self._build_summary()
        artifact = {
            "schema_version": self.SCHEMA_VERSION,
            "tool": "gate-fuzz",
            "tool_version": GATE_FUZZ_VERSION,
            "property": self.property_name,
            "test_run_timestamp": self._started_at.isoformat(),
            "test_cases": self._cases,
            "summary": summary,
        }
        # Filename uses YYYYMMDDTHHMMSS for sortability + uniqueness via PID.
        stamp = self._started_at.strftime("%Y%m%dT%H%M%S")
        path = self.output_dir / f"{stamp}-{os.getpid()}-{self.property_name}.json"
        path.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _build_summary(self) -> dict[str, Any]:
        py_accept = sum(1 for c in self._cases if self._py_verdict(c) is True)
        py_reject = sum(1 for c in self._cases if self._py_verdict(c) is False)
        rs_accept = sum(1 for c in self._cases if self._rs_verdict(c) is True)
        rs_reject = sum(1 for c in self._cases if self._rs_verdict(c) is False)
        parity = py_accept == rs_accept and py_reject == rs_reject
        return {
            "total_cases": len(self._cases),
            "python_accept_count": py_accept,
            "python_reject_count": py_reject,
            "rust_accept_count": rs_accept,
            "rust_reject_count": rs_reject,
            "parity": parity,
        }

    @staticmethod
    def _py_verdict(case: dict[str, Any]) -> bool | None:
        for key in ("python_verify_result", "replay_send_python_verify", "first_send_python_verify"):
            if key in case:
                return bool(case[key])
        return None

    @staticmethod
    def _rs_verdict(case: dict[str, Any]) -> bool | None:
        for key in ("rust_verify_result", "replay_send_rust_verify", "first_send_rust_verify"):
            if key in case:
                return bool(case[key])
        return None


# ----------------------------------------------------------------------
# Convenience: shared canonical_json reference oracle
# ----------------------------------------------------------------------

def gate_python_canonical_json(value: Any) -> bytes:
    """Wrap `gate.hashing.canonical_json`; assumes gate-python on path."""
    from gate.hashing import canonical_json
    return canonical_json(value)


def gate_python_gate_hash(value: Any) -> str:
    """Wrap `gate.hashing.gate_hash`."""
    from gate.hashing import gate_hash
    return gate_hash(value)

"""P2: canonical_json byte-equivalence across languages.

For any canonical-JSON-safe value `x`:

    gate_python.canonical_json(x) == gate_rust.canonical_json(x)

This is the foundational cross-language property. The W5 13-vector set
is the empirical baseline; this property extends coverage to randomly
generated values within the canonical-JSON subspace.

R7 mitigation: divergence here surfaces as a property failure with the
specific failing value (Hypothesis shrinking will minimise it).
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings

from gate_fuzz.harness import RustCli, ensure_gate_python_on_path, gate_python_canonical_json
from gate_fuzz.strategies import canonical_json_value

ensure_gate_python_on_path()

pytestmark = pytest.mark.property


@pytest.fixture(scope="module")
def rust_cli_session(rust_cli_binary):
    """Per-module subprocess, bound to the ``rust_cli_binary`` session
    fixture from conftest.py. That fixture skips (not errors) when the
    binary is absent, so this file no longer resolves the binary path
    itself at collection time.
    """
    with RustCli(rust_cli_binary) as client:
        yield client


@settings(
    max_examples=100,
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(value=canonical_json_value())
def test_canonical_json_byte_equivalent(value, rust_cli_session):
    py_bytes = gate_python_canonical_json(value)
    rs_bytes = rust_cli_session.canonical_json(value)
    assert py_bytes == rs_bytes, (
        f"canonical_json divergence: python={py_bytes!r}, rust={rs_bytes!r}, value={value!r}"
    )


@settings(
    max_examples=100,
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(value=canonical_json_value())
def test_gate_hash_equivalent(value, rust_cli_session):
    """Stronger formulation: same sha256 over canonical bytes -> same hash string."""
    from gate.hashing import gate_hash
    py_hash = gate_hash(value)
    rs_hash = rust_cli_session.gate_hash(value)
    assert py_hash == rs_hash, (
        f"gate_hash divergence: python={py_hash}, rust={rs_hash}, value={value!r}"
    )

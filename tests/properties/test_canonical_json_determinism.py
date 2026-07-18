"""P1: canonical_json is deterministic within each language.

For any canonical-JSON-safe value `x`:

    gate_python.canonical_json(x) == gate_python.canonical_json(x)
    gate_rust.canonical_json(x)   == gate_rust.canonical_json(x)

Single-language property; does not exercise cross-language equivalence
(that is P2's job).
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings

from gate_fuzz.harness import RustCli, ensure_gate_python_on_path
from gate_fuzz.strategies import canonical_json_value

ensure_gate_python_on_path()

pytestmark = pytest.mark.property


@settings(
    max_examples=100,
    deadline=1500,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(value=canonical_json_value())
def test_python_canonical_json_is_deterministic(value):
    """gate-python: same input -> same canonical bytes across calls."""
    from gate.hashing import canonical_json
    first = canonical_json(value)
    second = canonical_json(value)
    assert first == second


@pytest.fixture(scope="module")
def rust_cli_session(rust_cli_binary):
    """Per-module subprocess: spawned once for all examples in this file,
    bound to the ``rust_cli_binary`` session fixture from conftest.py.
    That fixture skips (not errors) when the binary is absent.
    """
    with RustCli(rust_cli_binary) as client:
        yield client


@settings(
    max_examples=100,
    deadline=1500,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(value=canonical_json_value())
def test_rust_canonical_json_is_deterministic(value, rust_cli_session):
    """gate-rust (via CLI): same input -> same canonical bytes across calls."""
    first = rust_cli_session.canonical_json(value)
    second = rust_cli_session.canonical_json(value)
    assert first == second

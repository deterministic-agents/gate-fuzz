"""P3: envelope hash byte-equivalence across languages.

For matching kwargs into `build_request` / `build_response`:

    gate_hash(gate_python.build_request(**kwargs))
        == gate_hash(gate_rust.build_request(**kwargs))

STATUS in W7 v1.0.0: this property is DEFERRED. The Rust CLI's
`build_request_envelope` and `build_response_envelope` ops return
INTERNAL_ERROR `NOT_YET_IMPLEMENTED` pending the structured-to-flat
kwargs translator that maps gate-python's 28 kwargs into gate-rust's
`ToolRequestBuilder` fluent API (which uses grouped methods like
`.agent(instance_id, name, version, attested)` and `.tool(name,
category, risk_tier, schema_hash)`).

The test is parked here so the file count matches PHASE-1.md (8
deliverables in L3) and so the activation path is obvious: once the
Rust envelope-builder dispatch lands, remove the `pytest.skip` marker
and run.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.property, pytest.mark.skip(
    reason="W7 v1.0.0: build_request_envelope / build_response_envelope return NOT_YET_IMPLEMENTED; see protocol.rs op_build_request_envelope. Activate when Rust envelope dispatch is wired."
)]


def test_build_request_envelope_hash_byte_equivalent():
    """Placeholder. See module docstring for activation path."""
    pytest.skip("deferred")


def test_build_response_envelope_hash_byte_equivalent():
    """Placeholder. See module docstring for activation path."""
    pytest.skip("deferred")

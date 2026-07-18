"""P4: ledger event hash byte-equivalence across languages.

For matching kwargs into `build_event`:

    gate_python.build_event(**kwargs)["hash_chain"]["event_hash"]
        == gate_rust.build_event(**kwargs).hash_chain.event_hash

Exercises the strip-event_hash-and-signatures-before-hashing pattern
from both sides (gate-python ledger.py lines 155-198; gate-rust
ledger.rs build_event + compute_event_hash).

STATUS in W7 v1.0.0: DEFERRED for the same reason as P3 (the Rust CLI's
`build_ledger_event` op returns NOT_YET_IMPLEMENTED pending the
structured-to-flat kwargs translator that maps gate-python's 17 kwargs
into the `BuildEventParams` struct with enum coercion for ActionType +
RetentionClass). Activation path identical to P3.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.property, pytest.mark.skip(
    reason="W7 v1.0.0: build_ledger_event returns NOT_YET_IMPLEMENTED; see protocol.rs op_build_ledger_event. Activate when Rust ledger dispatch is wired."
)]


def test_build_event_hash_byte_equivalent():
    """Placeholder. See module docstring for activation path."""
    pytest.skip("deferred")


def test_verify_chain_parity():
    """Placeholder. verify_chain over a Python-built event list compared
    against the Rust verifier. Deferred with the same dependency.
    """
    pytest.skip("deferred")

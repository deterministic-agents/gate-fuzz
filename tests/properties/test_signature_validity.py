"""P5: sign-verify roundtrip works within each language.

Per SO1.3 path-b reframing: ECDSA signatures are non-deterministic in
both gate-python (cryptography lib) and gate-rust (ring), so byte
equivalence across languages is NOT a property. This test is the sanity
check that each language's `sign_action -> verify_signature` roundtrip
holds for any payload + key.

The substantive cross-language property is P6 (verification symmetry)
in `test_verification_symmetry.py`.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings

from gate_fuzz.harness import RustCli, ensure_gate_python_on_path
from gate_fuzz.strategies import canonical_json_value, signing_key_material

ensure_gate_python_on_path()

pytestmark = pytest.mark.property


@pytest.fixture(scope="module")
def rust_cli_session(rust_cli_binary):
    """Per-module subprocess, bound to the ``rust_cli_binary`` session
    fixture from conftest.py, which skips (not errors) when the binary
    is absent.
    """
    with RustCli(rust_cli_binary) as client:
        yield client


@settings(
    max_examples=50,
    deadline=3000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(payload=canonical_json_value(), material=signing_key_material())
def test_python_sign_verify_roundtrip(payload, material):
    """gate-python: sign -> verify should pass on the original payload."""
    from cryptography.hazmat.primitives import serialization
    from gate.signing import sign_action, verify_signature

    private_key = serialization.load_der_private_key(material["pkcs8_der"], password=None)
    public_key = private_key.public_key()
    record = sign_action(payload=payload, private_key=private_key, key_id=material["key_id"])
    assert verify_signature(payload=payload, signature_record=record, public_key=public_key)


@settings(
    max_examples=50,
    deadline=3000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(payload=canonical_json_value(), material=signing_key_material())
def test_rust_sign_verify_roundtrip(payload, material, rust_cli_session):
    """gate-rust (via CLI): sign -> verify should pass on the original payload."""
    record = rust_cli_session.sign_action(
        payload=payload,
        private_key_pkcs8=material["pkcs8_der"],
        key_id=material["key_id"],
    )
    valid = rust_cli_session.verify_signature(
        payload=payload,
        signature_record=record,
        public_key_sec1=material["sec1_public"],
    )
    assert valid is True

"""P6: cross-language verification symmetry.

The substantive cross-language signing property (per SO1.3 path-b):

- A signature produced by gate-python MUST verify in gate-rust.
- A signature produced by gate-rust MUST verify in gate-python.

Byte equivalence on signatures is not claimed (ECDSA is
non-deterministic on both sides by default); only verification
symmetry is.

This property emits Check15 evidence (per SO1.4) for each test run.
The `Check15EvidenceWriter` aggregates the cases into one artifact at
`output/check15-evidence/<timestamp>.json`.

Case types emitted, each recording MEASURED python/rust verdicts (both
sides are run through their verify path; neither verdict is assumed):

- python_signs_rust_verifies  - symmetry direction 1
- rust_signs_python_verifies  - symmetry direction 2
- invalid_signature           - signature verified against a different
                                payload; both sides must reject
- spoofed_sender              - signature verified against a different
                                public key; both sides must reject

The nonce_replay and expired_envelope case types are NOT emitted here:
they are envelope-level semantics (nonce tracking, expiry timestamps)
that the sign/verify primitives in this file do not model. They depend
on the build_request_envelope / build_response_envelope CLI ops, which
still return NOT_YET_IMPLEMENTED (see
`test_envelope_hash_byte_equivalence.py`). Add them when the Rust
envelope-builder dispatch lands.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings

from gate_fuzz.harness import (
    Check15EvidenceWriter,
    RustCli,
    ensure_gate_python_on_path,
)
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


@pytest.fixture(scope="module")
def check15_writer():
    writer = Check15EvidenceWriter(property_name="test_verification_symmetry")
    yield writer
    path = writer.flush()
    print(f"\n[Check15 evidence artifact] {path}")


def _python_sign(payload, material):
    from cryptography.hazmat.primitives import serialization
    from gate.signing import sign_action

    private_key = serialization.load_der_private_key(material["pkcs8_der"], password=None)
    return sign_action(payload=payload, private_key=private_key, key_id=material["key_id"])


def _python_verify(payload, record, material):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
    from gate.signing import verify_signature

    # Reconstruct the public key object from SEC1 bytes.
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        SECP256R1(), material["sec1_public"]
    )
    return verify_signature(payload=payload, signature_record=record, public_key=public_key)


@settings(
    max_examples=30,
    deadline=4000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(payload=canonical_json_value(), material=signing_key_material())
def test_python_signature_verifies_in_rust(
    payload, material, rust_cli_session, check15_writer
):
    """Python signs; Rust verifies. Symmetry direction 1."""
    record = _python_sign(payload, material)
    # Measure both sides. The Python verdict is Python verifying its own
    # signature over the same payload - not assumed true because we made
    # the signature, but actually run through verify_signature.
    python_valid = _python_verify(payload, record, material)
    rust_valid = rust_cli_session.verify_signature(
        payload=payload,
        signature_record=record,
        public_key_sec1=material["sec1_public"],
    )
    check15_writer.record_case({
        "case": "python_signs_rust_verifies",
        "input_payload_summary": str(payload)[:80],
        "python_verify_result": python_valid,
        "rust_verify_result": rust_valid,
        "rationale": "Python-produced signature should be valid under Rust verification",
    })
    assert python_valid, "Python failed to verify its own signature"
    assert rust_valid, (
        f"Rust failed to verify a Python-signed payload: payload={payload!r}, "
        f"signature={record['signature']!r}"
    )


@settings(
    max_examples=30,
    deadline=4000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(payload=canonical_json_value(), material=signing_key_material())
def test_rust_signature_verifies_in_python(
    payload, material, rust_cli_session, check15_writer
):
    """Rust signs; Python verifies. Symmetry direction 2."""
    record = rust_cli_session.sign_action(
        payload=payload,
        private_key_pkcs8=material["pkcs8_der"],
        key_id=material["key_id"],
    )
    python_valid = _python_verify(payload, record, material)
    # Measure both sides. The Rust verdict is Rust verifying its own
    # signature over the same payload, run through the CLI verify op
    # rather than assumed true because Rust produced the signature.
    rust_valid = rust_cli_session.verify_signature(
        payload=payload,
        signature_record=record,
        public_key_sec1=material["sec1_public"],
    )
    check15_writer.record_case({
        "case": "rust_signs_python_verifies",
        "input_payload_summary": str(payload)[:80],
        "python_verify_result": python_valid,
        "rust_verify_result": rust_valid,
        "rationale": "Rust-produced signature should be valid under Python verification",
    })
    assert rust_valid, "Rust failed to verify its own signature"
    assert python_valid, (
        f"Python failed to verify a Rust-signed payload: payload={payload!r}, "
        f"signature={record['signature']!r}"
    )


@settings(
    max_examples=15,
    deadline=4000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(
    payload=canonical_json_value(),
    other_payload=canonical_json_value(),
    material=signing_key_material(),
)
def test_invalid_signature_rejected_in_both(
    payload, other_payload, material, rust_cli_session, check15_writer
):
    """Sign payload A, verify against payload B - should fail in both.

    Skipped via `assume()` if Hypothesis happens to draw two
    canonically-equal payloads.
    """
    from hypothesis import assume

    from gate.hashing import canonical_json
    assume(canonical_json(payload) != canonical_json(other_payload))

    record = _python_sign(payload, material)
    python_valid = _python_verify(other_payload, record, material)
    rust_valid = rust_cli_session.verify_signature(
        payload=other_payload,
        signature_record=record,
        public_key_sec1=material["sec1_public"],
    )
    check15_writer.record_case({
        "case": "invalid_signature",
        "input_payload_summary": str(payload)[:80],
        "signature_modification": "verified against unrelated payload",
        "python_verify_result": python_valid,
        "rust_verify_result": rust_valid,
        "rationale": "Both implementations should reject a signature over a different payload",
    })
    assert python_valid is False, "Python wrongly accepted invalid signature"
    assert rust_valid is False, "Rust wrongly accepted invalid signature"


@settings(
    max_examples=15,
    deadline=4000,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(
    payload=canonical_json_value(),
    signer_material=signing_key_material(),
    other_material=signing_key_material(),
)
def test_spoofed_sender_rejected_in_both(
    payload, signer_material, other_material, rust_cli_session, check15_writer
):
    """Sign with key A, verify against key B's public key - reject in both.

    This is the spoofed-sender case: a signature is genuine for the
    payload but attributed to (verified against) an unrelated public
    key. Both gate-python and gate-rust must reject it. `assume()`
    guards against the astronomically unlikely case of two draws
    yielding the same public key.
    """
    from hypothesis import assume

    assume(signer_material["sec1_public"] != other_material["sec1_public"])

    record = _python_sign(payload, signer_material)
    # Verify the genuine signature against the WRONG public key.
    python_valid = _python_verify(payload, record, other_material)
    rust_valid = rust_cli_session.verify_signature(
        payload=payload,
        signature_record=record,
        public_key_sec1=other_material["sec1_public"],
    )
    check15_writer.record_case({
        "case": "spoofed_sender",
        "input_payload_summary": str(payload)[:80],
        "signature_modification": "verified against a different signer's public key",
        "python_verify_result": python_valid,
        "rust_verify_result": rust_valid,
        "rationale": "Both implementations should reject a signature attributed to the wrong key",
    })
    assert python_valid is False, "Python wrongly accepted a spoofed-sender signature"
    assert rust_valid is False, "Rust wrongly accepted a spoofed-sender signature"

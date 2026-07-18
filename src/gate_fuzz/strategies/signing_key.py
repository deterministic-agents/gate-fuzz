"""P-256 signing key strategy (L2.4).

Generates valid P-256 keypairs usable by both gate-python (via
`cryptography` lib) and gate-rust (via `ring`). Both languages are
RFC 5480 / RFC 5915 PKCS8 compatible. The strategy yields a tuple of
`(private_key_pkcs8_der, public_key_sec1_uncompressed)` byte strings so
property tests can sign in one language and verify in the other.

Per SO1.3 path-b: ECDSA signatures are non-deterministic in both
libraries; this strategy generates KEYS only, not signatures. The
properties P5 (single-language sign-verify roundtrip) and P6
(cross-language verification symmetry) exercise the signing operations
themselves at test time.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st


def _generate_p256_keypair() -> tuple[bytes, bytes]:
    """Return `(pkcs8_der, sec1_uncompressed_public_key)`.

    Uses the `cryptography` library (already a gate-python dep). The
    resulting PKCS8 DER bytes are loadable by gate-rust's
    `SigningKey::from_pkcs8`; the SEC1 uncompressed public key bytes
    (0x04 || X || Y, 65 bytes for P-256) are the cross-language wire
    format for `verify_signature`.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    pkcs8_der = private.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = private.public_key()
    sec1_uncompressed = public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return pkcs8_der, sec1_uncompressed


def signing_key_material() -> st.SearchStrategy[dict[str, Any]]:
    """Strategy yielding `{"pkcs8_der": bytes, "sec1_public": bytes, "key_id": str}`.

    Each draw generates a fresh keypair via `cryptography` and returns
    the cross-language bytes. Keys are not cached; each example draws
    a new key.
    """
    return st.builds(_make_key_dict, st.integers(min_value=0, max_value=2**31 - 1))


def _make_key_dict(key_index: int) -> dict[str, Any]:
    pkcs8_der, sec1_uncompressed = _generate_p256_keypair()
    return {
        "pkcs8_der": pkcs8_der,
        "sec1_public": sec1_uncompressed,
        "key_id": f"fuzz-key-{key_index:08x}",
    }

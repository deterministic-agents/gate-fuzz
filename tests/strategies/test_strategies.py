"""Meta-tests for the L2 strategies (PHASE-1 R1 mitigation).

Strategies that short-circuit at validation produce property tests
that pass trivially. These meta-tests assert that of N generated
examples, all N reach the verifier successfully:

- json_value examples canonicalise via gate-python's
  `hashing.canonical_json` without raising.
- build_request_params examples construct a valid envelope via
  `gate.envelopes.build_request` without raising.
- build_event_params examples construct a valid ledger event via
  `gate.ledger.build_event` without raising.
- signing_key_material yields a valid PKCS8 DER + SEC1 public key
  pair (`cryptography` can load both).

A strategy's outputs failing more than 50% of the time at the
verifier is treated as broken.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings

# Make src/ importable
HERE = Path(__file__).resolve().parent
SRC = HERE.parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Optionally pull in gate-python from the source tree. The gate package
# lives at the repo root, not under src/; the previous default appended
# an incorrect /src suffix that silently produced ImportError inside a
# try/except and masked the missing coverage. Aligned with the pyproject
# comment and README example.
_GP_SRC = os.environ.get(
    "GATE_PYTHON_SRC",
    str(HERE.parent.parent.parent.parent / "workstream-5" / "gate-python"),
)
if _GP_SRC and _GP_SRC not in sys.path:
    sys.path.insert(0, _GP_SRC)

try:
    from gate.hashing import canonical_json  # type: ignore[import-not-found]
    from gate.envelopes import build_request  # type: ignore[import-not-found]
    from gate.ledger import build_event  # type: ignore[import-not-found]
    GATE_PYTHON_AVAILABLE = True
except ImportError:
    GATE_PYTHON_AVAILABLE = False

from gate_fuzz.strategies import (
    build_event_params,
    build_request_params,
    canonical_json_value,
    negative_float_value,
    signing_key_material,
)


pytestmark = pytest.mark.meta


# ----------------------------------------------------------------------
# json_value reach test
# ----------------------------------------------------------------------

# Use small budget for fast meta-tests; the real property tests do bigger
_META_SETTINGS = settings(
    max_examples=50,
    deadline=2000,  # ms per example; CI runners can be slow
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)


@_META_SETTINGS
@given(value=canonical_json_value())
def test_json_value_canonicalises_without_raising(value):
    """Every generated json_value MUST be canonicalisable.

    Failure means the json_value strategy produced something that
    Python's `json.dumps(value, allow_nan=False, sort_keys=True,
    ensure_ascii=False, separators=(",", ":"))` rejects, which would
    surface as P1/P2 property failures rather than meta-failure.
    """
    import json
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert isinstance(encoded, str)


@pytest.mark.skipif(not GATE_PYTHON_AVAILABLE, reason="gate-python not importable")
@_META_SETTINGS
@given(value=canonical_json_value())
def test_json_value_canonicalises_via_gate_python(value):
    """gate-python's canonical_json accepts every generated example."""
    output = canonical_json(value)
    assert isinstance(output, bytes)


# ----------------------------------------------------------------------
# Block B float subspace reach tests
# ----------------------------------------------------------------------

@pytest.mark.skipif(not GATE_PYTHON_AVAILABLE, reason="gate-python not importable")
@_META_SETTINGS
@given(value=canonical_json_value())
def test_positive_floats_are_in_round4_subspace(value):
    """Every float reachable from `canonical_json_value` is round4-stable.

    Block B locks the hashable float surface to the four-decimal-place
    subspace. `_round4_float` folds random draws through round4 before
    they enter the value tree, so applying round4 again must be a no-op
    for every float the strategy can produce. A float that shifts under
    a second round4 would be outside the subspace and would surface as a
    P2 byte-equivalence divergence.
    """
    from gate.rounding import round4

    def _check(v):
        if isinstance(v, float):
            assert round4(v) == v, f"float {v!r} is outside the round4 subspace"
        elif isinstance(v, list):
            for item in v:
                _check(item)
        elif isinstance(v, dict):
            for item in v.values():
                _check(item)

    _check(value)


@pytest.mark.skipif(not GATE_PYTHON_AVAILABLE, reason="gate-python not importable")
@_META_SETTINGS
@given(value=negative_float_value())
def test_negative_floats_are_outside_round4_subspace(value):
    """Every `negative_float_value` draw genuinely needs normalisation.

    A negative/rejection strategy that accidentally produced in-subspace
    values would assert nothing. Each draw must therefore be shifted by
    round4 (it carries precision beyond four decimal places, or collapses
    toward zero), matching the `negative_vectors` documentation in
    gate-python's canonical_json_vectors.json.
    """
    from gate.rounding import round4

    assert round4(value) != value, (
        f"negative float {value!r} was already in the round4 subspace; "
        "it does not exercise the normalisation path"
    )


# ----------------------------------------------------------------------
# build_request_params reach test
# ----------------------------------------------------------------------

@pytest.mark.skipif(not GATE_PYTHON_AVAILABLE, reason="gate-python not importable")
@_META_SETTINGS
@given(params=build_request_params())
def test_build_request_params_reaches_envelope_construction(params):
    """Every generated kwargs set MUST produce a valid envelope.

    If gate-python's `build_request` rejects the kwargs, the strategy
    is generating invalid examples and downstream P3 envelope-hash
    properties would short-circuit at validation rather than exercise
    the cross-language hash logic.
    """
    envelope = build_request(**params)
    assert isinstance(envelope, dict)
    # Required envelope fields per the schema
    assert envelope["run_id"] == params["run_id"]
    assert envelope["tenant_id"] == params["tenant_id"]


# ----------------------------------------------------------------------
# build_event_params reach test
# ----------------------------------------------------------------------

@pytest.mark.skipif(not GATE_PYTHON_AVAILABLE, reason="gate-python not importable")
@_META_SETTINGS
@given(params=build_event_params())
def test_build_event_params_reaches_event_construction(params):
    """Every generated kwargs set MUST produce a valid LedgerEvent."""
    event = build_event(**params)
    assert isinstance(event, dict)
    assert event["run_id"] == params["run_id"]
    assert event["tenant_id"] == params["tenant_id"]


# ----------------------------------------------------------------------
# signing_key_material reach test
# ----------------------------------------------------------------------

@_META_SETTINGS
@given(material=signing_key_material())
def test_signing_key_material_produces_loadable_pkcs8(material):
    """Every keypair MUST be loadable by `cryptography`.

    PKCS8 round-trip via the cryptography lib establishes the key
    material is valid; this is the same path gate-python uses
    internally, so a load failure here would fail P5/P6 property
    tests too.
    """
    from cryptography.hazmat.primitives import serialization

    loaded = serialization.load_der_private_key(material["pkcs8_der"], password=None)
    assert loaded is not None
    assert len(material["sec1_public"]) == 65, "P-256 uncompressed = 65 bytes"
    assert material["sec1_public"][0] == 0x04, "SEC1 uncompressed prefix is 0x04"
    assert material["key_id"].startswith("fuzz-key-")

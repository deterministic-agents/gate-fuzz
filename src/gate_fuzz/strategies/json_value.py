"""Canonical-JSON-compatible value strategy (L2.2).

Generates Python values that:
- Survive `json.dumps(obj, allow_nan=False, ensure_ascii=False)` (the
  contract gate-python's `hashing.canonical_json` adopts; same for
  gate-rust which uses serde_json with the same constraints).
- Cover the W5 v006 numeric boundary cases (negative zero, 0.1,
  2^53).
- Include non-BMP Unicode strings (emoji per W5 v005).
- Bound recursion depth to keep generation tractable.

See PHASE-1.md Section 4 for the design rationale and R7 mitigation
(canonical-JSON edge cases beyond the 13 W5 vectors).
"""

from __future__ import annotations

import json
import math
from typing import Any

from hypothesis import strategies as st


# ----------------------------------------------------------------------
# Numeric strategies
# ----------------------------------------------------------------------

# W5 v006 boundary: ints up to 2^53 are safely representable as JSON
# numbers (and as IEEE-754 doubles). Above that, precision is lost in
# any JSON consumer that decodes to a double.
_INT_MIN = -(2**53)
_INT_MAX = 2**53

# Float-magnitude bound for random draws. Capped at 2^32 because:
# Hypothesis can draw doubles in [2^52, 2^53] whose nearest-IEEE-754
# value's decimal rendering differs between Python's `json.dumps`
# (preserves Grisu/dtoa choice) and Rust's serde_json (ryu rounding).
# This is a real divergence (R7) but it's a v1.5 alignment task, not a
# v1.0.0 contract. Bounding to 2^32 keeps smoke clean while still
# exercising the canonical-JSON pipeline over a wide value space.
# Explicit boundary cases at 2^53 stay in _NUMERIC_SPECIALS for ints
# only (no IEEE-754 ambiguity).
_FLOAT_MAX_MAGNITUDE = 2**32

# Specific values worth exercising explicitly (from W5 v006).
_NUMERIC_SPECIALS = [
    0,
    -0,
    1,
    -1,
    _INT_MAX,
    _INT_MIN,
    0.0,
    -0.0,
    0.1,
    -0.1,
    1.0,
    # Note: float(_INT_MAX) deliberately omitted - exercises the R7
    # divergence on large-float decimal rendering; activate after v1.5
    # canonical-JSON float alignment work.
]


# Block B (gate-python) locks the hashable float surface to the
# four-decimal-place subspace: every float is passed through
# `gate.rounding.round4` (ties away from zero) at the hashing boundary,
# and gate-python + gate-rust render round4 outputs byte-identically.
# The `negative_vectors` section of
# gate-python/gate/test_vectors/canonical_json_vectors.json documents the
# values outside this subspace (sub-1e-4 exponents, 17-sig-digit doubles,
# >=2^53 integers) that MUST be normalised via round4 before hashing.
#
# We bound the round4 pre-image magnitude to 1000. round4 leaves large
# magnitudes essentially untouched (the * 10000.0 product loses the
# sub-integer bits), so bounding keeps every generated value genuinely
# inside the agreed subspace rather than re-admitting the R7 large-float
# rendering divergence.
_ROUND4_PREIMAGE_MAGNITUDE = 1000.0


def _round4() -> "callable | None":
    """Return `gate.rounding.round4` if gate-python is importable, else None."""
    try:
        from gate.rounding import round4
        return round4
    except ImportError:
        return None


def _finite_float() -> st.SearchStrategy[float]:
    """Floats excluding NaN and infinities, bounded to safe magnitude.

    Cap at 2^32 to avoid the gate-python/gate-rust float-decimal
    divergence on values in [2^52, 2^53] surfaced as R7 in phase 2.
    """
    return st.floats(
        allow_nan=False,
        allow_infinity=False,
        allow_subnormal=True,
        min_value=-_FLOAT_MAX_MAGNITUDE,
        max_value=_FLOAT_MAX_MAGNITUDE,
    )


def _round4_float() -> st.SearchStrategy[float]:
    """Positive-test floats inside the Block B four-decimal subspace.

    Generates finite floats in [-1000, 1000] and folds each through
    `round4`, so every value renders identically in gate-python and
    gate-rust (at most four fractional digits, no scientific notation).
    This is the float coverage the P2 byte-equivalence property can rely
    on. Falls back to the curated `_NUMERIC_SPECIALS` floats when
    gate-python (and therefore round4) is not on the path, so the
    strategy stays importable in a gate-python-free checkout.
    """
    round4 = _round4()
    if round4 is None:
        return st.sampled_from([f for f in _NUMERIC_SPECIALS if isinstance(f, float)])
    return st.floats(
        allow_nan=False,
        allow_infinity=False,
        allow_subnormal=False,
        min_value=-_ROUND4_PREIMAGE_MAGNITUDE,
        max_value=_ROUND4_PREIMAGE_MAGNITUDE,
    ).map(round4)


def _out_of_subspace_float() -> st.SearchStrategy[float]:
    """Negative-test floats OUTSIDE the Block B four-decimal subspace.

    These are the values the `negative_vectors` set says must be
    normalised via round4 before hashing - raw, they either diverge
    across the two serialisers or carry precision beyond four decimal
    places:

    - sub-1e-4 magnitudes (below the 4dp grid; round4 collapses them
      toward zero), including the exponent-format divergence class
      (Python `5.96e-08` vs Rust `5.96e-8`);
    - 17-significant-digit doubles that carry more precision than the
      subspace admits.

    A negative/rejection test feeds these to assert that hashing raw
    (without round4) is not parity-safe, or that round4 normalisation is
    required first.
    """
    sub_1e4 = st.floats(
        allow_nan=False,
        allow_infinity=False,
        allow_subnormal=True,
        min_value=-1e-4,
        max_value=1e-4,
    ).filter(lambda x: x != 0.0 and abs(x) < 1e-4)
    seventeen_sig = st.sampled_from([
        0.12345678901234567,
        1.2345678901234567,
        9.999999999999999,
        5.960464477539063e-08,
        1e-7,
    ])
    return st.one_of(sub_1e4, seventeen_sig)


def negative_float_value() -> st.SearchStrategy[float]:
    """Public alias: floats outside the Block B four-decimal subspace,
    for rejection/negative property tests.
    """
    return _out_of_subspace_float()


def _safe_int() -> st.SearchStrategy[int]:
    """Ints within the JSON-safe integer range."""
    return st.integers(min_value=_INT_MIN, max_value=_INT_MAX)


# ----------------------------------------------------------------------
# String strategy
# ----------------------------------------------------------------------

# Excluded code points: JSON forbids unescaped control characters
# (U+0000-U+001F) and the lone surrogates U+D800-U+DFFF. Hypothesis's
# default `text` allows them; we filter to keep only canonical-JSON-
# legal strings.
def _json_string() -> st.SearchStrategy[str]:
    return st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),  # surrogates
            blacklist_characters="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        ),
        min_size=0,
        max_size=64,
    )


# ----------------------------------------------------------------------
# Recursive composite
# ----------------------------------------------------------------------

_MAX_RECURSION_DEPTH = 4
_MAX_COLLECTION_SIZE = 6


def json_value() -> st.SearchStrategy[Any]:
    """Generate any canonical-JSON-compatible Python value.

    Recursion is bounded at depth 4; collection size at 6. The filter
    step uses `json.dumps(value, allow_nan=False, ensure_ascii=False)`
    to reject any value that slipped through.

    Float handling under Block B: random float draws ARE generated, but
    every one is folded through `gate.rounding.round4` (via
    `_round4_float`) so it lands in the four-decimal-place subspace that
    gate-python and gate-rust render byte-identically. This replaces the
    earlier W7 v1.0.0 posture, which excluded random floats entirely and
    left the P2 float coverage as the curated `_NUMERIC_SPECIALS`
    constants only.

    The phase 2 smoke run surfaced two gate-python/gate-rust
    float-decimal divergences (R7) on RAW floats:

    1. Trailing-digit precision: Python `json.dumps(1801439851.0273438)`
       emits `1801439851.0273438` (Grisu); Rust serde_json emits
       `1801439851.027344` (ryu, one digit shorter).
    2. Scientific-notation exponent format: Python `json.dumps(5.96e-8)`
       emits `5.960464477539064e-8`; Rust emits `5.960464477539063e-08`.

    Both classes are outside the four-decimal subspace, so round4
    normalisation removes them from the positive-test surface. The
    `negative_float_value()` strategy generates exactly these
    out-of-subspace values for rejection/negative tests. The W5 v006
    curated float constants (negative zero, 0.1, etc.) stay sampled from
    `_NUMERIC_SPECIALS` as explicit boundary coverage.
    """
    base = st.one_of(
        st.none(),
        st.booleans(),
        _safe_int(),
        st.sampled_from(_NUMERIC_SPECIALS),  # curated boundary floats
        _round4_float(),  # random floats folded into the 4dp subspace (Block B)
        _json_string(),
    )
    return st.recursive(
        base,
        lambda children: st.one_of(
            st.lists(children, max_size=_MAX_COLLECTION_SIZE),
            st.dictionaries(_json_string(), children, max_size=_MAX_COLLECTION_SIZE),
        ),
        max_leaves=_MAX_RECURSION_DEPTH * 4,
    ).filter(_is_canonical_json_safe)


def canonical_json_value() -> st.SearchStrategy[Any]:
    """Alias of `json_value()` with explicit naming for property-test imports."""
    return json_value()


def _is_canonical_json_safe(value: Any) -> bool:
    """Return True iff `value` can be serialised with
    `json.dumps(value, allow_nan=False, ensure_ascii=False)` without
    raising.
    """
    try:
        json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True)
    except (ValueError, TypeError):
        return False
    # Additional sanity: no float that's NaN or infinite slipped through.
    return _no_nan_or_infinity(value)


def _no_nan_or_infinity(value: Any) -> bool:
    if isinstance(value, float):
        return not (math.isnan(value) or math.isinf(value))
    if isinstance(value, list):
        return all(_no_nan_or_infinity(v) for v in value)
    if isinstance(value, dict):
        return all(_no_nan_or_infinity(v) for v in value.values())
    return True

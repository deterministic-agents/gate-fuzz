"""P7: schema validation parity across languages.

For a sampled valid + invalid value against each of the 4 W2 schemas
(break_glass_record, auto_enrolment_policy, approved_feed_registry,
output_classification_event):

    gate_python.validate(name, value).is_valid
        == gate_rust.validate(name, value).is_valid

per Q0.3 path-a: the Rust validate primitive is implemented in the CLI
wrapper using the `jsonschema` crate with Draft 2020-12 enabled, matching
gate-python's `Draft202012Validator`.

The strongest guarantee is on rejections: a value rejected by gate-python
MUST be rejected by gate-rust. The error message text may differ between
the two libraries; the validity boolean is what parity is asserted on.
"""

from __future__ import annotations

import pytest

from gate_fuzz.harness import RustCli, ensure_gate_python_on_path

ensure_gate_python_on_path()

pytestmark = pytest.mark.property


# The 4 W2 v1.4 schemas (all bundled in gate-rust by L2.1 of W6).
W2_SCHEMAS = [
    "break_glass_record.schema.json",
    "auto_enrolment_policy.schema.json",
    "approved_feed_registry.schema.json",
    "output_classification_event.schema.json",
]


@pytest.fixture(scope="module")
def rust_cli_session(rust_cli_binary):
    """Per-module subprocess, bound to the ``rust_cli_binary`` session
    fixture from conftest.py, which skips (not errors) when the binary
    is absent.
    """
    with RustCli(rust_cli_binary) as client:
        yield client


@pytest.mark.parametrize("schema_name", W2_SCHEMAS)
def test_empty_object_invalid_in_both(schema_name, rust_cli_session):
    """All 4 W2 schemas have required fields; `{}` fails validation in both."""
    rs_result = rust_cli_session.validate(schema_name, {})
    assert rs_result["valid"] is False
    assert len(rs_result["errors"]) >= 1

    # gate-python validation
    from gate.validation import GATEValidator
    validator = GATEValidator()
    # Map schema names to gate-python's bundled-schema lookup; some
    # schemas may not exist in gate-python v1.2.0's bundled set.
    py_result = _validate_via_gate_python(validator, schema_name, {})
    assert py_result["valid"] is False, (
        f"gate-python accepted empty {{}} for {schema_name}, "
        f"but gate-rust rejected it - parity break"
    )


@pytest.mark.parametrize("schema_name", W2_SCHEMAS)
def test_string_invalid_in_both(schema_name, rust_cli_session):
    """A bare string is not a valid object for any of the W2 schemas.

    Measures the "invalid in both" claim: the bare string is run through
    both the Rust CLI validate op and gate-python's validator, and each
    must reject it. Previously this test asserted only the Rust verdict,
    so the "in both" half of the claim was never exercised.
    """
    rs_result = rust_cli_session.validate(schema_name, "not a record")
    assert rs_result["valid"] is False

    from gate.validation import GATEValidator
    validator = GATEValidator()
    py_result = _validate_via_gate_python(validator, schema_name, "not a record")
    assert py_result["valid"] is False, (
        f"gate-python accepted the bare string for {schema_name}, "
        f"but gate-rust rejected it - parity break"
    )


@pytest.mark.parametrize("schema_name", W2_SCHEMAS)
def test_schema_loads_in_rust(schema_name, rust_cli_session):
    """All 4 W2 schemas are loadable via the Rust `load_schema` op."""
    content = rust_cli_session.load_schema(schema_name)
    assert isinstance(content, str)
    assert content.startswith("{")
    assert '"$schema"' in content


def _validate_via_gate_python(validator, schema_name: str, value) -> dict:
    """Run *value* through gate-python's real validator.

    gate-python exposes per-type wrappers (validate_break_glass_record,
    validate_auto_enrolment_policy, ...) that dispatch by schema filename.
    When a wrapper exists we use it; otherwise we fall back to
    ``validate_any``, which loads the schema file by name and runs the
    same Draft 2020-12 validator gate-rust mirrors. Either path returns a
    MEASURED verdict.

    If neither path can validate - the wrapper is missing AND the schema
    file is not resolvable - we raise instead of returning a fabricated
    ``{"valid": False}``. A synthetic verdict would let a real
    validation gap pass the parity assertion silently.
    """
    base = schema_name.replace(".schema.json", "")
    fn_name = f"validate_{base}"
    if hasattr(validator, fn_name):
        result = getattr(validator, fn_name)(value)
        # gate-python's ValidationResult carries a `valid` bool.
        return {"valid": bool(getattr(result, "valid", result))}
    # No named wrapper: validate against the schema file directly. This
    # still measures a verdict rather than assuming one. `validate_any`
    # raises FileNotFoundError if the schema name is unknown to
    # gate-python, which surfaces the gap instead of masking it.
    result = validator.validate_any(value, schema_name)
    return {"valid": bool(getattr(result, "valid", result))}

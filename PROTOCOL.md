# gate-fuzz cross-language protocol (line-delimited JSON)

Protocol version: **v1.0**

This document is the source-of-truth contract between:

- the Python harness (writes JSON lines to stdin of a long-lived `gate-rust-cli` subprocess; reads JSON lines from stdout)
- the Rust CLI wrapper (`tools/gate-rust-cli/`; reads stdin lines; writes stdout lines; reserves stderr for non-protocol diagnostics)

Both sides MUST implement this spec verbatim. Divergence is a bug in the diverging side.

## Wire format

One JSON object per line. UTF-8 encoding. `\n` (LF) terminator after each JSON object. Lines that fail to parse as JSON return a structured `MALFORMED_JSON` error on the response channel, with `id` set to `null` if the malformed line had no id.

## Request envelope

```json
{
  "id": 1,
  "op": "canonical_json",
  "params": { ... operation-specific ... }
}
```

- `id` (integer): monotonically increasing per process; correlates request to response.
- `op` (string): one of the 10 operations enumerated below.
- `params` (object): operation-specific parameter set. Empty object `{}` when the op takes no parameters.

## Response envelope

Success:

```json
{
  "id": 1,
  "result": { ... operation-specific ... },
  "error": null
}
```

Error:

```json
{
  "id": 1,
  "result": null,
  "error": {
    "code": "...",
    "message": "..."
  }
}
```

- `id`: mirrors the request id. Out-of-order responses are tolerated by id-keyed buffering on the Python side.
- `result`: operation-specific result, OR `null` if error.
- `error`: structured error object, OR `null` if success.
  - `error.code`: one of `MALFORMED_JSON`, `UNKNOWN_OP`, `INVALID_PARAMS`, `INTERNAL_ERROR`, `SCHEMA_NOT_FOUND`, `PROTOCOL_VERSION_MISMATCH`.
  - `error.message`: human-readable diagnostic.

### Error handling contract

**Structural errors** return a structured `error`:

- `MALFORMED_JSON`: input line did not parse as JSON, or was not a JSON object.
- `UNKNOWN_OP`: `op` field did not match any of the 10 operations.
- `INVALID_PARAMS`: `params` was missing required fields, or had a field of the wrong type.
- `INTERNAL_ERROR`: gate-rust raised an unexpected error.
- `SCHEMA_NOT_FOUND`: `load_schema` called with a name not in the bundle.
- `PROTOCOL_VERSION_MISMATCH`: handshake detected version skew (reserved for future use).

**Domain errors** return a `result` with the domain-specific shape:

- `verify_signature` returns `result: { "valid": false }` (never an error) on signature mismatch.
- `validate` returns `result: { "valid": false, "errors": [...] }` on validation failure.
- `verify_chain` returns `result: { "passed": false, ... }` on chain break.

This keeps protocol-level errors (machine readable, structural) distinct from domain-level negative outcomes (semantic, expected in property tests).

## Operations (10)

### 1. canonical_json

- Source: gate-python `hashing.canonical_json(obj) -> bytes`; gate-rust `canonical_json::canonical_json(value: &Value) -> Vec<u8>`.
- params:
  ```json
  { "value": <any JSON value> }
  ```
- result:
  ```json
  { "bytes": "<base64-encoded canonical bytes>" }
  ```
  Base64 standard encoding (RFC 4648) so the bytes round-trip cleanly through the JSON wire.

### 2. gate_hash

- Source: gate-python `hashing.gate_hash(obj) -> str` (returns `"sha256:<64 hex>"`); gate-rust `canonical_json::gate_hash(value: &Value) -> String`.
- params:
  ```json
  { "value": <any JSON value> }
  ```
- result:
  ```json
  { "hash": "sha256:<64 lowercase hex>" }
  ```

### 3. build_request_envelope

- Source: gate-python `envelopes.build_request` (28 kwargs); gate-rust `envelopes::ToolRequestBuilder`.
- params: object mirroring gate-python kwargs verbatim. Optional kwargs (image_digest, config_hash, toolset_hash, idempotency_key, prompt_bundle_hash, orm_risk_score, tokens_remaining, tool_calls_remaining, cost_usd_remaining, source_labels, span_id, control_plane_version) absent when not provided; required kwargs always present.
- result:
  ```json
  { "envelope": <full envelope dict> }
  ```

### 4. build_response_envelope

- Source: gate-python `envelopes.build_response`; gate-rust `envelopes::ToolResponseBuilder`.
- params: object mirroring gate-python kwargs. Optional kwargs: snapshot_uri, replay_trace_step_id, error_code.
- result:
  ```json
  { "envelope": <full envelope dict> }
  ```

### 5. build_ledger_event

- Source: gate-python `ledger.build_event`; gate-rust `ledger::build_event`.
- params: object mirroring gate-python kwargs. Optional kwargs: trace_id, replay_trace_step_id, hitl_approval_id, invariant_bundle_hash, tool_name, agent_instance_id, sequence_number. `GENESIS` constant for prev_event_hash MUST match across languages (gate-python `ledger.GENESIS` / gate-rust `ledger::GENESIS`).
- result:
  ```json
  { "event": <full event dict> }
  ```

### 6. verify_chain

- Source: gate-python `ledger.verify_chain(events, expected_first_prev_hash=GENESIS)`; gate-rust `ledger::verify_chain(events, expected_first_prev_hash)`.
- params:
  ```json
  {
    "events": [<event dict>, ...],
    "expected_first_prev_hash": "sha256:000...000"
  }
  ```
- result:
  ```json
  {
    "passed": true,
    "events_verified": 3,
    "errors": []
  }
  ```

### 7. sign_action

- Source: gate-python `signing.sign_action(*, payload, private_key, key_id)`; gate-rust `signing::sign_action(payload, signing_key, key_id)`.
- params:
  ```json
  {
    "payload": <any JSON value>,
    "private_key_pkcs8_b64": "<base64-encoded PKCS8 DER>",
    "key_id": "key-001"
  }
  ```
- result:
  ```json
  {
    "signature_record": {
      "signing_key_id": "key-001",
      "algorithm": "ES256",
      "signature": "<base64url-no-padding>"
    }
  }
  ```

### 8. verify_signature

- Source: gate-python `signing.verify_signature(*, payload, signature_record, public_key)`; gate-rust `signing::verify_signature(payload, record, public_key_bytes)`.
- params:
  ```json
  {
    "payload": <any JSON value>,
    "signature_record": { "signing_key_id": "...", "algorithm": "ES256", "signature": "..." },
    "public_key_sec1_b64": "<base64-encoded SEC1 uncompressed public key bytes>"
  }
  ```
- result:
  ```json
  { "valid": true }
  ```
  `valid: false` on signature mismatch is a domain outcome, NOT a structural error. The op never returns a structural error for an invalid signature; the response always succeeds and the boolean carries the outcome.

### 9. load_schema

- Source: gate-rust `schemas::load_schema(name: &str) -> Option<&'static str>`. The Rust side is the load surface (gate-python uses its `validation` module's bundled `GATEValidator`; the protocol exposes the gate-rust loader for parity).
- params:
  ```json
  { "name": "break_glass_record.schema.json" }
  ```
- result on hit:
  ```json
  { "schema_json": "<schema content as JSON string>" }
  ```
  on miss: structured error `SCHEMA_NOT_FOUND`.

### 10. validate

- Source: gate-rust CLI wrapper backed by the `jsonschema` crate (Draft 2020-12 to match gate-python's `Draft202012Validator` per validation.py line 33). gate-python equivalent: `validation.validate_tool_envelope` and the 11 other validator functions.
- params:
  ```json
  {
    "schema_name": "tool_envelope.schema.json",
    "value": <any JSON value>
  }
  ```
- result:
  ```json
  {
    "valid": true,
    "errors": []
  }
  ```
  or on failure:
  ```json
  {
    "valid": false,
    "errors": ["<error message>", "..."]
  }
  ```

## Subprocess lifecycle

Per SO1.2 (one subprocess per property test):

- Python harness spawns the CLI binary at property-test entry.
- The subprocess runs the stdin -> dispatch -> stdout loop forever (or until stdin closes).
- Python sends N requests per Hypothesis example, awaits N matching responses (by id).
- At property-test exit, Python closes the subprocess's stdin; subprocess reads EOF, exits cleanly.

Per-example overhead is one JSON write + one JSON read over the pre-open pipes (sub-millisecond).

## Protocol versioning

This document carries a `Protocol version` header at the top. v1.0 matches the W7 v1.0.0 release. Future protocol revisions (additive ops; widened param sets) bump the version. Both sides should assert the same version on subprocess startup; mismatched version returns a structured error `PROTOCOL_VERSION_MISMATCH`. Version negotiation is reserved for v1.1 and beyond.

## References

- W7 PHASE-1.md Section 3 (the planning-time source for this spec).
- gate-python v1.2.0 source surfaces verified verbatim at phase 1 closure.
- gate-rust v1.0.0 source surfaces verified verbatim at phase 1 closure.

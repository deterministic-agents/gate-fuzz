//! Protocol handlers for gate-rust-cli.
//!
//! Each of the 10 ops in PROTOCOL.md is dispatched here. Handlers take a
//! `&Value` of operation-specific params and return `Result<Value,
//! ProtocolError>`. The `main.rs` stdin/stdout loop wraps each handler
//! result in the response envelope shape.
//!
//! For the L1 phase 2 deliverable, the four envelope/ledger handlers
//! (build_request_envelope, build_response_envelope, build_ledger_event,
//! verify_chain) return `INTERNAL_ERROR { code: "NOT_YET_IMPLEMENTED" }`
//! pending L3 property work. The handlers exist (dispatch works) but
//! the body of each is a single error return until the L3 properties
//! consume them; surfacing the half-built state here keeps L1's
//! cargo-build gate green while preserving the protocol surface.

use base64::Engine;
use jsonschema::JSONSchema;
use serde_json::{json, Value};

use gate_rust::canonical_json::{canonical_json, gate_hash};
use gate_rust::schemas::load_schema;
use gate_rust::signing::{sign_action, verify_signature, SignatureRecord, SigningKey};

/// Protocol-level errors that map to structured `error.code` strings in
/// the response envelope.
#[derive(Debug)]
pub enum ProtocolError {
    UnknownOp(String),
    InvalidParams(String),
    Internal(String),
    SchemaNotFound(String),
}

impl ProtocolError {
    /// Convert to the structured error block in the response envelope.
    pub fn to_error_value(&self) -> Value {
        let (code, message) = match self {
            ProtocolError::UnknownOp(op) => ("UNKNOWN_OP", format!("unknown op: {}", op)),
            ProtocolError::InvalidParams(msg) => ("INVALID_PARAMS", msg.clone()),
            ProtocolError::Internal(msg) => ("INTERNAL_ERROR", msg.clone()),
            ProtocolError::SchemaNotFound(name) => {
                ("SCHEMA_NOT_FOUND", format!("schema not found: {}", name))
            }
        };
        json!({ "code": code, "message": message })
    }
}

/// Dispatch a single op to its handler.
pub fn dispatch(op: &str, params: &Value) -> Result<Value, ProtocolError> {
    match op {
        "canonical_json" => op_canonical_json(params),
        "gate_hash" => op_gate_hash(params),
        "build_request_envelope" => op_build_request_envelope(params),
        "build_response_envelope" => op_build_response_envelope(params),
        "build_ledger_event" => op_build_ledger_event(params),
        "verify_chain" => op_verify_chain(params),
        "sign_action" => op_sign_action(params),
        "verify_signature" => op_verify_signature(params),
        "load_schema" => op_load_schema(params),
        "validate" => op_validate(params),
        other => Err(ProtocolError::UnknownOp(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pull a required field from a params object as a `&Value`.
fn require<'a>(params: &'a Value, field: &str) -> Result<&'a Value, ProtocolError> {
    params
        .get(field)
        .ok_or_else(|| ProtocolError::InvalidParams(format!("missing field: {}", field)))
}

/// Pull a required string from a params object.
fn require_str<'a>(params: &'a Value, field: &str) -> Result<&'a str, ProtocolError> {
    require(params, field)?
        .as_str()
        .ok_or_else(|| ProtocolError::InvalidParams(format!("field {} must be string", field)))
}

fn b64_decode_standard(s: &str, field: &str) -> Result<Vec<u8>, ProtocolError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| {
            ProtocolError::InvalidParams(format!("{} failed base64 decode: {}", field, e))
        })
}

// ---------------------------------------------------------------------------
// Op 1: canonical_json
// ---------------------------------------------------------------------------

fn op_canonical_json(params: &Value) -> Result<Value, ProtocolError> {
    let value = require(params, "value")?;
    let bytes = canonical_json(value);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(json!({ "bytes": b64 }))
}

// ---------------------------------------------------------------------------
// Op 2: gate_hash
// ---------------------------------------------------------------------------

fn op_gate_hash(params: &Value) -> Result<Value, ProtocolError> {
    let value = require(params, "value")?;
    let hash = gate_hash(value);
    Ok(json!({ "hash": hash }))
}

// ---------------------------------------------------------------------------
// Op 3: build_request_envelope (L3 deferred)
// ---------------------------------------------------------------------------

fn op_build_request_envelope(_params: &Value) -> Result<Value, ProtocolError> {
    Err(ProtocolError::Internal(
        "NOT_YET_IMPLEMENTED: build_request_envelope is wired in W7 phase 2 L3 (envelope hash byte equivalence property)".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Op 4: build_response_envelope (L3 deferred)
// ---------------------------------------------------------------------------

fn op_build_response_envelope(_params: &Value) -> Result<Value, ProtocolError> {
    Err(ProtocolError::Internal(
        "NOT_YET_IMPLEMENTED: build_response_envelope is wired in W7 phase 2 L3".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Op 5: build_ledger_event (L3 deferred)
// ---------------------------------------------------------------------------

fn op_build_ledger_event(_params: &Value) -> Result<Value, ProtocolError> {
    Err(ProtocolError::Internal(
        "NOT_YET_IMPLEMENTED: build_ledger_event is wired in W7 phase 2 L3 (ledger event hash byte equivalence property)".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Op 6: verify_chain (L3 deferred)
// ---------------------------------------------------------------------------

fn op_verify_chain(_params: &Value) -> Result<Value, ProtocolError> {
    Err(ProtocolError::Internal(
        "NOT_YET_IMPLEMENTED: verify_chain is wired in W7 phase 2 L3".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Op 7: sign_action
// ---------------------------------------------------------------------------

fn op_sign_action(params: &Value) -> Result<Value, ProtocolError> {
    let payload = require(params, "payload")?;
    let pkcs8_b64 = require_str(params, "private_key_pkcs8_b64")?;
    let key_id = require_str(params, "key_id")?;
    let pkcs8 = b64_decode_standard(pkcs8_b64, "private_key_pkcs8_b64")?;
    let signing_key = SigningKey::from_pkcs8(&pkcs8)
        .map_err(|e| ProtocolError::Internal(format!("from_pkcs8: {}", e)))?;
    let record = sign_action(payload, &signing_key, key_id)
        .map_err(|e| ProtocolError::Internal(format!("sign_action: {}", e)))?;
    Ok(json!({
        "signature_record": {
            "signing_key_id": record.signing_key_id,
            "algorithm": record.algorithm,
            "signature": record.signature,
        }
    }))
}

// ---------------------------------------------------------------------------
// Op 8: verify_signature
// ---------------------------------------------------------------------------

fn op_verify_signature(params: &Value) -> Result<Value, ProtocolError> {
    let payload = require(params, "payload")?;
    let record_value = require(params, "signature_record")?;
    let pub_b64 = require_str(params, "public_key_sec1_b64")?;
    let record: SignatureRecord = serde_json::from_value(record_value.clone())
        .map_err(|e| ProtocolError::InvalidParams(format!("signature_record: {}", e)))?;
    let pub_bytes = b64_decode_standard(pub_b64, "public_key_sec1_b64")?;
    let valid = verify_signature(payload, &record, &pub_bytes)
        .map_err(|e| ProtocolError::Internal(format!("verify_signature: {}", e)))?;
    Ok(json!({ "valid": valid }))
}

// ---------------------------------------------------------------------------
// Op 9: load_schema
// ---------------------------------------------------------------------------

fn op_load_schema(params: &Value) -> Result<Value, ProtocolError> {
    let name = require_str(params, "name")?;
    match load_schema(name) {
        Some(content) => Ok(json!({ "schema_json": content })),
        None => Err(ProtocolError::SchemaNotFound(name.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Op 10: validate
// ---------------------------------------------------------------------------

fn op_validate(params: &Value) -> Result<Value, ProtocolError> {
    let schema_name = require_str(params, "schema_name")?;
    let value = require(params, "value")?;
    let schema_str = load_schema(schema_name)
        .ok_or_else(|| ProtocolError::SchemaNotFound(schema_name.to_string()))?;
    let schema_value: Value = serde_json::from_str(schema_str)
        .map_err(|e| ProtocolError::Internal(format!("schema parse: {}", e)))?;
    let compiled = JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema_value)
        .map_err(|e| ProtocolError::Internal(format!("schema compile: {}", e)))?;
    let result = compiled.validate(value);
    match result {
        Ok(_) => Ok(json!({ "valid": true, "errors": [] })),
        Err(errors) => {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            Ok(json!({ "valid": false, "errors": messages }))
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_empty_object() {
        let result = dispatch("canonical_json", &json!({"value": {}}))
            .expect("dispatch should succeed for canonical_json {}");
        let bytes_b64 = result
            .get("bytes")
            .and_then(|v| v.as_str())
            .expect("result.bytes should be a string");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(bytes_b64)
            .expect("base64 should decode");
        assert_eq!(bytes, b"{}");
    }

    #[test]
    fn gate_hash_known_value() {
        let result = dispatch("gate_hash", &json!({"value": {}}))
            .expect("dispatch should succeed for gate_hash {}");
        let hash = result.get("hash").and_then(|v| v.as_str()).expect("hash");
        // sha256("{}") = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
        assert_eq!(
            hash,
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn unknown_op_returns_unknown_op_error() {
        let err = dispatch("nope", &json!({})).expect_err("nope should not dispatch");
        match err {
            ProtocolError::UnknownOp(s) => assert_eq!(s, "nope"),
            other => panic!("expected UnknownOp, got {:?}", other),
        }
    }

    #[test]
    fn load_schema_known() {
        let result =
            dispatch("load_schema", &json!({"name": "break_glass_record.schema.json"}))
                .expect("dispatch load_schema");
        assert!(result.get("schema_json").is_some());
    }

    #[test]
    fn load_schema_missing() {
        let err = dispatch("load_schema", &json!({"name": "no_such.schema.json"}))
            .expect_err("missing schema returns error");
        match err {
            ProtocolError::SchemaNotFound(_) => {}
            other => panic!("expected SchemaNotFound, got {:?}", other),
        }
    }

    #[test]
    fn validate_against_known_schema_with_invalid_value() {
        // empty object is invalid against break_glass_record (required fields)
        let result = dispatch(
            "validate",
            &json!({
                "schema_name": "break_glass_record.schema.json",
                "value": {}
            }),
        )
        .expect("dispatch validate");
        assert_eq!(result["valid"], json!(false));
        assert!(result["errors"].as_array().unwrap().len() >= 1);
    }

    #[test]
    fn deferred_op_returns_internal_error_with_marker() {
        let err = dispatch("build_request_envelope", &json!({}))
            .expect_err("deferred op returns error");
        match err {
            ProtocolError::Internal(msg) => assert!(msg.contains("NOT_YET_IMPLEMENTED")),
            other => panic!("expected Internal, got {:?}", other),
        }
    }
}

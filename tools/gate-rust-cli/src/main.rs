//! gate-rust-cli: line-delimited JSON wrapper over the gate-rust crate.
//!
//! See PROTOCOL.md (sibling repo `v1.4/workstream-7/gate-fuzz/PROTOCOL.md`)
//! for the full protocol specification.

use std::io::{self, BufRead, Write};

use serde_json::{json, Value};

mod protocol;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line_result in stdin.lock().lines() {
        let response = match line_result {
            Ok(line) => handle_line(&line),
            Err(e) => json!({
                "id": Value::Null,
                "result": Value::Null,
                "error": {
                    "code": "MALFORMED_JSON",
                    "message": format!("stdin read error: {}", e),
                }
            }),
        };
        let serialised = serde_json::to_string(&response)
            .unwrap_or_else(|e| format!(r#"{{"id":null,"result":null,"error":{{"code":"INTERNAL_ERROR","message":"serialisation error: {}"}}}}"#, e));
        writeln!(stdout_lock, "{}", serialised).expect("stdout write");
        stdout_lock.flush().expect("stdout flush");
    }
}

/// Parse a single stdin line + dispatch + format the response envelope.
fn handle_line(line: &str) -> Value {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "id": Value::Null,
                "result": Value::Null,
                "error": {
                    "code": "MALFORMED_JSON",
                    "message": format!("line did not parse as JSON: {}", e),
                }
            });
        }
    };
    if !request.is_object() {
        return json!({
            "id": Value::Null,
            "result": Value::Null,
            "error": {
                "code": "MALFORMED_JSON",
                "message": "request must be a JSON object",
            }
        });
    }
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let op = match request.get("op").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return json!({
                "id": id,
                "result": Value::Null,
                "error": {
                    "code": "MALFORMED_JSON",
                    "message": "request missing string op field",
                }
            });
        }
    };
    let default_params = json!({});
    let params = request.get("params").unwrap_or(&default_params);
    match protocol::dispatch(&op, params) {
        Ok(result) => json!({
            "id": id,
            "result": result,
            "error": Value::Null,
        }),
        Err(e) => json!({
            "id": id,
            "result": Value::Null,
            "error": e.to_error_value(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_canonical_json_via_handle_line() {
        let line = r#"{"id":1,"op":"canonical_json","params":{"value":{}}}"#;
        let response = handle_line(line);
        assert_eq!(response["id"], json!(1));
        assert_eq!(response["error"], Value::Null);
        let bytes_b64 = response["result"]["bytes"].as_str().expect("bytes string");
        // base64("{}") = "e30="
        assert_eq!(bytes_b64, "e30=");
    }

    #[test]
    fn malformed_line_returns_malformed_json_with_null_id() {
        let response = handle_line("{not valid");
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], "MALFORMED_JSON");
    }

    #[test]
    fn missing_op_returns_malformed_json() {
        let response = handle_line(r#"{"id":2}"#);
        assert_eq!(response["id"], json!(2));
        assert_eq!(response["error"]["code"], "MALFORMED_JSON");
    }

    #[test]
    fn unknown_op_returns_unknown_op() {
        let response = handle_line(r#"{"id":3,"op":"nope","params":{}}"#);
        assert_eq!(response["id"], json!(3));
        assert_eq!(response["error"]["code"], "UNKNOWN_OP");
    }
}

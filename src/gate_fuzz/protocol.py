"""Python subprocess client for gate-rust-cli.

Spawns the gate-rust-cli binary, sends line-delimited JSON requests over
stdin, reads line-delimited JSON responses from stdout. Per SO1.2 the
subprocess lifecycle is one-per-property-test; a single client instance
is reused across many Hypothesis examples.

See PROTOCOL.md (sibling file) for the wire-format spec.
"""

from __future__ import annotations

import base64
import itertools
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any


class ProtocolError(RuntimeError):
    """Structural protocol error: malformed JSON, unknown op, invalid params.

    Domain errors (signature verification failure, schema validation
    failure) are NOT raised; they come back in the `result` field.
    """

    def __init__(self, code: str, message: str, request_id: int | None = None) -> None:
        super().__init__(f"{code}: {message} (id={request_id})")
        self.code = code
        self.message = message
        self.request_id = request_id


class RustCliClient:
    """Long-lived subprocess client around gate-rust-cli.

    Thread-safe for serial use within a single property test. Per SO1.2
    there is no expectation of concurrent use; callers serialise their
    requests.
    """

    def __init__(self, binary_path: Path | str) -> None:
        self._binary_path = Path(binary_path)
        if not self._binary_path.exists():
            raise FileNotFoundError(
                f"gate-rust-cli binary not found at {self._binary_path}. "
                "Run `cargo build --release` in tools/gate-rust-cli/ first."
            )
        self._proc: subprocess.Popen[bytes] | None = None
        self._id_counter = itertools.count(1)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the subprocess."""
        if self._proc is not None:
            return
        self._proc = subprocess.Popen(
            [str(self._binary_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,  # unbuffered binary mode; we manage newlines
        )

    def close(self) -> None:
        """Close stdin (subprocess exits cleanly) and wait."""
        if self._proc is None:
            return
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
            self._proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        finally:
            self._proc = None

    def __enter__(self) -> RustCliClient:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()

    # ------------------------------------------------------------------
    # Request/response
    # ------------------------------------------------------------------

    def call(self, op: str, params: dict[str, Any] | None = None) -> Any:
        """Send one request, wait for the matching response, return `result`.

        Raises ProtocolError if the response carries a structural error.
        Returns the `result` field on success (which may itself be a
        domain-level negative outcome like `{"valid": false, ...}`).
        """
        if self._proc is None:
            raise RuntimeError("client not started; call start() or use as context manager")
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("subprocess pipes unavailable")

        with self._lock:
            request_id = next(self._id_counter)
            request = {"id": request_id, "op": op, "params": params or {}}
            line = (json.dumps(request) + "\n").encode("utf-8")
            self._proc.stdin.write(line)
            self._proc.stdin.flush()

            response_line = self._proc.stdout.readline()
            if not response_line:
                stderr_bytes = self._proc.stderr.read() if self._proc.stderr else b""
                raise RuntimeError(
                    f"subprocess EOF before response (op={op}); "
                    f"stderr={stderr_bytes.decode('utf-8', errors='replace')}"
                )

            try:
                response = json.loads(response_line.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"subprocess sent non-JSON line: {response_line!r} ({e})"
                ) from e

            if response.get("id") != request_id:
                raise RuntimeError(
                    f"id mismatch: request={request_id}, response={response.get('id')}"
                )

            if response.get("error") is not None:
                err = response["error"]
                raise ProtocolError(
                    code=err.get("code", "UNKNOWN"),
                    message=err.get("message", ""),
                    request_id=request_id,
                )

            return response.get("result")

    # ------------------------------------------------------------------
    # Convenience wrappers around the 10 ops
    # ------------------------------------------------------------------

    def canonical_json(self, value: Any) -> bytes:
        """Op 1. Returns the canonical bytes."""
        result = self.call("canonical_json", {"value": value})
        return base64.b64decode(result["bytes"])

    def gate_hash(self, value: Any) -> str:
        """Op 2. Returns `'sha256:<64 hex>'`."""
        return self.call("gate_hash", {"value": value})["hash"]

    def build_request_envelope(self, **kwargs: Any) -> dict[str, Any]:
        """Op 3. Pass-through kwargs mirror gate-python build_request."""
        return self.call("build_request_envelope", kwargs)["envelope"]

    def build_response_envelope(self, **kwargs: Any) -> dict[str, Any]:
        """Op 4. Pass-through kwargs mirror gate-python build_response."""
        return self.call("build_response_envelope", kwargs)["envelope"]

    def build_ledger_event(self, **kwargs: Any) -> dict[str, Any]:
        """Op 5. Pass-through kwargs mirror gate-python build_event."""
        return self.call("build_ledger_event", kwargs)["event"]

    def verify_chain(
        self, events: list[dict[str, Any]], expected_first_prev_hash: str
    ) -> dict[str, Any]:
        """Op 6. Returns `{"passed": bool, "events_verified": int, "errors": [...]}`."""
        return self.call(
            "verify_chain",
            {"events": events, "expected_first_prev_hash": expected_first_prev_hash},
        )

    def sign_action(
        self, payload: Any, private_key_pkcs8: bytes, key_id: str
    ) -> dict[str, Any]:
        """Op 7. PKCS8 DER bytes are b64-encoded on the wire."""
        result = self.call(
            "sign_action",
            {
                "payload": payload,
                "private_key_pkcs8_b64": base64.b64encode(private_key_pkcs8).decode("ascii"),
                "key_id": key_id,
            },
        )
        return result["signature_record"]

    def verify_signature(
        self,
        payload: Any,
        signature_record: dict[str, Any],
        public_key_sec1: bytes,
    ) -> bool:
        """Op 8. SEC1 uncompressed public key bytes are b64-encoded on the wire."""
        result = self.call(
            "verify_signature",
            {
                "payload": payload,
                "signature_record": signature_record,
                "public_key_sec1_b64": base64.b64encode(public_key_sec1).decode("ascii"),
            },
        )
        return bool(result["valid"])

    def load_schema(self, name: str) -> str:
        """Op 9. Returns the schema source as a JSON string."""
        return self.call("load_schema", {"name": name})["schema_json"]

    def validate(self, schema_name: str, value: Any) -> dict[str, Any]:
        """Op 10. Returns `{"valid": bool, "errors": [...]}`."""
        return self.call("validate", {"schema_name": schema_name, "value": value})


# ----------------------------------------------------------------------
# Default binary location
# ----------------------------------------------------------------------

DEFAULT_BINARY_ENV_VAR = "GATE_RUST_CLI_BIN"


def default_binary_path() -> Path:
    """Resolve the gate-rust-cli binary path.

    Order of precedence:
    1. `GATE_RUST_CLI_BIN` environment variable.
    2. `CARGO_TARGET_DIR/release/gate-rust-cli` if `CARGO_TARGET_DIR` is set.
    3. The default cargo target dir at `tools/gate-rust-cli/target/release/gate-rust-cli`.
    """
    env_override = os.environ.get(DEFAULT_BINARY_ENV_VAR)
    if env_override:
        return Path(env_override)
    cargo_target = os.environ.get("CARGO_TARGET_DIR")
    if cargo_target:
        return Path(cargo_target) / "release" / "gate-rust-cli"
    # Default: tools/gate-rust-cli/target/release/gate-rust-cli relative
    # to the gate-fuzz package root.
    here = Path(__file__).resolve().parent.parent.parent
    return here / "tools" / "gate-rust-cli" / "target" / "release" / "gate-rust-cli"

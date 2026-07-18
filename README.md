# gate-fuzz

Cross-language differential property tests for GATE v1.4. Pairs
**gate-python v1.2.0** against **gate-rust v1.0.0** via line-delimited
JSON over a long-lived subprocess, using Hypothesis to drive
generation.

Companion workstream W7 of the coordinated GATE v1.4 framework release.
See `PROTOCOL.md` for the wire-format spec and the W7 PHASE-1.md for
the design and risk register.

## Scope in v1.4 vs public roadmap

The public v1.4 roadmap named three gate-fuzz deliverables. This release
ships one. The other two move to v1.5.

**v1.4 (shipped):** Python-to-Rust differential harness. Seven declared
properties (five active, two deferred to v1.1 pending the envelope /
ledger builder dispatch) exercised via Hypothesis strategies driving a
line-delimited-JSON subprocess protocol between gate-python v1.2.0 and
gate-rust v1.0.0. This is the byte-equivalence contract enforcement
surface for the two implementations.

**v1.5 (deferred):**

- **Bundle-derived Hypothesis strategies.** Strategies generated from
  the signed C09 invariant bundle so that every operator-defined
  invariant produces a property test without further authoring. The
  v1.4 harness uses hand-authored strategies drawn from the four W2
  schemas plus canonical-JSON pathological inputs.
- **HTTP-level protocol fuzzer against a running Tool Gateway.** A
  black-box HTTP fuzzer that produces malformed and adversarial
  ToolRequestEnvelope traffic against a live gateway instance and
  asserts fail-closed behaviour. Not present in v1.4; a subprocess-
  driven library fuzzer over the gate-python and gate-rust surfaces
  is what ships instead.
- **PARTIAL-check mapping.** A README table mapping each gate-fuzz
  property to the specific gate-conformance PARTIAL check whose
  evidence the property closes. Not present in v1.4. Operators may
  attach gate-fuzz output artefacts to Check15 evidence submissions
  today (as supplementary negative-test attestation), but the runner
  does not unilaterally consume them.

Operators who need the v1.5 items today: raise a v1.5 tracking issue on
the deterministic-agents / gate-fuzz repo so scope confirmation lands
against a public commitment before the v1.5 workstream opens.

## What it does

For seven cross-language properties, gate-fuzz drives both
implementations with the same generated inputs and asserts the contract
between them:

| Id | Property | Status in v1.0.0 |
|---|---|---|
| P1 | `canonical_json` is deterministic within each language | ACTIVE |
| P2 | `canonical_json` is byte-equivalent across languages | ACTIVE |
| P3 | envelope `request_hash` / `response_hash` byte-equivalent | DEFERRED (envelope builder dispatch wired in next minor) |
| P4 | ledger `event_hash` byte-equivalent | DEFERRED (same dependency as P3) |
| P5 | sign-verify roundtrip works within each language | ACTIVE |
| P6 | a signature in one language verifies in the other | ACTIVE |
| P7 | the same value validates identically against the 4 W2 schemas | ACTIVE |

Two properties (P3, P4) are deferred at v1.0.0: the Rust CLI's envelope
and ledger builders return `INTERNAL_ERROR { code: NOT_YET_IMPLEMENTED }`
pending the structured-to-flat kwargs translator. Both tests are
present with the activation path documented in their module docstrings.

## Install

gate-fuzz consumes gate-python and gate-rust from sibling source trees,
not from PyPI / crates.io.

Prerequisites:
- Python >= 3.11 with `pip` and `venv`
- Rust toolchain >= 1.78
- gate-python source at `../../workstream-5/gate-python/` (or set
  `GATE_PYTHON_SRC` env var)
- gate-rust source at `../../workstream-6/gate-rust/` (path is referenced
  in `tools/gate-rust-cli/Cargo.toml`)

Build:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
(cd tools/gate-rust-cli && cargo build --release)
```

The Rust binary lands at
`tools/gate-rust-cli/target/release/gate-rust-cli`; the Python harness
finds it automatically (or via `GATE_RUST_CLI_BIN` env var).

## Run

Three run modes; budget shape per PHASE-0 Axis 7:

```bash
gate-fuzz smoke      # 100 examples / property; PR-style fast feedback
gate-fuzz standard   # 1000 examples / property; merge-to-main
gate-fuzz soak       # 10000 examples / property; weekly soak
```

To reproduce a single failing property:

```bash
gate-fuzz reproduce-failure tests/properties/test_X.py::test_Y \
    --write-script repro.sh
```

The `--write-script` flag emits a self-contained bash reproduction
script that activates the venv, exports the needed env vars, and re-runs
the property against the persisted Hypothesis example database.

## Interpret failures

A failing property test is one of three things:

1. **Real cross-language divergence.** The properties are designed to
   surface byte-level differences between gate-python and gate-rust;
   shrunk Hypothesis output gives the minimal input that triggers the
   divergence. File against the relevant workstream.
2. **Strategy false-negative.** The generated example is invalid in
   one language and accepted in the other; the L2.5 meta-tests are the
   guard. If meta-tests pass but a property fails, this is unlikely.
3. **Test bug.** The property assertion is too strong (e.g. asserting
   byte equivalence on a non-deterministic surface like ECDSA
   signatures - see SO1.3 path-b for the v1.0.0 reframing).

Phase 2 surfaced one real R7 finding: gate-python `json.dumps` and
gate-rust `serde_json` diverge on float decimal representation for
arbitrary draws (e.g. `1801439851.0273438` -> py `1801439851.0273438`,
rs `1801439851.027344`). v1.0.0 mitigates by bounding the json_value
strategy to the W5 v006 vector set's safe float subspace; the broader
float-alignment work is a v1.5 candidate.

## Check15 evidence

The verification-symmetry property (P6) emits Check15 evidence
artifacts to `output/check15-evidence/<timestamp>.json` per the SO1.4
spec. Operators attach these to their Check15 evidence packet alongside
their gate-conformance run. The runner does not unilaterally consume
them; the artifact is an operator-attached supplementary evidence file.

The artifact JSON shape is documented in W7 PHASE-1.md Section 5.

## CI

`.github/workflows/ci.yml` matches SO1.5: GitHub Actions matrix on
Python 3.11 + 3.13, Ubuntu-latest, with `smoke` on every PR, `standard`
on push to main, and `soak` available via `workflow_dispatch`.
Hypothesis example database persists as a CI artifact for run-to-run
shrinking.

## See also

- `PROTOCOL.md` - line-delimited JSON wire spec.
- W7 phase 0 and phase 1 planning documents (12 axes + 29 deliverables
  + 11 risks + 5 sign-off questions) have been relocated to
  `v1.4/release-audit-trail/W7-PHASE-0.md` and
  `v1.4/release-audit-trail/W7-PHASE-1.md` so the gate-fuzz bundle
  published at `github.com/deterministic-agents/gate-fuzz` carries only
  the artefacts a downstream consumer needs. The relocation matches
  the W9 pattern from the post-first-independent-review remediation
  pass (B9 finding); applied to W7 by the post-second-independent-
  review remediation pass for symmetry.
- `BUNDLE-REVIEW.md` - phase 2 closure summary; matches the
  W4/W5/W6 BUNDLE-REVIEW pattern.
- `CHANGELOG-v1.0.0.md` - release notes.
- `v1.4/RELEASE-PROCESS.md` - coordinated framework release runbook.
- gate-python v1.2.0 at `../../workstream-5/gate-python/`.
- gate-rust v1.0.0 at `../../workstream-6/gate-rust/`.

## License

MIT. See `LICENSE` (verbatim copy of gate-python's LICENSE).

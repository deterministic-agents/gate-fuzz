# gate-fuzz v1.0.0 - 2026-08-18

First release. Coordinated with the GATE v1.4 framework release.

## Pairings

| Dependency | Pinned version |
|---|---|
| gate-python | v1.2.0 |
| gate-rust | v1.0.0 |
| GATE framework | v1.4 |

## Shipped

30 logical deliverables across 5 layers (the planned 29 from PHASE-1.md
Section 2 plus the CI workflow as L5.5 per the PHASE-2 prompt's ci.yml
placement clause).

| Layer | Count | Summary |
|---|---|---|
| L1 Foundation | 8 | pyproject.toml, PROTOCOL.md, gate-rust-cli (Cargo.toml + main.rs + protocol.rs), Python protocol client, L1 round-trip test |
| L2 Strategies | 5 | json_value, envelope_params, signing_key strategies + package init + meta-tests |
| L3 Properties | 8 | shared harness + 7 property test files (P1, P2, P3*, P4*, P5, P6, P7); P3+P4 deferred at v1.0.0 |
| L4 Harness + CLI | 4 | cli.py, config.py, reporting.py, test_harness.py |
| L5 Documentation | 5 | README.md, this CHANGELOG, BUNDLE-REVIEW.md, LICENSE, .github/workflows/ci.yml |

*P3 (envelope hash) and P4 (ledger event hash) tests are present but
skipped at v1.0.0; the Rust CLI's `build_request_envelope`,
`build_response_envelope`, and `build_ledger_event` ops return
`INTERNAL_ERROR { code: NOT_YET_IMPLEMENTED }` pending the structured-
to-flat kwargs translator. Activation path is documented in each test
module's docstring.

## Properties active

| Id | Active | Notes |
|---|---|---|
| P1 canonical_json determinism | yes | within each language |
| P2 canonical_json byte equivalence | yes | gate-python vs gate-rust |
| P3 envelope hash byte equivalence | NO (deferred) | Rust envelope dispatch pending |
| P4 ledger event hash byte equivalence | NO (deferred) | Rust ledger dispatch pending |
| P5 sign-verify roundtrip | yes | per SO1.3 path-b reframing |
| P6 verification symmetry | yes | substantive cross-language signing test |
| P7 schema validation parity | yes | jsonschema Draft 2020-12 per SO1.1 |

## Sign-off decisions applied (SO1.x)

- SO1.1: `jsonschema` crate (v0.18 with `draft202012` feature). Activated.
- SO1.2: one subprocess per property test via pytest module-scope fixture. Activated.
- SO1.3: path-b chosen. ECDSA byte-equivalence not asserted; P5 is single-language sanity, P6 is the substantive cross-language property.
- SO1.4: Check15 evidence artifact shape applied verbatim. Artifact at `output/check15-evidence/<timestamp>.json`; operator-attached.
- SO1.5: GitHub Actions matrix (Python 3.11+3.13, ubuntu-latest, smoke-PR / standard-merge / soak-dispatch). See `.github/workflows/ci.yml`.

## R1-R11 final disposition

R1 (strategy short-circuit) - mitigated by L2.5 meta-tests (5 passing).
R2 (subprocess overhead) - mitigated by long-lived per-test subprocess; sub-millisecond per example.
R3 (no Rust validate primitive) - mitigated by CLI wrapper using jsonschema crate.
R4 (Cargo path-dep fragility) - documented in PROTOCOL.md + RELEASE-PROCESS.md.
R5 (non-determinism) - resolved via SO1.3 path-b.
R6 (paper-update framing) - resolved upstream via Q0.5 Path A.
**R7 (canonical-JSON float edge cases)** - **REAL FINDING surfaced at phase 2 smoke.** gate-python `json.dumps` and gate-rust `serde_json` diverge on float decimal representation outside the W5 v006 vector set (example: `1801439851.0273438` -> py `1801439851.0273438`, rs `1801439851.027344`; also exponent format differs `e-8` vs `e-08`). v1.0.0 mitigates by sampling floats from W5 v006 safe-set only; broader float-alignment is a v1.5 candidate.
R8 (Hypothesis database staleness) - mitigated by CI artifact retention + per-run profile selection.
R9 (jsonschema Draft compatibility) - jsonschema crate 0.18 with `draft202012` feature confirmed working at L1 cargo build.
R10 (ECDSA non-determinism) - resolved via SO1.3 path-b.
R11 (Check15 shape drift) - mitigated by versioned `schema_version: "v1.0"` field in artifact; bump on shape change.

## Known issues

1. P3 + P4 deferred (see above).
2. R7 float-edge-case divergence (see above).
3. Test-run noise: P6 occasionally generates two payloads that canonicalise to the same bytes; the `assume()` guard skips these examples and they don't count toward the 30-example budget.

## Validation outcome (live, phase 2 closure)

- L1 cargo build: PASS (release profile, jsonschema crate 0.18 with draft202012 feature)
- L1 cargo test: 11 passed (6 protocol + 4 main + 1 noop)
- L1 pytest round-trip: 1 passed
- L2 meta-tests: 5 passed
- L3 properties: 21 passed, 4 skipped (P3+P4)
- L4 harness tests: 9 passed
- L4 CLI: --version + --help responsive
- Full suite: 27 passed, 4 skipped, 0 failures, 0 errors

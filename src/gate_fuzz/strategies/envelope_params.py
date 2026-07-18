"""W2-schema-aware envelope/event parameter strategies (L2.3).

Generates valid params for:
- `gate.envelopes.build_request` (28 kwargs)
- `gate.envelopes.build_response` (13 kwargs)
- `gate.ledger.build_event` (17 kwargs)

Field shapes verified against gate-python source surfaces at phase 1
closure (PHASE-1.md Section 6). Enum values mirror gate-rust enum
definitions in `gate_rust/src/envelopes.rs` (Environment, ToolCategory,
RiskTier, Status, Decision) and `gate_rust/src/ledger.rs` (ActionType,
RetentionClass).

The meta-test layer L2.5 verifies generated examples reach the
verifier without short-circuiting at validation.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

from gate_fuzz.strategies.json_value import json_value


# ----------------------------------------------------------------------
# Enum vocabularies (verified against gate-rust enum definitions)
# ----------------------------------------------------------------------

ENVIRONMENTS = ("dev", "test", "prod")
TOOL_CATEGORIES = (
    "read_only",
    "reversible_write",
    "irreversible_write",
    "financial",
    "infrastructure",
    "multi_agent",
)
RISK_TIERS = ("low", "medium", "high", "critical")
# Vocabulary aligned to the shipped gate-contracts v1.2.0 schemas.
# These previously hardcoded values that did not match the schemas
# (e.g., "failure" vs the schema's "error", or "tool_call" instead of
# the "tool.invoke" convention). See gate-python's constants module for
# the authoritative enumerations; the fuzz suite MUST NOT invent
# vocabulary that the schemas would reject at validation time.
STATUSES = ("success", "error", "denied", "timeout")
DECISIONS = ("allow", "deny", "invariant_halt")
ACTION_TYPES = (
    "tool.invoke",
    "memory.read",
    "memory.write",
    "hitl.decision",
    "breaker.trigger",
    "agent.lifecycle",
)
RETENTION_CLASSES = (
    "sandbox_hot_30d",
    "prod_hot_365d",
    "prod_cold_6y_worm",
    "regulated_cold_7y_plus",
)


# ----------------------------------------------------------------------
# Primitive shape strategies
# ----------------------------------------------------------------------

def _slug(min_size: int = 2, max_size: int = 16) -> st.SearchStrategy[str]:
    return st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
        min_size=min_size,
        max_size=max_size,
    ).filter(lambda s: s.strip("-") != "")  # disallow leading/trailing-only hyphens


def _identifier(min_size: int = 1, max_size: int = 24) -> st.SearchStrategy[str]:
    return st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
        min_size=min_size,
        max_size=max_size,
    ).filter(lambda s: not s[0].isdigit())


def _uuid_str() -> st.SearchStrategy[str]:
    return st.uuids(version=4).map(str)


def _sha256_str() -> st.SearchStrategy[str]:
    return st.text(alphabet="0123456789abcdef", min_size=64, max_size=64).map(
        lambda h: f"sha256:{h}"
    )


def _agent_instance_id() -> st.SearchStrategy[str]:
    return st.tuples(_slug(), _uuid_str()).map(
        lambda t: f"spiffe://{t[0]}.example/agent/{t[1]}"
    )


def _iso8601_z() -> st.SearchStrategy[str]:
    return st.datetimes(
        min_value=__import__("datetime").datetime(2026, 1, 1),
        max_value=__import__("datetime").datetime(2027, 1, 1),
    ).map(lambda dt: dt.isoformat() + "Z")


# ----------------------------------------------------------------------
# build_request strategy (28 kwargs mirror gate-python)
# ----------------------------------------------------------------------

@st.composite
def build_request_params(draw: st.DrawFn) -> dict[str, Any]:
    """Generate kwargs for `gate.envelopes.build_request`.

    Required kwargs always present; optional kwargs present 50% of
    the time for mixed coverage.
    """
    params: dict[str, Any] = {
        "run_id": draw(_uuid_str()),
        "trace_id": draw(_uuid_str()),
        "tenant_id": draw(_slug()),
        "environment": draw(st.sampled_from(ENVIRONMENTS)),
        "agent_instance_id": draw(_agent_instance_id()),
        "agent_name": draw(_identifier()),
        "agent_version": draw(_slug(min_size=1, max_size=8)),
        "attested": draw(st.booleans()),
        "tool_name": draw(_identifier()),
        "tool_category": draw(st.sampled_from(TOOL_CATEGORIES)),
        "risk_tier": draw(st.sampled_from(RISK_TIERS)),
        "payload": draw(json_value()),
        "policy_bundle_hash": draw(_sha256_str()),
        "tool_schema_hash": draw(_sha256_str()),
    }

    # Optional kwargs (12 total, present ~50% of the time individually)
    if draw(st.booleans()):
        params["image_digest"] = draw(_sha256_str())
    if draw(st.booleans()):
        params["config_hash"] = draw(_sha256_str())
    if draw(st.booleans()):
        params["toolset_hash"] = draw(_sha256_str())
    if draw(st.booleans()):
        params["idempotency_key"] = draw(_uuid_str())
    if draw(st.booleans()):
        params["prompt_bundle_hash"] = draw(_sha256_str())
    if draw(st.booleans()):
        params["orm_risk_score"] = draw(st.floats(min_value=0.0, max_value=1.0))
    if draw(st.booleans()):
        params["tokens_remaining"] = draw(st.integers(min_value=0, max_value=10**6))
    if draw(st.booleans()):
        params["tool_calls_remaining"] = draw(st.integers(min_value=0, max_value=10**4))
    if draw(st.booleans()):
        params["cost_usd_remaining"] = draw(st.floats(min_value=0.0, max_value=1000.0))
    if draw(st.booleans()):
        params["source_labels"] = draw(
            st.lists(_identifier(), max_size=4)
        )
    if draw(st.booleans()):
        params["span_id"] = draw(_uuid_str())
    if draw(st.booleans()):
        params["control_plane_version"] = draw(_slug(min_size=1, max_size=8))

    return params


# ----------------------------------------------------------------------
# build_response strategy (13 kwargs mirror gate-python)
# ----------------------------------------------------------------------

@st.composite
def build_response_params(draw: st.DrawFn) -> dict[str, Any]:
    """Generate kwargs for `gate.envelopes.build_response`.

    `request_envelope` is generated as a stub dict; in property tests
    the harness substitutes a real envelope built via `build_request`
    first.
    """
    params: dict[str, Any] = {
        "request_envelope": draw(st.fixed_dictionaries({
            "run_id": _uuid_str(),
            "trace_id": _uuid_str(),
        })),
        "tool_output": draw(json_value()),
        "status": draw(st.sampled_from(STATUSES)),
        "duration_ms": draw(st.integers(min_value=0, max_value=300_000)),
        "decision_id": draw(_uuid_str()),
        "decision": draw(st.sampled_from(DECISIONS)),
        "obligations": draw(st.lists(_identifier(), max_size=4)),
        "policy_bundle_hash": draw(_sha256_str()),
        "ledger_event_id": draw(_uuid_str()),
    }
    if draw(st.booleans()):
        params["snapshot_uri"] = f"s3://bucket/snap/{draw(_uuid_str())}"
    if draw(st.booleans()):
        params["replay_trace_step_id"] = draw(_uuid_str())
    if draw(st.booleans()):
        params["error_code"] = draw(_identifier())

    return params


# ----------------------------------------------------------------------
# build_event strategy (17 kwargs mirror gate-python)
# ----------------------------------------------------------------------

@st.composite
def build_event_params(draw: st.DrawFn, *, genesis: bool = True) -> dict[str, Any]:
    """Generate kwargs for `gate.ledger.build_event`.

    When `genesis=True` the `prev_event_hash` defaults to the `GENESIS`
    sentinel; otherwise a random sha256-shaped string is drawn.
    """
    params: dict[str, Any] = {
        "run_id": draw(_uuid_str()),
        "tenant_id": draw(_slug()),
        "environment": draw(st.sampled_from(ENVIRONMENTS)),
        "action_type": draw(st.sampled_from(ACTION_TYPES)),
        "policy_decision_id": draw(_uuid_str()),
        "tool_request_hash": draw(_sha256_str()),
        "tool_response_hash": draw(_sha256_str()),
        "prev_event_hash": "GENESIS" if genesis else draw(_sha256_str()),
        "sink_uri": f"s3://ledger/{draw(_slug())}/events",
        "retention_class": draw(st.sampled_from(RETENTION_CLASSES)),
    }
    if draw(st.booleans()):
        params["trace_id"] = draw(_uuid_str())
    if draw(st.booleans()):
        params["replay_trace_step_id"] = draw(_uuid_str())
    if draw(st.booleans()):
        params["hitl_approval_id"] = draw(_uuid_str())
    if draw(st.booleans()):
        params["invariant_bundle_hash"] = draw(_sha256_str())
    if draw(st.booleans()):
        params["tool_name"] = draw(_identifier())
    if draw(st.booleans()):
        params["agent_instance_id"] = draw(_agent_instance_id())
    if draw(st.booleans()):
        params["sequence_number"] = draw(st.integers(min_value=0, max_value=10**6))

    return params

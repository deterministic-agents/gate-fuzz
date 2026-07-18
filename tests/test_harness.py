"""Smoke test of harness mechanics (L4.4).

Confirms:
- config loads each run mode.
- JUnit XML writes a valid XML file.
- Failure reproduction script generator writes an executable script.
- Hypothesis profile registration is idempotent.
- Check15EvidenceWriter writes a parseable artifact.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from gate_fuzz.config import MODES, get_mode, register_hypothesis_profiles
from gate_fuzz.harness import Check15EvidenceWriter
from gate_fuzz.reporting import (
    human_summary,
    write_failure_reproduction,
    write_junit_xml,
)


# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

def test_three_modes_registered():
    assert set(MODES) == {"smoke", "standard", "soak"}


def test_get_mode_returns_correct_budget():
    assert get_mode("smoke").max_examples == 100
    assert get_mode("standard").max_examples == 1000
    assert get_mode("soak").max_examples == 10_000


def test_get_mode_unknown_raises():
    with pytest.raises(KeyError, match="unknown run mode"):
        get_mode("nope")


def test_hypothesis_profile_registration_idempotent():
    """Calling twice should not raise."""
    register_hypothesis_profiles()
    register_hypothesis_profiles()


# ----------------------------------------------------------------------
# JUnit XML
# ----------------------------------------------------------------------

def test_junit_xml_writes_valid_xml(tmp_path):
    out = tmp_path / "out.xml"
    write_junit_xml(
        out_path=out,
        suite_name="smoke-test-suite",
        test_results=[
            {"name": "test_a", "status": "pass", "duration_s": 0.1},
            {"name": "test_b", "status": "fail", "duration_s": 0.2, "message": "boom"},
            {"name": "test_c", "status": "skip", "duration_s": 0.0},
        ],
    )
    assert out.exists()
    root = ET.parse(out).getroot()
    assert root.tag == "testsuite"
    assert root.get("tests") == "3"
    assert root.get("failures") == "1"
    assert root.get("skipped") == "1"
    assert len(root.findall("testcase")) == 3


# ----------------------------------------------------------------------
# Failure reproduction script
# ----------------------------------------------------------------------

def test_failure_reproduction_writes_executable_script(tmp_path):
    out = tmp_path / "repro.sh"
    written = write_failure_reproduction(
        out_path=out,
        property_name="tests/properties/test_canonical_json_byte_equivalence.py::test_canonical_json_byte_equivalent",
        hypothesis_seed="abc123",
    )
    assert written.exists()
    assert written.stat().st_mode & 0o111  # executable bits
    body = written.read_text()
    assert "test_canonical_json_byte_equivalent" in body
    assert "HYPOTHESIS_SEED=abc123" in body
    assert "GATE_RUST_CLI_BIN" in body
    assert "GATE_PYTHON_SRC" in body
    assert body.startswith("#!/usr/bin/env bash")


# ----------------------------------------------------------------------
# Human summary
# ----------------------------------------------------------------------

def test_human_summary_has_expected_shape():
    out = human_summary(
        suite_name="gate-fuzz smoke",
        pass_count=10,
        fail_count=2,
        skip_count=1,
        duration_s=12.345,
    )
    assert "gate-fuzz smoke" in out
    assert "10/13" in out
    assert "2 failed" in out
    assert "1 skipped" in out


# ----------------------------------------------------------------------
# Check15 evidence writer
# ----------------------------------------------------------------------

def test_check15_writer_emits_valid_artifact(tmp_path):
    writer = Check15EvidenceWriter(
        property_name="test_smoke",
        output_dir=tmp_path,
    )
    writer.record_case({
        "case": "spoofed_sender",
        "input_envelope_hash": "sha256:abc",
        "spoofing_modification": "sender_id changed",
        "python_verify_result": False,
        "rust_verify_result": False,
        "rationale": "both reject",
    })
    writer.record_case({
        "case": "spoofed_sender",
        "input_envelope_hash": "sha256:def",
        "spoofing_modification": "sender_id changed",
        "python_verify_result": True,  # disagrees -> parity should be false
        "rust_verify_result": False,
        "rationale": "divergence",
    })
    path = writer.flush()
    assert path.exists()
    artifact = json.loads(path.read_text())
    assert artifact["schema_version"] == "v1.0"
    assert artifact["tool"] == "gate-fuzz"
    assert artifact["property"] == "test_smoke"
    assert len(artifact["test_cases"]) == 2
    summary = artifact["summary"]
    assert summary["total_cases"] == 2
    assert summary["python_accept_count"] == 1
    assert summary["python_reject_count"] == 1
    assert summary["rust_accept_count"] == 0
    assert summary["rust_reject_count"] == 2
    assert summary["parity"] is False


def test_check15_writer_parity_true_on_full_agreement(tmp_path):
    writer = Check15EvidenceWriter(
        property_name="test_parity",
        output_dir=tmp_path,
    )
    for _ in range(3):
        writer.record_case({
            "case": "spoofed_sender",
            "python_verify_result": False,
            "rust_verify_result": False,
        })
    artifact_path = writer.flush()
    artifact = json.loads(artifact_path.read_text())
    assert artifact["summary"]["parity"] is True

"""JUnit XML output + human summary + failure-reproduction script (L4.3).

The Hypothesis database (`.hypothesis/`) already preserves failing
example seeds for shrinking + replay. This module wraps it in a
self-contained reproduction script the operator can copy into a bug
report.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET


def write_junit_xml(
    *,
    out_path: Path | str,
    suite_name: str,
    test_results: Iterable[dict],
) -> Path:
    """Write a minimal JUnit XML report.

    `test_results` is an iterable of dicts each with at minimum:
        {"name": str, "status": "pass"|"fail"|"skip", "duration_s": float,
         "message": str | None}
    """
    suite = ET.Element("testsuite", attrib={"name": suite_name})
    pass_count = fail_count = skip_count = 0
    for r in test_results:
        case = ET.SubElement(
            suite,
            "testcase",
            attrib={
                "name": r["name"],
                "time": f"{r.get('duration_s', 0.0):.4f}",
            },
        )
        status = r.get("status", "pass")
        if status == "fail":
            failure = ET.SubElement(case, "failure")
            failure.text = r.get("message") or ""
            fail_count += 1
        elif status == "skip":
            ET.SubElement(case, "skipped")
            skip_count += 1
        else:
            pass_count += 1
    suite.set("tests", str(pass_count + fail_count + skip_count))
    suite.set("failures", str(fail_count))
    suite.set("skipped", str(skip_count))
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(suite)
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    return out_path


def write_failure_reproduction(
    *,
    out_path: Path | str,
    property_name: str,
    hypothesis_seed: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> Path:
    """Produce a bash script that reproduces a single failing property.

    The Hypothesis example database persists the failing seed under
    `.hypothesis/`. The reproduction script:
    1. Activates the venv.
    2. Exports the relevant env vars (GATE_RUST_CLI_BIN, GATE_PYTHON_SRC).
    3. Re-runs pytest against just the failing property.
    4. (Optional) sets `HYPOTHESIS_SEED` if `hypothesis_seed` is known.
    """
    extra_env = extra_env or {}
    lines: list[str] = [
        "#!/usr/bin/env bash",
        "# gate-fuzz failure reproduction script",
        f"# Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"# Failing property: {property_name}",
        "set -euo pipefail",
        "",
        "# 1. Activate venv (adjust path if your venv lives elsewhere)",
        '[ -z "${VIRTUAL_ENV:-}" ] && echo "Activate your venv first." && exit 1',
        "",
        "# 2. Cross-language environment",
    ]
    lines.append('export GATE_RUST_CLI_BIN="${GATE_RUST_CLI_BIN:-tools/gate-rust-cli/target/release/gate-rust-cli}"')
    lines.append('export GATE_PYTHON_SRC="${GATE_PYTHON_SRC:-../../workstream-5/gate-python}"')
    for key, value in extra_env.items():
        lines.append(f'export {key}="{value}"')
    lines.extend([
        "",
        "# 3. Hypothesis behaviour: re-use the persisted DB so the prior",
        "#    failing seed shrinks again.",
        "export HYPOTHESIS_PROFILE=ci",
        "",
        "# 4. Re-run the property",
        f"python3 -m pytest {property_name} -v --no-header",
    ])
    if hypothesis_seed:
        lines.insert(-2, f"export HYPOTHESIS_SEED={hypothesis_seed}")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(out_path, 0o755)
    return out_path


def human_summary(
    *,
    suite_name: str,
    pass_count: int,
    fail_count: int,
    skip_count: int,
    duration_s: float,
) -> str:
    """One-line + breakdown human summary for stdout."""
    total = pass_count + fail_count + skip_count
    return (
        f"\n{suite_name}: {pass_count}/{total} passed "
        f"({fail_count} failed, {skip_count} skipped) in {duration_s:.1f}s\n"
    )

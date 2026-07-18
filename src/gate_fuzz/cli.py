"""gate-fuzz CLI entry point (L4.1).

Wraps pytest invocation with Hypothesis profile selection (smoke /
standard / soak / reproduce-failure modes per PHASE-0 Axis 7 and SO1.5).

Usage:

    gate-fuzz smoke                    # PR-style fast run
    gate-fuzz standard                 # merge-to-main run
    gate-fuzz soak                     # weekly soak (manual dispatch)
    gate-fuzz reproduce-failure PROP   # re-run a failing property

Exit codes mirror pytest:
    0 = all passed
    1 = test failure
    2 = collection / config error
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from gate_fuzz.config import MODES, get_mode
from gate_fuzz.reporting import human_summary, write_failure_reproduction


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gate-fuzz",
        description="Cross-language differential property tests for GATE v1.4.",
    )
    parser.add_argument("--version", action="version", version="gate-fuzz 1.0.0")
    sub = parser.add_subparsers(dest="mode", required=True)

    for mode_name in MODES:
        m = sub.add_parser(
            mode_name,
            help=f"Run mode {mode_name}: {MODES[mode_name].max_examples} examples/property",
        )
        m.add_argument(
            "--junitxml",
            default=None,
            help="Path to write JUnit XML output (optional)",
        )
        m.add_argument(
            "--testpaths",
            default="tests/properties",
            help="pytest --testpaths (default: tests/properties)",
        )

    repro = sub.add_parser(
        "reproduce-failure",
        help="Re-run a previously-failed property using the Hypothesis DB",
    )
    repro.add_argument("property_id", help="pytest node id, e.g. tests/properties/...::test_X")
    repro.add_argument(
        "--write-script",
        default=None,
        help="If set, ALSO write a self-contained reproduction script to this path",
    )

    return parser


def _run_pytest_with_profile(mode_name: str, junitxml: str | None, testpaths: str) -> int:
    """Invoke pytest with the given Hypothesis profile via env var."""
    cfg = get_mode(mode_name)
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        testpaths,
        "--no-header",
        "-q",
        f"--hypothesis-profile={mode_name}",
    ]
    if junitxml:
        cmd.append(f"--junitxml={junitxml}")
    start = time.monotonic()
    print(f"gate-fuzz {mode_name}: {cfg.max_examples} examples/property, "
          f"deadline {cfg.deadline_ms}ms, paths={testpaths}", flush=True)
    proc = subprocess.run(cmd)
    elapsed = time.monotonic() - start
    # pytest already printed the authoritative pass/fail/skip counts.
    # Emitting a second banner that reads "0/0 passed" contradicts pytest's
    # summary and confuses operators reading CI logs; the CLI now prints
    # only the gate-fuzz timing footer.
    sys.stdout.write(
        f"gate-fuzz {mode_name}: completed in {elapsed:.1f}s. "
        f"See pytest summary above for pass / fail / skip counts.\n"
    )
    return proc.returncode


def _reproduce_failure(property_id: str, write_script: str | None) -> int:
    """Re-run a failing property; optionally also write a reproduction script."""
    if write_script:
        path = write_failure_reproduction(
            out_path=write_script,
            property_name=property_id,
        )
        print(f"reproduction script written: {path}", flush=True)
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        property_id,
        "-v",
        "--no-header",
    ]
    return subprocess.run(cmd).returncode


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    # Register profiles so the --hypothesis-profile flag resolves
    from gate_fuzz.config import register_hypothesis_profiles
    register_hypothesis_profiles()

    if args.mode in MODES:
        return _run_pytest_with_profile(args.mode, args.junitxml, args.testpaths)
    if args.mode == "reproduce-failure":
        return _reproduce_failure(args.property_id, args.write_script)
    parser.error(f"unknown mode: {args.mode}")
    return 2  # unreachable; parser.error exits


if __name__ == "__main__":
    raise SystemExit(main())

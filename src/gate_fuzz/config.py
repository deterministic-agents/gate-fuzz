"""Run-mode configuration for gate-fuzz (L4.2).

Three run modes per PHASE-0 Axis 7:

| Mode    | Examples / property | Deadline (ms) | Trigger                |
|---------|---------------------|---------------|------------------------|
| smoke   | 100                 | 200           | every PR (CI)          |
| standard| 1000                | 1000          | push to main (CI)      |
| soak    | 10000               | 5000          | manual dispatch (CI)   |

The Hypothesis settings dict is passed into properties via the
`@settings(**get_mode_settings(mode))` decoration pattern OR via
`settings.register_profile + load_profile` at CLI entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

RunMode = Literal["smoke", "standard", "soak"]


@dataclass(frozen=True)
class ModeConfig:
    """Per-mode Hypothesis budget."""

    name: RunMode
    max_examples: int
    deadline_ms: int

    def as_hypothesis_kwargs(self) -> dict:
        return {
            "max_examples": self.max_examples,
            "deadline": self.deadline_ms,
        }


SMOKE = ModeConfig(name="smoke", max_examples=100, deadline_ms=200)
STANDARD = ModeConfig(name="standard", max_examples=1000, deadline_ms=1000)
SOAK = ModeConfig(name="soak", max_examples=10_000, deadline_ms=5000)

MODES: dict[str, ModeConfig] = {
    "smoke": SMOKE,
    "standard": STANDARD,
    "soak": SOAK,
}


def get_mode(name: str) -> ModeConfig:
    """Look up a mode by name; raises KeyError on unknown."""
    if name not in MODES:
        raise KeyError(f"unknown run mode: {name!r}; valid: {sorted(MODES)}")
    return MODES[name]


def register_hypothesis_profiles() -> None:
    """Register each mode as a Hypothesis profile.

    After this call, properties using `@settings()` without args will
    pick up the active profile. Activate via `settings.load_profile(name)`.
    """
    from hypothesis import settings

    for mode in MODES.values():
        settings.register_profile(mode.name, **mode.as_hypothesis_kwargs())

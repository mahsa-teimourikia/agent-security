"""Real Hypothesis SDK checks for Advanced 07."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "advanced" / "07-agent-security-testing-and-fuzzing"
SPEC = importlib.util.spec_from_file_location("advanced_07_hypothesis", COURSE / "hypothesis_adapter.py")
assert SPEC and SPEC.loader
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


def test_hypothesis_finds_baseline_parser_differential() -> None:
    result = ADAPTER.find_unsafe_encoded_bypass()
    assert result["unsafe_effect"] is True
    assert result["secure_status"] == "deny"
    assert result["secure_reason"] == "command-not-canonical"


def test_hypothesis_properties_and_state_machine_hold() -> None:
    result = ADAPTER.run_hypothesis_suite()
    assert result["properties"] == 2
    assert result["examples_per_property"] == 80
    assert result["stateful_scenarios"] == 40
    assert result["stateful_steps"] == 12

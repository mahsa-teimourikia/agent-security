"""Real Hypothesis integration checks for Foundation 03."""
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "03-security-invariants-and-blast-radius"
sys.path.insert(0, str(COURSE))
SPEC = importlib.util.spec_from_file_location("foundation_03_hypothesis", COURSE / "hypothesis_adapter.py")
assert SPEC and SPEC.loader
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


def test_generated_properties_hold_for_deterministic_examples() -> None:
    assert ADAPTER.run_properties() == {"properties": 3, "generated_examples_per_property": 75}

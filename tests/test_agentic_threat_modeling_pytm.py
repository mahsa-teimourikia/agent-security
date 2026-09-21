"""Real OWASP pytm adapter checks for Foundation 02."""
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "02-threat-modeling-agentic-systems"
SPEC = importlib.util.spec_from_file_location("foundation_02_pytm", COURSE / "pytm_adapter.py")
assert SPEC and SPEC.loader
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


def test_pytm_builds_the_course_dfd_with_agent_and_llm_primitives() -> None:
    summary = ADAPTER.demo()
    assert summary.element_count == 9 and summary.flow_count == 7
    assert {"Actor", "Agent", "LLM", "Server", "Datastore"} <= set(summary.element_types)
    assert summary.dot_source.startswith("digraph tm")
    assert all(item in summary.dot_source for item in ("F1 request", "F6 business", "Tool policy"))

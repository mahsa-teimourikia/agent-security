"""OpenTelemetry evidence contract for Foundation 01."""
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "01-agent-security-architecture-and-trust-boundaries"
SPEC = importlib.util.spec_from_file_location("foundation_01_trust_boundaries_otel", COURSE / "otel_adapter.py")
assert SPEC and SPEC.loader
OTEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = OTEL
SPEC.loader.exec_module(OTEL)


def test_otel_exports_only_the_bounded_decision_contract() -> None:
    report, spans = OTEL.demo()
    assert report.trace_completeness_rate == 1
    assert spans
    assert all(span.name == "agent.boundary.decision" for span in spans)
    assert all(set(span.attributes) == OTEL.ALLOWED_ATTRIBUTES for span in spans)
    rendered = repr([dict(span.attributes) for span in spans])
    for forbidden in ("user:7", "case:42", "synthetic-content", "local-teaching-key", "claimed_subject"):
        assert forbidden not in rendered

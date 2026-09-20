"""Privacy and behavior tests for the OpenTelemetry course adapter."""
import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).parents[1]


def load_module():
    path = ROOT / "curriculum/advanced/03-production-gate/03_production_gate_otel.py"
    spec = importlib.util.spec_from_file_location("advanced_03_production_gate_otel_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_otel_adapter_emits_one_allowlisted_decision_span():
    module = load_module()
    decision, spans = module.credential_free_demo()
    assert decision.ready and len(spans) == 1
    attributes = dict(spans[0].attributes)
    assert attributes["release.state"] == "ready"
    assert attributes["release.evidence_count"] == 7
    assert attributes["release.blocker_count"] == 0


def test_otel_adapter_does_not_export_sensitive_dossier_content():
    module = load_module()
    _, spans = module.credential_free_demo()
    rendered = repr(dict(spans[0].attributes))
    assert "evidence.example" not in rendered
    assert "operator fallback" not in rendered
    assert "integrity_tag" not in rendered
    assert "payload_digest" not in rendered

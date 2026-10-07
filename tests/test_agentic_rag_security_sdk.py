"""Real Pydantic and OpenTelemetry adapter checks for Intermediate 08."""
import importlib.util
import json
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "08-agentic-rag-security"


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, COURSE / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SDK = load("agentic_rag_security_sdk_tests", "sdk_adapter.py")


def runtime(run_id: str = "run:sdk-test"):
    scenario = SDK.LAB.build_scenario()
    scenario.start_run("attest:north", run_id)
    return SDK.RAGToolRuntime(scenario, "attest:north", run_id)


def test_input_schema_is_strict_and_has_no_authority_fields() -> None:
    schema = SDK.SearchToolInput.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"query", "top_k"}
    assert {"tenant_id", "subject_id", "groups", "clearance", "policy_version"}.isdisjoint(schema["properties"])


def test_output_schema_is_strict_and_provenance_bearing() -> None:
    schema = SDK.SearchToolOutput.model_json_schema()
    assert schema["additionalProperties"] is False
    evidence = schema["$defs"]["EvidenceProjection"]
    assert evidence["additionalProperties"] is False
    assert {"chunk_id", "source_id", "source_version", "chunk_digest", "index_generation", "trust_label"} <= set(evidence["properties"])


def test_safe_tool_call_returns_only_current_tenant_evidence() -> None:
    tool_runtime = runtime()
    tracer, _ = SDK.configure_in_memory_tracing()
    output = json.loads(SDK.secure_search_tool(
        tool_runtime, {"query": "support case retention period", "top_k": 4}, tracer=tracer,
    ))
    assert output["status"] == "allow"
    ids = {item["source_id"] for item in output["evidence"]}
    assert "src:north:retention" in ids
    assert "src:south:retention" not in ids
    assert all(item["trust_label"] == "retrieved-evidence-not-instructions" for item in output["evidence"])


def test_extra_scope_field_is_rejected_before_boundary_call() -> None:
    tool_runtime = runtime()
    tracer, exporter = SDK.configure_in_memory_tracing()
    output = json.loads(SDK.secure_search_tool(
        tool_runtime,
        {"query": "retention", "top_k": 3, "tenant_id": "south"},
        tracer=tracer,
    ))
    assert (output["status"], output["reason"]) == ("deny", "invalid-tool-input")
    assert tool_runtime.request_sequence == 0
    assert exporter.get_finished_spans() == ()


def test_invalid_types_and_bounds_are_rejected() -> None:
    invalid = [
        {"query": "retention", "top_k": "3"},
        {"query": "", "top_k": 3},
        {"query": "retention", "top_k": 5},
        {"query": ["retention"], "top_k": 3},
    ]
    for index, payload in enumerate(invalid):
        tool_runtime = runtime(f"run:invalid:{index}")
        tracer, _ = SDK.configure_in_memory_tracing()
        output = json.loads(SDK.secure_search_tool(tool_runtime, payload, tracer=tracer))
        assert (output["status"], output["reason"]) == ("deny", "invalid-tool-input")


def test_telemetry_records_decision_not_raw_query_or_evidence() -> None:
    tool_runtime = runtime()
    tracer, exporter = SDK.configure_in_memory_tracing()
    SDK.secure_search_tool(
        tool_runtime, {"query": "support case retention period", "top_k": 3}, tracer=tracer,
    )
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    attributes = dict(spans[0].attributes)
    serialized = json.dumps(attributes, sort_keys=True)
    assert attributes["gen_ai.operation.name"] == "retrieval"
    assert attributes["rag.decision"] == "allow"
    assert attributes["rag.evidence.count"] > 0
    assert len(attributes["rag.query.digest"]) == 64
    assert "support case retention period" not in serialized
    assert "730 days" not in serialized


def test_demo_proves_no_model_or_network_calls() -> None:
    report = SDK.demo()
    assert report["model_calls"] == report["network_calls"] == 0
    assert report["finished_spans"] == 1
    assert report["telemetry_has_query_digest"]
    assert report["telemetry_omits_raw_query"]
    assert report["telemetry_omits_evidence_text"]

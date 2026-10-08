"""Pydantic and OpenTelemetry adapter for the Agentic RAG security boundary.

This module uses the real installed libraries but performs no model or network
calls. A production agent framework can register ``secure_search_tool`` as its
read-only retrieval tool while keeping ``RAGToolRuntime`` application-owned.
"""
from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import BaseModel, ConfigDict, Field, ValidationError


COURSE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("agentic_rag_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


class SearchToolInput(BaseModel):
    """Only model-proposable search fields; identity and policy are absent."""

    model_config = ConfigDict(extra="forbid", strict=True)

    query: str = Field(min_length=1, max_length=240)
    top_k: int = Field(default=3, ge=1, le=4)


class ClaimProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    key: str
    value: str
    unit: str


class EvidenceProjection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    chunk_id: str
    source_id: str
    source_version: int
    chunk_digest: str
    index_generation: int
    source_title: str
    locator: str
    authority: str
    score: float
    trust_label: str
    quoted_text: str
    claims: tuple[ClaimProjection, ...]


class SearchToolOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    status: str
    reason: str
    evidence: tuple[EvidenceProjection, ...]
    trace_id: str


@dataclass
class RAGToolRuntime:
    scenario: Any
    attestation: str
    run_id: str
    request_sequence: int = 0

    def next_request_id(self) -> str:
        self.request_sequence += 1
        return f"{self.run_id}:search:{self.request_sequence}"


def configure_in_memory_tracing() -> tuple[Any, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("agent-security.agentic-rag", "1.0"), exporter


def secure_search_tool(runtime: RAGToolRuntime, payload: dict[str, Any], *, tracer: Any) -> str:
    """Validate a narrow call, execute the trusted boundary, and emit safe telemetry."""
    try:
        request = SearchToolInput.model_validate(payload)
    except ValidationError:
        return SearchToolOutput(
            status=LAB.DecisionStatus.DENY.value,
            reason="invalid-tool-input",
            evidence=(),
            trace_id=f"trace:{runtime.run_id}:invalid",
        ).model_dump_json()

    request_id = runtime.next_request_id()
    with tracer.start_as_current_span("rag.retrieve") as span:
        span.set_attribute("gen_ai.operation.name", "retrieval")
        span.set_attribute("rag.run.id", runtime.run_id)
        span.set_attribute("rag.request.id", request_id)
        span.set_attribute("rag.query.digest", LAB.digest(request.query))
        span.set_attribute("rag.requested.top_k", request.top_k)
        issued = runtime.scenario.broker.issue(
            runtime.attestation,
            request_id=request_id,
            run_id=runtime.run_id,
            proposal=LAB.QueryProposal(request.query, request.top_k),
        )
        if not issued.grant:
            span.set_attribute("rag.decision", issued.status.value)
            span.set_attribute("rag.reason", issued.reason)
            span.set_attribute("rag.evidence.count", 0)
            return SearchToolOutput(
                status=issued.status.value,
                reason=issued.reason,
                evidence=(),
                trace_id=issued.receipt.trace_id,
            ).model_dump_json()
        result = runtime.scenario.retriever.retrieve(runtime.attestation, issued.grant)
        span.set_attribute("rag.decision", result.status.value)
        span.set_attribute("rag.reason", result.reason)
        span.set_attribute("rag.evidence.count", len(result.evidence))
        span.set_attribute("rag.policy.version", issued.grant.policy_version)
        span.set_attribute("rag.index.generation", issued.grant.index_generation)
        output = SearchToolOutput(
            status=result.status.value,
            reason=result.reason,
            evidence=tuple(
                EvidenceProjection(
                    chunk_id=item.ref.chunk_id,
                    source_id=item.ref.source_id,
                    source_version=item.ref.source_version,
                    chunk_digest=item.ref.chunk_digest,
                    index_generation=item.ref.index_generation,
                    source_title=item.source_title,
                    locator=item.locator,
                    authority=item.authority.value,
                    score=item.score,
                    trust_label="retrieved-evidence-not-instructions",
                    quoted_text=item.quoted_text,
                    claims=tuple(
                        ClaimProjection(key=fact.key, value=fact.value, unit=fact.unit)
                        for fact in item.claims
                    ),
                )
                for item in result.evidence
            ),
            trace_id=result.receipt.trace_id,
        )
        return output.model_dump_json()


def demo() -> dict[str, Any]:
    scenario = LAB.build_scenario()
    scenario.start_run("attest:north", "run:sdk-demo")
    runtime = RAGToolRuntime(scenario, "attest:north", "run:sdk-demo")
    tracer, exporter = configure_in_memory_tracing()
    safe = json.loads(secure_search_tool(
        runtime, {"query": "support case retention period", "top_k": 3}, tracer=tracer,
    ))
    forged_scope = json.loads(secure_search_tool(
        runtime,
        {"query": "retention", "top_k": 3, "tenant_id": "south"},
        tracer=tracer,
    ))
    spans = exporter.get_finished_spans()
    span_attributes = dict(spans[0].attributes)
    serialized_spans = json.dumps(span_attributes, sort_keys=True)
    return {
        "input_schema": SearchToolInput.model_json_schema(),
        "output_schema": SearchToolOutput.model_json_schema(),
        "safe_status": safe["status"],
        "safe_source_ids": sorted(item["source_id"] for item in safe["evidence"]),
        "forged_scope_status": forged_scope["status"],
        "forged_scope_reason": forged_scope["reason"],
        "finished_spans": len(spans),
        "telemetry_has_query_digest": "rag.query.digest" in span_attributes,
        "telemetry_omits_raw_query": "support case retention period" not in serialized_spans,
        "telemetry_omits_evidence_text": "730 days" not in serialized_spans,
        "model_calls": 0,
        "network_calls": 0,
    }


def main() -> None:
    report = demo()
    assert report["safe_status"] == "allow"
    assert "src:south:retention" not in report["safe_source_ids"]
    assert report["forged_scope_status"] == "deny"
    assert report["forged_scope_reason"] == "invalid-tool-input"
    assert report["finished_spans"] == 1
    assert report["telemetry_has_query_digest"]
    assert report["telemetry_omits_raw_query"]
    assert report["telemetry_omits_evidence_text"]
    assert report["model_calls"] == report["network_calls"] == 0
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

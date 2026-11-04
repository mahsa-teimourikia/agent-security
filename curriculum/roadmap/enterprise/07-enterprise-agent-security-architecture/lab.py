"""Exercise mediated enterprise architecture and effect-boundary enforcement."""
from dataclasses import asdict, dataclass, replace
import json

import enterprise_architecture as arch
import enterprise_architecture_fixtures as fixtures
from enterprise_architecture_otel import DecisionTelemetry


@dataclass(frozen=True)
class Evaluation:
    cases: int
    unsafe_allows: int
    valid_allow_rate: float
    cross_tenant_rejection_rate: float
    unmediated_path_rejection_rate: float
    dependency_unknown_rate: float
    false_blocks: int


def without_control(architecture: arch.Architecture, flow_id: str, control: str) -> arch.Architecture:
    flows = tuple(
        replace(flow, controls=flow.controls - {control}) if flow.flow_id == flow_id else flow
        for flow in architecture.flows
    )
    return replace(architecture, version=architecture.version + 1, flows=flows)


def evaluate_controls() -> Evaluation:
    valid = fixtures.gateway().decide(fixtures.request(), fixtures.NOW)
    cross_tenant = [
        fixtures.gateway().decide(
            fixtures.request(request_id=f"cross-{index}", resource_tenant=tenant), fixtures.NOW)
        for index, tenant in enumerate(("south", "west", "global"), 1)
    ]
    weak_architecture = without_control(fixtures.architecture(), "runtime-to-effect", "policy-enforcement")
    unmediated = [
        fixtures.gateway(architecture_value=weak_architecture).decide(
            fixtures.request(request_id=f"unmediated-{index}"), fixtures.NOW)
        for index in range(1, 4)
    ]
    unavailable = [
        fixtures.gateway(policy_value=fixtures.policy(available=False)).decide(
            fixtures.request(request_id=f"unavailable-{index}"), fixtures.NOW)
        for index in range(1, 4)
    ]
    all_receipts = [valid, *cross_tenant, *unmediated, *unavailable]
    unsafe_allows = sum(
        receipt.state is arch.DecisionState.ALLOW for receipt in [*cross_tenant, *unmediated, *unavailable]
    )
    return Evaluation(
        cases=len(all_receipts),
        unsafe_allows=unsafe_allows,
        valid_allow_rate=float(valid.state is arch.DecisionState.ALLOW),
        cross_tenant_rejection_rate=sum(item.reason == "cross-tenant" for item in cross_tenant) / len(cross_tenant),
        unmediated_path_rejection_rate=sum(item.reason == "unmediated-path" for item in unmediated) / len(unmediated),
        dependency_unknown_rate=sum(item.state is arch.DecisionState.UNKNOWN for item in unavailable) / len(unavailable),
        false_blocks=int(valid.state is not arch.DecisionState.ALLOW),
    )


def run_lab() -> dict:
    architecture = fixtures.architecture()
    report = arch.evaluate_architecture(architecture, fixtures.NOW)
    assert report.release_ready
    assert report.control_coverage == 1.0
    assert report.owner_coverage == 1.0

    gateway = fixtures.gateway(architecture)
    allowed = gateway.decide(fixtures.request(), fixtures.NOW)
    assert allowed.state is arch.DecisionState.ALLOW
    assert gateway.verify(allowed)

    # The agent's claimed intent cannot change authenticated tenant scope.
    cross_tenant = gateway.decide(
        fixtures.request(request_id="request-cross", resource_tenant="south"), fixtures.NOW)
    assert cross_tenant.state is arch.DecisionState.DENY
    assert cross_tenant.reason == "cross-tenant"

    # A direct runtime-to-effect route missing one control is a structural gap.
    weak = without_control(architecture, "runtime-to-effect", "policy-enforcement")
    weak_report = arch.evaluate_architecture(weak, fixtures.NOW)
    assert weak_report.unmediated_paths == ("runtime-to-effect",)
    bypass = fixtures.gateway(architecture_value=weak).decide(fixtures.request(), fixtures.NOW)
    assert bypass.reason == "unmediated-path"

    # Dependency failure is explicit UNKNOWN, never fabricated success.
    unknown = fixtures.gateway(policy_value=fixtures.policy(available=False)).decide(
        fixtures.request(request_id="request-outage"), fixtures.NOW)
    assert unknown.state is arch.DecisionState.UNKNOWN

    telemetry = DecisionTelemetry()
    for receipt in (allowed, cross_tenant, bypass, unknown):
        telemetry.emit(receipt)
    spans = telemetry.finished()
    assert len(spans) == 4
    assert all("agent.reason" in span.attributes for span in spans)
    assert all("prompt" not in key for span in spans for key in span.attributes)

    evaluation = evaluate_controls()
    assert evaluation.unsafe_allows == 0
    assert evaluation.valid_allow_rate == 1.0
    assert evaluation.cross_tenant_rejection_rate == 1.0
    assert evaluation.unmediated_path_rejection_rate == 1.0
    assert evaluation.dependency_unknown_rate == 1.0

    return {
        "architecture": asdict(report),
        "allowed": asdict(allowed),
        "cross_tenant": asdict(cross_tenant),
        "bypass": asdict(bypass),
        "dependency_outage": asdict(unknown),
        "telemetry_spans": len(spans),
        "evaluation": asdict(evaluation),
    }


if __name__ == "__main__":
    print(json.dumps(run_lab(), indent=2, default=lambda value: value.value))

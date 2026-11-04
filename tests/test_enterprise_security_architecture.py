"""Invariant tests for Enterprise Course 07 security architecture."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/07-enterprise-agent-security-architecture"
sys.path.insert(0, str(ROOT))
import enterprise_architecture as arch  # noqa: E402
import enterprise_architecture_fixtures as fx  # noqa: E402
from enterprise_architecture_otel import DecisionTelemetry  # noqa: E402

LAB_SPEC = importlib.util.spec_from_file_location("enterprise_07_course_lab", ROOT / "lab.py")
assert LAB_SPEC and LAB_SPEC.loader
course_lab = importlib.util.module_from_spec(LAB_SPEC)
sys.modules[LAB_SPEC.name] = course_lab
LAB_SPEC.loader.exec_module(course_lab)


def test_reference_architecture_is_release_ready():
    report = arch.evaluate_architecture(fx.architecture(), fx.NOW)
    assert report.release_ready
    assert report.control_coverage == 1.0
    assert report.owner_coverage == 1.0
    assert not report.unmediated_paths
    assert not report.single_points_of_failure


@pytest.mark.parametrize("flow_id,control", [
    ("edge-to-orchestrator", "workload-identity"),
    ("orchestrator-to-runtime", "tenant-bind"),
    ("runtime-to-data", "data-authorization"),
    ("runtime-to-effect", "policy-enforcement"),
    ("runtime-to-effect", "egress-control"),
    ("runtime-to-protocol", "transport-security"),
    ("runtime-to-protocol", "evidence-receipt"),
])
def test_missing_required_control_exposes_unmediated_path(flow_id, control):
    changed = course_lab.without_control(fx.architecture(), flow_id, control)
    report = arch.evaluate_architecture(changed, fx.NOW)
    assert flow_id in report.unmediated_paths
    assert not report.release_ready


def test_authority_flow_must_fail_closed():
    value = fx.architecture()
    flows = tuple(replace(item, fail_mode="open") if item.flow_id == "runtime-to-effect" else item for item in value.flows)
    report = arch.evaluate_architecture(replace(value, flows=flows), fx.NOW)
    assert "runtime-to-effect" in report.unmediated_paths


@pytest.mark.parametrize("component_id", ["effect-gateway", "policy-service", "evidence-pipeline"])
def test_critical_control_plane_requires_redundant_failure_domains(component_id):
    value = fx.architecture()
    components = tuple(
        replace(item, replicas=1, failure_domains=("az-a",)) if item.component_id == component_id else item
        for item in value.components)
    report = arch.evaluate_architecture(replace(value, components=components), fx.NOW)
    assert component_id in report.single_points_of_failure


@pytest.mark.parametrize("object_kind", ["component", "flow", "risk"])
def test_every_governed_object_requires_an_owner(object_kind):
    value = fx.architecture()
    if object_kind == "component":
        value = replace(value, components=(replace(value.components[0], owner=""), *value.components[1:]))
    elif object_kind == "flow":
        value = replace(value, flows=(replace(value.flows[0], owner=""), *value.flows[1:]))
    else:
        value = replace(value, residual_risks=(replace(value.residual_risks[0], owner=""), *value.residual_risks[1:]))
    report = arch.evaluate_architecture(value, fx.NOW)
    assert report.owner_coverage < 1.0
    assert not report.release_ready


@pytest.mark.parametrize("status,expires,field", [
    ("open", 1_500, "open_residual_risks"),
    ("accepted", 999, "expired_residual_risks"),
])
def test_residual_risk_must_be_closed_or_current(status, expires, field):
    value = fx.architecture()
    risks = (replace(value.residual_risks[0], status=status, expires_at=expires), *value.residual_risks[1:])
    report = arch.evaluate_architecture(replace(value, residual_risks=risks), fx.NOW)
    assert getattr(report, field)
    assert not report.release_ready


def test_duplicate_component_is_rejected():
    value = fx.architecture()
    with pytest.raises(ValueError, match="duplicate-component"):
        arch.evaluate_architecture(replace(value, components=value.components + (value.components[0],)), fx.NOW)


def test_unknown_flow_endpoint_is_rejected():
    value = fx.architecture()
    flows = (replace(value.flows[0], target="missing"), *value.flows[1:])
    with pytest.raises(ValueError, match="unknown-endpoint"):
        arch.evaluate_architecture(replace(value, flows=flows), fx.NOW)


def test_valid_request_is_allowed_with_signed_receipt():
    gateway = fx.gateway()
    receipt = gateway.decide(fx.request(), fx.NOW)
    assert receipt.state is arch.DecisionState.ALLOW
    assert receipt.reason == "authorized"
    assert gateway.verify(receipt)


@pytest.mark.parametrize("change,reason", [
    ({"flow_id": "unknown"}, "unknown-flow"),
    ({"resource_tenant": "south"}, "cross-tenant"),
    ({"capability": "refund.issue"}, "capability-mismatch"),
    ({"proposal_digest": ""}, "missing-proposal-digest"),
    ({"policy_version": "policy-17"}, "stale-policy"),
    ({"authenticated_principal": "ungranted"}, "not-granted"),
])
def test_effect_gateway_rejects_invalid_request(change, reason):
    receipt = fx.gateway().decide(fx.request(**change), fx.NOW)
    assert receipt.state is arch.DecisionState.DENY
    assert receipt.reason == reason


def test_expired_policy_is_denied():
    receipt = fx.gateway(policy_value=fx.policy(expires_at=fx.NOW)).decide(fx.request(), fx.NOW)
    assert (receipt.state, receipt.reason) == (arch.DecisionState.DENY, "stale-policy")


def test_policy_dependency_failure_is_unknown():
    receipt = fx.gateway(policy_value=fx.policy(available=False)).decide(fx.request(), fx.NOW)
    assert (receipt.state, receipt.reason) == (arch.DecisionState.UNKNOWN, "policy-unavailable")


def test_unmediated_path_cannot_execute():
    value = course_lab.without_control(fx.architecture(), "runtime-to-effect", "policy-enforcement")
    receipt = fx.gateway(architecture_value=value).decide(fx.request(), fx.NOW)
    assert receipt.reason == "unmediated-path"


def test_fail_open_authority_path_cannot_execute():
    value = fx.architecture()
    flows = tuple(
        replace(item, fail_mode="open") if item.flow_id == "runtime-to-effect" else item
        for item in value.flows)
    receipt = fx.gateway(architecture_value=replace(value, flows=flows)).decide(fx.request(), fx.NOW)
    assert receipt.reason == "unsafe-fail-mode"


def test_tampered_receipt_does_not_verify():
    gateway = fx.gateway()
    receipt = gateway.decide(fx.request(), fx.NOW)
    assert not gateway.verify(replace(receipt, state=arch.DecisionState.DENY))


def test_otel_adapter_emits_minimized_real_sdk_span():
    receipt = fx.gateway().decide(fx.request(), fx.NOW)
    telemetry = DecisionTelemetry()
    telemetry.emit(receipt)
    span = telemetry.finished()[0]
    assert span.attributes["agent.decision"] == "allow"
    assert span.attributes["agent.reason"] == "authorized"
    assert all("prompt" not in key and "content" not in key for key in span.attributes)


def test_evaluation_denominators_and_rates_are_exact():
    report = course_lab.evaluate_controls()
    assert report.cases == 10
    assert report.unsafe_allows == 0
    assert report.valid_allow_rate == 1.0
    assert report.cross_tenant_rejection_rate == 1.0
    assert report.unmediated_path_rejection_rate == 1.0
    assert report.dependency_unknown_rate == 1.0
    assert report.false_blocks == 0


def test_lab_runs_top_to_bottom():
    result = course_lab.run_lab()
    assert result["architecture"]["release_ready"]

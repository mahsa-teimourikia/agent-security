"""Focused regressions for Foundation 04 secure tool interfaces."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "04-secure-tool-and-action-interface-design"
SPEC = importlib.util.spec_from_file_location("foundation_04_interfaces", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


def execute(gateway, actor, proposal):
    grant = LAB.issue_demo_grant(proposal, actor, grant_id=f"grant:{proposal.logical_operation_id}", now=NOW)
    gateway.register_grant(grant)
    return gateway.dispatch(actor, proposal, grant_id=grant.grant_id, now=NOW)


def test_broad_tools_and_unknown_versions_fail_closed() -> None:
    gateway, actor = LAB.build_gateway()
    broad = LAB.ToolProposal("run_shell", "1.0.0", {"command": "refund --all"}, "attack:broad")
    stale = LAB.ToolProposal("read_refund_policy", "0.9.0", {"policy_id": "policy:refunds"}, "attack:stale")
    assert LAB.unsafe_broad_dispatch(broad)
    assert gateway.dispatch(actor, broad, now=NOW).reason == "tool-unregistered"
    assert gateway.dispatch(actor, stale, now=NOW).reason == "contract-version"


def test_strict_input_contract_rejects_extras_and_boolean_integer_confusion() -> None:
    gateway, actor = LAB.build_gateway()
    extra = replace(LAB.refund_proposal("attack:extra"), arguments={
        "case_id": "case:north:42", "amount_cents": 100, "currency": "CAD", "is_admin": True,
    })
    boolean = LAB.refund_proposal("attack:boolean", True)
    assert execute(gateway, actor, extra).reason == "unknown-field"
    assert execute(gateway, actor, boolean).reason == "field-type"
    assert not gateway.provider.effects


def test_schema_valid_input_still_requires_business_and_authority_checks() -> None:
    gateway, actor = LAB.build_gateway()
    cross_tenant = LAB.ToolProposal("issue_approved_refund", "1.0.0", {
        "case_id": "case:south:9", "amount_cents": 100, "currency": "CAD",
    }, "attack:tenant")
    too_large = LAB.refund_proposal("attack:limit", 20_000)
    missing_grant = LAB.refund_proposal("attack:grant", 100)
    assert execute(gateway, actor, cross_tenant).reason == "tenant"
    assert execute(gateway, actor, too_large).reason == "refundable-limit"
    assert gateway.dispatch(actor, missing_grant, now=NOW).reason == "grant-required"


def test_grant_is_exact_current_and_server_owned() -> None:
    gateway, actor = LAB.build_gateway()
    original = LAB.refund_proposal("refund:binding", 500)
    grant = LAB.issue_demo_grant(original, actor, grant_id="grant:binding", now=NOW)
    gateway.register_grant(grant)
    changed = replace(original, arguments={**original.arguments, "amount_cents": 501})
    assert gateway.dispatch(actor, changed, grant_id=grant.grant_id, now=NOW).reason == "grant-binding"
    gateway.grants[grant.grant_id] = replace(grant, expires_at=NOW)
    assert gateway.dispatch(actor, original, grant_id=grant.grant_id, now=NOW).reason == "grant-expired"


def test_idempotency_returns_prior_result_and_rejects_collision() -> None:
    gateway, actor = LAB.build_gateway()
    proposal = LAB.refund_proposal("refund:stable", 500)
    grant = LAB.issue_demo_grant(proposal, actor, grant_id="grant:stable", now=NOW)
    gateway.register_grant(grant)
    first = gateway.dispatch(actor, proposal, grant_id=grant.grant_id, now=NOW)
    duplicate = gateway.dispatch(actor, proposal, grant_id=grant.grant_id, now=NOW)
    changed = replace(proposal, arguments={**proposal.arguments, "amount_cents": 501})
    changed_grant = LAB.issue_demo_grant(changed, actor, grant_id="grant:changed", now=NOW)
    gateway.register_grant(changed_grant)
    collision = gateway.dispatch(actor, changed, grant_id=changed_grant.grant_id, now=NOW)
    assert first.effect_applied and duplicate.status is LAB.DecisionStatus.DUPLICATE
    assert first.result == duplicate.result and gateway.provider.calls == 1
    assert collision.reason == "operation-id-collision"


def test_output_is_validated_before_admission() -> None:
    gateway, actor = LAB.build_gateway(provider_mode=LAB.ProviderMode.MALFORMED_OUTPUT)
    decision = execute(gateway, actor, LAB.refund_proposal("refund:bad-output", 500))
    assert decision.status is LAB.DecisionStatus.ERROR
    assert decision.reason == "output-unknown-field" and decision.result is None


def test_unknown_outcome_is_reconciled_without_redispatch() -> None:
    gateway, actor = LAB.build_gateway(provider_mode=LAB.ProviderMode.TIMEOUT_AFTER_COMMIT)
    proposal = LAB.refund_proposal("refund:unknown", 500)
    grant = LAB.issue_demo_grant(proposal, actor, grant_id="grant:unknown", now=NOW)
    gateway.register_grant(grant)
    unknown = gateway.dispatch(actor, proposal, grant_id=grant.grant_id, now=NOW)
    recovered = gateway.dispatch(actor, proposal, grant_id=grant.grant_id, now=NOW + timedelta(seconds=1))
    assert unknown.status is LAB.DecisionStatus.UNKNOWN and unknown.reason == "outcome-unknown"
    assert recovered.status is LAB.DecisionStatus.DUPLICATE and recovered.reason == "reconciled-confirmed"
    assert gateway.provider.calls == 1 and len(gateway.provider.effects) == 1


def test_trace_contains_digests_not_raw_arguments() -> None:
    gateway, actor = LAB.build_gateway()
    proposal = LAB.ToolProposal("propose_refund", "1.0.0", {
        "case_id": "case:north:42", "amount_cents": 500, "reason_code": "service",
    }, "proposal:trace")
    assert gateway.dispatch(actor, proposal, now=NOW).successful
    rendered = repr(gateway.traces[-1])
    assert "case:north:42" not in rendered and "reason_code" not in rendered
    assert len(gateway.traces[-1].arguments_digest) == 64


def test_evaluation_separates_safety_utility_and_failures() -> None:
    report, cases = LAB.evaluate_controls(now=NOW)
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (12, 3, 7, 2)
    assert report.attack_block_rate == report.valid_task_success_rate == 1
    assert report.attack_effect_rate == 0
    assert report.unsafe_baseline_attack_acceptance_rate == 1
    assert report.trace_completeness_rate == 1
    assert all(not item.decision.effect_applied for item in cases if item.kind is LAB.CaseKind.ATTACK)


def test_architecture_diagram_is_validated_and_deterministic() -> None:
    render_spec = importlib.util.spec_from_file_location("foundation_04_diagram", COURSE / "render_architecture.py")
    assert render_spec and render_spec.loader
    renderer = importlib.util.module_from_spec(render_spec)
    sys.modules[render_spec.name] = renderer
    render_spec.loader.exec_module(renderer)
    spec = json.loads((COURSE / "architecture-spec.json").read_text())
    renderer.validate(spec)
    assert renderer.render(spec) == (COURSE / "architecture.svg").read_text()

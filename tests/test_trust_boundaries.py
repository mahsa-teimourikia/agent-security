"""Focused security regressions for Foundation 01 trust boundaries."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "01-agent-security-architecture-and-trust-boundaries"
SPEC = importlib.util.spec_from_file_location("foundation_01_trust_boundaries", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)

ActorContext = LAB.ActorContext
BoundaryCatalog = LAB.BoundaryCatalog
BoundaryController = LAB.BoundaryController
BoundarySpec = LAB.BoundarySpec
DependencyState = LAB.DependencyState
GrantRegistry = LAB.GrantRegistry
Operation = LAB.Operation
Zone = LAB.Zone
build_catalog = LAB.build_catalog
evaluate_controls = LAB.evaluate_controls
issue_demo_grant = LAB.issue_demo_grant
request_for = LAB.request_for
unsafe_schema_only_baseline = LAB.unsafe_schema_only_baseline
REQUIRED_BOUNDARIES = LAB.REQUIRED_BOUNDARIES

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
ACTOR = ActorContext(
    "user:7",
    "north",
    frozenset({"evidence:read", "ticket:propose", "tool:invoke"}),
)


def test_catalog_is_complete_and_requires_deterministic_observable_controls() -> None:
    catalog = build_catalog()
    assert catalog.audit(REQUIRED_BOUNDARIES) == {
        "present": 9,
        "required": 9,
        "coverage": 1.0,
        "missing": [],
        "unexpected": [],
    }
    invalid = BoundarySpec(
        "bad", Zone.AGENT, Zone.APPLICATION, "proposal", frozenset({Operation.PROPOSE_TICKET}),
        "ticket:propose", "model", ("request_id",),
    )
    with pytest.raises(ValueError, match="deterministic enforcement owner"):
        BoundaryCatalog([invalid])


def test_model_identity_route_and_cross_tenant_claims_never_grant_authority() -> None:
    controller = BoundaryController(build_catalog())
    context = request_for("B2-gateway-context", Operation.BUILD_CONTEXT, request_id="context")
    assert controller.cross(ACTOR, context, now=NOW).allowed
    assert controller.cross(ACTOR, replace(context, request_id="tenant", resource_tenant="south"), now=NOW).reason == "tenant"
    assert controller.cross(ACTOR, replace(context, request_id="provenance", provenance_verified=False), now=NOW).reason == "evidence-provenance"

    proposal = request_for(
        "B4-model-runtime", Operation.PROPOSE_TICKET, request_id="admin-claim", claimed_subject="admin"
    )
    limited = replace(ACTOR, scopes=frozenset({"evidence:read"}))
    denied = controller.cross(limited, proposal, now=NOW)
    assert not denied.allowed and denied.reason == "scope" and denied.subject == ACTOR.subject

    unproven_context = request_for(
        "B3-context-model", Operation.GENERATE_PROPOSAL, request_id="unproven-context", evidence_ids=()
    )
    context_actor = replace(ACTOR, scopes=ACTOR.scopes | {"agent:invoke"})
    assert controller.cross(context_actor, unproven_context, now=NOW).reason == "evidence-provenance"

    bypass = controller.cross(ACTOR, replace(context, request_id="bypass", boundary_id="direct-api"), now=NOW)
    wrong_route = controller.cross(ACTOR, replace(context, request_id="route", source=Zone.AGENT), now=NOW)
    assert bypass.reason == "unregistered-boundary"
    assert wrong_route.reason == "boundary-route-mismatch"


def test_schema_only_baseline_demonstrates_why_shape_is_not_authority() -> None:
    request = request_for(
        "B2-gateway-context", Operation.BUILD_CONTEXT, request_id="baseline-attack",
        resource_tenant="south",
    )
    assert unsafe_schema_only_baseline(request)
    decision = BoundaryController(build_catalog()).cross(ACTOR, request, now=NOW)
    assert not decision.allowed and decision.reason == "tenant"


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (DependencyState(identity_available=False), "identity-unavailable"),
        (DependencyState(policy_available=False), "policy-unavailable"),
        (DependencyState(telemetry_available=False), "telemetry-unavailable"),
    ],
)
def test_dependencies_fail_closed_with_reasoned_evidence(state: object, reason: str) -> None:
    request = request_for("B2-gateway-context", Operation.BUILD_CONTEXT, request_id=reason)
    decision = BoundaryController(build_catalog()).cross(ACTOR, request, state=state, now=NOW)
    assert not decision.allowed and decision.reason == reason and decision.policy_version


def test_effect_grant_is_exact_expiring_single_use_and_kill_switch_aware() -> None:
    actor = replace(ACTOR, scopes=ACTOR.scopes | {"tool:invoke"})
    request = request_for(
        "B5-runtime-tool", Operation.CREATE_TICKET, request_id="effect", evidence_ids=(),
        logical_operation_id="ticket:case:42:v1",
    )
    without_operation_id = replace(request, logical_operation_id=None)
    assert BoundaryController(build_catalog()).cross(actor, without_operation_id, now=NOW).reason == "logical-operation-id-required"
    missing = BoundaryController(build_catalog()).cross(actor, request, now=NOW)
    assert missing.reason == "effect-grant-required"

    grant = issue_demo_grant(request, actor, grant_id="grant:1", expires_at=NOW + timedelta(minutes=5))
    controller = BoundaryController(build_catalog(), GrantRegistry({grant.grant_id: grant}))
    granted = replace(request, request_id="granted", effect_grant_id=grant.grant_id)
    altered = replace(granted, request_id="altered", resource_id="case:43")
    altered_operation = replace(granted, request_id="altered-operation", logical_operation_id="ticket:case:42:v2")
    assert controller.cross(actor, altered, now=NOW).reason == "invalid-or-replayed-effect-grant"
    assert controller.cross(actor, altered_operation, now=NOW).reason == "invalid-or-replayed-effect-grant"
    assert controller.cross(actor, granted, now=NOW).allowed
    assert controller.cross(actor, replace(granted, request_id="replay"), now=NOW).reason == "invalid-or-replayed-effect-grant"

    disabled_controller = BoundaryController(build_catalog(), GrantRegistry({grant.grant_id: grant}))
    disabled = disabled_controller.cross(actor, granted, state=DependencyState(effects_enabled=False), now=NOW)
    assert disabled.reason == "effects-disabled" and grant.grant_id not in disabled_controller.grants.consumed

    expired = issue_demo_grant(request, actor, grant_id="grant:old", expires_at=NOW)
    expired_result = BoundaryController(build_catalog(), GrantRegistry({expired.grant_id: expired})).cross(
        actor, replace(request, effect_grant_id=expired.grant_id), now=NOW
    )
    assert expired_result.reason == "invalid-or-replayed-effect-grant"

    naive_expiry = issue_demo_grant(request, actor, grant_id="grant:naive", expires_at=NOW.replace(tzinfo=None))
    naive_result = BoundaryController(build_catalog(), GrantRegistry({naive_expiry.grant_id: naive_expiry})).cross(
        actor, replace(request, effect_grant_id=naive_expiry.grant_id), now=NOW
    )
    assert naive_result.reason == "invalid-or-replayed-effect-grant"


def test_concurrent_effect_grant_allows_at_most_one_crossing() -> None:
    request = request_for(
        "B5-runtime-tool", Operation.CREATE_TICKET, request_id="race", evidence_ids=(),
        logical_operation_id="ticket:case:42:race",
    )
    grant = issue_demo_grant(request, ACTOR, grant_id="grant:race", expires_at=NOW + timedelta(minutes=5))
    controller = BoundaryController(build_catalog(), GrantRegistry({grant.grant_id: grant}))

    def invoke(index: int):
        return controller.cross(
            ACTOR,
            replace(request, request_id=f"race:{index}", effect_grant_id=grant.grant_id),
            now=NOW,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(invoke, range(8)))
    assert sum(decision.allowed for decision in decisions) == 1
    assert sum(decision.reason == "invalid-or-replayed-effect-grant" for decision in decisions) == 7


def test_evaluation_has_explicit_populations_and_redacted_events() -> None:
    report, events = evaluate_controls()
    assert (report.cases, report.negative_cases, report.attack_cases, report.dependency_failure_cases, report.valid_cases) == (8, 6, 5, 1, 2)
    assert report.unexpected_allow_rate == 0
    assert report.valid_task_success_rate == report.trace_completeness_rate == 1
    assert report.inventory_coverage == report.observed_boundary_coverage == 1
    assert (report.observed_boundaries, report.expected_boundaries) == (9, 9)
    rendered = repr(events)
    assert "synthetic-content" not in rendered and "case:42" not in rendered

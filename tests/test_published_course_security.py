"""Focused negative tests for the hardened published courses."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mcp():
    return load("published_mcp", "curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.py")


@pytest.fixture(scope="module")
def incident():
    return load("published_incident", "curriculum/intermediate/03-incident-recovery/03_incident_recovery.py")


@pytest.fixture(scope="module")
def attack_eval():
    return load("published_attack_eval", "curriculum/advanced/01-attack-evaluation/01_attack_evaluation.py")


@pytest.fixture(scope="module")
def delegation():
    return load("published_delegation", "curriculum/advanced/02-multi-agent-security/02_multi_agent_security.py")


@pytest.fixture(scope="module")
def production():
    return load("published_production", "curriculum/advanced/03-production-gate/03_production_gate.py")


def mcp_fixture(mcp):
    gateway = mcp.Gateway({"trusted": {"search": mcp.ToolSpec("search", "search", frozenset({"query"}))}})
    identity = mcp.ClientIdentity("agent", "north")
    token = mcp.AccessToken("agent", "north", "mcp-gateway", frozenset({"search"}), NOW + timedelta(minutes=5), "secret-token")
    return gateway, identity, token, mcp.ToolCall("trusted", "search", {"query": "retention"})


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("audience", "token-audience"),
        ("server", "untrusted-server"),
        ("schema", "argument-schema"),
        ("expired", "token-expired"),
        ("tenant", "identity-binding"),
    ],
)
def test_mcp_gateway_denies_boundary_confusion(mcp, mutation, reason):
    gateway, identity, token, call = mcp_fixture(mcp)
    if mutation == "audience":
        token = mcp.AccessToken(token.subject, token.tenant, "other-api", token.scopes, token.expires_at, token.token_id)
    elif mutation == "server":
        call = mcp.ToolCall("evil", call.tool, call.arguments)
    elif mutation == "schema":
        call = mcp.ToolCall(call.server, call.tool, {"query": "x", "admin": "true"})
    elif mutation == "expired":
        token = mcp.AccessToken(token.subject, token.tenant, token.audience, token.scopes, NOW, token.token_id)
    elif mutation == "tenant":
        identity = mcp.ClientIdentity(identity.subject, "south")
    result = gateway.dispatch(identity, token, call, now=NOW)
    assert result["status"] == "deny"
    assert result["receipt"].reason == reason
    assert "secret-token" not in repr(result)


def test_mcp_gateway_enforces_quota_atomically_for_sequence(mcp):
    gateway, identity, token, call = mcp_fixture(mcp)
    gateway.per_subject_limit = 1
    assert gateway.dispatch(identity, token, call, now=NOW)["status"] == "allow"
    assert gateway.dispatch(identity, token, call, now=NOW)["receipt"].reason == "rate-limit"


def test_incident_recovery_rejects_tampered_checkpoint(incident):
    run, responder, planner, _, signal, receipt, checkpoint, plan = incident.build_scenario(now=NOW)
    assert run.detect(signal, now=NOW)
    assert run.contain(receipt, responder=responder, now=NOW)
    tampered = incident.CheckpointSnapshot(
        checkpoint.checkpoint_id,
        checkpoint.run_id,
        checkpoint.tenant,
        incident.checkpoint_digest({"version": 2}),
        checkpoint.policy_version,
        checkpoint.credential_version,
        checkpoint.created_at,
    )
    assert not run.propose_recovery(plan, tampered, planner=planner, now=NOW)


def test_incident_recovery_requires_independent_operator(incident):
    run, responder, planner, _, signal, receipt, checkpoint, plan = incident.build_scenario(now=NOW)
    assert run.detect(signal, now=NOW)
    assert run.contain(receipt, responder=responder, now=NOW)
    assert run.propose_recovery(plan, checkpoint, planner=planner, now=NOW)
    self_approver = incident.ActorContext(plan.requested_by, "north", frozenset({"recovery-approver"}))
    approval = incident.issue_approval(plan, self_approver, approval_id="self-approval", now=NOW)
    assert not run.authorize_recovery(
        approval,
        checkpoint,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
        now=NOW,
    )


def test_incident_effect_blocks_duplicate_provider_call(incident):
    run = incident.demo()
    blocked = run.execute_effect(
        attempt_id="retry",
        capability="ticket:write",
        now=NOW,
        provider=lambda _: incident.ProviderResult(incident.EffectState.CONFIRMED, "duplicate"),
    )
    assert blocked.reason == "duplicate-confirmed"
    assert run.verify_event_chain()


def evaluation_fixture(attack_eval):
    suite, run = attack_eval.build_suite(now=NOW, attempts=1)
    return suite, run, attack_eval.safe_results(suite, run)


def test_attack_evaluation_blocks_severe_success(attack_eval):
    suite, run, results = evaluation_fixture(attack_eval)
    case = next(item for item in suite.cases if item.severity is attack_eval.Severity.CRITICAL)
    index = next(i for i, item in enumerate(results) if item.case_id == case.case_id)
    results[index] = attack_eval.result_for(suite, run, case, 1, outcome=attack_eval.Outcome.ALLOWED)
    report = attack_eval.evaluate(suite, run, results, now=run.ended_at)
    assert not report.ready and report.severe_attack_successes == 1


def test_attack_evaluation_blocks_missing_and_untraceable(attack_eval):
    suite, run, results = evaluation_fixture(attack_eval)
    results[0] = replace(results[0], trace_id="", evidence_ids=())
    report = attack_eval.evaluate(suite, run, results[:-1], now=run.ended_at)
    assert any(item.startswith("untraceable:") for item in report.blockers)
    assert any(item.startswith("missing-attempts:") for item in report.blockers)


def test_attack_evaluation_rejects_duplicate_ids(attack_eval):
    suite, run, results = evaluation_fixture(attack_eval)
    with pytest.raises(ValueError, match="unique"):
        attack_eval.evaluate(suite, run, [*results, results[0]], now=run.ended_at)


def test_delegation_cannot_amplify_scope(delegation):
    service, _, authority, parent, _, request = delegation.build_scenario(now=NOW)
    decision = service.issue(
        authority,
        parent,
        replace(request, scopes=frozenset({"search", "delete"})),
        now=NOW,
    )
    assert not decision.allowed and decision.reason == "scope"


def test_delegation_enforces_identity_tenant_artifact_and_budget(delegation):
    service, registry, authority, parent, worker, request = delegation.build_scenario(now=NOW)
    issued = service.issue(authority, parent, replace(request, budget=1), now=NOW)
    assert issued.envelope
    session = delegation.WorkerSession(issued.envelope, service, registry, "research-runtime")
    operation = delegation.OperationRequest("op-1", "try-1", "search", "case:42", "evidence-list")
    candidate = delegation.candidate_for(issued.envelope, operation)
    assert not session.execute(replace(worker, tenant="south"), operation, candidate, now=NOW).allowed
    assert session.execute(worker, operation, candidate, now=NOW).allowed
    second = replace(operation, operation_id="op-2", attempt_id="try-2")
    assert session.execute(worker, second, delegation.candidate_for(issued.envelope, second), now=NOW).reason == "budget"


def valid_evidence(production):
    return [production.Evidence(kind, f"artifact:{kind}", "v7", "team:security", NOW, True) for kind in production.REQUIRED_EVIDENCE]


@pytest.mark.parametrize("failure", ["empty", "stale", "failed", "severe", "expired-risk"])
def test_production_gate_rejects_invalid_evidence(production, failure):
    evidence = valid_evidence(production)
    severe = 0
    risks = [production.RiskAcceptance("R-1", "owner:a", "bounded pilot risk", NOW + timedelta(days=1))]
    if failure in {"empty", "stale", "failed"}:
        item = evidence[0]
        evidence[0] = production.Evidence(
            item.kind,
            "" if failure == "empty" else item.value,
            item.version,
            item.owner,
            NOW - timedelta(days=31) if failure == "stale" else item.observed_at,
            failure != "failed",
        )
    elif failure == "severe":
        severe = 1
    else:
        risks = [production.RiskAcceptance("R-1", "owner:a", "bounded pilot risk", NOW)]
    decision = production.evaluate_release(evidence, severe_attack_successes=severe, residual_risks=risks, now=NOW)
    assert not decision.ready and decision.blockers

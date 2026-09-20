"""Invariant tests for Advanced 02 multi-agent delegation security."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
PATH = ROOT / "curriculum/advanced/02-multi-agent-security/02_multi_agent_security.py"
SPEC = importlib.util.spec_from_file_location("advanced_02_multi_agent", PATH)
assert SPEC and SPEC.loader
delegation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = delegation
SPEC.loader.exec_module(delegation)
NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)


def issued_session(*, budget: int = 2):
    service, registry, authority, parent, worker, request = delegation.build_scenario(now=NOW)
    request = replace(request, budget=budget)
    decision = service.issue(authority, parent, request, now=NOW)
    assert decision.allowed and decision.envelope
    session = delegation.WorkerSession(
        decision.envelope,
        service,
        registry,
        "research-runtime",
    )
    return service, registry, authority, parent, worker, request, session


def operation(index: int = 1, **changes):
    base = delegation.OperationRequest(
        f"op-{index}",
        f"attempt-{index}",
        "search",
        "case:42",
        "evidence-list",
    )
    return replace(base, **changes)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"tenant": "south"}, "tenant"),
        ({"child_workload_id": "spiffe://attacker"}, "child-ineligible"),
        ({"audience": "billing-runtime"}, "audience"),
        ({"scopes": frozenset({"delete"})}, "scope"),
        ({"resources": frozenset({"case:99"})}, "resource"),
        ({"artifact_types": frozenset({"raw-secret"})}, "artifact-contract"),
        ({"budget": 4}, "budget"),
        ({"expires_at": NOW + timedelta(hours=2)}, "lifetime"),
        ({"depth": 2}, "delegation-depth"),
        ({"parent_envelope_id": "invented"}, "lineage"),
    ],
)
def test_issuance_rejects_each_widening_dimension(changes, reason):
    service, _, authority, parent, _, request = delegation.build_scenario(now=NOW)
    decision = service.issue(authority, parent, replace(request, **changes), now=NOW)
    assert not decision.allowed
    assert decision.reason == reason
    assert decision.envelope is None


def test_issuance_binds_authenticated_parent_and_request_replay():
    service, _, authority, parent, _, request = delegation.build_scenario(now=NOW)
    denied = service.issue(authority, replace(parent, authenticated=False), request, now=NOW)
    assert denied.reason == "parent-unauthenticated"
    substituted = service.issue(
        authority,
        replace(parent, workload_id="spiffe://attacker"),
        request,
        now=NOW,
    )
    assert substituted.reason == "parent-identity-binding"

    first = service.issue(authority, parent, request, now=NOW)
    replay = service.issue(authority, parent, request, now=NOW)
    mutation = service.issue(
        authority,
        parent,
        replace(request, scopes=frozenset({"read"})),
        now=NOW,
    )
    assert first.allowed and replay.reason == "idempotent-reissue"
    assert replay.envelope == first.envelope
    assert not mutation.allowed and mutation.reason == "request-replay-mismatch"


def test_issuance_rejects_empty_security_identifiers():
    service, _, authority, parent, _, request = delegation.build_scenario(now=NOW)
    decision = service.issue(authority, parent, replace(request, request_id=""), now=NOW)
    assert not decision.allowed and decision.reason == "identity-fields"


def test_idempotent_issuance_does_not_resurrect_old_policy_envelope():
    service, _, authority, parent, _, request = delegation.build_scenario(now=NOW)
    assert service.issue(authority, parent, request, now=NOW).allowed
    service.policy = replace(service.policy, version="policy-8")
    replay = service.issue(authority, parent, request, now=NOW)
    assert not replay.allowed and replay.reason == "policy-version"


def test_aggregate_budget_and_fanout_do_not_multiply_parent_authority():
    service, _, authority, parent, _, request = delegation.build_scenario(now=NOW)
    assert service.issue(authority, parent, request, now=NOW).allowed
    second = replace(request, request_id="delegate-43", budget=1)
    third = replace(request, request_id="delegate-44", budget=1)
    assert service.issue(authority, parent, second, now=NOW).allowed
    denied = service.issue(authority, parent, third, now=NOW)
    assert not denied.allowed
    assert denied.reason in {"fan-out", "aggregate-budget"}


def test_tampered_envelope_fails_integrity_before_use():
    service, registry, _, _, worker, _, session = issued_session()
    session.envelope = replace(session.envelope, budget=99)
    request = operation()
    decision = session.execute(worker, request, delegation.candidate_for(session.envelope, request), now=NOW)
    assert not decision.allowed and decision.reason == "envelope-integrity"
    assert session.consumed == 0
    assert service and registry


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("identity", "worker-identity-binding"),
        ("audience", "audience"),
        ("policy", "policy-version"),
        ("revocation", "revoked-lineage"),
        ("expiry", "expired"),
        ("scope", "scope"),
        ("resource", "resource"),
        ("artifact", "artifact-contract"),
    ],
)
def test_use_time_boundary_rechecks_current_context(mutation, reason):
    _, registry, _, _, worker, _, session = issued_session()
    request = operation()
    now = NOW
    if mutation == "identity":
        worker = replace(worker, workload_id="spiffe://attacker")
    elif mutation == "audience":
        session.runtime_audience = "other-runtime"
    elif mutation == "policy":
        session.service.policy = replace(session.service.policy, version="policy-8")
    elif mutation == "revocation":
        registry.revoke(session.envelope.envelope_id)
    elif mutation == "expiry":
        now = session.envelope.expires_at
    elif mutation == "scope":
        request = replace(request, operation="delete")
    elif mutation == "resource":
        request = replace(request, resource_id="case:99")
    elif mutation == "artifact":
        request = replace(request, artifact_type="raw-secret")
    decision = session.execute(worker, request, delegation.candidate_for(session.envelope, request), now=now)
    assert not decision.allowed and decision.reason == reason
    assert session.consumed == 0


def test_idempotent_retry_returns_same_artifact_without_spending_again():
    _, _, _, _, worker, _, session = issued_session()
    first_request = operation()
    first = session.execute(
        worker,
        first_request,
        delegation.candidate_for(session.envelope, first_request),
        now=NOW,
    )
    retry_request = replace(first_request, attempt_id="attempt-retry")
    retry = session.execute(
        worker,
        retry_request,
        delegation.candidate_for(session.envelope, retry_request),
        now=NOW,
    )
    assert first.allowed and retry.allowed and retry.replayed
    assert retry.reason == "idempotent-replay"
    assert retry.artifact == first.artifact
    assert session.consumed == 1


def test_same_operation_id_cannot_be_mutated_and_replayed():
    _, _, _, _, worker, _, session = issued_session()
    request = operation()
    assert session.execute(
        worker,
        request,
        delegation.candidate_for(session.envelope, request),
        now=NOW,
    ).allowed
    retry = replace(request, attempt_id="attempt-retry")
    changed = delegation.candidate_for(session.envelope, retry, content="different")
    decision = session.execute(worker, retry, changed, now=NOW)
    assert not decision.allowed and decision.reason == "operation-replay-mismatch"
    assert session.consumed == 1


def test_attempt_id_cannot_be_reused_for_a_different_operation():
    _, _, _, _, worker, _, session = issued_session()
    first = operation()
    assert session.execute(worker, first, delegation.candidate_for(session.envelope, first), now=NOW).allowed
    second = operation(2, attempt_id=first.attempt_id)
    denied = session.execute(worker, second, delegation.candidate_for(session.envelope, second), now=NOW)
    assert not denied.allowed and denied.reason == "attempt-replay"


def test_empty_operation_identifiers_fail_closed():
    _, _, _, _, worker, _, session = issued_session()
    request = operation(operation_id="")
    decision = session.execute(worker, request, delegation.candidate_for(session.envelope, request), now=NOW)
    assert not decision.allowed and decision.reason == "operation-contract"


@pytest.mark.parametrize(
    ("candidate_change", "reason"),
    [
        ({"producer": "other"}, "result-binding"),
        ({"tenant": "south"}, "result-binding"),
        ({"evidence_ids": ()}, "evidence-contract"),
        ({"content": ""}, "result-size"),
        ({"content": "x" * 513}, "result-size"),
    ],
)
def test_result_admission_rejects_unbound_or_invalid_artifacts(candidate_change, reason):
    _, _, _, _, worker, _, session = issued_session()
    request = operation()
    candidate = replace(delegation.candidate_for(session.envelope, request), **candidate_change)
    decision = session.execute(worker, request, candidate, now=NOW)
    assert not decision.allowed and decision.reason == reason
    assert decision.artifact is None and session.consumed == 0


def test_budget_is_atomic_under_concurrent_workers():
    _, _, _, _, worker, _, session = issued_session(budget=2)

    def run(index: int):
        request = operation(index)
        return session.execute(
            worker,
            request,
            delegation.candidate_for(session.envelope, request, content=f"E-{index}"),
            now=NOW,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(run, range(1, 9)))
    assert sum(decision.allowed for decision in decisions) == 2
    assert sum(decision.reason == "budget" for decision in decisions) == 6
    assert session.consumed == 2


def test_termination_blocks_even_an_idempotent_retry():
    _, _, _, _, worker, _, session = issued_session()
    request = operation()
    assert session.execute(worker, request, delegation.candidate_for(session.envelope, request), now=NOW).allowed
    session.terminate(reason="suspected compromise")
    retry = replace(request, attempt_id="attempt-retry")
    decision = session.execute(worker, retry, delegation.candidate_for(session.envelope, retry), now=NOW)
    assert not decision.allowed and decision.reason == "terminated"


def test_evaluation_metrics_use_attack_and_valid_task_denominators():
    _, _, _, _, worker, _, session = issued_session()
    good_request = operation()
    good = session.execute(
        worker,
        good_request,
        delegation.candidate_for(session.envelope, good_request),
        now=NOW,
    )
    attack_request = operation(2, operation="delete")
    attack = session.execute(
        worker,
        attack_request,
        delegation.candidate_for(session.envelope, attack_request),
        now=NOW,
    )
    report = delegation.evaluate_cases(
        [
            delegation.EvaluationCase("valid", True, good),
            delegation.EvaluationCase("escalation", False, attack),
        ]
    )
    assert report.attack_success_rate == 0.0
    assert report.blocked_valid_task_rate == 0.0
    assert report.blocked_attacks == 1


def test_receipts_omit_content_and_signing_material():
    _, _, _, _, worker, _, session = issued_session()
    request = operation()
    secret_marker = "sensitive-result-content"
    decision = session.execute(
        worker,
        request,
        delegation.candidate_for(session.envelope, request, content=secret_marker),
        now=NOW,
    )
    assert decision.allowed
    assert secret_marker not in repr(decision.receipt)
    assert "credential-free-course-key" not in repr(session.receipts)

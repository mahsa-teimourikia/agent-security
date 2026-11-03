"""Namespaced deterministic fixtures for Enterprise Course 05."""
from __future__ import annotations

from dataclasses import dataclass, replace

import pydantic_adapter as adapter
import release_readiness as rr


ALL_KINDS = frozenset(rr.EvidenceKind)


@dataclass
class CourseScenario:
    keyring: adapter.FixtureHMACKeyring
    store: rr.EvidenceStore
    gate: rr.ReleaseGate
    record: rr.ReleaseRecord
    actor: rr.ReleaseActor
    authorizer: rr.CurrentAuthorizer
    provider: rr.SyntheticDeploymentProvider
    executor: rr.RolloutExecutor
    exception_authorities: dict[str, rr.TrustedAuthority]
    approval_authorities: dict[str, rr.TrustedAuthority]


def requirements() -> tuple[rr.EvidenceRequirement, ...]:
    return (
        rr.EvidenceRequirement(rr.EvidenceKind.BUILD_PROVENANCE, 300, 1.0, False),
        rr.EvidenceRequirement(rr.EvidenceKind.UNIT_TEST, 300, 0.99),
        rr.EvidenceRequirement(rr.EvidenceKind.INTEGRATION_TEST, 300, 0.98),
        rr.EvidenceRequirement(rr.EvidenceKind.ADVERSARIAL_EVAL, 180, 0.95, False),
        rr.EvidenceRequirement(rr.EvidenceKind.SUPPLY_CHAIN, 300, 1.0, False),
        rr.EvidenceRequirement(rr.EvidenceKind.ROLLBACK_DRILL, 180, 1.0, False),
        rr.EvidenceRequirement(rr.EvidenceKind.OBSERVABILITY, 180, 1.0),
        rr.EvidenceRequirement(rr.EvidenceKind.RUNBOOK, 600, 1.0),
        rr.EvidenceRequirement(rr.EvidenceKind.OWNER_APPROVAL, 180, 1.0, False),
    )


def make_evidence(
    keyring: adapter.FixtureHMACKeyring,
    *,
    release_digest: str = "sha256:candidate-500",
    tenant: str = "north",
    environment: str = "production",
    policy_version: str = "release-policy-2026-11",
    issued_at: int = 100,
) -> tuple[rr.ReleaseEvidence, ...]:
    rows = (
        (rr.EvidenceKind.BUILD_PROVENANCE, 1, 1, "ci://build/500"),
        (rr.EvidenceKind.UNIT_TEST, 100, 100, "ci://unit/500"),
        (rr.EvidenceKind.INTEGRATION_TEST, 50, 50, "ci://integration/500"),
        (rr.EvidenceKind.ADVERSARIAL_EVAL, 40, 40, "eval://adversarial/500"),
        (rr.EvidenceKind.SUPPLY_CHAIN, 1, 1, "attestation://slsa/500"),
        (rr.EvidenceKind.ROLLBACK_DRILL, 4, 4, "drill://rollback/500"),
        (rr.EvidenceKind.OBSERVABILITY, 6, 6, "monitor://coverage/500"),
        (rr.EvidenceKind.RUNBOOK, 1, 1, "runbook://support-agent/5"),
        (rr.EvidenceKind.OWNER_APPROVAL, 1, 1, "approval://owner/500"),
    )
    result: list[rr.ReleaseEvidence] = []
    for kind, checked, passed, source in rows:
        item = rr.ReleaseEvidence(
            evidence_id=f"evidence:{kind.value}:500",
            release_digest=release_digest,
            tenant=tenant,
            environment=environment,
            kind=kind,
            producer_id="ci:north",
            policy_version=policy_version,
            issued_at=issued_at,
            expires_at=issued_at + 600,
            result=rr.EvidenceResult.PASS,
            checked=checked,
            passed=passed,
            severe_failures=0,
            owner=f"owner:{kind.value}",
            source_uri=source,
            payload_digest=rr.digest({"kind": kind.value, "run": 500, "checked": checked}),
        )
        result.append(keyring.sign_evidence(item, "ci-evidence-2026-11"))
    return tuple(result)


def build_scenario() -> CourseScenario:
    keyring = adapter.fixture_keyring()
    producer = rr.TrustedProducer(
        "ci:north", "north", "ci-evidence-2026-11", ALL_KINDS,
    )
    store = rr.EvidenceStore({producer.producer_id: producer}, keyring)
    for item in make_evidence(keyring):
        assert store.admit(item, now=120).status is rr.Admission.ADMITTED

    exception_authorities = {
        "risk-committee-2026-11": rr.TrustedAuthority(
            "risk-committee-2026-11", "north", "risk-exception",
        ),
    }
    approval_authorities = {
        "release-board-2026-11": rr.TrustedAuthority(
            "release-board-2026-11", "north", "release-approval",
        ),
    }
    gate = rr.ReleaseGate(store, keyring, exception_authorities, requirements())
    record = rr.ReleaseRecord(
        "release:support-agent:500", "north", "production",
        "sha256:candidate-500", "sha256:stable-499",
    )
    actor = rr.ReleaseActor("operator:north:7", "north", frozenset({"release-operator"}))
    authorizer = rr.CurrentAuthorizer(frozenset({("north", "production", "write-support-case")}))
    provider = rr.SyntheticDeploymentProvider(metrics={
        record.candidate_digest: rr.CanaryMetrics(100, 0, 0.01, 1.0, 420, 0.08),
    })
    executor = rr.RolloutExecutor(
        gate, keyring, approval_authorities, "release-policy-2026-11",
    )
    return CourseScenario(
        keyring, store, gate, record, actor, authorizer, provider, executor,
        exception_authorities, approval_authorities,
    )


def approved_release(
    scenario: CourseScenario,
    *,
    now: int = 120,
    approval_id: str = "approval:release:500",
    exceptions: tuple[rr.RiskException, ...] = (),
) -> tuple[rr.GateDecision, rr.ReleasePlan, rr.ReleaseApproval]:
    decision = scenario.gate.evaluate(
        release_digest=scenario.record.candidate_digest,
        tenant=scenario.record.tenant,
        environment=scenario.record.environment,
        policy_version=scenario.executor.current_policy_version,
        now=now,
        exceptions=exceptions,
    )
    plan = rr.bind_plan(rr.ReleasePlan(
        plan_id="plan:release:500",
        release_digest=scenario.record.candidate_digest,
        stable_digest=scenario.record.stable_digest,
        tenant=scenario.record.tenant,
        environment=scenario.record.environment,
        requested_autonomy="write-support-case",
        policy_version=scenario.executor.current_policy_version,
        evidence_set_digest=decision.evidence_set_digest,
        exception_set_digest=decision.exception_set_digest,
        gate_evaluated_at=decision.evaluated_at,
        canary_percent=10,
        max_error_rate=0.02,
        min_safety_rate=1.0,
        max_p95_latency_ms=500,
        max_cost_per_task=0.10,
        logical_operation_id="rollout:support-agent:500:production",
    ))
    approval = rr.ReleaseApproval(
        approval_id=approval_id,
        plan_digest=plan.plan_digest,
        release_digest=plan.release_digest,
        tenant=plan.tenant,
        environment=plan.environment,
        expected_release_version=scenario.record.version,
        approved_by="release-approver:north:4",
        issued_at=now,
        expires_at=now + 30,
    )
    return decision, plan, scenario.keyring.sign_approval(approval, "release-board-2026-11")


def signed_exception(
    scenario: CourseScenario,
    blocker_code: str,
    *,
    now: int = 120,
) -> rr.RiskException:
    item = rr.RiskException(
        exception_id=f"exception:{blocker_code}:500",
        release_digest=scenario.record.candidate_digest,
        tenant=scenario.record.tenant,
        environment=scenario.record.environment,
        blocker_code=blocker_code,
        owner="risk-owner:north",
        approved_by="risk-committee:north",
        issued_at=now,
        expires_at=now + 30,
    )
    return scenario.keyring.sign_exception(item, "risk-committee-2026-11")


def replace_signed_evidence(
    scenario: CourseScenario,
    evidence_id: str,
    **changes: object,
) -> rr.ReleaseEvidence:
    original = scenario.store.evidence[evidence_id]
    changed = replace(original, **changes, proof="")
    return scenario.keyring.sign_evidence(changed, "ci-evidence-2026-11")

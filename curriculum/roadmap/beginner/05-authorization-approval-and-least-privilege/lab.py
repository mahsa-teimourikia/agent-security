"""Credential-free authorization and exact-approval lab for Foundation 05.

The model proposes an operation. Trusted application state supplies the actor,
tenant, resource, policy, and approver. A policy decision point (PDP) returns
ALLOW, PAUSE, DENY, or ERROR; an enforcement point (PEP) reauthorizes at the
effect boundary and atomically consumes an exact approval before one effect.

The in-memory policy, stores, lock, and clock are teaching analogues. They prove
the control sequence inside one process, not distributed consistency, durable
revocation, production identity, or key protection.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import json
from threading import Lock
from typing import Any


CATALOG = frozenset(
    {
        "read_refund_policy",
        "read_case_summary",
        "propose_refund",
        "issue_approved_refund",
        "admin_refunds",
    }
)


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    PAUSE = "pause"
    DENY = "deny"
    ERROR = "error"


class ApprovalState(str, Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    REVOKED = "revoked"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class ActorContext:
    """Authenticated application context; never populated from model output."""

    subject: str
    workload: str
    tenant: str
    roles: frozenset[str]
    scopes: frozenset[str]
    session_assurance: str = "mfa"
    authenticated: bool = True


@dataclass(frozen=True)
class ApproverContext:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class ActionProposal:
    """Untrusted operation and business arguments proposed by an agent."""

    operation: str
    resource_id: str
    amount_cents: int
    currency: str
    purpose: str
    logical_operation_id: str
    model_claimed_role: str = ""


@dataclass
class RefundCase:
    case_id: str
    tenant: str
    owner_subject: str
    active: bool
    refundable_cents: int
    version: int = 1


@dataclass
class PolicySnapshot:
    version: str = "northwind-authz-5"
    direct_refund_limit_cents: int = 1_000
    maximum_refund_cents: int = 10_000
    approval_ttl: timedelta = timedelta(minutes=5)


@dataclass(frozen=True)
class AuthorizationDecision:
    decision_id: str
    status: DecisionStatus
    reason: str
    policy_version: str
    request_digest: str
    proposal_digest: str
    resource_version: int

    @property
    def successful(self) -> bool:
        return self.status is DecisionStatus.ALLOW


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    decision_id: str
    decision_request_digest: str
    proposal_digest: str
    subject: str
    workload: str
    tenant: str
    operation: str
    resource_id: str
    resource_version: int
    policy_version: str
    approver_subject: str
    issued_at: datetime
    expires_at: datetime


@dataclass
class ApprovalRecord:
    receipt: ApprovalReceipt
    state: ApprovalState = ApprovalState.ISSUED


@dataclass(frozen=True)
class ExecutionDecision:
    decision_id: str
    status: DecisionStatus
    reason: str
    logical_operation_id: str
    effect_applied: bool = False
    approval_id: str = ""

    @property
    def successful(self) -> bool:
        return self.status is DecisionStatus.ALLOW


@dataclass(frozen=True)
class TraceEntry:
    trace_id: str
    decision_id: str
    subject: str
    workload: str
    tenant: str
    operation: str
    resource_id: str
    proposal_digest: str
    policy_version: str
    approval_id: str
    status: str
    reason: str
    effect_applied: bool


def canonical_digest(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def proposal_digest(proposal: ActionProposal) -> str:
    """Bind authority to the exact effect; claimed role remains non-authoritative."""

    return canonical_digest(
        {
            "operation": proposal.operation,
            "resource_id": proposal.resource_id,
            "amount_cents": proposal.amount_cents,
            "currency": proposal.currency,
            "purpose": proposal.purpose,
            "logical_operation_id": proposal.logical_operation_id,
        }
    )


def minimum_tool_set(actor: ActorContext, resource: RefundCase | None) -> frozenset[str]:
    """Derive visible tools from trusted context; discovery still is not authority."""

    if not actor.authenticated:
        return frozenset()
    tools: set[str] = set()
    if "policy:read" in actor.scopes:
        tools.add("read_refund_policy")
    if resource and resource.tenant == actor.tenant:
        if "case:read" in actor.scopes:
            tools.add("read_case_summary")
        if "support-agent" in actor.roles and "refund:propose" in actor.scopes:
            tools.add("propose_refund")
        if (
            "support-agent" in actor.roles
            and "refund:execute" in actor.scopes
            and actor.session_assurance == "mfa"
            and resource.active
        ):
            tools.add("issue_approved_refund")
    return frozenset(tools)


class PolicyDecisionPoint:
    """Deterministic PDP using trusted identity and policy-information inputs."""

    def __init__(self, policy: PolicySnapshot, cases: dict[str, RefundCase]) -> None:
        self.policy = policy
        self.cases = cases
        self.available = True

    def evaluate(self, actor: ActorContext, proposal: ActionProposal) -> AuthorizationDecision:
        resource = self.cases.get(proposal.resource_id)
        resource_version = resource.version if resource else 0
        digest = proposal_digest(proposal)
        request = {
            "subject": actor.subject,
            "workload": actor.workload,
            "tenant": actor.tenant,
            "roles": sorted(actor.roles),
            "scopes": sorted(actor.scopes),
            "session_assurance": actor.session_assurance,
            "operation": proposal.operation,
            "resource_id": proposal.resource_id,
            "resource_version": resource_version,
            "proposal_digest": digest,
            "policy_version": self.policy.version,
        }
        request_digest = canonical_digest(request)
        decision_id = f"decision:{request_digest[:16]}"

        def decide(status: DecisionStatus, reason: str) -> AuthorizationDecision:
            return AuthorizationDecision(
                decision_id,
                status,
                reason,
                self.policy.version,
                request_digest,
                digest,
                resource_version,
            )

        if not self.available:
            return decide(DecisionStatus.ERROR, "pdp-unavailable")
        if not actor.authenticated:
            return decide(DecisionStatus.DENY, "actor-unauthenticated")
        if proposal.operation not in CATALOG or proposal.operation == "admin_refunds":
            return decide(DecisionStatus.DENY, "operation-not-allowed")
        required_scopes = {
            "read_refund_policy": "policy:read",
            "read_case_summary": "case:read",
            "propose_refund": "refund:propose",
            "issue_approved_refund": "refund:execute",
        }
        if required_scopes[proposal.operation] not in actor.scopes:
            return decide(DecisionStatus.DENY, "scope")
        if proposal.operation == "read_refund_policy":
            return decide(DecisionStatus.ALLOW, "policy-read")
        if resource is None:
            return decide(DecisionStatus.DENY, "resource-unknown")
        if resource.tenant != actor.tenant:
            return decide(DecisionStatus.DENY, "tenant")
        if not resource.active:
            return decide(DecisionStatus.DENY, "resource-inactive")
        if proposal.operation == "read_case_summary":
            return decide(DecisionStatus.ALLOW, "case-read")
        if "support-agent" not in actor.roles:
            return decide(DecisionStatus.DENY, "relationship")
        if proposal.purpose != "customer-remediation":
            return decide(DecisionStatus.DENY, "purpose")
        if proposal.operation == "propose_refund":
            return decide(DecisionStatus.ALLOW, "proposal-only")
        if type(proposal.amount_cents) is not int or proposal.amount_cents < 1:
            return decide(DecisionStatus.DENY, "amount")
        if proposal.currency != "CAD":
            return decide(DecisionStatus.DENY, "currency")
        if proposal.amount_cents > min(resource.refundable_cents, self.policy.maximum_refund_cents):
            return decide(DecisionStatus.DENY, "amount-limit")
        if actor.session_assurance != "mfa":
            return decide(DecisionStatus.DENY, "session-assurance")
        if proposal.amount_cents > self.policy.direct_refund_limit_cents:
            return decide(DecisionStatus.PAUSE, "independent-approval-required")
        return decide(DecisionStatus.ALLOW, "least-privilege-direct-limit")


class ApprovalStore:
    """Server-owned receipt state. Presented objects are never trusted by value."""

    def __init__(self) -> None:
        self.records: dict[str, ApprovalRecord] = {}
        self.available = True

    def issue(
        self,
        decision: AuthorizationDecision,
        actor: ActorContext,
        proposal: ActionProposal,
        approver: ApproverContext,
        *,
        approval_id: str,
        now: datetime,
        ttl: timedelta,
    ) -> ApprovalReceipt:
        if decision.status is not DecisionStatus.PAUSE:
            raise ValueError("approval requires a paused authorization decision")
        if decision.proposal_digest != proposal_digest(proposal):
            raise ValueError("decision-proposal-binding")
        if not approver.authenticated:
            raise ValueError("approver-unauthenticated")
        if approver.tenant != actor.tenant:
            raise ValueError("approver-tenant")
        if "finance-approver" not in approver.roles:
            raise ValueError("approver-role")
        if approver.subject == actor.subject:
            raise ValueError("separation-of-duties")
        if approval_id in self.records:
            raise ValueError("approval-id-reused")
        receipt = ApprovalReceipt(
            approval_id,
            decision.decision_id,
            decision.request_digest,
            decision.proposal_digest,
            actor.subject,
            actor.workload,
            actor.tenant,
            proposal.operation,
            proposal.resource_id,
            decision.resource_version,
            decision.policy_version,
            approver.subject,
            now,
            now + ttl,
        )
        self.records[approval_id] = ApprovalRecord(receipt)
        return receipt

    def revoke(self, approval_id: str) -> None:
        record = self.records.get(approval_id)
        if record and record.state is ApprovalState.ISSUED:
            record.state = ApprovalState.REVOKED


class PolicyEnforcementPoint:
    """Reauthorize and atomically consume approval at the side-effect boundary."""

    def __init__(self, pdp: PolicyDecisionPoint, approvals: ApprovalStore) -> None:
        self.pdp = pdp
        self.approvals = approvals
        self.effects: dict[str, dict[str, Any]] = {}
        self.traces: list[TraceEntry] = []
        self._lock = Lock()
        self._trace_sequence = 0

    def enforce(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        *,
        approval_id: str = "",
        now: datetime | None = None,
    ) -> ExecutionDecision:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            decision = self.pdp.evaluate(actor, proposal)
            if decision.status is DecisionStatus.ERROR:
                return self._record(actor, proposal, decision, decision.status, decision.reason, approval_id)
            if decision.status is DecisionStatus.DENY:
                return self._record(actor, proposal, decision, decision.status, decision.reason, approval_id)
            if proposal.operation != "issue_approved_refund":
                return self._record(actor, proposal, decision, DecisionStatus.ALLOW, decision.reason, approval_id)
            if proposal.logical_operation_id in self.effects:
                return self._record(actor, proposal, decision, DecisionStatus.DENY, "operation-replayed", approval_id)

            record: ApprovalRecord | None = None
            if decision.status is DecisionStatus.PAUSE:
                if not self.approvals.available:
                    return self._record(actor, proposal, decision, DecisionStatus.ERROR, "approval-store-unavailable", approval_id)
                record = self.approvals.records.get(approval_id)
                reason = self._approval_error(record, actor, proposal, decision, now)
                if reason:
                    return self._record(actor, proposal, decision, DecisionStatus.DENY, reason, approval_id)

            # In one critical section: current authorization, receipt state,
            # provider effect, and single-use transition. A distributed system
            # must replace this with durable transactional or compare-and-swap state.
            self.effects[proposal.logical_operation_id] = {
                "receipt_id": f"refund:{canonical_digest(proposal.logical_operation_id)[:12]}",
                "resource_id": proposal.resource_id,
                "amount_cents": proposal.amount_cents,
                "currency": proposal.currency,
            }
            if record:
                record.state = ApprovalState.CONSUMED
            return self._record(
                actor,
                proposal,
                decision,
                DecisionStatus.ALLOW,
                "approved-effect" if record else "direct-limit-effect",
                approval_id,
                effect_applied=True,
            )

    @staticmethod
    def _approval_error(
        record: ApprovalRecord | None,
        actor: ActorContext,
        proposal: ActionProposal,
        decision: AuthorizationDecision,
        now: datetime,
    ) -> str | None:
        if record is None:
            return "approval-required"
        receipt = record.receipt
        if record.state is ApprovalState.REVOKED:
            return "approval-revoked"
        if record.state is ApprovalState.CONSUMED:
            return "approval-replayed"
        if receipt.expires_at <= now:
            return "approval-expired"
        if (
            receipt.subject != actor.subject
            or receipt.workload != actor.workload
            or receipt.tenant != actor.tenant
        ):
            return "approval-identity"
        if (
            receipt.operation != proposal.operation
            or receipt.resource_id != proposal.resource_id
            or receipt.proposal_digest != proposal_digest(proposal)
        ):
            return "approval-binding"
        if (
            receipt.policy_version != decision.policy_version
            or receipt.resource_version != decision.resource_version
            or receipt.decision_request_digest != decision.request_digest
        ):
            return "approval-stale"
        return None

    def _record(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        authorization: AuthorizationDecision,
        status: DecisionStatus,
        reason: str,
        approval_id: str,
        *,
        effect_applied: bool = False,
    ) -> ExecutionDecision:
        self._trace_sequence += 1
        self.traces.append(
            TraceEntry(
                f"trace:{self._trace_sequence:04d}",
                authorization.decision_id,
                actor.subject,
                actor.workload,
                actor.tenant,
                proposal.operation,
                proposal.resource_id,
                proposal_digest(proposal),
                authorization.policy_version,
                approval_id,
                status.value,
                reason,
                effect_applied,
            )
        )
        return ExecutionDecision(
            authorization.decision_id,
            status,
            reason,
            proposal.logical_operation_id,
            effect_applied,
            approval_id,
        )


def build_scenario() -> tuple[
    PolicyEnforcementPoint,
    ActorContext,
    ApproverContext,
    dict[str, RefundCase],
]:
    cases = {
        "case:north:42": RefundCase("case:north:42", "north", "customer:42", True, 10_000),
        "case:north:43": RefundCase("case:north:43", "north", "customer:43", False, 10_000),
        "case:south:9": RefundCase("case:south:9", "south", "customer:9", True, 10_000),
    }
    policy = PolicySnapshot()
    pdp = PolicyDecisionPoint(policy, cases)
    pep = PolicyEnforcementPoint(pdp, ApprovalStore())
    actor = ActorContext(
        "employee:7",
        "workload:support-agent",
        "north",
        frozenset({"support-agent"}),
        frozenset({"policy:read", "case:read", "refund:propose", "refund:execute"}),
    )
    approver = ApproverContext(
        "employee:finance-3", "north", frozenset({"finance-approver"})
    )
    return pep, actor, approver, cases


def refund_proposal(
    operation_id: str = "refund:case:north:42:1",
    amount_cents: int = 2_500,
    *,
    resource_id: str = "case:north:42",
    purpose: str = "customer-remediation",
    model_claimed_role: str = "",
) -> ActionProposal:
    return ActionProposal(
        "issue_approved_refund",
        resource_id,
        amount_cents,
        "CAD",
        purpose,
        operation_id,
        model_claimed_role,
    )


def authorize_and_approve(
    pep: PolicyEnforcementPoint,
    actor: ActorContext,
    approver: ApproverContext,
    proposal: ActionProposal,
    *,
    approval_id: str,
    now: datetime,
) -> ApprovalReceipt:
    decision = pep.pdp.evaluate(actor, proposal)
    return pep.approvals.issue(
        decision,
        actor,
        proposal,
        approver,
        approval_id=approval_id,
        now=now,
        ttl=pep.pdp.policy.approval_ttl,
    )


def unsafe_role_only_authorization(actor: ActorContext, proposal: ActionProposal) -> bool:
    """Deliberately unsafe baseline: prompt role or broad role grants execution."""

    return proposal.operation == "issue_approved_refund" and (
        proposal.model_claimed_role == "admin" or "support-agent" in actor.roles
    )


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    kind: CaseKind
    decision: ExecutionDecision
    baseline_accepts: bool
    trace_complete: bool


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    attack_block_rate: float
    attack_effect_rate: float
    valid_task_success_rate: float
    blocked_valid_task_rate: float
    baseline_attack_acceptance_rate: float
    trace_completeness_rate: float
    least_privilege_exposure_reduction: float


def evaluate_controls(
    *, now: datetime | None = None
) -> tuple[EvaluationReport, tuple[EvaluationCase, ...]]:
    """Run explicit valid, attack, and dependency-failure populations."""

    now = now or datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
    results: list[EvaluationCase] = []

    def capture(
        name: str,
        kind: CaseKind,
        pep: PolicyEnforcementPoint,
        actor: ActorContext,
        proposal: ActionProposal,
        decision: ExecutionDecision,
    ) -> None:
        trace = pep.traces[-1]
        complete = all(
            (
                trace.trace_id,
                trace.decision_id,
                trace.subject,
                trace.workload,
                trace.tenant,
                trace.operation,
                trace.proposal_digest,
                trace.policy_version,
                trace.status,
                trace.reason,
            )
        )
        results.append(
            EvaluationCase(
                name,
                kind,
                decision,
                unsafe_role_only_authorization(actor, proposal),
                complete,
            )
        )

    def fresh() -> tuple[PolicyEnforcementPoint, ActorContext, ApproverContext, dict[str, RefundCase]]:
        return build_scenario()

    pep, actor, _, _ = fresh()
    read = ActionProposal("read_refund_policy", "policy:refunds", 0, "", "support", "valid:read")
    capture("valid-read", CaseKind.VALID, pep, actor, read, pep.enforce(actor, read, now=now))

    pep, actor, _, _ = fresh()
    propose = ActionProposal("propose_refund", "case:north:42", 2_500, "CAD", "customer-remediation", "valid:propose")
    capture("valid-proposal", CaseKind.VALID, pep, actor, propose, pep.enforce(actor, propose, now=now))

    pep, actor, _, _ = fresh()
    direct = refund_proposal("valid:direct", 500)
    capture("valid-direct-limit", CaseKind.VALID, pep, actor, direct, pep.enforce(actor, direct, now=now))

    pep, actor, approver, _ = fresh()
    approved = refund_proposal("valid:approved", 2_500)
    receipt = authorize_and_approve(pep, actor, approver, approved, approval_id="approval:valid", now=now)
    capture("valid-approved", CaseKind.VALID, pep, actor, approved, pep.enforce(actor, approved, approval_id=receipt.approval_id, now=now))

    pep, actor, _, _ = fresh()
    low_actor = replace(actor, roles=frozenset(), scopes=frozenset())
    claimed = refund_proposal("attack:claimed-role", 500, model_claimed_role="admin")
    capture("model-claimed-role", CaseKind.ATTACK, pep, low_actor, claimed, pep.enforce(low_actor, claimed, now=now))

    pep, actor, _, _ = fresh()
    cross = refund_proposal("attack:cross-tenant", 500, resource_id="case:south:9")
    capture("cross-tenant", CaseKind.ATTACK, pep, actor, cross, pep.enforce(actor, cross, now=now))

    pep, actor, _, _ = fresh()
    missing = refund_proposal("attack:missing-approval", 2_500)
    capture("missing-approval", CaseKind.ATTACK, pep, actor, missing, pep.enforce(actor, missing, now=now))

    pep, actor, approver, _ = fresh()
    original = refund_proposal("attack:altered", 2_500)
    bound = authorize_and_approve(pep, actor, approver, original, approval_id="approval:altered", now=now)
    altered = replace(original, amount_cents=4_000)
    capture("altered-amount", CaseKind.ATTACK, pep, actor, altered, pep.enforce(actor, altered, approval_id=bound.approval_id, now=now))

    pep, actor, _, _ = fresh()
    forged = refund_proposal("attack:forged", 2_500)
    capture("forged-approval", CaseKind.ATTACK, pep, actor, forged, pep.enforce(actor, forged, approval_id="approval:invented", now=now))

    pep, actor, approver, _ = fresh()
    revoked = refund_proposal("attack:revoked", 2_500)
    revoked_receipt = authorize_and_approve(pep, actor, approver, revoked, approval_id="approval:revoked", now=now)
    pep.approvals.revoke(revoked_receipt.approval_id)
    capture("revoked-approval", CaseKind.ATTACK, pep, actor, revoked, pep.enforce(actor, revoked, approval_id=revoked_receipt.approval_id, now=now))

    pep, actor, approver, _ = fresh()
    replayed = refund_proposal("attack:replay", 2_500)
    replay_receipt = authorize_and_approve(pep, actor, approver, replayed, approval_id="approval:replay", now=now)
    first = pep.enforce(actor, replayed, approval_id=replay_receipt.approval_id, now=now)
    assert first.successful
    capture("replayed-approval", CaseKind.ATTACK, pep, actor, replayed, pep.enforce(actor, replayed, approval_id=replay_receipt.approval_id, now=now))

    pep, actor, approver, cases = fresh()
    stale = refund_proposal("attack:state-change", 2_500)
    stale_receipt = authorize_and_approve(pep, actor, approver, stale, approval_id="approval:stale", now=now)
    cases[stale.resource_id].version += 1
    capture("resource-changed", CaseKind.ATTACK, pep, actor, stale, pep.enforce(actor, stale, approval_id=stale_receipt.approval_id, now=now))

    pep, actor, _, _ = fresh()
    pdp_failure = refund_proposal("failure:pdp", 500)
    pep.pdp.available = False
    capture("pdp-unavailable", CaseKind.FAILURE, pep, actor, pdp_failure, pep.enforce(actor, pdp_failure, now=now))

    pep, actor, _, _ = fresh()
    approval_failure = refund_proposal("failure:approval-store", 2_500)
    pep.approvals.available = False
    capture("approval-store-unavailable", CaseKind.FAILURE, pep, actor, approval_failure, pep.enforce(actor, approval_failure, now=now))

    valid = [item for item in results if item.kind is CaseKind.VALID]
    attacks = [item for item in results if item.kind is CaseKind.ATTACK]
    failures = [item for item in results if item.kind is CaseKind.FAILURE]
    pep, actor, _, cases = fresh()
    exposed = minimum_tool_set(actor, cases["case:north:42"])
    report = EvaluationReport(
        len(results),
        len(valid),
        len(attacks),
        len(failures),
        sum(not item.decision.successful for item in attacks) / len(attacks),
        sum(item.decision.effect_applied for item in attacks) / len(attacks),
        sum(item.decision.successful for item in valid) / len(valid),
        sum(not item.decision.successful for item in valid) / len(valid),
        sum(item.baseline_accepts for item in attacks) / len(attacks),
        sum(item.trace_complete for item in results) / len(results),
        (len(CATALOG) - len(exposed)) / len(CATALOG),
    )
    return report, tuple(results)


def concurrency_probe(*, workers: int = 8, now: datetime | None = None) -> tuple[int, int, int]:
    """Race one approval across workers and prove exactly one effect."""

    from concurrent.futures import ThreadPoolExecutor

    now = now or datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
    pep, actor, approver, _ = build_scenario()
    proposal = refund_proposal("race:one-effect", 2_500)
    receipt = authorize_and_approve(
        pep, actor, approver, proposal, approval_id="approval:race", now=now
    )

    def call(_: int) -> ExecutionDecision:
        return pep.enforce(actor, proposal, approval_id=receipt.approval_id, now=now)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        decisions = list(pool.map(call, range(workers)))
    allowed = sum(item.successful for item in decisions)
    denied = sum(not item.successful for item in decisions)
    return allowed, denied, len(pep.effects)


def main() -> None:
    report, cases = evaluate_controls()
    allowed, denied, effects = concurrency_probe()
    print("Foundation 05 — authorization, approval, and least privilege")
    print(json.dumps(report.__dict__, indent=2, sort_keys=True))
    print("decisions:", ", ".join(f"{item.name}={item.decision.status.value}:{item.decision.reason}" for item in cases))
    print(f"concurrency: allowed={allowed}, denied={denied}, effects={effects}")
    assert report.attack_block_rate == 1.0
    assert report.attack_effect_rate == 0.0
    assert report.valid_task_success_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert allowed == effects == 1 and denied == 7


if __name__ == "__main__":
    main()

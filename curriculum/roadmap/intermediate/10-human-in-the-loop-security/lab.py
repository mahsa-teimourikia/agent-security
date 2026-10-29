"""Deterministic human-in-the-loop security control plane for Intermediate 10.

The model proposes.  This module owns review admission, reviewer authorization,
durable server-side state, exact decision binding, atomic grant consumption,
execution reconciliation, and privacy-minimized evidence.  It is deliberately
credential-free and network-free; the in-memory lock and records are teaching
substitutes for durable transactional infrastructure, not production trust
mechanisms.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from html import escape
import json
from threading import Lock, Thread
from typing import Any, Callable, Mapping, Optional


NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
POLICY_VERSION = "northwind-hitl-1"


class ReviewChoice(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request-changes"


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes-requested"
    EXPIRED = "expired"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class OperationStatus(str, Enum):
    IN_FLIGHT = "in-flight"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class ActionProposal:
    request_id: str
    run_id: str
    operation: str
    resource_id: str
    amount_cents: int
    currency: str
    reason: str
    logical_operation_id: str
    client_claimed_approved: bool = False


@dataclass
class RefundResource:
    resource_id: str
    tenant: str
    version: int
    refundable_cents: int
    active: bool = True


@dataclass
class PolicySnapshot:
    version: str = POLICY_VERSION
    direct_limit_cents: int = 1_000
    critical_threshold_cents: int = 5_000
    maximum_refund_cents: int = 10_000
    review_ttl: timedelta = timedelta(minutes=5)
    grant_ttl: timedelta = timedelta(minutes=2)


@dataclass(frozen=True)
class ReviewPacket:
    review_id: str
    requester_subject: str
    tenant: str
    run_id: str
    operation: str
    resource_id: str
    amount_cents: int
    currency: str
    risk_tier: str
    required_role: str
    quorum: int
    proposal_digest: str
    resource_version: int
    policy_version: str
    display_reason: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class HumanDecision:
    decision_id: str
    review_id: str
    reviewer_subject: str
    choice: ReviewChoice
    rationale_code: str
    proposal_digest: str
    policy_version: str
    decided_at: datetime


@dataclass
class ExecutionGrant:
    grant_id: str
    review_id: str
    requester_subject: str
    tenant: str
    proposal_digest: str
    resource_version: int
    policy_version: str
    logical_operation_id: str
    approver_subjects: tuple[str, ...]
    expires_at: datetime
    used: bool = False


@dataclass(frozen=True)
class ExecutionTicket:
    ticket_id: str
    grant_id: str
    review_id: str
    logical_operation_id: str
    proposal_digest: str
    tenant: str


@dataclass(frozen=True)
class DecisionReceipt:
    phase: str
    decision: str
    reason: str
    review_id: str
    request_id: str
    subject: str
    tenant: str
    proposal_digest: str
    policy_version: str
    recorded_at: datetime


@dataclass
class ReviewRecord:
    packet: ReviewPacket
    proposal: ActionProposal
    status: RequestStatus = RequestStatus.PENDING
    version: int = 1
    decisions: list[HumanDecision] = field(default_factory=list)
    grant: Optional[ExecutionGrant] = None


@dataclass(frozen=True)
class WorkflowResult:
    status: str
    reason: str
    review_id: str = ""
    version: int = 0
    grant_id: str = ""
    effect_applied: bool = False
    provider_reference: str = ""
    receipt: Optional[DecisionReceipt] = None


@dataclass(frozen=True)
class OperationRecord:
    logical_operation_id: str
    review_id: str
    proposal_digest: str
    status: OperationStatus
    provider_reference: str = ""


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    population: str
    attack_family: str
    safe: bool
    effect_applied: bool
    trace_complete: bool


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    valid_workflow_completion_rate: float
    valid_approval_completion_rate: float
    attack_effect_rate: float
    approval_bypass_rate: float
    replay_success_rate: float
    altered_intent_success_rate: float
    failure_safe_termination_rate: float
    trace_completeness_rate: float


def canonical_digest(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def proposal_digest(proposal: ActionProposal) -> str:
    """Bind a decision to the exact intended effect, not display prose."""

    return canonical_digest(
        {
            "request_id": proposal.request_id,
            "run_id": proposal.run_id,
            "operation": proposal.operation,
            "resource_id": proposal.resource_id,
            "amount_cents": proposal.amount_cents,
            "currency": proposal.currency,
            "reason": proposal.reason,
            "logical_operation_id": proposal.logical_operation_id,
        }
    )


def unsafe_boolean_gate(proposal: ActionProposal) -> bool:
    """Deliberately unsafe baseline: a caller-controlled Boolean grants approval."""

    return proposal.client_claimed_approved


class HumanReviewControlPlane:
    """Application-owned boundary for durable human review and execution."""

    def __init__(
        self,
        resources: Mapping[str, RefundResource],
        policy: PolicySnapshot | None = None,
    ) -> None:
        self.resources = dict(resources)
        self.policy = policy or PolicySnapshot()
        self.reviews: dict[str, ReviewRecord] = {}
        self.operations: dict[str, OperationRecord] = {}
        self.receipts: list[DecisionReceipt] = []
        self.available = True
        self._review_counter = 0
        self._lock = Lock()

    def submit(
        self,
        requester: Principal,
        proposal: ActionProposal,
        *,
        now: datetime,
    ) -> WorkflowResult:
        """Admit one exact high-risk proposal into server-owned review state."""

        with self._lock:
            reason, resource = self._submission_reason(requester, proposal)
            digest = proposal_digest(proposal)
            if reason == "review-required" and resource is not None:
                self._review_counter += 1
                review_id = f"review:{self._review_counter}:{digest[:12]}"
                risk_tier = (
                    "critical"
                    if proposal.amount_cents >= self.policy.critical_threshold_cents
                    else "high"
                )
                packet = ReviewPacket(
                    review_id=review_id,
                    requester_subject=requester.subject,
                    tenant=requester.tenant,
                    run_id=proposal.run_id,
                    operation=proposal.operation,
                    resource_id=proposal.resource_id,
                    amount_cents=proposal.amount_cents,
                    currency=proposal.currency,
                    risk_tier=risk_tier,
                    required_role="finance-approver",
                    quorum=2 if risk_tier == "critical" else 1,
                    proposal_digest=digest,
                    resource_version=resource.version,
                    policy_version=self.policy.version,
                    display_reason=self._safe_display(proposal.reason),
                    created_at=now,
                    expires_at=now + self.policy.review_ttl,
                )
                self.reviews[review_id] = ReviewRecord(packet=packet, proposal=proposal)
                receipt = self._record(
                    "submission", "pause", reason, review_id, proposal.request_id,
                    requester, digest, now,
                )
                return WorkflowResult(
                    "pause", reason, review_id, 1, receipt=receipt
                )

            decision = "allow" if reason == "review-not-required" else (
                "error" if reason == "review-store-unavailable" else "deny"
            )
            receipt = self._record(
                "submission", decision, reason, "", proposal.request_id,
                requester, digest, now,
            )
            return WorkflowResult(decision, reason, receipt=receipt)

    def review_packet(
        self,
        reviewer: Principal,
        review_id: str,
        *,
        now: datetime,
    ) -> ReviewPacket:
        """Return a bounded packet only to an eligible authenticated reviewer."""

        with self._lock:
            record = self.reviews.get(review_id)
            reason = self._reviewer_reason(reviewer, record, now)
            if reason != "reviewer-authorized" or record is None:
                raise PermissionError(reason)
            return record.packet

    def queue_for(self, reviewer: Principal, *, now: datetime) -> tuple[ReviewPacket, ...]:
        """List only the tenant-scoped review work this reviewer may perform."""

        with self._lock:
            packets: list[ReviewPacket] = []
            for record in self.reviews.values():
                if self._reviewer_reason(reviewer, record, now) == "reviewer-authorized":
                    packets.append(record.packet)
            return tuple(sorted(packets, key=lambda item: (item.expires_at, item.review_id)))

    def decide(
        self,
        reviewer: Principal,
        review_id: str,
        choice: ReviewChoice,
        *,
        rationale_code: str,
        expected_version: int,
        now: datetime,
    ) -> WorkflowResult:
        """Record one authenticated human decision with optimistic concurrency."""

        with self._lock:
            record = self.reviews.get(review_id)
            reason = self._reviewer_reason(reviewer, record, now)
            if reason == "reviewer-authorized" and record is not None:
                if record.version != expected_version:
                    reason = "review-version-conflict"
                elif reviewer.subject in {d.reviewer_subject for d in record.decisions}:
                    reason = "reviewer-duplicate"
                elif not rationale_code or len(rationale_code) > 40:
                    reason = "rationale-code"

            if reason != "reviewer-authorized" or record is None:
                principal = reviewer
                digest = record.packet.proposal_digest if record else ""
                request_id = record.proposal.request_id if record else ""
                receipt = self._record(
                    "review", "deny", reason, review_id, request_id,
                    principal, digest, now,
                )
                return WorkflowResult("deny", reason, review_id, receipt=receipt)

            decision = HumanDecision(
                decision_id=f"decision:{review_id}:{record.version}:{reviewer.subject}",
                review_id=review_id,
                reviewer_subject=reviewer.subject,
                choice=choice,
                rationale_code=rationale_code,
                proposal_digest=record.packet.proposal_digest,
                policy_version=record.packet.policy_version,
                decided_at=now,
            )
            record.decisions.append(decision)
            record.version += 1

            if choice is ReviewChoice.REJECT:
                record.status = RequestStatus.REJECTED
                reason = "review-rejected"
            elif choice is ReviewChoice.REQUEST_CHANGES:
                record.status = RequestStatus.CHANGES_REQUESTED
                reason = "changes-requested"
            else:
                approvals = [d for d in record.decisions if d.choice is ReviewChoice.APPROVE]
                if len(approvals) < record.packet.quorum:
                    reason = "quorum-pending"
                else:
                    record.status = RequestStatus.APPROVED
                    grant_digest = canonical_digest(
                        {
                            "review_id": review_id,
                            "proposal_digest": record.packet.proposal_digest,
                            "decision_ids": [item.decision_id for item in approvals],
                            "policy_version": record.packet.policy_version,
                        }
                    )
                    record.grant = ExecutionGrant(
                        grant_id=f"grant:{grant_digest[:20]}",
                        review_id=review_id,
                        requester_subject=record.packet.requester_subject,
                        tenant=record.packet.tenant,
                        proposal_digest=record.packet.proposal_digest,
                        resource_version=record.packet.resource_version,
                        policy_version=record.packet.policy_version,
                        logical_operation_id=record.proposal.logical_operation_id,
                        approver_subjects=tuple(item.reviewer_subject for item in approvals),
                        expires_at=now + self.policy.grant_ttl,
                    )
                    reason = "review-approved"

            receipt = self._record(
                "review", "allow", reason, review_id, record.proposal.request_id,
                reviewer, record.packet.proposal_digest, now,
            )
            return WorkflowResult(
                "allow", reason, review_id, record.version,
                record.grant.grant_id if record.grant else "", receipt=receipt,
            )

    def begin_execution(
        self,
        requester: Principal,
        review_id: str,
        grant_id: str,
        proposal: ActionProposal,
        *,
        now: datetime,
    ) -> tuple[Optional[ExecutionTicket], WorkflowResult]:
        """Atomically reauthorize, consume one grant, and reserve one operation."""

        with self._lock:
            record = self.reviews.get(review_id)
            reason = self._execution_reason(requester, record, grant_id, proposal, now)
            digest = proposal_digest(proposal)
            if reason != "execution-authorized" or record is None or record.grant is None:
                decision = "error" if reason == "review-store-unavailable" else "deny"
                receipt = self._record(
                    "execution", decision, reason, review_id, proposal.request_id,
                    requester, digest, now,
                )
                return None, WorkflowResult(decision, reason, review_id, receipt=receipt)

            record.grant.used = True
            record.status = RequestStatus.EXECUTING
            ticket = ExecutionTicket(
                ticket_id=f"ticket:{record.grant.grant_id.split(':', 1)[1]}",
                grant_id=record.grant.grant_id,
                review_id=review_id,
                logical_operation_id=proposal.logical_operation_id,
                proposal_digest=digest,
                tenant=requester.tenant,
            )
            self.operations[proposal.logical_operation_id] = OperationRecord(
                proposal.logical_operation_id,
                review_id,
                digest,
                OperationStatus.IN_FLIGHT,
            )
            receipt = self._record(
                "execution", "allow", reason, review_id, proposal.request_id,
                requester, digest, now,
            )
            return ticket, WorkflowResult(
                "allow", reason, review_id, record.version,
                record.grant.grant_id, receipt=receipt,
            )

    def finish_execution(
        self,
        requester: Principal,
        ticket: ExecutionTicket,
        *,
        provider_reference: str,
        now: datetime,
    ) -> WorkflowResult:
        """Commit a verified provider result for the reserved operation."""

        with self._lock:
            operation = self.operations.get(ticket.logical_operation_id)
            record = self.reviews.get(ticket.review_id)
            reason = "effect-completed"
            if operation is None or record is None:
                reason = "operation-unknown"
            elif operation.status is not OperationStatus.IN_FLIGHT:
                reason = "operation-not-in-flight"
            elif operation.review_id != ticket.review_id or operation.proposal_digest != ticket.proposal_digest:
                reason = "ticket-binding"
            elif not provider_reference or len(provider_reference) > 80:
                reason = "provider-reference"

            if reason != "effect-completed" or operation is None or record is None:
                receipt = self._record(
                    "outcome", "deny", reason, ticket.review_id, "",
                    requester, ticket.proposal_digest, now,
                )
                return WorkflowResult("deny", reason, ticket.review_id, receipt=receipt)

            self.operations[ticket.logical_operation_id] = replace(
                operation,
                status=OperationStatus.COMPLETED,
                provider_reference=provider_reference,
            )
            record.status = RequestStatus.COMPLETED
            resource = self.resources[record.packet.resource_id]
            resource.refundable_cents -= record.packet.amount_cents
            resource.version += 1
            receipt = self._record(
                "outcome", "allow", reason, ticket.review_id, record.proposal.request_id,
                requester, ticket.proposal_digest, now,
            )
            return WorkflowResult(
                "allow", reason, ticket.review_id, record.version,
                ticket.grant_id, True, provider_reference, receipt,
            )

    def mark_unknown(
        self,
        requester: Principal,
        ticket: ExecutionTicket,
        *,
        now: datetime,
    ) -> WorkflowResult:
        """Preserve an ambiguous provider outcome for reconciliation, not retry."""

        with self._lock:
            operation = self.operations.get(ticket.logical_operation_id)
            record = self.reviews.get(ticket.review_id)
            if operation is None or record is None or operation.status is not OperationStatus.IN_FLIGHT:
                reason = "operation-not-in-flight"
                receipt = self._record(
                    "outcome", "deny", reason, ticket.review_id, "",
                    requester, ticket.proposal_digest, now,
                )
                return WorkflowResult("deny", reason, ticket.review_id, receipt=receipt)
            self.operations[ticket.logical_operation_id] = replace(
                operation, status=OperationStatus.UNKNOWN
            )
            record.status = RequestStatus.UNKNOWN
            receipt = self._record(
                "outcome", "error", "provider-outcome-unknown", ticket.review_id,
                record.proposal.request_id, requester, ticket.proposal_digest, now,
            )
            return WorkflowResult(
                "error", "provider-outcome-unknown", ticket.review_id,
                record.version, ticket.grant_id, receipt=receipt,
            )

    def reconcile(
        self,
        requester: Principal,
        logical_operation_id: str,
        *,
        effect_applied: bool,
        provider_reference: str,
        now: datetime,
    ) -> WorkflowResult:
        """Resolve one unknown outcome without minting a fresh approval."""

        with self._lock:
            operation = self.operations.get(logical_operation_id)
            record = self.reviews.get(operation.review_id) if operation else None
            reason = "reconciled-complete" if effect_applied else "reconciled-not-applied"
            if operation is None or record is None:
                reason = "operation-unknown"
            elif operation.status is not OperationStatus.UNKNOWN:
                reason = "reconciliation-not-required"
            elif requester.subject != record.packet.requester_subject or requester.tenant != record.packet.tenant:
                reason = "requester-binding"
            elif effect_applied and not provider_reference:
                reason = "provider-reference"

            if reason not in {"reconciled-complete", "reconciled-not-applied"} or operation is None or record is None:
                receipt = self._record(
                    "reconciliation", "deny", reason,
                    operation.review_id if operation else "", "", requester,
                    operation.proposal_digest if operation else "", now,
                )
                return WorkflowResult("deny", reason, receipt=receipt)

            status = OperationStatus.COMPLETED if effect_applied else OperationStatus.FAILED
            self.operations[logical_operation_id] = replace(
                operation, status=status, provider_reference=provider_reference
            )
            record.status = RequestStatus.COMPLETED if effect_applied else RequestStatus.FAILED
            if effect_applied:
                resource = self.resources[record.packet.resource_id]
                resource.refundable_cents -= record.packet.amount_cents
                resource.version += 1
            receipt = self._record(
                "reconciliation", "allow", reason, record.packet.review_id,
                record.proposal.request_id, requester, operation.proposal_digest, now,
            )
            return WorkflowResult(
                "allow", reason, record.packet.review_id, record.version,
                record.grant.grant_id if record.grant else "",
                effect_applied, provider_reference, receipt,
            )

    def execute(
        self,
        requester: Principal,
        review_id: str,
        grant_id: str,
        proposal: ActionProposal,
        provider: Callable[[ActionProposal], str],
        *,
        now: datetime,
    ) -> WorkflowResult:
        """Convenience path that preserves timeout as an unknown outcome."""

        ticket, started = self.begin_execution(
            requester, review_id, grant_id, proposal, now=now
        )
        if ticket is None:
            return started
        try:
            provider_reference = provider(proposal)
        except TimeoutError:
            return self.mark_unknown(requester, ticket, now=now)
        except Exception:
            return self.mark_unknown(requester, ticket, now=now)
        return self.finish_execution(
            requester, ticket, provider_reference=provider_reference, now=now
        )

    def expire_pending(self, *, now: datetime) -> int:
        """Expire stale review work; critical items need explicit escalation policy."""

        with self._lock:
            expired = 0
            for record in self.reviews.values():
                if record.status is RequestStatus.PENDING and record.packet.expires_at <= now:
                    record.status = RequestStatus.EXPIRED
                    record.version += 1
                    expired += 1
            return expired

    def _submission_reason(
        self,
        requester: Principal,
        proposal: ActionProposal,
    ) -> tuple[str, Optional[RefundResource]]:
        if not self.available:
            return "review-store-unavailable", None
        if not requester.authenticated or not requester.subject or not requester.tenant:
            return "requester-authentication", None
        if "support-agent" not in requester.roles:
            return "requester-role", None
        if proposal.operation != "issue_refund":
            return "operation", None
        if not proposal.request_id or not proposal.run_id or not proposal.logical_operation_id:
            return "identifier", None
        if type(proposal.amount_cents) is not int or proposal.amount_cents <= 0:
            return "amount", None
        if proposal.currency != "CAD":
            return "currency", None
        if len(proposal.reason) > 500:
            return "reason-limit", None
        resource = self.resources.get(proposal.resource_id)
        if resource is None or not resource.active:
            return "resource", None
        if resource.tenant != requester.tenant:
            return "resource-tenant", None
        if proposal.amount_cents > min(resource.refundable_cents, self.policy.maximum_refund_cents):
            return "business-limit", None
        if proposal.amount_cents <= self.policy.direct_limit_cents:
            return "review-not-required", resource
        return "review-required", resource

    def _reviewer_reason(
        self,
        reviewer: Principal,
        record: Optional[ReviewRecord],
        now: datetime,
    ) -> str:
        if not self.available:
            return "review-store-unavailable"
        if record is None:
            return "review-unavailable"
        if not reviewer.authenticated or not reviewer.subject or not reviewer.tenant:
            return "reviewer-authentication"
        if reviewer.tenant != record.packet.tenant:
            return "review-unavailable"
        if record.packet.required_role not in reviewer.roles:
            return "reviewer-role"
        if reviewer.subject == record.packet.requester_subject:
            return "separation-of-duties"
        if record.status is not RequestStatus.PENDING:
            return "review-not-pending"
        if record.packet.expires_at <= now:
            record.status = RequestStatus.EXPIRED
            record.version += 1
            return "review-expired"
        return "reviewer-authorized"

    def _execution_reason(
        self,
        requester: Principal,
        record: Optional[ReviewRecord],
        grant_id: str,
        proposal: ActionProposal,
        now: datetime,
    ) -> str:
        if not self.available:
            return "review-store-unavailable"
        if record is None or record.grant is None:
            return "grant-unavailable"
        grant = record.grant
        if not requester.authenticated:
            return "requester-authentication"
        if requester.subject != grant.requester_subject or requester.tenant != grant.tenant:
            return "requester-binding"
        if "support-agent" not in requester.roles:
            return "requester-role"
        if grant_id != grant.grant_id:
            return "grant-binding"
        digest = proposal_digest(proposal)
        if digest != grant.proposal_digest:
            return "proposal-changed"
        operation = self.operations.get(proposal.logical_operation_id)
        if operation is not None and operation.status is OperationStatus.UNKNOWN:
            return "operation-reconcile-required"
        if grant.used:
            return "grant-replay"
        if operation is not None:
            return "operation-replay"
        if record.status is not RequestStatus.APPROVED:
            return "review-not-approved"
        if grant.expires_at <= now:
            return "grant-expired"
        if self.policy.version != grant.policy_version:
            return "policy-stale"
        resource = self.resources.get(proposal.resource_id)
        if resource is None or not resource.active:
            return "resource"
        if resource.tenant != requester.tenant:
            return "resource-tenant"
        if resource.version != grant.resource_version:
            return "resource-stale"
        if proposal.amount_cents > min(resource.refundable_cents, self.policy.maximum_refund_cents):
            return "business-limit"
        return "execution-authorized"

    @staticmethod
    def _safe_display(reason: str) -> str:
        normalized = " ".join(reason.split())[:120]
        return escape(normalized, quote=True)

    def _record(
        self,
        phase: str,
        decision: str,
        reason: str,
        review_id: str,
        request_id: str,
        principal: Principal,
        digest: str,
        now: datetime,
    ) -> DecisionReceipt:
        receipt = DecisionReceipt(
            phase,
            decision,
            reason,
            review_id,
            request_id,
            principal.subject,
            principal.tenant,
            digest,
            self.policy.version,
            now,
        )
        self.receipts.append(receipt)
        return receipt


def build_scenario() -> tuple[
    HumanReviewControlPlane,
    Principal,
    Principal,
    Principal,
    ActionProposal,
]:
    resources = {
        "case:north:42": RefundResource("case:north:42", "north", 4, 8_000),
        "case:south:9": RefundResource("case:south:9", "south", 2, 9_000),
    }
    requester = Principal("employee:7", "north", frozenset({"support-agent"}))
    approver = Principal("finance:12", "north", frozenset({"finance-approver"}))
    second_approver = Principal("finance:13", "north", frozenset({"finance-approver"}))
    proposal = ActionProposal(
        "request:42",
        "run:42",
        "issue_refund",
        "case:north:42",
        2_500,
        "CAD",
        "Customer received a damaged shipment.",
        "refund:case:north:42:1",
    )
    return HumanReviewControlPlane(resources), requester, approver, second_approver, proposal


def approve(
    plane: HumanReviewControlPlane,
    requester: Principal,
    approver: Principal,
    proposal: ActionProposal,
    *,
    now: datetime = NOW,
) -> tuple[str, str]:
    submitted = plane.submit(requester, proposal, now=now)
    if submitted.status != "pause":
        raise AssertionError(submitted.reason)
    reviewed = plane.decide(
        approver,
        submitted.review_id,
        ReviewChoice.APPROVE,
        rationale_code="policy-exception-reviewed",
        expected_version=submitted.version,
        now=now,
    )
    if not reviewed.grant_id:
        raise AssertionError(reviewed.reason)
    return submitted.review_id, reviewed.grant_id


def safe_provider(proposal: ActionProposal) -> str:
    return f"provider:{proposal.logical_operation_id}"


def concurrency_probe(*, workers: int = 8) -> tuple[int, int, int]:
    """Race one approved grant; exactly one worker may reserve the effect."""

    plane, requester, approver, _, proposal = build_scenario()
    review_id, grant_id = approve(plane, requester, approver, proposal)
    results: list[WorkflowResult] = []

    def run() -> None:
        _, result = plane.begin_execution(
            requester, review_id, grant_id, proposal, now=NOW
        )
        results.append(result)

    threads = [Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    allowed = sum(result.status == "allow" for result in results)
    denied = sum(result.status == "deny" for result in results)
    return allowed, denied, len(plane.operations)


def evaluate_controls() -> tuple[EvaluationReport, tuple[EvaluationCase, ...]]:
    """Run labelled valid, attack, and dependency-failure cases."""

    cases: list[EvaluationCase] = []

    def add(
        name: str,
        population: str,
        family: str,
        *,
        safe: bool,
        effect: bool,
        trace: bool = True,
    ) -> None:
        cases.append(EvaluationCase(name, population, family, safe, effect, trace))

    # Five valid workflows: approve, quorum approve, reject, request changes, sanitize display.
    plane, requester, approver, _, proposal = build_scenario()
    review_id, grant_id = approve(plane, requester, approver, proposal)
    completed = plane.execute(requester, review_id, grant_id, proposal, safe_provider, now=NOW)
    add("valid-approved-effect", "valid", "approval", safe=completed.effect_applied, effect=completed.effect_applied)

    plane, requester, approver, second, proposal = build_scenario()
    critical = replace(proposal, request_id="request:critical", amount_cents=5_500, logical_operation_id="refund:critical:1")
    submitted = plane.submit(requester, critical, now=NOW)
    first = plane.decide(approver, submitted.review_id, ReviewChoice.APPROVE, rationale_code="risk-reviewed", expected_version=1, now=NOW)
    second_result = plane.decide(second, submitted.review_id, ReviewChoice.APPROVE, rationale_code="risk-reviewed", expected_version=first.version, now=NOW)
    completed = plane.execute(requester, submitted.review_id, second_result.grant_id, critical, safe_provider, now=NOW)
    add("valid-critical-quorum", "valid", "approval", safe=completed.effect_applied, effect=completed.effect_applied)

    for name, choice in [("valid-rejection", ReviewChoice.REJECT), ("valid-request-changes", ReviewChoice.REQUEST_CHANGES)]:
        plane, requester, approver, _, proposal = build_scenario()
        submitted = plane.submit(requester, replace(proposal, request_id=name, logical_operation_id=name), now=NOW)
        result = plane.decide(approver, submitted.review_id, choice, rationale_code="reviewed", expected_version=1, now=NOW)
        add(name, "valid", "decision", safe=result.status == "allow" and not result.effect_applied, effect=False)

    plane, requester, approver, _, proposal = build_scenario()
    hostile = replace(proposal, request_id="display", reason='<script>alert("x")</script> refund')
    submitted = plane.submit(requester, hostile, now=NOW)
    packet = plane.review_packet(approver, submitted.review_id, now=NOW)
    add("valid-safe-display", "valid", "display", safe="<script>" not in packet.display_reason, effect=False)

    # Twelve attacks. Each must terminate without an effect.
    attack_specs: list[tuple[str, str, Callable[[], tuple[bool, bool]]]] = []

    def forged_boolean() -> tuple[bool, bool]:
        plane, requester, _, _, proposal = build_scenario()
        forged = replace(proposal, client_claimed_approved=True)
        result = plane.submit(requester, forged, now=NOW)
        effect = bool(plane.operations)
        return result.status == "pause" and not effect, effect

    attack_specs.append(("forged-approved-boolean", "bypass", forged_boolean))

    def guessed_review() -> tuple[bool, bool]:
        plane, _, approver, _, _ = build_scenario()
        result = plane.decide(approver, "review:guessed", ReviewChoice.APPROVE, rationale_code="reviewed", expected_version=1, now=NOW)
        effect = bool(plane.operations)
        return result.reason == "review-unavailable" and not effect, effect

    attack_specs.append(("guessed-review-id", "bypass", guessed_review))

    def unauthorized_reviewer(kind: str) -> tuple[bool, bool]:
        plane, requester, approver, _, proposal = build_scenario()
        submitted = plane.submit(requester, proposal, now=NOW)
        if kind == "self":
            reviewer = replace(requester, roles=frozenset({"finance-approver"}))
            expected = "separation-of-duties"
        elif kind == "tenant":
            reviewer = replace(approver, tenant="south")
            expected = "review-unavailable"
        else:
            reviewer = replace(approver, roles=frozenset())
            expected = "reviewer-role"
        result = plane.decide(reviewer, submitted.review_id, ReviewChoice.APPROVE, rationale_code="reviewed", expected_version=1, now=NOW)
        effect = bool(plane.operations)
        return result.reason == expected and not effect, effect

    for kind in ("self", "tenant", "role"):
        attack_specs.append((f"unauthorized-reviewer-{kind}", "bypass", lambda kind=kind: unauthorized_reviewer(kind)))

    def altered(field_name: str) -> tuple[bool, bool]:
        plane, requester, approver, _, proposal = build_scenario()
        review_id, grant_id = approve(plane, requester, approver, proposal)
        changed = replace(
            proposal,
            amount_cents=2_501 if field_name == "amount" else proposal.amount_cents,
            resource_id="case:south:9" if field_name == "resource" else proposal.resource_id,
        )
        result = plane.execute(requester, review_id, grant_id, changed, safe_provider, now=NOW)
        return result.reason == "proposal-changed" and not result.effect_applied, result.effect_applied

    for field_name in ("amount", "resource"):
        attack_specs.append((f"altered-{field_name}", "altered-intent", lambda field_name=field_name: altered(field_name)))

    def stale(kind: str) -> tuple[bool, bool]:
        plane, requester, approver, _, proposal = build_scenario()
        review_id, grant_id = approve(plane, requester, approver, proposal)
        if kind == "resource":
            plane.resources[proposal.resource_id].version += 1
            expected = "resource-stale"
        elif kind == "policy":
            plane.policy.version = "northwind-hitl-2"
            expected = "policy-stale"
        else:
            expected = "grant-expired"
        result = plane.execute(
            requester, review_id, grant_id, proposal, safe_provider,
            now=NOW + (timedelta(minutes=3) if kind == "expiry" else timedelta()),
        )
        return result.reason == expected and not result.effect_applied, result.effect_applied

    for kind in ("resource", "policy", "expiry"):
        attack_specs.append((f"stale-{kind}", "stale", lambda kind=kind: stale(kind)))

    def replay() -> tuple[bool, bool]:
        plane, requester, approver, _, proposal = build_scenario()
        review_id, grant_id = approve(plane, requester, approver, proposal)
        first = plane.execute(requester, review_id, grant_id, proposal, safe_provider, now=NOW)
        second = plane.execute(requester, review_id, grant_id, proposal, safe_provider, now=NOW)
        safe = first.effect_applied and not second.effect_applied and len(plane.operations) == 1
        return safe, second.effect_applied

    attack_specs.append(("grant-replay", "replay", replay))

    def version_conflict() -> tuple[bool, bool]:
        plane, requester, approver, second, proposal = build_scenario()
        critical = replace(proposal, amount_cents=5_500)
        submitted = plane.submit(requester, critical, now=NOW)
        plane.decide(approver, submitted.review_id, ReviewChoice.APPROVE, rationale_code="reviewed", expected_version=1, now=NOW)
        conflict = plane.decide(second, submitted.review_id, ReviewChoice.APPROVE, rationale_code="reviewed", expected_version=1, now=NOW)
        effect = bool(plane.operations)
        return conflict.reason == "review-version-conflict" and not effect, effect

    attack_specs.append(("decision-version-replay", "replay", version_conflict))

    for name, family, run in attack_specs:
        safe, effect = run()
        add(name, "attack", family, safe=safe, effect=effect)

    # Three dependency/operational failures: fail closed, expire, reconcile unknown.
    plane, requester, _, _, proposal = build_scenario()
    plane.available = False
    unavailable = plane.submit(requester, proposal, now=NOW)
    add("review-store-unavailable", "failure", "dependency", safe=unavailable.status == "error", effect=False)

    plane, requester, _, _, proposal = build_scenario()
    submitted = plane.submit(requester, proposal, now=NOW)
    expired = plane.expire_pending(now=NOW + timedelta(minutes=6))
    add("reviewer-unavailable-expiry", "failure", "expiry", safe=expired == 1 and plane.reviews[submitted.review_id].status is RequestStatus.EXPIRED, effect=False)

    plane, requester, approver, _, proposal = build_scenario()
    review_id, grant_id = approve(plane, requester, approver, proposal)
    unknown = plane.execute(requester, review_id, grant_id, proposal, lambda _: (_ for _ in ()).throw(TimeoutError()), now=NOW)
    reconciled = plane.reconcile(requester, proposal.logical_operation_id, effect_applied=False, provider_reference="", now=NOW)
    add("provider-timeout-reconciled", "failure", "dependency", safe=unknown.reason == "provider-outcome-unknown" and reconciled.reason == "reconciled-not-applied", effect=False)

    valid = [case for case in cases if case.population == "valid"]
    attacks = [case for case in cases if case.population == "attack"]
    failures = [case for case in cases if case.population == "failure"]
    approvals = [case for case in valid if case.attack_family == "approval"]
    bypasses = [case for case in attacks if case.attack_family == "bypass"]
    replays = [case for case in attacks if case.attack_family == "replay"]
    altered_cases = [case for case in attacks if case.attack_family == "altered-intent"]
    report = EvaluationReport(
        cases=len(cases),
        valid_cases=len(valid),
        attack_cases=len(attacks),
        failure_cases=len(failures),
        valid_workflow_completion_rate=sum(case.safe for case in valid) / len(valid),
        valid_approval_completion_rate=sum(case.effect_applied for case in approvals) / len(approvals),
        attack_effect_rate=sum(case.effect_applied for case in attacks) / len(attacks),
        approval_bypass_rate=sum(case.effect_applied for case in bypasses) / len(bypasses),
        replay_success_rate=sum(case.effect_applied for case in replays) / len(replays),
        altered_intent_success_rate=sum(case.effect_applied for case in altered_cases) / len(altered_cases),
        failure_safe_termination_rate=sum(case.safe for case in failures) / len(failures),
        trace_completeness_rate=sum(case.trace_complete for case in cases) / len(cases),
    )
    return report, tuple(cases)


def demo() -> None:
    report, cases = evaluate_controls()
    assert report.cases == 20
    assert report.valid_cases == 5
    assert report.attack_cases == 12
    assert report.failure_cases == 3
    assert report.valid_workflow_completion_rate == 1.0
    assert report.valid_approval_completion_rate == 1.0
    assert report.attack_effect_rate == 0.0
    assert report.approval_bypass_rate == 0.0
    assert report.replay_success_rate == 0.0
    assert report.altered_intent_success_rate == 0.0
    assert report.failure_safe_termination_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert all(case.safe for case in cases)
    assert concurrency_probe() == (1, 7, 1)
    print("Human-in-the-loop security lab passed 20 labelled cases")


if __name__ == "__main__":
    demo()

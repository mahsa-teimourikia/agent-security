"""Security Foundations and Tool Policy — credential-free lab.

The model proposes actions; trusted application code authorizes, validates,
and executes them.  This module implements a deterministic pre-execution
policy for an expense-assistant scenario using only the Python standard
library and synthetic fixtures.

Scenario:  An expense assistant can read receipts, calculate totals, preview
a claim, and submit a reimbursement.  Every action must pass a seven-step
control sequence before reaching the (simulated) side-effect boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 1. Data structures
# ---------------------------------------------------------------------------

class Decision(Enum):
    """Terminal policy states."""
    ALLOW = "allow"
    DENY = "deny"
    PAUSE = "pause"


class RiskLevel(Enum):
    """Operation risk classification."""
    LOW = "low"
    HIGH = "high"


@dataclass(frozen=True)
class ActorContext:
    """Trusted application context — created from an authenticated session.

    In production this would be populated by an IAM / OIDC session layer
    or workload-identity system.  In this lab it is constructed from
    ``IDENTITY_REGISTRY``, a deterministic teaching substitute.

    A Python dataclass is not inherently trusted.  Trust comes from
    *provenance* — the fact that application code, not model output,
    created this instance using the authoritative identity registry.

    Fields:
        subject:  Authenticated principal identifier (e.g. ``"emp-42"``).
        tenant:   Tenant the principal belongs to (e.g. ``"acme"``).
        scopes:   Granted permission scopes (e.g. ``{"expense:read"}``).
        run_id:   Correlation identifier for the current agent run.
    """
    subject: str
    tenant: str
    scopes: frozenset[str] = frozenset()
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass(frozen=True)
class ActionProposal:
    """Untrusted action proposed by the model.

    This structure carries no identity, authorization, or approval.
    The policy engine treats every field as untrusted input.

    Fields:
        operation:    Requested operation name.
        resource_id:  Target resource identifier.
        arguments:    Operation-specific arguments (untrusted, validated by policy).
    """
    operation: str
    resource_id: str
    arguments: dict[str, Any] = field(default_factory=dict)


def proposal_digest(proposal: ActionProposal) -> str:
    """Return a stable digest for the exact proposed effect.

    The digest binds approval and audit evidence to the operation, primary
    resource, and complete argument payload.  It is evidence of equality, not
    a signature or an authorization decision.
    """
    canonical = json.dumps(
        {
            "operation": proposal.operation,
            "resource_id": proposal.resource_id,
            "arguments": proposal.arguments,
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ResourceMeta:
    """Trusted lookup result from the application resource registry.

    In production this would come from an authoritative catalog or
    database.  In this lab it is looked up from ``RESOURCE_REGISTRY``.

    Fields:
        resource_id:    Canonical resource identifier.
        owning_tenant:  Tenant that owns this resource.
        classification: Data classification label.
    """
    resource_id: str
    owning_tenant: str
    classification: str = "internal"


@dataclass(frozen=True)
class ApprovalReceipt:
    """Approval evidence — untrusted until verified by the approval store.

    Having a structurally correct ``ApprovalReceipt`` object does NOT
    mean the approval is authentic.  The ``ApprovalStore`` must confirm
    that the receipt was actually issued and has not been consumed.

    In production this would be a signed token or server-stored record
    verified through a durable approval service.  In this lab, the
    ``ApprovalStore`` provides deterministic in-memory verification.

    Fields:
        receipt_id:  Stable receipt identifier.
        subject:     The principal who was approved.
        tenant:      The tenant scope of the approval.
        operation:   The approved operation.
        resource_id: The approved resource.
        proposal_digest: Digest of operation, resource, and exact arguments.
        run_id:      Agent run for which the receipt was issued.
        policy_version: Policy version reviewed by the approver.
        approver:    Who granted the approval.
        issued_at:   When the approval was issued (UTC).
        expires_at:  When the receipt expires (UTC).
    """
    receipt_id: str
    subject: str
    tenant: str
    operation: str
    resource_id: str
    proposal_digest: str
    run_id: str
    policy_version: str
    approver: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class PolicyRule:
    """Per-operation policy configuration.

    Fields:
        operation:       Operation name.
        required_scope:  Scope the actor must possess.
        risk:            Risk classification.
        max_amount:      Maximum ``amount`` argument value (``None`` = no limit).
        cost:            Budget cost per invocation.
        required_args:   Set of argument keys that MUST be present.
        allowed_args:    Set of all argument keys that MAY be present.
    """
    operation: str
    required_scope: str
    risk: RiskLevel
    max_amount: Optional[float] = None
    cost: int = 1
    required_args: frozenset[str] = frozenset()
    allowed_args: frozenset[str] = frozenset()


@dataclass
class PolicyDecision:
    """Trusted decision output from the deterministic policy engine.

    Fields:
        state:       Terminal decision (allow / deny / pause).
        reason:      Stable, machine-readable reason code.
        details:     Optional human-readable context (never secrets).
    """
    state: Decision
    reason: str
    details: str = ""


@dataclass(frozen=True)
class EvaluationObservation:
    """One labelled policy outcome used for deterministic evaluation."""

    expected_state: str
    actual_state: str
    terminal_state: str
    correlation_id: str
    reason: str
    proposal_digest: str
    policy_version: str


@dataclass(frozen=True)
class EvaluationMetrics:
    """Metrics with explicit populations and denominators."""

    case_count: int
    correct_decision_count: int
    decision_accuracy: float | None
    attack_case_count: int
    unauthorized_execution_count: int
    unauthorized_execution_rate: float | None
    valid_case_count: int
    valid_task_success_count: int
    valid_task_success_rate: float | None
    trace_complete_count: int
    trace_coverage: float | None


def calculate_evaluation_metrics(
    observations: list[EvaluationObservation],
) -> EvaluationMetrics:
    """Calculate transparent policy metrics without hiding denominators."""
    case_count = len(observations)
    correct = sum(
        item.actual_state == item.expected_state for item in observations
    )
    attacks = [item for item in observations if item.expected_state != "allow"]
    unauthorized = sum(
        item.terminal_state == "executed" for item in attacks
    )
    valid = [item for item in observations if item.expected_state == "allow"]
    valid_success = sum(
        item.actual_state == "allow" and item.terminal_state == "executed"
        for item in valid
    )
    trace_complete = sum(
        all(
            (
                item.correlation_id,
                item.reason,
                item.proposal_digest,
                item.policy_version,
            )
        )
        for item in observations
    )

    return EvaluationMetrics(
        case_count=case_count,
        correct_decision_count=correct,
        decision_accuracy=correct / case_count if case_count else None,
        attack_case_count=len(attacks),
        unauthorized_execution_count=unauthorized,
        unauthorized_execution_rate=(
            unauthorized / len(attacks) if attacks else None
        ),
        valid_case_count=len(valid),
        valid_task_success_count=valid_success,
        valid_task_success_rate=valid_success / len(valid) if valid else None,
        trace_complete_count=trace_complete,
        trace_coverage=trace_complete / case_count if case_count else None,
    )


# ---------------------------------------------------------------------------
# 2. Audit evidence
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    """Application-produced evidence for the audit pipeline.

    One event is emitted per policy evaluation.  No hidden reasoning,
    sensitive argument values, secrets, or raw payloads are recorded.

    ``policy_state`` records the decision: allow | deny | pause.
    ``terminal_state`` records the lifecycle outcome: executed | blocked.
    """
    correlation_id: str
    subject: str
    tenant: str
    operation: str
    resource_id: str
    proposal_digest: str
    policy_version: str
    policy_state: str      # "allow" | "deny" | "pause"
    reason: str
    budget_remaining: int
    approval_receipt_id: Optional[str] = None
    terminal_state: str = "decided"  # "executed" | "blocked"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 3. Trusted registries and stores (simulated application services)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IdentityRecord:
    """A single entry in the identity registry."""
    subject: str
    tenant: str
    scopes: frozenset[str]


# --- Identity registry (deterministic teaching substitute for IAM) ---
IDENTITY_REGISTRY: dict[str, IdentityRecord] = {
    "emp-42": IdentityRecord(
        "emp-42", "acme",
        frozenset({"expense:read", "expense:submit"}),
    ),
    "emp-77": IdentityRecord(
        "emp-77", "acme",
        frozenset({"expense:read"}),
    ),
    "mgr-10": IdentityRecord(
        "mgr-10", "acme",
        frozenset({"expense:read", "expense:submit", "expense:approve"}),
    ),
}

# --- Resource registry (authoritative catalog) ---
RESOURCE_REGISTRY: dict[str, ResourceMeta] = {
    "receipt-101": ResourceMeta("receipt-101", "acme", "internal"),
    "receipt-102": ResourceMeta("receipt-102", "acme", "internal"),
    "receipt-200": ResourceMeta("receipt-200", "globex", "confidential"),
    "claim-501":   ResourceMeta("claim-501",   "acme", "internal"),
}

# --- Policy configuration ---
POLICY_RULES: dict[str, PolicyRule] = {
    "read_receipt":    PolicyRule(
        "read_receipt", "expense:read", RiskLevel.LOW,
        cost=1, required_args=frozenset(), allowed_args=frozenset(),
    ),
    "calculate_total": PolicyRule(
        "calculate_total", "expense:read", RiskLevel.LOW,
        cost=1, required_args=frozenset({"receipt_ids"}), allowed_args=frozenset({"receipt_ids"}),
    ),
    "preview_claim":   PolicyRule(
        "preview_claim", "expense:read", RiskLevel.LOW,
        cost=1, required_args=frozenset({"receipt_ids"}), allowed_args=frozenset({"receipt_ids"}),
    ),
    "submit_claim":    PolicyRule(
        "submit_claim", "expense:submit", RiskLevel.HIGH,
        max_amount=5000.0, cost=5, required_args=frozenset({"amount"}), allowed_args=frozenset({"amount"}),
    ),
}

RUN_BUDGET: int = 20  # max total cost per run
POLICY_VERSION = "expense-policy-2026-09-01"


# --- Approval store (simulated trusted approval service) ---

class ApprovalStore:
    """In-memory simulated approval service.

    In production this would be a durable workflow/approval service
    with server-side storage, signed tokens, or nonce/JTI tracking.

    This deterministic in-memory store demonstrates that having a
    structurally correct ``ApprovalReceipt`` object is NOT the same as
    possessing authentic approval evidence — the receipt must exist in
    the store and must not have been consumed.
    """

    def __init__(self) -> None:
        self._issued: dict[str, ApprovalReceipt] = {}
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def issue(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        *,
        approver: str = "mgr-10",
        policy_version: str = POLICY_VERSION,
        minutes_valid: int = 30,
        now: Optional[datetime] = None,
    ) -> ApprovalReceipt:
        """Issue approval for one exact proposal after trusted identity checks."""
        if now is None:
            now = datetime.now(timezone.utc)
        if minutes_valid <= 0:
            raise ValueError("approval lifetime must be positive")

        actor_record = IDENTITY_REGISTRY.get(actor.subject)
        if (
            actor_record is None
            or actor.tenant != actor_record.tenant
            or not actor.scopes <= actor_record.scopes
        ):
            raise PermissionError("approval subject must come from trusted identity state")

        approver_record = IDENTITY_REGISTRY.get(approver)
        if (
            approver_record is None
            or approver_record.tenant != actor.tenant
            or "expense:approve" not in approver_record.scopes
        ):
            raise PermissionError("approver lacks authority for this tenant")

        receipt = ApprovalReceipt(
            receipt_id=uuid.uuid4().hex[:12],
            subject=actor.subject,
            tenant=actor.tenant,
            operation=proposal.operation,
            resource_id=proposal.resource_id,
            proposal_digest=proposal_digest(proposal),
            run_id=actor.run_id,
            policy_version=policy_version,
            approver=approver,
            issued_at=now,
            expires_at=now + timedelta(minutes=minutes_valid),
        )
        with self._lock:
            self._issued[receipt.receipt_id] = receipt
        return receipt

    def verify(
        self,
        receipt: ApprovalReceipt,
        actor: ActorContext,
        proposal: ActionProposal,
        policy_version: str,
        now: datetime,
    ) -> Optional[PolicyDecision]:
        """Verify a receipt's authenticity, binding, expiry, and replay state.

        Returns ``None`` if the receipt is valid, or a ``PolicyDecision``
        describing why verification failed.
        """
        with self._lock:
            return self._verification_error(
                receipt, actor, proposal, policy_version, now,
            )

    def verify_and_consume(
        self,
        receipt: ApprovalReceipt,
        actor: ActorContext,
        proposal: ActionProposal,
        policy_version: str,
        now: datetime,
    ) -> Optional[PolicyDecision]:
        """Atomically revalidate and consume a single-use approval."""
        with self._lock:
            error = self._verification_error(
                receipt, actor, proposal, policy_version, now,
            )
            if error is not None:
                return error
            self._consumed.add(receipt.receipt_id)
            return None

    def _verification_error(
        self,
        receipt: ApprovalReceipt,
        actor: ActorContext,
        proposal: ActionProposal,
        policy_version: str,
        now: datetime,
    ) -> Optional[PolicyDecision]:
        """Return a deterministic reason when an approval is not executable."""
        stored = self._issued.get(receipt.receipt_id)
        if stored is None or stored != receipt:
            return PolicyDecision(
                Decision.DENY, "approval_unknown",
                "Approval receipt was not issued by the trusted approval service.",
            )

        # Replay: receipt must not have been consumed
        if receipt.receipt_id in self._consumed:
            return PolicyDecision(
                Decision.DENY, "approval_replayed",
                "Approval receipt has already been consumed.",
            )

        # Binding: receipt must match the requesting actor and proposal
        if receipt.subject != actor.subject:
            return PolicyDecision(
                Decision.DENY, "approval_subject_mismatch",
                "Approval receipt is bound to a different subject.",
            )
        if receipt.tenant != actor.tenant:
            return PolicyDecision(
                Decision.DENY, "approval_tenant_mismatch",
                "Approval receipt is bound to a different tenant.",
            )
        if receipt.run_id != actor.run_id:
            return PolicyDecision(
                Decision.DENY, "approval_run_mismatch",
                "Approval receipt is bound to a different agent run.",
            )
        if receipt.operation != proposal.operation:
            return PolicyDecision(
                Decision.DENY, "approval_operation_mismatch",
                "Approval receipt is for a different operation.",
            )
        if receipt.resource_id != proposal.resource_id:
            return PolicyDecision(
                Decision.DENY, "approval_resource_mismatch",
                "Approval receipt is for a different resource.",
            )
        try:
            current_digest = proposal_digest(proposal)
        except (TypeError, ValueError):
            return PolicyDecision(
                Decision.DENY, "proposal_not_canonical",
                "Proposal arguments cannot be bound to deterministic evidence.",
            )
        if receipt.proposal_digest != current_digest:
            return PolicyDecision(
                Decision.DENY, "approval_proposal_mismatch",
                "Approval receipt is bound to different tool arguments.",
            )
        if receipt.policy_version != policy_version:
            return PolicyDecision(
                Decision.DENY, "approval_policy_mismatch",
                "Approval receipt was evaluated under a different policy version.",
            )

        # Lifetime: reject future-issued and expired receipts.
        if now < receipt.issued_at:
            return PolicyDecision(
                Decision.DENY, "approval_not_yet_valid",
                "Approval receipt was issued in the future.",
            )
        if now >= receipt.expires_at:
            return PolicyDecision(
                Decision.DENY, "approval_expired",
                "Approval receipt has expired.",
            )

        return None  # receipt is valid


# ---------------------------------------------------------------------------
# 4. Argument validation
# ---------------------------------------------------------------------------

def authorize_resource(
    actor: ActorContext,
    resource_id: str,
) -> Optional[PolicyDecision]:
    """Authorize access to a single resource."""
    resource = RESOURCE_REGISTRY.get(resource_id)
    if resource is None:
        return PolicyDecision(
            Decision.DENY, "unknown_resource",
            f"Resource '{resource_id}' is not in the registry.",
        )
    if resource.owning_tenant != actor.tenant:
        return PolicyDecision(
            Decision.DENY, "cross_tenant",
            f"Resource belongs to '{resource.owning_tenant}', "
            f"not '{actor.tenant}'.",
        )
    return None


def _is_finite_positive_number(value: Any) -> bool:
    """True if value is a finite positive number, excluding booleans."""
    # isinstance(True, int) is True, so reject booleans explicitly
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    if math.isnan(value) or math.isinf(value):
        return False
    return value > 0


def validate_arguments(
    operation: str,
    rule: PolicyRule,
    arguments: dict[str, Any],
) -> Optional[PolicyDecision]:
    """Deterministic per-operation argument validation.

    Returns ``None`` if arguments are valid, or a ``PolicyDecision``
    describing the validation failure.
    """
    arg_keys = set(arguments.keys())

    # Check required arguments
    missing = rule.required_args - arg_keys
    if missing:
        return PolicyDecision(
            Decision.DENY, "missing_argument",
            f"Missing required argument(s): {sorted(missing)}.",
        )

    # Reject unexpected arguments
    unexpected = arg_keys - rule.allowed_args
    if unexpected:
        return PolicyDecision(
            Decision.DENY, "unexpected_argument",
            f"Unexpected argument(s): {sorted(unexpected)}.",
        )

    # Per-operation schema checks
    if operation == "read_receipt":
        # No arguments expected
        pass

    elif operation in ("calculate_total", "preview_claim"):
        receipt_ids = arguments.get("receipt_ids")
        if not isinstance(receipt_ids, list):
            return PolicyDecision(
                Decision.DENY, "invalid_argument",
                "Argument 'receipt_ids' must be a list.",
            )
        if not receipt_ids:
            return PolicyDecision(
                Decision.DENY, "invalid_argument",
                "Argument 'receipt_ids' must not be empty.",
            )
        for rid in receipt_ids:
            if not isinstance(rid, str) or not rid:
                return PolicyDecision(
                    Decision.DENY, "invalid_argument",
                    "Elements in 'receipt_ids' must be non-empty strings.",
                )

    elif operation == "submit_claim":
        amount = arguments.get("amount")
        if not _is_finite_positive_number(amount):
            return PolicyDecision(
                Decision.DENY, "invalid_argument",
                f"Amount must be a finite positive number, got {amount!r}.",
            )
        if rule.max_amount is not None and amount > rule.max_amount:
            return PolicyDecision(
                Decision.DENY, "amount_exceeded",
                f"Amount {amount} exceeds limit {rule.max_amount}.",
            )

    return None  # arguments are valid


# ---------------------------------------------------------------------------
# 5. Policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Deterministic pre-execution policy enforcer.

    Checks are applied in a fixed seven-step sequence.  The first
    failing check produces a ``deny`` or ``pause`` and short-circuits.
    Only ``allow`` reaches the execution stub.  Every evaluation emits
    exactly one ``AuditEvent``.

    Budget is charged only for actions that pass all controls and
    are allowed to execute.
    """

    def __init__(
        self,
        budget: int = RUN_BUDGET,
        approval_store: Optional[ApprovalStore] = None,
        policy_version: str = POLICY_VERSION,
    ) -> None:
        self._budget_remaining: int = budget
        self._audit_log: list[AuditEvent] = []
        self._execution_log: list[str] = []
        self._approval_store: Optional[ApprovalStore] = approval_store
        self._policy_version = policy_version

    # --- Public read-only properties ---

    @property
    def budget_remaining(self) -> int:
        """Remaining execution budget for this run."""
        return self._budget_remaining

    @property
    def execution_count(self) -> int:
        """Number of actions that reached the execution stub."""
        return len(self._execution_log)

    @property
    def audit_log(self) -> list[AuditEvent]:
        """Chronological list of audit events for this run."""
        return list(self._audit_log)

    # --- Public API ---

    def evaluate(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        approval: Optional[ApprovalReceipt] = None,
        *,
        now: Optional[datetime] = None,
    ) -> PolicyDecision:
        """Run the seven-step control sequence and record an audit event.

        Args:
            actor:     Trusted application context.
            proposal:  Untrusted action from the model.
            approval:  Optional approval evidence (untrusted until verified).
            now:       Override wall-clock for deterministic testing.

        Returns:
            A ``PolicyDecision`` with state, reason, and optional details.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        decision, consume_approval = self._apply_controls(actor, proposal, approval, now)

        event = AuditEvent(
            correlation_id=actor.run_id,
            subject=actor.subject,
            tenant=actor.tenant,
            operation=proposal.operation,
            resource_id=proposal.resource_id,
            proposal_digest=self._safe_proposal_digest(proposal),
            policy_version=self._policy_version,
            policy_state=decision.state.value,
            reason=decision.reason,
            budget_remaining=self._budget_remaining,
            approval_receipt_id=approval.receipt_id if approval else None,
            terminal_state="decided",
        )

        if decision.state is Decision.ALLOW:
            self._execute_stub(proposal)
            event.terminal_state = "executed"
        else:
            event.terminal_state = "blocked"

        self._audit_log.append(event)
        return decision

    # --- Control sequence (private) ---

    def _apply_controls(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        approval: Optional[ApprovalReceipt],
        now: datetime,
    ) -> tuple[PolicyDecision, bool]:
        """Seven-step deterministic control sequence.
        
        Returns:
            (PolicyDecision, consume_approval: bool)
        """
        
        # Step 1 — Authenticate subject and resolve authoritative tenant/scopes
        identity = IDENTITY_REGISTRY.get(actor.subject) if actor.subject else None
        if identity is None:
            return PolicyDecision(
                Decision.DENY, "unknown_subject",
                f"Subject '{actor.subject}' is not in the identity registry.",
            ), False
        if actor.tenant != identity.tenant:
            return PolicyDecision(
                Decision.DENY, "subject_tenant_mismatch",
                f"Subject '{actor.subject}' belongs to tenant "
                f"'{identity.tenant}', not '{actor.tenant}'.",
            ), False
        if not actor.scopes <= identity.scopes:
            escalated = actor.scopes - identity.scopes
            return PolicyDecision(
                Decision.DENY, "invalid_scope_grant",
                f"Scopes {sorted(escalated)} are not granted to "
                f"'{actor.subject}'.",
            ), False

        # Step 2 — Operation allowlist and required scope
        rule = POLICY_RULES.get(proposal.operation)
        if rule is None:
            return PolicyDecision(
                Decision.DENY, "operation_not_allowed",
                f"Operation '{proposal.operation}' is not allowlisted.",
            ), False
        if rule.required_scope not in actor.scopes:
            return PolicyDecision(
                Decision.DENY, "missing_scope",
                f"Scope '{rule.required_scope}' is required.",
            ), False

        # Step 3 — Resolve resource metadata and enforce tenant ownership
        auth_error = authorize_resource(actor, proposal.resource_id)
        if auth_error is not None:
            return auth_error, False

        # Authorize indirectly referenced resources in arguments
        receipt_ids = proposal.arguments.get("receipt_ids")
        if isinstance(receipt_ids, list):
            for rid in receipt_ids:
                if isinstance(rid, str) and rid:
                    auth_error = authorize_resource(actor, rid)
                    if auth_error is not None:
                        return auth_error, False

        # Step 4 — Validate argument schema and business rules
        arg_error = validate_arguments(
            proposal.operation, rule, proposal.arguments,
        )
        if arg_error is not None:
            return arg_error, False

        # Step 5 — Classify risk and determine approval requirement
        if rule.risk is RiskLevel.HIGH and approval is None:
            return PolicyDecision(
                Decision.PAUSE, "approval_required",
                "High-risk operation requires human approval.",
            ), False

        # Step 6 — Verify approval authenticity + binding + expiry + replay
        consume_approval = False
        if rule.risk is RiskLevel.HIGH and approval is not None:
            if self._approval_store is None:
                # The absence of a security dependency must fail closed.
                return PolicyDecision(
                    Decision.DENY, "approval_verifier_unavailable",
                    "No trusted approval store is configured to verify the receipt.",
                ), False
            
            verification_error = self._approval_store.verify(
                approval, actor, proposal, self._policy_version, now,
            )
            if verification_error is not None:
                return verification_error, False
            consume_approval = True

        # Step 7 — Enforce per-run execution budget
        if self._budget_remaining < rule.cost:
            return PolicyDecision(
                Decision.DENY, "budget_exhausted",
                f"Run budget exhausted ({self._budget_remaining} "
                f"remaining, {rule.cost} required).",
            ), False

        # Close the verify/use race immediately before granting execution.
        if consume_approval and approval is not None and self._approval_store is not None:
            verification_error = self._approval_store.verify_and_consume(
                approval, actor, proposal, self._policy_version, now,
            )
            if verification_error is not None:
                return verification_error, False
        self._budget_remaining -= rule.cost

        return PolicyDecision(Decision.ALLOW, "all_checks_passed"), consume_approval

    @staticmethod
    def _safe_proposal_digest(proposal: ActionProposal) -> str:
        """Produce audit evidence without letting malformed data hide a decision."""
        try:
            return proposal_digest(proposal)
        except (TypeError, ValueError):
            return "unavailable"



    def _execute_stub(self, proposal: ActionProposal) -> None:
        """Safe, in-memory side-effect stub.

        In production this would be an idempotent tool/API call.
        In the lab it only records that execution was reached.
        """
        self._execution_log.append(
            f"EXECUTED: {proposal.operation} on {proposal.resource_id}"
        )


# ---------------------------------------------------------------------------
# 6. Helper for creating actor contexts from the identity registry
# ---------------------------------------------------------------------------

def make_actor(
    subject: str,
    *,
    run_id: Optional[str] = None,
) -> ActorContext:
    """Create an ``ActorContext`` from the trusted identity registry.

    This is the correct way to create actor contexts in this lab.
    Identity, tenant, and scopes are resolved from ``IDENTITY_REGISTRY``,
    not from untrusted input.

    Raises ``KeyError`` if the subject is not in the registry.
    """
    record = IDENTITY_REGISTRY[subject]
    return ActorContext(
        subject=record.subject,
        tenant=record.tenant,
        scopes=record.scopes,
        run_id=run_id or uuid.uuid4().hex[:12],
    )


# ---------------------------------------------------------------------------
# 7. Demonstration (runs when the module is executed directly)
# ---------------------------------------------------------------------------

def run_demo() -> None:
    """Run a labelled set of scenarios and print structured results."""

    NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    # --- Trusted approval store ---
    store = ApprovalStore()

    # --- Trusted actor contexts (from identity registry) ---
    acme_employee = make_actor("emp-42", run_id="demo-run-001")
    read_only_emp = make_actor("emp-77", run_id="demo-run-003")

    unknown_actor = ActorContext(
        subject="hacker-99", tenant="acme",
        scopes=frozenset({"expense:read", "expense:submit"}),
        run_id="demo-run-002",
    )
    forged_tenant_actor = ActorContext(
        subject="emp-42", tenant="globex",
        scopes=frozenset({"expense:read", "expense:submit"}),
        run_id="demo-run-004",
    )

    # --- Issue legitimate approval receipts via the store ---
    valid_write = ActionProposal(
        "submit_claim", "claim-501", {"amount": 250.0},
    )
    forged_write = ActionProposal(
        "submit_claim", "claim-501", {"amount": 100.0},
    )
    wrong_resource_write = ActionProposal(
        "submit_claim", "claim-999", {"amount": 100.0},
    )
    valid_receipt = store.issue(
        acme_employee, valid_write, now=NOW, minutes_valid=30,
    )
    forged_receipt = store.issue(
        read_only_emp, forged_write, now=NOW, minutes_valid=30,
    )
    expired_receipt = store.issue(
        acme_employee, forged_write,
        now=NOW - timedelta(minutes=31), minutes_valid=30,
    )
    wrong_resource_receipt = store.issue(
        acme_employee, wrong_resource_write, now=NOW, minutes_valid=30,
    )

    # --- Fabricated receipt (never issued by the store) ---
    fabricated_receipt = ApprovalReceipt(
        receipt_id="made-up-id",
        subject="emp-42", tenant="acme",
        operation="submit_claim", resource_id="claim-501",
        proposal_digest=proposal_digest(forged_write),
        run_id=acme_employee.run_id,
        policy_version=POLICY_VERSION,
        approver="mgr-10",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )

    # --- Receipt for replay test ---
    replay_receipt = store.issue(
        acme_employee, forged_write, now=NOW, minutes_valid=30,
    )

    # --- Scenarios ---
    scenarios: list[tuple[str, ActorContext, ActionProposal, Optional[ApprovalReceipt], str, str]] = [
        (
            "Permitted same-tenant read",
            acme_employee,
            ActionProposal("read_receipt", "receipt-101"),
            None,
            "allow", "all_checks_passed",
        ),
        (
            "Unknown subject denied",
            unknown_actor,
            ActionProposal("read_receipt", "receipt-101"),
            None,
            "deny", "unknown_subject",
        ),
        (
            "Known subject + forged tenant denied",
            forged_tenant_actor,
            ActionProposal("read_receipt", "receipt-101"),
            None,
            "deny", "subject_tenant_mismatch",
        ),
        (
            "Missing scope for submit",
            read_only_emp,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            forged_receipt,
            "deny", "missing_scope",
        ),
        (
            "Cross-tenant resource denied",
            acme_employee,
            ActionProposal("read_receipt", "receipt-200"),
            None,
            "deny", "cross_tenant",
        ),
        (
            "Unallowlisted operation denied",
            acme_employee,
            ActionProposal("delete_receipt", "receipt-101"),
            None,
            "deny", "operation_not_allowed",
        ),
        (
            "Malformed amount denied",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": -50.0}),
            valid_receipt,
            "deny", "invalid_argument",
        ),
        (
            "Boolean amount rejected",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": True}),
            valid_receipt,
            "deny", "invalid_argument",
        ),
        (
            "Amount exceeds limit",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 9999.0}),
            valid_receipt,
            "deny", "amount_exceeded",
        ),
        (
            "Unexpected argument rejected",
            acme_employee,
            ActionProposal("read_receipt", "receipt-101", {"extra": "data"}),
            None,
            "deny", "unexpected_argument",
        ),
        (
            "High-risk write without approval paused",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            None,
            "pause", "approval_required",
        ),
        (
            "Fabricated receipt denied",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            fabricated_receipt,
            "deny", "approval_unknown",
        ),
        (
            "Forged approval (wrong subject) denied",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            forged_receipt,
            "deny", "approval_subject_mismatch",
        ),
        (
            "Expired approval denied",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            expired_receipt,
            "deny", "approval_expired",
        ),
        (
            "Approval bound to wrong resource denied",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            wrong_resource_receipt,
            "deny", "approval_resource_mismatch",
        ),
        (
            "Valid approved write allowed",
            acme_employee,
            valid_write,
            valid_receipt,
            "allow", "all_checks_passed",
        ),
    ]

    engine = PolicyEngine(budget=RUN_BUDGET, approval_store=store)
    print("=" * 72)
    print("Security Foundations and Tool Policy — Scenario Evaluation")
    print("=" * 72)

    failures: list[str] = []
    observations: list[EvaluationObservation] = []

    for label, actor, proposal, approval, exp_state, exp_reason in scenarios:
        decision = engine.evaluate(actor, proposal, approval, now=NOW)
        event = engine.audit_log[-1]
        observations.append(
            EvaluationObservation(
                expected_state=exp_state,
                actual_state=decision.state.value,
                terminal_state=event.terminal_state,
                correlation_id=event.correlation_id,
                reason=event.reason,
                proposal_digest=event.proposal_digest,
                policy_version=event.policy_version,
            )
        )
        status = "PASS" if (
            decision.state.value == exp_state and decision.reason == exp_reason
        ) else "FAIL"
        if status == "FAIL":
            failures.append(label)
        print(f"\n[{status}] {label}")
        print(f"  decision : {decision.state.value}")
        print(f"  reason   : {decision.reason}")
        if decision.details:
            print(f"  details  : {decision.details}")

    # --- Replay test ---
    replay_decision = engine.evaluate(
        acme_employee,
        ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
        replay_receipt,
        now=NOW,
    )
    status = "PASS" if replay_decision.state is Decision.ALLOW else "FAIL"
    if status == "FAIL":
        failures.append("Replay first use")
    print(f"\n[{status}] Replay: first use allowed")
    print(f"  decision : {replay_decision.state.value}")
    print(f"  reason   : {replay_decision.reason}")

    replay_decision_2 = engine.evaluate(
        acme_employee,
        ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
        replay_receipt,
        now=NOW,
    )
    status = "PASS" if (
        replay_decision_2.state is Decision.DENY
        and replay_decision_2.reason == "approval_replayed"
    ) else "FAIL"
    if status == "FAIL":
        failures.append("Replay second use")
    print(f"\n[{status}] Replay: second use denied")
    print(f"  decision : {replay_decision_2.state.value}")
    print(f"  reason   : {replay_decision_2.reason}")

    # --- Budget exhaustion ---
    print(f"\n--- Budget remaining: {engine.budget_remaining} ---")
    budget_engine = PolicyEngine(budget=1, approval_store=store)
    budget_engine.evaluate(
        acme_employee,
        ActionProposal("read_receipt", "receipt-101"),
        now=NOW,
    )
    budget_decision = budget_engine.evaluate(
        acme_employee,
        ActionProposal("read_receipt", "receipt-102"),
        now=NOW,
    )
    status = "PASS" if (
        budget_decision.state is Decision.DENY
        and budget_decision.reason == "budget_exhausted"
    ) else "FAIL"
    if status == "FAIL":
        failures.append("Budget exhaustion")
    print(f"\n[{status}] Budget exhaustion")
    print(f"  decision : {budget_decision.state.value}")
    print(f"  reason   : {budget_decision.reason}")

    # --- Execution-event invariant ---
    denied_or_paused_executed = [
        e for e in engine.audit_log
        if e.policy_state in ("deny", "pause") and e.terminal_state == "executed"
    ]
    invariant_ok = len(denied_or_paused_executed) == 0
    status = "PASS" if invariant_ok else "FAIL"
    if not invariant_ok:
        failures.append("Execution invariant")
    print(f"\n[{status}] Execution invariant: denied/paused → never executed")
    print(f"  violations: {len(denied_or_paused_executed)}")

    # --- Audit log summary ---
    log = engine.audit_log
    allowed_count = sum(1 for e in log if e.policy_state == "allow")
    executed_count = sum(1 for e in log if e.terminal_state == "executed")
    print(f"\n--- Audit log: {len(log)} events, "
          f"{allowed_count} allowed, {executed_count} executed ---")

    metrics = calculate_evaluation_metrics(observations)
    print("\n--- Labelled evaluation metrics (primary scenarios only) ---")
    print(
        f"decision accuracy       : {metrics.correct_decision_count}/"
        f"{metrics.case_count} = {metrics.decision_accuracy:.1%}"
    )
    print(
        f"unauthorized execution  : {metrics.unauthorized_execution_count}/"
        f"{metrics.attack_case_count} = "
        f"{metrics.unauthorized_execution_rate:.1%}"
    )
    print(
        f"valid-task success      : {metrics.valid_task_success_count}/"
        f"{metrics.valid_case_count} = {metrics.valid_task_success_rate:.1%}"
    )
    print(
        f"decision trace coverage : {metrics.trace_complete_count}/"
        f"{metrics.case_count} = {metrics.trace_coverage:.1%}"
    )

    print("\n" + "=" * 72)
    if failures:
        print(f"FAILURES ({len(failures)}): {', '.join(failures)}")
        raise SystemExit(1)
    else:
        print("All scenarios passed.")


if __name__ == "__main__":
    run_demo()

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

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 1. Trust-boundary data structures
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
    """Trusted session context — set by authentication, never by model text.

    Fields:
        subject:  Authenticated principal identifier (e.g. ``"emp-42"``).
        tenant:   Tenant the principal belongs to (e.g. ``"acme"``).
        scopes:   Granted permission scopes (e.g. ``{"expense:read", "expense:submit"}``).
        run_id:   Correlation identifier for the current agent run.
    """
    subject: str
    tenant: str
    scopes: frozenset[str] = frozenset()
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass(frozen=True)
class ActionProposal:
    """Untrusted action proposed by the model.

    Fields:
        operation:    Requested operation name.
        resource_id:  Target resource identifier.
        arguments:    Operation-specific arguments (untrusted, must be validated).
    """
    operation: str
    resource_id: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceMeta:
    """Trusted resource metadata — looked up from a registry, not from the request.

    Fields:
        resource_id:    Canonical resource identifier.
        owning_tenant:  Tenant that owns this resource.
        classification: Data classification label (e.g. ``"internal"``).
    """
    resource_id: str
    owning_tenant: str
    classification: str = "internal"


@dataclass(frozen=True)
class ApprovalReceipt:
    """Cryptographically-verifiable approval evidence (simulated here).

    In production this would be a signed token or server-stored record.
    The lab uses in-memory binding checks only.

    Fields:
        receipt_id:  Stable receipt identifier.
        subject:     The principal who was approved.
        tenant:      The tenant scope of the approval.
        operation:   The approved operation.
        resource_id: The approved resource.
        approver:    Who granted the approval.
        expires_at:  When the receipt expires (UTC).
    """
    receipt_id: str
    subject: str
    tenant: str
    operation: str
    resource_id: str
    approver: str
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
    """
    operation: str
    required_scope: str
    risk: RiskLevel
    max_amount: Optional[float] = None
    cost: int = 1


@dataclass
class PolicyDecision:
    """Immutable record of a single policy evaluation.

    Fields:
        state:       Terminal decision (allow / deny / pause).
        reason:      Stable, machine-readable reason code.
        details:     Optional human-readable context (never secrets).
    """
    state: Decision
    reason: str
    details: str = ""


# ---------------------------------------------------------------------------
# 2. Audit evidence
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    """Redacted, structured record of a policy decision or execution attempt.

    No hidden reasoning, sensitive argument values, or raw payloads.
    """
    correlation_id: str
    subject: str
    tenant: str
    operation: str
    resource_id: str
    policy_state: str
    reason: str
    approval_receipt_id: Optional[str] = None
    terminal_state: str = "decided"  # "decided" | "executed" | "blocked"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 3. Policy engine
# ---------------------------------------------------------------------------

# --- Synthetic resource registry (trusted lookup) ---
RESOURCE_REGISTRY: dict[str, ResourceMeta] = {
    "receipt-101":  ResourceMeta("receipt-101",  "acme", "internal"),
    "receipt-102":  ResourceMeta("receipt-102",  "acme", "internal"),
    "receipt-200":  ResourceMeta("receipt-200",  "globex", "confidential"),
    "claim-501":    ResourceMeta("claim-501",    "acme", "internal"),
}

# --- Policy configuration ---
POLICY_RULES: dict[str, PolicyRule] = {
    "read_receipt":    PolicyRule("read_receipt",    "expense:read",    RiskLevel.LOW,  cost=1),
    "calculate_total": PolicyRule("calculate_total", "expense:read",    RiskLevel.LOW,  cost=1),
    "preview_claim":   PolicyRule("preview_claim",   "expense:read",    RiskLevel.LOW,  cost=1),
    "submit_claim":    PolicyRule("submit_claim",    "expense:submit",  RiskLevel.HIGH, max_amount=5000.0, cost=5),
}

KNOWN_SUBJECTS: set[str] = {"emp-42", "emp-77", "mgr-10"}

RUN_BUDGET: int = 20  # max total cost per run


class PolicyEngine:
    """Deterministic pre-execution policy enforcer.

    Checks are applied in a fixed order.  The first failing check produces
    a ``deny`` or ``pause`` and short-circuits.  Only ``allow`` reaches the
    execution stub.  Every evaluation emits exactly one ``AuditEvent``.
    """

    def __init__(self, budget: int = RUN_BUDGET) -> None:
        self._budget_remaining: int = budget
        self.audit_log: list[AuditEvent] = []
        self._execution_log: list[str] = []

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
            actor:     Trusted session context.
            proposal:  Untrusted action from the model.
            approval:  Optional approval evidence for high-risk actions.
            now:       Override wall-clock for deterministic testing.

        Returns:
            A ``PolicyDecision`` with state, reason, and optional details.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        decision = self._apply_controls(actor, proposal, approval, now)

        event = AuditEvent(
            correlation_id=actor.run_id,
            subject=actor.subject,
            tenant=actor.tenant,
            operation=proposal.operation,
            resource_id=proposal.resource_id,
            policy_state=decision.state.value,
            reason=decision.reason,
            approval_receipt_id=approval.receipt_id if approval else None,
            terminal_state="decided",
        )

        if decision.state is Decision.ALLOW:
            self._execute_stub(proposal)
            event.terminal_state = "executed"
        else:
            event.terminal_state = "blocked"

        self.audit_log.append(event)
        return decision

    # --- Control sequence (private) ---

    def _apply_controls(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        approval: Optional[ApprovalReceipt],
        now: datetime,
    ) -> PolicyDecision:
        """Seven-step deterministic control sequence."""

        # Step 1 — Known authenticated subject and tenant
        if not actor.subject or actor.subject not in KNOWN_SUBJECTS:
            return PolicyDecision(Decision.DENY, "unknown_subject",
                                 f"Subject '{actor.subject}' is not recognised.")
        if not actor.tenant:
            return PolicyDecision(Decision.DENY, "missing_tenant",
                                 "Actor context has no tenant.")

        # Step 2 — Operation allowlist and required scope
        rule = POLICY_RULES.get(proposal.operation)
        if rule is None:
            return PolicyDecision(Decision.DENY, "operation_not_allowed",
                                 f"Operation '{proposal.operation}' is not allowlisted.")
        if rule.required_scope not in actor.scopes:
            return PolicyDecision(Decision.DENY, "missing_scope",
                                 f"Scope '{rule.required_scope}' is required.")

        # Step 3 — Resource ownership / tenant match
        resource = RESOURCE_REGISTRY.get(proposal.resource_id)
        if resource is None:
            return PolicyDecision(Decision.DENY, "unknown_resource",
                                 f"Resource '{proposal.resource_id}' is not in the registry.")
        if resource.owning_tenant != actor.tenant:
            return PolicyDecision(Decision.DENY, "cross_tenant",
                                 f"Resource belongs to '{resource.owning_tenant}', "
                                 f"not '{actor.tenant}'.")

        # Step 4 — Argument schema and business rules
        if proposal.operation == "submit_claim":
            amount = proposal.arguments.get("amount")
            if amount is None:
                return PolicyDecision(Decision.DENY, "missing_argument",
                                     "Argument 'amount' is required for submit_claim.")
            if not isinstance(amount, (int, float)) or amount <= 0:
                return PolicyDecision(Decision.DENY, "invalid_argument",
                                     f"Amount must be a positive number, got {amount!r}.")
            if rule.max_amount is not None and amount > rule.max_amount:
                return PolicyDecision(Decision.DENY, "amount_exceeded",
                                     f"Amount {amount} exceeds limit {rule.max_amount}.")

        # Step 5 — Risk classification and approval requirement
        if rule.risk is RiskLevel.HIGH and approval is None:
            return PolicyDecision(Decision.PAUSE, "approval_required",
                                 "High-risk operation requires human approval.")

        # Step 6 — Approval binding and expiry
        if rule.risk is RiskLevel.HIGH and approval is not None:
            binding_error = self._check_approval_binding(
                actor, proposal, approval, now
            )
            if binding_error is not None:
                return binding_error

        # Step 7 — Per-run budget
        if self._budget_remaining < rule.cost:
            return PolicyDecision(Decision.DENY, "budget_exhausted",
                                 f"Run budget exhausted ({self._budget_remaining} "
                                 f"remaining, {rule.cost} required).")
        self._budget_remaining -= rule.cost

        return PolicyDecision(Decision.ALLOW, "all_checks_passed")

    @staticmethod
    def _check_approval_binding(
        actor: ActorContext,
        proposal: ActionProposal,
        receipt: ApprovalReceipt,
        now: datetime,
    ) -> Optional[PolicyDecision]:
        """Validate that an approval receipt is correctly bound and current."""
        if receipt.subject != actor.subject:
            return PolicyDecision(Decision.DENY, "approval_subject_mismatch",
                                 "Approval receipt is bound to a different subject.")
        if receipt.tenant != actor.tenant:
            return PolicyDecision(Decision.DENY, "approval_tenant_mismatch",
                                 "Approval receipt is bound to a different tenant.")
        if receipt.operation != proposal.operation:
            return PolicyDecision(Decision.DENY, "approval_operation_mismatch",
                                 "Approval receipt is for a different operation.")
        if receipt.resource_id != proposal.resource_id:
            return PolicyDecision(Decision.DENY, "approval_resource_mismatch",
                                 "Approval receipt is for a different resource.")
        if now >= receipt.expires_at:
            return PolicyDecision(Decision.DENY, "approval_expired",
                                 "Approval receipt has expired.")
        return None  # binding is valid

    def _execute_stub(self, proposal: ActionProposal) -> None:
        """Safe, in-memory side-effect stub.

        In production, this is where the real tool call would happen
        (database write, API call, etc.).  In the lab it only records
        that execution was reached.
        """
        self._execution_log.append(
            f"EXECUTED: {proposal.operation} on {proposal.resource_id}"
        )


# ---------------------------------------------------------------------------
# 4. Demonstration (runs when the module is executed directly)
# ---------------------------------------------------------------------------

def _make_receipt(
    subject: str,
    tenant: str,
    operation: str,
    resource_id: str,
    *,
    approver: str = "mgr-10",
    minutes_valid: int = 30,
    now: Optional[datetime] = None,
) -> ApprovalReceipt:
    """Helper: create a correctly-bound approval receipt."""
    if now is None:
        now = datetime.now(timezone.utc)
    return ApprovalReceipt(
        receipt_id=uuid.uuid4().hex[:12],
        subject=subject,
        tenant=tenant,
        operation=operation,
        resource_id=resource_id,
        approver=approver,
        expires_at=now + timedelta(minutes=minutes_valid),
    )


def run_demo() -> None:
    """Run a labelled set of scenarios and print structured results."""

    NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    # --- Trusted actor contexts ---
    acme_employee = ActorContext(
        subject="emp-42", tenant="acme",
        scopes=frozenset({"expense:read", "expense:submit"}),
        run_id="demo-run-001",
    )
    unknown_actor = ActorContext(
        subject="hacker-99", tenant="acme",
        scopes=frozenset({"expense:read", "expense:submit"}),
        run_id="demo-run-002",
    )
    no_submit_scope = ActorContext(
        subject="emp-77", tenant="acme",
        scopes=frozenset({"expense:read"}),
        run_id="demo-run-003",
    )

    # --- Approval receipts ---
    valid_receipt = _make_receipt(
        "emp-42", "acme", "submit_claim", "claim-501",
        now=NOW, minutes_valid=30,
    )
    forged_receipt = _make_receipt(
        "emp-77", "acme", "submit_claim", "claim-501",  # wrong subject
        now=NOW, minutes_valid=30,
    )
    expired_receipt = _make_receipt(
        "emp-42", "acme", "submit_claim", "claim-501",
        now=NOW, minutes_valid=-10,  # already expired
    )
    wrong_resource_receipt = _make_receipt(
        "emp-42", "acme", "submit_claim", "claim-999",  # different resource
        now=NOW, minutes_valid=30,
    )

    # --- Scenarios ---
    scenarios: list[tuple[str, ActorContext, ActionProposal, Optional[ApprovalReceipt], str, str]] = [
        # (label, actor, proposal, approval, expected_state, expected_reason)
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
            "Missing scope for submit",
            no_submit_scope,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            _make_receipt("emp-77", "acme", "submit_claim", "claim-501", now=NOW),
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
            "Amount exceeds limit",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 9999.0}),
            valid_receipt,
            "deny", "amount_exceeded",
        ),
        (
            "High-risk write without approval paused",
            acme_employee,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            None,
            "pause", "approval_required",
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
            ActionProposal("submit_claim", "claim-501", {"amount": 250.0}),
            valid_receipt,
            "allow", "all_checks_passed",
        ),
    ]

    engine = PolicyEngine(budget=RUN_BUDGET)
    print("=" * 72)
    print("Security Foundations and Tool Policy — Scenario Evaluation")
    print("=" * 72)

    failures: list[str] = []

    for label, actor, proposal, approval, exp_state, exp_reason in scenarios:
        decision = engine.evaluate(actor, proposal, approval, now=NOW)
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

    # --- Budget exhaustion ---
    print(f"\n--- Budget remaining: {engine._budget_remaining} ---")
    budget_engine = PolicyEngine(budget=1)
    # Use 1 cost on a read
    budget_engine.evaluate(
        acme_employee,
        ActionProposal("read_receipt", "receipt-101"),
        now=NOW,
    )
    # Now budget is 0 — next should be denied
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
    allowed_count = sum(1 for e in engine.audit_log if e.policy_state == "allow")
    executed_count = sum(1 for e in engine.audit_log if e.terminal_state == "executed")
    print(f"\n--- Audit log: {len(engine.audit_log)} events, "
          f"{allowed_count} allowed, {executed_count} executed ---")

    print("\n" + "=" * 72)
    if failures:
        print(f"FAILURES ({len(failures)}): {', '.join(failures)}")
        raise SystemExit(1)
    else:
        print("All scenarios passed.")


if __name__ == "__main__":
    run_demo()

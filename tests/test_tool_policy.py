"""Focused tests for curriculum/beginner/01-tool-policy/01_tool_policy.py.

Table-driven tests covering all required adversarial and boundary cases.
Uses only the standard library (unittest).  Runs from the repository root
with ``PYTHONPATH=. python3 -m pytest tests/test_tool_policy.py -v``.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add the module directory to sys.path so we can import by filename.
_module_dir = Path(__file__).resolve().parent.parent / "curriculum" / "beginner" / "01-tool-policy"
if str(_module_dir) not in sys.path:
    sys.path.insert(0, str(_module_dir))

# Now we can import the lab module by its underscore name.
# We use importlib to handle the leading-digit filename.
import importlib
_mod = importlib.import_module("01_tool_policy")

# Pull names into this module's namespace for convenience.
ActorContext = _mod.ActorContext
ActionProposal = _mod.ActionProposal
ApprovalReceipt = _mod.ApprovalReceipt
ApprovalStore = _mod.ApprovalStore
AuditEvent = _mod.AuditEvent
Decision = _mod.Decision
PolicyDecision = _mod.PolicyDecision
PolicyEngine = _mod.PolicyEngine
RiskLevel = _mod.RiskLevel
make_actor = _mod.make_actor
RUN_BUDGET = _mod.RUN_BUDGET


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

ACME_EMPLOYEE = make_actor("emp-42", run_id="test-run-001")
READ_ONLY_EMPLOYEE = make_actor("emp-77", run_id="test-run-002")

UNKNOWN_ACTOR = ActorContext(
    subject="hacker-99", tenant="acme",
    scopes=frozenset({"expense:read", "expense:submit"}),
    run_id="test-run-003",
)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestToolPolicy(unittest.TestCase):
    """Table-driven policy evaluation tests."""

    def setUp(self):
        self.store = ApprovalStore()
        self.valid_receipt = self.store.issue(
            "emp-42", "acme", "submit_claim", "claim-501", now=NOW, minutes_valid=30,
        )

    def _eval(self, actor, proposal, approval=None, budget=RUN_BUDGET):
        engine = PolicyEngine(budget=budget, approval_store=self.store)
        decision = engine.evaluate(actor, proposal, approval, now=NOW)
        return decision, engine

    # --- Identity & Authorization ---

    def test_permitted_read(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.ALLOW)
        self.assertEqual(d.reason, "all_checks_passed")
        self.assertEqual(eng.execution_count, 1)

    def test_unknown_subject(self):
        d, eng = self._eval(
            UNKNOWN_ACTOR,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "unknown_subject")
        self.assertEqual(eng.execution_count, 0)

    def test_empty_subject_denied(self):
        empty_actor = ActorContext(
            subject="", tenant="acme",
            scopes=frozenset({"expense:read"}),
        )
        d, eng = self._eval(
            empty_actor,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "unknown_subject")
        self.assertEqual(eng.execution_count, 0)

    def test_forged_tenant(self):
        forged_tenant_actor = ActorContext(
            subject="emp-42", tenant="globex",
            scopes=frozenset({"expense:read", "expense:submit"}),
        )
        d, eng = self._eval(
            forged_tenant_actor,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "subject_tenant_mismatch")
        self.assertEqual(eng.execution_count, 0)

    def test_escalated_scope(self):
        escalated_actor = ActorContext(
            subject="emp-77", tenant="acme",
            scopes=frozenset({"expense:read", "expense:submit", "expense:approve"}),
        )
        d, eng = self._eval(
            escalated_actor,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_scope_grant")
        self.assertEqual(eng.execution_count, 0)

    def test_missing_scope(self):
        receipt = self.store.issue("emp-77", "acme", "submit_claim", "claim-501", now=NOW)
        d, eng = self._eval(
            READ_ONLY_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "missing_scope")
        self.assertEqual(eng.execution_count, 0)

    def test_cross_tenant_resource(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-200"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "cross_tenant")
        self.assertEqual(eng.execution_count, 0)

    def test_unknown_resource(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-999"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "unknown_resource")
        self.assertEqual(eng.execution_count, 0)

    def test_unallowlisted_operation(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("delete_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "operation_not_allowed")
        self.assertEqual(eng.execution_count, 0)

    # --- Arguments ---

    def test_missing_amount(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "missing_argument")

    def test_malformed_amount_negative(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": -50.0}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_malformed_amount_zero(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 0}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_malformed_amount_string(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": "one hundred"}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_malformed_amount_bool(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": True}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_malformed_amount_nan(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": float("nan")}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_malformed_amount_inf(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": float("inf")}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_amount_exceeds_limit(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 9999.0}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "amount_exceeded")

    def test_unexpected_argument(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101", {"extra": "data"}),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "unexpected_argument")

    def test_missing_receipt_ids(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("calculate_total", "receipt-101", {}),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "missing_argument")

    def test_empty_receipt_ids(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("calculate_total", "receipt-101", {"receipt_ids": []}),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_receipt_ids_not_list(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("calculate_total", "receipt-101", {"receipt_ids": "receipt-101"}),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_receipt_ids_contains_int(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("calculate_total", "receipt-101", {"receipt_ids": ["receipt-101", 42]}),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_receipt_ids_contains_none(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("calculate_total", "receipt-101", {"receipt_ids": [None]}),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")

    def test_valid_receipt_ids(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("calculate_total", "receipt-101", {"receipt_ids": ["receipt-101", "receipt-102"]}),
        )
        self.assertEqual(d.state, Decision.ALLOW)
        self.assertEqual(d.reason, "all_checks_passed")

    # --- Approval ---

    def test_approval_required_pause(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
        )
        self.assertEqual(d.state, Decision.PAUSE)
        self.assertEqual(d.reason, "approval_required")

    def test_approval_verifier_unavailable(self):
        engine = PolicyEngine(budget=RUN_BUDGET) # No approval store
        fake = ApprovalReceipt(
            receipt_id="fabricated",
            subject="emp-42",
            tenant="acme",
            operation="submit_claim",
            resource_id="claim-501",
            approver="mgr-10",
            expires_at=NOW + timedelta(minutes=30)
        )
        d = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            fake,
            now=NOW
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_verifier_unavailable")
        self.assertEqual(engine.execution_count, 0)

    def test_fabricated_approval(self):
        fabricated = ApprovalReceipt(
            receipt_id="made-up", subject="emp-42", tenant="acme",
            operation="submit_claim", resource_id="claim-501",
            approver="mgr-10", expires_at=NOW + timedelta(minutes=30),
        )
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            fabricated,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_unknown")

    def test_forged_approval_wrong_subject(self):
        forged = self.store.issue("emp-77", "acme", "submit_claim", "claim-501", now=NOW)
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            forged,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_subject_mismatch")

    def test_approval_tenant_mismatch(self):
        wrong_tenant = self.store.issue("emp-42", "globex", "submit_claim", "claim-501", now=NOW)
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            wrong_tenant,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_tenant_mismatch")

    def test_approval_operation_mismatch(self):
        wrong_op = self.store.issue("emp-42", "acme", "delete_claim", "claim-501", now=NOW)
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            wrong_op,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_operation_mismatch")

    def test_expired_approval(self):
        expired = self.store.issue(
            "emp-42", "acme", "submit_claim", "claim-501",
            now=NOW, minutes_valid=-10,
        )
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            expired,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_expired")

    def test_approval_wrong_resource(self):
        wrong_res = self.store.issue(
            "emp-42", "acme", "submit_claim", "claim-999", now=NOW,
        )
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            wrong_res,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_resource_mismatch")

    def test_valid_approved_write(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 250.0}),
            self.valid_receipt,
        )
        self.assertEqual(d.state, Decision.ALLOW)
        self.assertEqual(d.reason, "all_checks_passed")
        self.assertEqual(eng.execution_count, 1)

    def test_approval_replay(self):
        receipt = self.store.issue("emp-42", "acme", "submit_claim", "claim-501", now=NOW)
        
        # First use
        d1, eng1 = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            receipt,
        )
        self.assertEqual(d1.state, Decision.ALLOW)
        self.assertEqual(eng1.execution_count, 1)

        # Second use (replay)
        d2, eng2 = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            receipt,
        )
        self.assertEqual(d2.state, Decision.DENY)
        self.assertEqual(d2.reason, "approval_replayed")
        self.assertEqual(eng2.execution_count, 0)

    def test_unrelated_low_risk_action_does_not_consume_approval(self):
        receipt = self.store.issue("emp-42", "acme", "submit_claim", "claim-501", now=NOW)
        engine = PolicyEngine(budget=RUN_BUDGET, approval_store=self.store)
        
        # Unrelated read request passes with the receipt, but shouldn't consume it
        d1 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
            receipt,
            now=NOW
        )
        self.assertEqual(d1.state, Decision.ALLOW)
        
        # Now submit claim should succeed because the receipt wasn't consumed
        d2 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            receipt,
            now=NOW
        )
        self.assertEqual(d2.state, Decision.ALLOW)
        
        # Replay should now fail
        d3 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            receipt,
            now=NOW
        )
        self.assertEqual(d3.state, Decision.DENY)
        self.assertEqual(d3.reason, "approval_replayed")

    # --- Budget ---

    def test_budget_exhaustion(self):
        engine = PolicyEngine(budget=1, approval_store=self.store)
        d1 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
            now=NOW,
        )
        self.assertEqual(d1.state, Decision.ALLOW)
        d2 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-102"),
            now=NOW,
        )
        self.assertEqual(d2.state, Decision.DENY)
        self.assertEqual(d2.reason, "budget_exhausted")
        self.assertEqual(engine.execution_count, 1)

    def test_denied_does_not_consume_budget(self):
        engine = PolicyEngine(budget=1, approval_store=self.store)
        d1 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": -100}), # invalid argument
            self.valid_receipt,
            now=NOW,
        )
        self.assertEqual(d1.state, Decision.DENY)
        self.assertEqual(engine.budget_remaining, 1)

    def test_paused_does_not_consume_budget(self):
        engine = PolicyEngine(budget=5, approval_store=self.store)
        d1 = engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100}), # needs approval
            now=NOW,
        )
        self.assertEqual(d1.state, Decision.PAUSE)
        self.assertEqual(engine.budget_remaining, 5)

    # --- Audit log invariants ---

    def test_audit_log_one_event_per_decision(self):
        engine = PolicyEngine()
        engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
            now=NOW,
        )
        engine.evaluate(
            UNKNOWN_ACTOR,
            ActionProposal("read_receipt", "receipt-101"),
            now=NOW,
        )
        self.assertEqual(len(engine.audit_log), 2)

    def test_audit_log_no_execution_on_deny_or_pause(self):
        engine = PolicyEngine(approval_store=self.store)
        engine.evaluate(
            UNKNOWN_ACTOR,
            ActionProposal("read_receipt", "receipt-101"),
            now=NOW,
        )
        engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            now=NOW,
        )
        for event in engine.audit_log:
            self.assertNotEqual(event.terminal_state, "executed",
                                f"Denied/paused event was marked as executed: {event}")
            self.assertEqual(event.terminal_state, "blocked")

    def test_audit_log_fields_populated(self):
        engine = PolicyEngine(approval_store=self.store)
        
        # 1. ALLOW (low risk, no approval)
        engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
            now=NOW,
        )
        
        # 2. DENY (cross-tenant)
        engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-200"),
            now=NOW,
        )
        
        # 3. PAUSE (missing approval)
        engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            now=NOW,
        )

        events = engine.audit_log
        self.assertEqual(len(events), 3)

        e_allow = events[0]
        self.assertEqual(e_allow.correlation_id, "test-run-001")
        self.assertEqual(e_allow.subject, "emp-42")
        self.assertEqual(e_allow.tenant, "acme")
        self.assertEqual(e_allow.operation, "read_receipt")
        self.assertEqual(e_allow.resource_id, "receipt-101")
        self.assertEqual(e_allow.policy_state, "allow")
        self.assertEqual(e_allow.terminal_state, "executed")
        self.assertIsNone(e_allow.approval_receipt_id)

        e_deny = events[1]
        self.assertEqual(e_deny.policy_state, "deny")
        self.assertEqual(e_deny.reason, "cross_tenant")
        self.assertEqual(e_deny.terminal_state, "blocked")

        e_pause = events[2]
        self.assertEqual(e_pause.policy_state, "pause")
        self.assertEqual(e_pause.reason, "approval_required")
        self.assertEqual(e_pause.terminal_state, "blocked")

    # --- Control Ordering Invariant ---

    def test_first_failed_control_ordering(self):
        # 1. unknown actor + malformed arguments -> unknown_subject
        d1, _ = self._eval(
            UNKNOWN_ACTOR,
            ActionProposal("submit_claim", "claim-501", {"amount": -100}),
        )
        self.assertEqual(d1.reason, "unknown_subject")

        # 2. missing scope + cross-tenant resource -> missing_scope
        d2, _ = self._eval(
            READ_ONLY_EMPLOYEE,
            ActionProposal("submit_claim", "receipt-200", {"amount": 100.0}),
        )
        self.assertEqual(d2.reason, "missing_scope")

        # 3. cross-tenant resource + malformed amount -> cross_tenant
        d3, _ = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "receipt-200", {"amount": -100}),
        )
        self.assertEqual(d3.reason, "cross_tenant")

        # 4. invalid arguments + no approval -> invalid_argument
        d4, _ = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": -100}),
        )
        self.assertEqual(d4.reason, "invalid_argument")

        # 5. valid request + missing approval -> approval_required
        d5, _ = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100}),
        )
        self.assertEqual(d5.reason, "approval_required")


if __name__ == "__main__":
    unittest.main()

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
AuditEvent = _mod.AuditEvent
Decision = _mod.Decision
PolicyDecision = _mod.PolicyDecision
PolicyEngine = _mod.PolicyEngine
RiskLevel = _mod.RiskLevel
KNOWN_SUBJECTS = _mod.KNOWN_SUBJECTS
POLICY_RULES = _mod.POLICY_RULES
RESOURCE_REGISTRY = _mod.RESOURCE_REGISTRY
RUN_BUDGET = _mod.RUN_BUDGET
_make_receipt = _mod._make_receipt


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

ACME_EMPLOYEE = ActorContext(
    subject="emp-42", tenant="acme",
    scopes=frozenset({"expense:read", "expense:submit"}),
    run_id="test-run-001",
)

READ_ONLY_EMPLOYEE = ActorContext(
    subject="emp-77", tenant="acme",
    scopes=frozenset({"expense:read"}),
    run_id="test-run-002",
)

UNKNOWN_ACTOR = ActorContext(
    subject="hacker-99", tenant="acme",
    scopes=frozenset({"expense:read", "expense:submit"}),
    run_id="test-run-003",
)

VALID_RECEIPT = _make_receipt(
    "emp-42", "acme", "submit_claim", "claim-501", now=NOW, minutes_valid=30,
)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestToolPolicy(unittest.TestCase):
    """Table-driven policy evaluation tests."""

    def _eval(self, actor, proposal, approval=None, budget=RUN_BUDGET):
        engine = PolicyEngine(budget=budget)
        decision = engine.evaluate(actor, proposal, approval, now=NOW)
        return decision, engine

    # --- Case 1: Permitted same-tenant read ---
    def test_permitted_read(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.ALLOW)
        self.assertEqual(d.reason, "all_checks_passed")
        self.assertEqual(len(eng._execution_log), 1)

    # --- Case 2: Unknown subject ---
    def test_unknown_subject(self):
        d, eng = self._eval(
            UNKNOWN_ACTOR,
            ActionProposal("read_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "unknown_subject")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 3: Missing scope ---
    def test_missing_scope(self):
        receipt = _make_receipt("emp-77", "acme", "submit_claim", "claim-501", now=NOW)
        d, eng = self._eval(
            READ_ONLY_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            receipt,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "missing_scope")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 4: Cross-tenant resource ---
    def test_cross_tenant_resource(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-200"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "cross_tenant")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 5: Unallowlisted operation ---
    def test_unallowlisted_operation(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("delete_receipt", "receipt-101"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "operation_not_allowed")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 6: Malformed amount ---
    def test_malformed_amount_negative(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": -50.0}),
            VALID_RECEIPT,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")
        self.assertEqual(len(eng._execution_log), 0)

    def test_malformed_amount_string(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": "one hundred"}),
            VALID_RECEIPT,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "invalid_argument")
        self.assertEqual(len(eng._execution_log), 0)

    def test_missing_amount(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {}),
            VALID_RECEIPT,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "missing_argument")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 7: Amount exceeds limit ---
    def test_amount_exceeds_limit(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 9999.0}),
            VALID_RECEIPT,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "amount_exceeded")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 8: High-risk write without approval → pause ---
    def test_approval_required_pause(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
        )
        self.assertEqual(d.state, Decision.PAUSE)
        self.assertEqual(d.reason, "approval_required")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 9: Forged approval (wrong subject) ---
    def test_forged_approval_wrong_subject(self):
        forged = _make_receipt(
            "emp-77", "acme", "submit_claim", "claim-501", now=NOW,
        )
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            forged,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_subject_mismatch")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 10: Expired approval ---
    def test_expired_approval(self):
        expired = _make_receipt(
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
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 11: Approval bound to wrong resource ---
    def test_approval_wrong_resource(self):
        wrong_res = _make_receipt(
            "emp-42", "acme", "submit_claim", "claim-999", now=NOW,
        )
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 100.0}),
            wrong_res,
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "approval_resource_mismatch")
        self.assertEqual(len(eng._execution_log), 0)

    # --- Case 12: Valid approved write ---
    def test_valid_approved_write(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("submit_claim", "claim-501", {"amount": 250.0}),
            VALID_RECEIPT,
        )
        self.assertEqual(d.state, Decision.ALLOW)
        self.assertEqual(d.reason, "all_checks_passed")
        self.assertEqual(len(eng._execution_log), 1)

    # --- Case 13: Budget exhaustion ---
    def test_budget_exhaustion(self):
        engine = PolicyEngine(budget=1)
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
        self.assertEqual(len(engine._execution_log), 1)

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
        engine = PolicyEngine()
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
        engine = PolicyEngine()
        engine.evaluate(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-101"),
            now=NOW,
        )
        event = engine.audit_log[0]
        self.assertEqual(event.correlation_id, "test-run-001")
        self.assertEqual(event.subject, "emp-42")
        self.assertEqual(event.tenant, "acme")
        self.assertEqual(event.operation, "read_receipt")
        self.assertEqual(event.resource_id, "receipt-101")
        self.assertEqual(event.policy_state, "allow")
        self.assertEqual(event.terminal_state, "executed")

    # --- Empty subject ---
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
        self.assertEqual(len(eng._execution_log), 0)

    # --- Unknown resource ---
    def test_unknown_resource(self):
        d, eng = self._eval(
            ACME_EMPLOYEE,
            ActionProposal("read_receipt", "receipt-999"),
        )
        self.assertEqual(d.state, Decision.DENY)
        self.assertEqual(d.reason, "unknown_resource")
        self.assertEqual(len(eng._execution_log), 0)


if __name__ == "__main__":
    unittest.main()

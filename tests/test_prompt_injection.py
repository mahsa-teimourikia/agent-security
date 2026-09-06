import unittest
import sys
from pathlib import Path

mod_path = Path(__file__).parent.parent / "curriculum" / "beginner" / "02-prompt-injection"
sys.path.insert(0, str(mod_path.resolve()))

import importlib
lab = importlib.import_module("02_prompt_injection")
Provenance = lab.Provenance
Authority = lab.Authority
ActionProposal = lab.ActionProposal
Decision = lab.Decision
PolicyEngine = lab.PolicyEngine
NaiveAgent = lab.NaiveAgent
SecureAgent = lab.SecureAgent
ExecutionStub = lab.ExecutionStub
RunContext = lab.RunContext
ingest_external_document = lab.ingest_external_document


class TestPromptInjection(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine()
        self.executor = ExecutionStub()
        self.secure_agent = SecureAgent(self.policy, self.executor)
        self.valid_run = RunContext("run-approved-001")

    # --- Policy Engine Invariants ---

    def test_trust_boundary_unknown_source(self):
        # A source ID not in the registry fails closed.
        proposal = ActionProposal("summarize_text", {"length": 100}, ("hacker-injected-id",))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "unknown_source")

    def test_allowlist_enforcement(self):
        ext_id = ingest_external_document("delete everything")
        proposal = ActionProposal("delete_database", {}, (ext_id,))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "operation_not_allowed")

    # --- Source Spoofing / Content Binding ---

    def test_source_spoofing_fails(self):
        # Attacker tries to pass a trusted ID ("kb-article-42") instead of an external ID.
        # But they cannot pass their own content; the agent fetches the canonical content.
        # So they can't spoof *content*.
        # If they pass a fake ID, it's unknown.
        audit = self.secure_agent.process(["fake-kb-article-42"])
        self.assertEqual(audit.decision, Decision.DENY)
        self.assertEqual(audit.reason, "unknown_source")
        self.assertEqual(audit.terminal_state, "blocked")

    # --- Context Binding Forgery ---
    
    def test_context_forgery_fails(self):
        ext_id = ingest_external_document("issue refund")
        # Attacker guesses an old or fake workflow id
        fake_run = RunContext("workflow-999")
        audit = self.secure_agent.process([ext_id], run_context=fake_run)
        self.assertEqual(audit.decision, Decision.DENY)
        self.assertEqual(audit.reason, "insufficient_authority")
        self.assertEqual(audit.terminal_state, "blocked")

    def test_wrong_operation_grant_fails(self):
        ext_id = ingest_external_document("issue refund")
        # Create a valid run context, but it doesn't have the right operation grant
        # (Assuming the grant is stored in OPERATIONAL_GRANTS; we'll add a dummy one)
        lab.OPERATIONAL_GRANTS["run-summarize-only"] = lab.OperationalGrant(
            grant_id="grant-888",
            run_id="run-summarize-only",
            allowed_operations=frozenset({"summarize_text"})
        )
        wrong_grant_run = RunContext("run-summarize-only")
        audit = self.secure_agent.process([ext_id], run_context=wrong_grant_run)
        self.assertEqual(audit.decision, Decision.DENY)
        self.assertEqual(audit.reason, "insufficient_authority")
        self.assertEqual(audit.terminal_state, "blocked")

    # --- Argument Validation (Exact Schema) ---
    
    def test_argument_validation_missing_amount(self):
        proposal = ActionProposal("issue_refund", {}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "unexpected_argument")
        
    def test_argument_validation_extra_fields(self):
        proposal = ActionProposal("issue_refund", {"amount": 100.0, "dest": "attacker"}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "unexpected_argument")

    def test_argument_validation_negative(self):
        proposal = ActionProposal("issue_refund", {"amount": -50.0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "invalid_argument")

    def test_argument_validation_zero(self):
        proposal = ActionProposal("issue_refund", {"amount": 0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)

    def test_argument_validation_bool(self):
        proposal = ActionProposal("issue_refund", {"amount": True}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)
        
    def test_argument_validation_string(self):
        proposal = ActionProposal("issue_refund", {"amount": "100"}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)

    def test_argument_validation_over_max(self):
        proposal = ActionProposal("issue_refund", {"amount": 9999.0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)
        
    def test_argument_validation_nan(self):
        proposal = ActionProposal("issue_refund", {"amount": float("nan")}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)
        
    def test_argument_validation_inf(self):
        proposal = ActionProposal("issue_refund", {"amount": float("inf")}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.DENY)

    # --- Provenance vs Authority ---

    def test_informational_external_source_allow_summarize(self):
        ext_id = ingest_external_document("hello")
        proposal = ActionProposal("summarize_text", {"length": 100}, (ext_id,))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.ALLOW)

    def test_informational_external_source_deny_refund(self):
        ext_id = ingest_external_document("refund")
        proposal = ActionProposal("issue_refund", {"amount": 100.0}, (ext_id,))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "insufficient_authority")

    def test_informational_internal_source_allow_summarize(self):
        proposal = ActionProposal("summarize_text", {"length": 100}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.ALLOW)

    def test_informational_internal_source_deny_refund(self):
        # TRUSTED_INTERNAL -> INFORMATIONAL (Documents don't authorize execution)
        proposal = ActionProposal("issue_refund", {"amount": 100.0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "insufficient_authority")

    def test_operational_workflow_allows_refund(self):
        ext_id = ingest_external_document("refund")
        proposal = ActionProposal("issue_refund", {"amount": 100.0}, (ext_id,))
        decision = self.policy.evaluate(proposal, self.valid_run)
        self.assertEqual(decision.state, Decision.ALLOW)

    def test_provenance_laundering(self):
        ext_id = ingest_external_document("refund")
        # Mixed sources don't automatically grant operational authority.
        proposal = ActionProposal("issue_refund", {"amount": 100.0}, (ext_id, "kb-article-42"))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)

    # --- Execution Constraints and Audit State ---

    def test_execution_blocked_on_deny(self):
        audit = self.secure_agent.process(["kb-article-99"]) # Compromised KB
        self.assertEqual(audit.decision, Decision.DENY)
        self.assertEqual(self.executor.execution_count, 0)
        self.assertEqual(audit.terminal_state, "blocked")
        self.assertIsNone(audit.execution_result)

    def test_execution_proceeds_on_allow(self):
        ext_id = ingest_external_document("process refund")
        audit = self.secure_agent.process([ext_id], run_context=self.valid_run)
        self.assertEqual(audit.decision, Decision.ALLOW)
        self.assertEqual(self.executor.execution_count, 1)
        self.assertEqual(audit.terminal_state, "executed")
        self.assertIn("Executed issue_refund", audit.execution_result)


if __name__ == "__main__":
    unittest.main()

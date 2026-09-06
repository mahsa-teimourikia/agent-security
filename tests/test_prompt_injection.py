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
OperationalGrant = lab.OperationalGrant
TrustedApplicationRun = lab.TrustedApplicationRun
ingest_external_document = lab.ingest_external_document


class TestPromptInjection(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine()
        self.executor = ExecutionStub()
        self.secure_agent = SecureAgent(self.policy, self.executor)
        self.valid_grant = lab.OPERATIONAL_GRANTS["run-approved-001"]

    # --- Policy Engine Invariants ---

    def test_trust_boundary_unknown_source(self):
        # A source ID not in the registry fails closed.
        proposal = ActionProposal("summarize_text", {"length": 100}, ("hacker-injected-id",))
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "unknown_source")

    def test_trust_boundary_missing_source(self):
        # A proposal without source_ids must fail closed.
        proposal = ActionProposal("summarize_text", {"length": 10}, ())
        decision = self.policy.evaluate(proposal)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "missing_source")

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
        
        # The true test of context forgery: the attacker KNOWS the correct run identifier
        known_run_id = "run-approved-001"
        
        # However, the untrusted API process() doesn't accept authorization metadata.
        # The attacker can only pass it as a source ID (where it will fail to lookup)
        # or it is ignored.
        audit = self.secure_agent.process([ext_id, known_run_id])
        
        # Because "run-approved-001" is not a valid document ID, the source resolution fails.
        self.assertEqual(audit.decision, Decision.DENY)
        self.assertEqual(audit.reason, "unknown_source")
        self.assertEqual(audit.terminal_state, "blocked")
        
        # If they ONLY pass valid source IDs, they never get operational authority 
        # because the agent wasn't given the grant by the trusted application.
        audit2 = self.secure_agent.process([ext_id])
        self.assertEqual(audit2.decision, Decision.DENY)
        self.assertEqual(audit2.reason, "insufficient_authority")
        self.assertEqual(audit2.terminal_state, "blocked")

    def test_wrong_operation_grant_fails(self):
        ext_id = ingest_external_document("issue refund")
        
        wrong_grant = lab.OPERATIONAL_GRANTS["run-summarize-only"]
        wrong_agent = SecureAgent(self.policy, self.executor, trusted_grant=wrong_grant)
        
        audit = wrong_agent.process([ext_id])
        self.assertEqual(audit.decision, Decision.DENY)
        self.assertEqual(audit.reason, "insufficient_authority")
        self.assertEqual(audit.terminal_state, "blocked")

    # --- Argument Validation (Exact Schema) ---
    
    def test_argument_validation_missing_amount(self):
        proposal = ActionProposal("issue_refund", {}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "unexpected_argument")
        
    def test_argument_validation_extra_fields(self):
        proposal = ActionProposal("issue_refund", {"amount": 100.0, "dest": "attacker"}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "unexpected_argument")

    def test_argument_validation_negative(self):
        proposal = ActionProposal("issue_refund", {"amount": -50.0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)
        self.assertEqual(decision.reason, "invalid_argument")

    def test_argument_validation_zero(self):
        proposal = ActionProposal("issue_refund", {"amount": 0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)

    def test_argument_validation_bool(self):
        proposal = ActionProposal("issue_refund", {"amount": True}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)
        
    def test_argument_validation_string(self):
        proposal = ActionProposal("issue_refund", {"amount": "100"}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)

    def test_argument_validation_over_max(self):
        proposal = ActionProposal("issue_refund", {"amount": 1500.0}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)
        
    def test_argument_validation_nan(self):
        proposal = ActionProposal("issue_refund", {"amount": float("nan")}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        self.assertEqual(decision.state, Decision.DENY)
        
    def test_argument_validation_inf(self):
        proposal = ActionProposal("issue_refund", {"amount": float("inf")}, ("kb-article-42",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
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
        
    def test_trusted_compromised_kb_with_grant_is_allow(self):
        # A compromised trusted KB with legitimate operational grant
        proposal = ActionProposal("issue_refund", {"amount": 100.0}, ("kb-article-99",))
        decision = self.policy.evaluate(proposal, self.valid_grant)
        # Because we supplied the valid_grant, the operation is permitted!
        self.assertEqual(decision.state, Decision.ALLOW)

    def test_operational_workflow_allows_refund(self):
        ext_id = ingest_external_document("refund")
        trusted_app = TrustedApplicationRun("run-approved-001", self.policy, self.executor)
        audit = trusted_app.handle_request([ext_id])
        self.assertEqual(audit.decision, Decision.ALLOW)

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
        trusted_app = TrustedApplicationRun("run-approved-001", self.policy, self.executor)
        audit = trusted_app.handle_request([ext_id])
        self.assertEqual(audit.decision, Decision.ALLOW)
        self.assertEqual(self.executor.execution_count, 1)
        self.assertEqual(audit.terminal_state, "executed")
        self.assertIn("Executed issue_refund", audit.execution_result)


if __name__ == "__main__":
    unittest.main()

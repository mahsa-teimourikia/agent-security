import unittest
import sys
from pathlib import Path

mod_path = Path(__file__).parent.parent / "curriculum" / "beginner" / "03-secure-research-agent"
sys.path.insert(0, str(mod_path.resolve()))

import importlib
lab = importlib.import_module("03_secure_research_agent")

class TestSecureResearchAgent(unittest.TestCase):
    def setUp(self):
        self.app = lab.ResearchApplication()
        # Keep internal component instances for low-level diagnostic tests
        self.employee_ctx_internal = lab.ResearchContextResolver.resolve("alice")
        self.agent_internal = lab.SecureResearchAgent(self.employee_ctx_internal)

    def test_application_boundary_prevents_escalation(self):
        # Alice tries to assert CONFIDENTIAL access
        # Since the API only takes the subject string, there is literally no parameter to pass claimed sensitivities.
        resp = self.app.answer("alice", "Project Phoenix budget")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")
        self.assertNotIn("doc-conf-01", audit.authorized_document_ids)
        self.assertEqual(resp.correlation_id, audit.correlation_id)

    def test_unknown_subject_fails_closed(self):
        resp = self.app.answer("unknown_eve", "ticket retention policy")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertEqual(audit.reason, "unknown_subject")
        self.assertEqual(resp.correlation_id, audit.correlation_id)

    def test_normal_relevant_retrieval(self):
        resp = self.app.answer("alice", "ticket retention policy")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "answered")
        self.assertIn("doc-int-01", resp.citations)
        self.assertIn("doc-int-01", audit.authorized_document_ids)
        self.assertEqual(resp.correlation_id, audit.correlation_id)

    def test_empty_query(self):
        resp = self.app.answer("alice", "   ")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "no_authorized_evidence")

    def test_oversized_query_rejected_and_redacted(self):
        long_query = "a" * 600
        resp = self.app.answer("alice", long_query)
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertEqual(audit.reason, "query_too_long")
        # Ensure the query is bounded in the audit log
        self.assertLessEqual(len(audit.query_preview), 53) # 50 chars + "..."
        
    def test_irrelevant_query(self):
        resp = self.app.answer("alice", "what color is the sky")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")

    def test_confidential_denied_to_normal_employee(self):
        resp = self.app.answer("alice", "Project Phoenix budget")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "no_authorized_evidence")
        
        # User response contains no confidential metadata
        self.assertNotIn("doc-conf-01", resp.citations)
        self.assertNotIn("Phoenix", str(resp.answer))
        
        # Audit log may retain the fact it was blocked
        self.assertIn("doc-conf-01", audit.blocked_document_ids)
        self.assertNotIn("doc-conf-01", audit.authorized_document_ids)
        
    def test_internal_component_data_minimization(self):
        # Explicit low-level component test to prove doc-conf-01 never hits the model
        resp, audit = self.agent_internal.answer_query("Project Phoenix budget")
        self.assertNotIn("doc-conf-01", self.agent_internal.model.last_evidence_received)

    def test_confidential_allowed_to_privileged_actor(self):
        resp = self.app.answer("bob", "Project Phoenix budget")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "answered")
        self.assertIn("doc-conf-01", audit.authorized_document_ids)
        self.assertIn("$4.2M", resp.answer)

    def test_obvious_poisoned_document(self):
        resp = self.app.answer("alice", "user profile")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertTrue(audit.suspicious_content_detected)
        self.assertIn("unauthorized_capability", audit.reason)

    def test_detector_bypass_poisoned_document(self):
        resp = self.app.answer("alice", "feature request")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        # Bypass detection heuristics
        self.assertFalse(audit.suspicious_content_detected)
        self.assertIn("unauthorized_capability", audit.reason)

    def test_trusted_poisoned_document(self):
        resp = self.app.answer("alice", "legacy operations")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertIn("unauthorized_capability", audit.reason)

    def test_action_denied(self):
        resp = self.app.answer("alice", "execute command")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertIn("unauthorized_capability", audit.reason)

    def test_zero_citation_rejected(self):
        resp = self.app.answer("alice", "zero citation for retention policy")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "missing_citation")

    def test_unknown_citation_rejected(self):
        resp = self.app.answer("alice", "make up citation for retention policy")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertIn("invalid_citation", audit.reason)

    def test_unretrieved_citation_rejected(self):
        resp = self.app.answer("alice", "cite unretrieved for retention policy")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "blocked")
        self.assertIn("invalid_citation", audit.reason)

    def test_citation_laundering_rejected(self):
        resp = self.app.answer("alice", "launder retention policy")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "unsupported_claim_contradicts_evidence")

    def test_second_unsupported_claim_fixture_rejected(self):
        resp = self.app.answer("alice", "minimum capability password rotation")
        audit = self.app.audit_sink.events[-1]
        self.assertEqual(resp.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "unsupported_claim")

    def test_synthetic_secret_not_in_unauthorized_audit(self):
        resp = self.app.answer("alice", "Project Phoenix budget")
        audit = self.app.audit_sink.events[-1]
        audit_str = str(audit.to_dict())
        self.assertNotIn("$4.2M", audit_str)
        self.assertNotIn("Project Phoenix launch budget is $4.2M", audit_str)

if __name__ == '__main__':
    unittest.main()

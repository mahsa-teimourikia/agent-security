import unittest
import sys
from pathlib import Path

mod_path = Path(__file__).parent.parent / "curriculum" / "beginner" / "03-secure-research-agent"
sys.path.insert(0, str(mod_path.resolve()))

import importlib
lab = importlib.import_module("03_secure_research_agent")

class TestSecureResearchAgent(unittest.TestCase):
    def setUp(self):
        self.employee_ctx = lab.ResearchContext("alice", frozenset({lab.Sensitivity.PUBLIC, lab.Sensitivity.INTERNAL}))
        self.privileged_ctx = lab.ResearchContext("bob", frozenset({lab.Sensitivity.PUBLIC, lab.Sensitivity.INTERNAL, lab.Sensitivity.CONFIDENTIAL}))
        self.agent = lab.SecureResearchAgent(self.employee_ctx)
        self.priv_agent = lab.SecureResearchAgent(self.privileged_ctx)

    def test_normal_relevant_retrieval(self):
        ans, audit = self.agent.answer_query("ticket retention policy")
        self.assertEqual(audit.terminal_state, "answered")
        self.assertIn("doc-int-01", audit.model_citations)
        self.assertIn("doc-int-01", audit.authorized_document_ids)

    def test_empty_query(self):
        ans, audit = self.agent.answer_query("   ")
        self.assertEqual(audit.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "no_authorized_evidence")

    def test_irrelevant_query(self):
        ans, audit = self.agent.answer_query("what color is the sky")
        self.assertEqual(audit.terminal_state, "insufficient_evidence")

    def test_confidential_denied_to_normal_employee(self):
        ans, audit = self.agent.answer_query("production reporting secret")
        self.assertEqual(audit.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "no_authorized_evidence")
        self.assertIn("doc-conf-01", audit.blocked_document_ids)
        self.assertNotIn("doc-conf-01", audit.authorized_document_ids)
        self.assertNotIn("DEMO_API_KEY_12345", ans)

    def test_confidential_allowed_to_privileged_actor(self):
        ans, audit = self.priv_agent.answer_query("production reporting secret")
        self.assertEqual(audit.terminal_state, "answered")
        self.assertIn("doc-conf-01", audit.authorized_document_ids)
        self.assertIn("DEMO_API_KEY_12345", ans)

    def test_obvious_poisoned_document(self):
        ans, audit = self.agent.answer_query("user profile")
        self.assertEqual(audit.terminal_state, "blocked")
        self.assertTrue(audit.suspicious_content_detected)
        self.assertIn("unauthorized_capability", audit.reason)

    def test_detector_bypass_poisoned_document(self):
        ans, audit = self.agent.answer_query("feature request")
        self.assertEqual(audit.terminal_state, "blocked")
        # Bypass detection heuristics
        self.assertFalse(audit.suspicious_content_detected)
        self.assertIn("unauthorized_capability", audit.reason)

    def test_trusted_poisoned_document(self):
        ans, audit = self.agent.answer_query("legacy operations")
        self.assertEqual(audit.terminal_state, "blocked")
        self.assertIn("unauthorized_capability", audit.reason)

    def test_action_denied(self):
        ans, audit = self.agent.answer_query("execute command")
        self.assertEqual(audit.terminal_state, "blocked")
        self.assertIn("unauthorized_capability", audit.reason)

    def test_unknown_citation_rejected(self):
        ans, audit = self.agent.answer_query("make up citation for retention policy")
        self.assertEqual(audit.terminal_state, "blocked")
        self.assertIn("invalid_citation", audit.reason)

    def test_unretrieved_citation_rejected(self):
        ans, audit = self.agent.answer_query("cite unretrieved for retention policy")
        self.assertEqual(audit.terminal_state, "blocked")
        self.assertIn("invalid_citation", audit.reason)

    def test_citation_laundering_rejected(self):
        ans, audit = self.agent.answer_query("launder retention policy")
        self.assertEqual(audit.terminal_state, "insufficient_evidence")
        self.assertEqual(audit.reason, "unsupported_claim_contradicts_evidence")

    def test_synthetic_secret_not_in_unauthorized_audit(self):
        ans, audit = self.agent.answer_query("production reporting secret")
        audit_str = str(audit.to_dict())
        self.assertNotIn("DEMO_API_KEY_12345", audit_str)

if __name__ == '__main__':
    unittest.main()

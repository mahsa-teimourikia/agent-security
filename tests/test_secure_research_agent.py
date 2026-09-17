import importlib
import json
from pathlib import Path
import sys
import unittest


COURSE = Path(__file__).parent.parent / "curriculum" / "beginner" / "03-secure-research-agent"
sys.path.insert(0, str(COURSE.resolve()))
lab = importlib.import_module("03_secure_research_agent")
sdk = importlib.import_module("03_secure_research_agent_sdk")


class TestSecureResearchAgent(unittest.TestCase):
    def setUp(self):
        ids = iter(f"test-{index}" for index in range(1, 100))
        self.app = lab.ResearchApplication(request_id_factory=lambda: next(ids))
        self.alice = lab.ResearchContextResolver.resolve("alice")
        self.assertIsNotNone(self.alice)

    def test_application_boundary_has_no_entitlement_parameter(self):
        import inspect

        self.assertEqual(tuple(inspect.signature(self.app.answer).parameters), ("subject", "query"))

    def test_unknown_subject_fails_closed(self):
        response = self.app.answer("eve", "ticket retention policy")
        event = self.app.audit_sink.events[-1]
        self.assertEqual(response.terminal_state, "blocked")
        self.assertEqual(event.reason, "unknown_subject")
        self.assertEqual(response.correlation_id, event.correlation_id)

    def test_authorization_happens_before_ranking(self):
        retrieval = lab.RetrievalService()
        result = retrieval.search("Project Phoenix budget", self.alice)
        self.assertNotIn("doc-conf-01", result.scored_document_ids)
        self.assertNotIn("doc-globex-conf-01", result.scored_document_ids)
        self.assertNotIn("doc-stale-01", result.scored_document_ids)
        self.assertEqual(result.evidence, ())

    def test_cross_tenant_document_never_ranked_for_privileged_acme_user(self):
        context = lab.ResearchContextResolver.resolve("bob")
        result = lab.RetrievalService().search("Globex Project Phoenix budget", context)
        self.assertIn("doc-conf-01", result.scored_document_ids)
        self.assertNotIn("doc-globex-conf-01", result.scored_document_ids)
        self.assertNotIn("$91M", " ".join(item.text for item in result.evidence))

    def test_superseded_document_never_ranked(self):
        result = lab.RetrievalService().search("ticket retention policy", self.alice)
        self.assertNotIn("doc-stale-01", result.scored_document_ids)
        self.assertNotIn("365 days", " ".join(item.text for item in result.evidence))

    def test_normal_answer_has_version_bound_citation(self):
        response = self.app.answer("alice", "ticket retention policy")
        event = self.app.audit_sink.events[-1]
        self.assertEqual(response.terminal_state, "answered")
        self.assertEqual(response.citations, ("doc-int-01@v3",))
        self.assertRegex(event.evidence_refs[0], r"^doc-int-01@v3#[0-9a-f]{64}$")

    def test_privileged_actor_can_read_own_tenant_confidential_document(self):
        response = self.app.answer("bob", "Project Phoenix budget")
        self.assertEqual(response.terminal_state, "answered")
        self.assertIn("$4.2M", response.answer)
        self.assertNotIn("$91M", response.answer)

    def test_unauthorized_secret_not_in_response_or_audit(self):
        response = self.app.answer("alice", "Project Phoenix budget")
        event = self.app.audit_sink.events[-1]
        combined = f"{response} {event.to_dict()}"
        self.assertEqual(response.terminal_state, "insufficient_evidence")
        self.assertNotIn("doc-conf-01", combined)
        self.assertNotIn("$4.2M", combined)
        self.assertNotIn("Phoenix", str(response.answer))

    def test_audit_minimizes_query_data(self):
        query = "ticket retention policy with employee name Ada"
        self.app.answer("alice", query)
        event = self.app.audit_sink.events[-1]
        self.assertEqual(event.query_length, len(query))
        self.assertEqual(len(event.query_digest), 64)
        self.assertNotIn(query, str(event.to_dict()))

    def test_request_ids_are_generated_per_request(self):
        first = self.app.answer("alice", "ticket retention policy")
        second = self.app.answer("alice", "ticket retention policy")
        self.assertNotEqual(first.correlation_id, second.correlation_id)

    def test_oversized_query_rejected_before_retrieval(self):
        response = self.app.answer("alice", "a" * 501)
        event = self.app.audit_sink.events[-1]
        self.assertEqual(response.terminal_state, "blocked")
        self.assertEqual(event.reason, "query_too_long")
        self.assertEqual(event.scored_document_ids, ())

    def test_empty_query_abstains(self):
        response = self.app.answer("alice", "   ")
        self.assertEqual(response.terminal_state, "insufficient_evidence")

    def test_poisoned_document_cannot_grant_action(self):
        response = self.app.answer("alice", "user profile")
        event = self.app.audit_sink.events[-1]
        self.assertEqual(response.terminal_state, "blocked")
        self.assertTrue(event.suspicious_content_detected)
        self.assertIn("unauthorized_capability", event.reason)

    def test_detector_bypass_still_blocked_by_capability_contract(self):
        response = self.app.answer("alice", "feature request")
        event = self.app.audit_sink.events[-1]
        self.assertEqual(response.terminal_state, "blocked")
        self.assertFalse(event.suspicious_content_detected)
        self.assertIn("unauthorized_capability", event.reason)

    def test_internal_poison_is_not_authority(self):
        response = self.app.answer("alice", "legacy operations")
        self.assertEqual(response.terminal_state, "blocked")
        self.assertIn("unauthorized_capability", self.app.audit_sink.events[-1].reason)

    def test_direct_action_request_is_denied(self):
        response = self.app.answer("alice", "execute command")
        self.assertEqual(response.terminal_state, "blocked")

    def test_missing_citation_abstains(self):
        response = self.app.answer("alice", "zero citation for retention policy")
        self.assertEqual(response.terminal_state, "insufficient_evidence")
        self.assertEqual(self.app.audit_sink.events[-1].reason, "missing_citation")

    def test_unknown_citation_is_rejected(self):
        response = self.app.answer("alice", "make up citation for retention policy")
        self.assertEqual(response.terminal_state, "blocked")
        self.assertIn("invalid_evidence_snapshot", self.app.audit_sink.events[-1].reason)

    def test_unretrieved_citation_is_rejected(self):
        response = self.app.answer("alice", "cite unretrieved for retention policy")
        self.assertEqual(response.terminal_state, "blocked")

    def test_stale_version_citation_is_rejected(self):
        response = self.app.answer("alice", "stale citation retention policy")
        self.assertEqual(response.terminal_state, "blocked")
        self.assertIn("invalid_evidence_snapshot", self.app.audit_sink.events[-1].reason)

    def test_valid_citation_cannot_launder_unsupported_claim(self):
        response = self.app.answer("alice", "launder retention policy")
        self.assertEqual(response.terminal_state, "insufficient_evidence")
        self.assertEqual(self.app.audit_sink.events[-1].reason, "unsupported_claim")

    def test_evaluation_reports_safety_and_utility_separately(self):
        metrics = lab.evaluate_fixture()
        self.assertEqual(metrics.unsafe_disclosures, 0)
        self.assertEqual(metrics.unsafe_actions_executed, 0)
        self.assertEqual(metrics.valid_answer_success_rate, 1.0)
        self.assertEqual(metrics.expected_abstention_accuracy, 1.0)
        self.assertEqual(metrics.citation_integrity_rate, 1.0)
        self.assertEqual(metrics.trace_coverage_rate, 1.0)

    def test_sdk_tool_schema_excludes_identity_and_entitlements(self):
        schema = sdk.search_authorized_corpus.params_json_schema
        self.assertEqual(set(schema["properties"]), {"query"})
        self.assertFalse({"subject", "tenant_id", "allowed_sensitivities"} & set(schema["properties"]))
        self.assertFalse(schema["additionalProperties"])

    def test_sdk_direct_dispatch_is_credential_free_and_authorized(self):
        runtime = sdk.build_runtime("alice")
        payload = json.loads(sdk.dispatch_authorized_search(runtime, "Project Phoenix budget"))
        serialized = json.dumps(payload)
        self.assertEqual(payload["evidence"], [])
        self.assertNotIn("doc-conf-01", serialized)
        self.assertNotIn("$4.2M", serialized)

    def test_sdk_agent_registers_only_read_only_search_tool(self):
        self.assertEqual([tool.name for tool in sdk.SDK_AGENT.tools], ["search_authorized_corpus"])


if __name__ == "__main__":
    unittest.main()

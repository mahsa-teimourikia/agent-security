"""Regression tests for the deterministic foundation security controls."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
import importlib.util

sys.path.insert(0, str(Path(__file__).parents[1] / "curriculum" / "shared"))
from foundation_lab import Action, Approval, ApprovalStore, ContextItem, arguments_hash, build_context
from runtime_security_lab import Delegation, Run, release_gate
sys.path.insert(0, str(Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "06-network-egress-ssrf-and-external-resource-security"))
from lab import FetchPolicy, allowed_url
_mcp_spec = importlib.util.spec_from_file_location("mcp_security_lab", Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "09-mcp-security" / "lab.py")
assert _mcp_spec and _mcp_spec.loader
_mcp_lab = importlib.util.module_from_spec(_mcp_spec)
sys.modules[_mcp_spec.name] = _mcp_lab
_mcp_spec.loader.exec_module(_mcp_lab)
_hitl_spec = importlib.util.spec_from_file_location(
    "hitl_security_lab",
    Path(__file__).parents[1]
    / "curriculum"
    / "roadmap"
    / "intermediate"
    / "10-human-in-the-loop-security"
    / "lab.py",
)
assert _hitl_spec and _hitl_spec.loader
_hitl_lab = importlib.util.module_from_spec(_hitl_spec)
sys.modules[_hitl_spec.name] = _hitl_lab
_hitl_spec.loader.exec_module(_hitl_lab)


NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


def valid_approval(action: Action, **changes: object) -> Approval:
    values = dict(approval_id="a-1", principal=action.principal, tenant=action.tenant,
                  operation=action.operation, resource=action.resource,
                  arguments_hash=arguments_hash(action), policy_version="v1",
                  expires_at=NOW + timedelta(minutes=1))
    values.update(changes)
    return Approval(**values)


class FoundationLabTests(unittest.TestCase):
    def test_context_enforces_authorization_and_tenant_boundary(self) -> None:
        admitted, trace = build_context([
            ContextItem("ok", "evidence", "north", "policy"),
            ContextItem("other", "memory", "south", "secret"),
            ContextItem("denied", "tool", "north", "result", authorized=False),
        ], "north")
        self.assertEqual([item.source_id for item in admitted], ["ok"])
        self.assertEqual([event["decision"] for event in trace], ["admit", "deny", "deny"])

    def test_write_requires_exact_unexpired_unused_approval(self) -> None:
        action = Action("u-1", "north", "issue_refund", "case-1", 100, "a-1")
        self.assertEqual(ApprovalStore({}).authorize(action, now=NOW)["decision"], "deny")
        store = ApprovalStore({"a-1": valid_approval(action)})
        self.assertEqual(store.authorize(action, now=NOW)["decision"], "allow")
        self.assertEqual(store.authorize(action, now=NOW)["decision"], "deny")
        changed = Action("u-1", "north", "issue_refund", "case-1", 101, "a-1")
        self.assertEqual(ApprovalStore({"a-1": valid_approval(action)}).authorize(changed, now=NOW)["decision"], "deny")
        self.assertEqual(ApprovalStore({"a-1": valid_approval(action, expires_at=NOW)}).authorize(action, now=NOW)["decision"], "deny")

    def test_runtime_controls_bound_delegation_egress_resume_and_replay(self) -> None:
        run = Run("r-1", "north", "s1", "p1")
        bad = Delegation("p", "c", "north", frozenset({"read"}), frozenset({"read", "write"}), NOW + timedelta(minutes=1))
        self.assertFalse(run.delegate(bad, now=NOW))
        self.assertFalse(run.egress_allowed("https://127.0.0.1/admin", {"127.0.0.1"}, resolved_ip="127.0.0.1"))
        self.assertTrue(run.commit_once("a-1"))
        self.assertFalse(run.commit_once("a-1"))
        self.assertFalse(run.resume(policy_version="p2", checkpoint_version="s1", authorized=True))
        self.assertFalse(release_gate({"owner"}, 0)["ready"])

    def test_ssrf_policy_checks_scheme_host_and_resolved_address(self) -> None:
        policy = FetchPolicy(frozenset({"api.example.test"}))
        self.assertFalse(allowed_url("http://api.example.test/x", policy, resolved_ip="8.8.8.8")["allow"])
        self.assertFalse(allowed_url("https://api.example.test/x", policy, resolved_ip="169.254.169.254")["allow"])
        self.assertFalse(allowed_url("https://api.example.test/x", policy, resolved_ip="not-an-ip")["allow"])
        self.assertTrue(allowed_url("https://api.example.test/x", policy, resolved_ip="8.8.8.8")["allow"])

    def test_mcp_gateway_rejects_discovery_audience_and_schema_bypasses(self) -> None:
        boundary, principal, token, document, registration = _mcp_lab.build_scenario()
        lease = _mcp_lab.admit_default_catalog(boundary, principal, document, registration)
        proposal = _mcp_lab.ToolProposal(
            "foundation-mcp", registration.server_id, "lookup_case",
            {"case_id": "case-n-100"}, lease.catalog_digest,
        )
        self.assertEqual(
            boundary.dispatch(
                principal, token, lease, proposal, _mcp_lab.safe_read_execution, now=_mcp_lab.NOW
            )["status"],
            "allow",
        )
        self.assertEqual(
            boundary.dispatch(
                principal, token, lease, replace(proposal, server_id="unknown"),
                _mcp_lab.safe_read_execution, now=_mcp_lab.NOW,
            )["status"],
            "deny",
        )
        self.assertEqual(
            boundary.dispatch(
                principal, replace(token, audience="api"), lease,
                replace(proposal, request_id="wrong-audience"),
                _mcp_lab.safe_read_execution, now=_mcp_lab.NOW,
            )["status"],
            "deny",
        )

    def test_human_review_ignores_client_approval_and_executes_once(self) -> None:
        plane, requester, approver, _, proposal = _hitl_lab.build_scenario()
        forged = replace(proposal, client_claimed_approved=True)
        submitted = plane.submit(requester, forged, now=_hitl_lab.NOW)
        reviewed = plane.decide(
            approver,
            submitted.review_id,
            _hitl_lab.ReviewChoice.APPROVE,
            rationale_code="foundation-regression",
            expected_version=submitted.version,
            now=_hitl_lab.NOW,
        )
        completed = plane.execute(
            requester,
            submitted.review_id,
            reviewed.grant_id,
            forged,
            _hitl_lab.safe_provider,
            now=_hitl_lab.NOW,
        )
        replay = plane.execute(
            requester,
            submitted.review_id,
            reviewed.grant_id,
            forged,
            _hitl_lab.safe_provider,
            now=_hitl_lab.NOW,
        )
        self.assertEqual(submitted.reason, "review-required")
        self.assertTrue(completed.effect_applied)
        self.assertFalse(replay.effect_applied)
        self.assertEqual(len(plane.operations), 1)

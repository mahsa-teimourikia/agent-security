"""Regression tests for the deterministic foundation security controls."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
import importlib.util

sys.path.insert(0, str(Path(__file__).parents[1] / "curriculum" / "shared"))
from foundation_lab import Action, Approval, ContextItem, arguments_hash, authorize, build_context
from runtime_security_lab import Delegation, Run, release_gate
sys.path.insert(0, str(Path(__file__).parents[1] / "curriculum" / "intermediate" / "13-network-egress-ssrf-and-external-resource-security"))
from lab import FetchPolicy, allowed_url
_mcp_spec = importlib.util.spec_from_file_location("mcp_security_lab", Path(__file__).parents[1] / "curriculum" / "intermediate" / "16-mcp-security" / "lab.py")
assert _mcp_spec and _mcp_spec.loader
_mcp_lab = importlib.util.module_from_spec(_mcp_spec)
sys.modules[_mcp_spec.name] = _mcp_lab
_mcp_spec.loader.exec_module(_mcp_lab)
Call, dispatch = _mcp_lab.Call, _mcp_lab.dispatch


NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


def valid_approval(action: Action, **changes: object) -> Approval:
    values = dict(approval_id="a-1", principal=action.principal, tenant=action.tenant,
                  operation=action.operation, resource=action.resource,
                  arguments_hash=arguments_hash(action), policy_version="v1",
                  expires_at=NOW + timedelta(minutes=1), used=False)
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
        self.assertEqual(authorize(action, None, now=NOW)["decision"], "pause")
        self.assertEqual(authorize(action, valid_approval(action), now=NOW)["decision"], "allow")
        changed = Action("u-1", "north", "issue_refund", "case-1", 101, "a-1")
        self.assertEqual(authorize(changed, valid_approval(action), now=NOW)["decision"], "deny")
        self.assertEqual(authorize(action, valid_approval(action, expires_at=NOW), now=NOW)["decision"], "deny")
        self.assertEqual(authorize(action, valid_approval(action, used=True), now=NOW)["decision"], "deny")

    def test_runtime_controls_bound_delegation_egress_resume_and_replay(self) -> None:
        run = Run("r-1", "north", "s1", "p1")
        bad = Delegation("p", "c", "north", frozenset({"read"}), frozenset({"read", "write"}), NOW + timedelta(minutes=1))
        self.assertFalse(run.delegate(bad, now=NOW))
        self.assertFalse(run.egress_allowed("https://127.0.0.1/admin", {"127.0.0.1"}))
        self.assertTrue(run.commit_once("a-1"))
        self.assertFalse(run.commit_once("a-1"))
        self.assertFalse(run.resume(policy_version="p2", checkpoint_version="s1", authorized=True))
        self.assertFalse(release_gate({"owner"}, 0)["ready"])

    def test_ssrf_policy_checks_scheme_host_and_resolved_address(self) -> None:
        policy = FetchPolicy(frozenset({"api.example.test"}))
        self.assertFalse(allowed_url("http://api.example.test/x", policy)["allow"])
        self.assertFalse(allowed_url("https://api.example.test/x", policy, resolved_ip="169.254.169.254")["allow"])
        self.assertTrue(allowed_url("https://api.example.test/x", policy, resolved_ip="8.8.8.8")["allow"])

    def test_mcp_gateway_rejects_discovery_audience_and_schema_bypasses(self) -> None:
        safe = Call("agent-gateway", "mcp-research-v1", "search_policy", "north", frozenset({"search_policy"}), {"query": "x"}, "mcp-gateway")
        self.assertEqual(dispatch(safe)["decision"], "allow")
        self.assertEqual(dispatch(Call(**{**safe.__dict__, "server": "unknown"}))["decision"], "deny")
        self.assertEqual(dispatch(Call(**{**safe.__dict__, "token_audience": "api"}))["decision"], "deny")

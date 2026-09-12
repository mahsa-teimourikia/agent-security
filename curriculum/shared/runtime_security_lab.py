"""Offline security lab for stateful, delegated, and operational agent controls."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from urllib.parse import urlparse


PRIVATE_HOSTS = {"localhost", "metadata.google.internal"}


@dataclass(frozen=True)
class Delegation:
    parent: str
    child: str
    tenant: str
    parent_scopes: frozenset[str]
    child_scopes: frozenset[str]
    expires_at: datetime


@dataclass
class Run:
    run_id: str
    tenant: str
    checkpoint_version: str
    policy_version: str
    status: str = "active"
    revoked: set[str] = field(default_factory=set)
    committed: set[str] = field(default_factory=set)
    trace: list[dict] = field(default_factory=list)

    def event(self, kind: str, **fields: object) -> None:
        self.trace.append({"run_id": self.run_id, "tenant": self.tenant, "event": kind, **fields})

    def delegate(self, envelope: Delegation, *, now: datetime) -> bool:
        allowed = envelope.tenant == self.tenant and envelope.child_scopes <= envelope.parent_scopes and envelope.expires_at > now
        self.event("delegation", child=envelope.child, allowed=allowed, scopes=sorted(envelope.child_scopes))
        return allowed

    def egress_allowed(self, url: str, allow_hosts: set[str]) -> bool:
        host = (urlparse(url).hostname or "").lower()
        try:
            private_ip = ip_address(host).is_private or ip_address(host).is_loopback
        except ValueError:
            private_ip = host in PRIVATE_HOSTS
        allowed = urlparse(url).scheme == "https" and host in allow_hosts and not private_ip
        self.event("egress", destination=host, allowed=allowed)
        return allowed

    def revoke(self, capability: str) -> None:
        self.revoked.add(capability)
        self.status = "read_only" if capability == "writes" else self.status
        self.event("revoked", capability=capability, status=self.status)

    def resume(self, *, policy_version: str, checkpoint_version: str, authorized: bool) -> bool:
        allowed = self.status != "stopped" and authorized and self.policy_version == policy_version and self.checkpoint_version == checkpoint_version
        self.status = "active" if allowed else "paused"
        self.event("resume", allowed=allowed, policy_version=policy_version, checkpoint_version=checkpoint_version)
        return allowed

    def commit_once(self, action_id: str, capability: str = "writes") -> bool:
        allowed = self.status == "active" and capability not in self.revoked and action_id not in self.committed
        if allowed:
            self.committed.add(action_id)
        self.event("action", action_id=action_id, capability=capability, allowed=allowed)
        return allowed


def release_gate(evidence: set[str], severe_failures: int) -> dict:
    required = {"threat_model", "attack_suite", "trace_coverage", "rollback_drill", "owner"}
    missing = sorted(required - evidence)
    return {"ready": not missing and severe_failures == 0, "missing": missing, "severe_failures": severe_failures}


def demo() -> Run:
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    run = Run("run-1", "north", "state-v1", "policy-v1")
    envelope = Delegation("orchestrator", "researcher", "north", frozenset({"search", "read"}), frozenset({"read"}), now + timedelta(minutes=5))
    assert run.delegate(envelope, now=now)
    assert not run.egress_allowed("http://localhost/admin", {"api.example.test"})
    assert run.egress_allowed("https://api.example.test/policy", {"api.example.test"})
    assert run.commit_once("close-9")
    assert not run.commit_once("close-9")
    run.revoke("writes")
    assert not run.commit_once("close-10")
    assert not run.resume(policy_version="policy-v2", checkpoint_version="state-v1", authorized=True)
    assert release_gate({"threat_model", "attack_suite", "trace_coverage", "rollback_drill", "owner"}, 0)["ready"]
    return run


if __name__ == "__main__":
    for event in demo().trace:
        print(event)

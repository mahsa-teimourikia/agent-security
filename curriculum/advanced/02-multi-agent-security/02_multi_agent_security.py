"""Attenuated multi-agent delegation with budgets and typed artifacts."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256


@dataclass(frozen=True)
class ParentAuthority:
    subject: str
    tenant: str
    scopes: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class DelegationEnvelope:
    envelope_id: str
    parent: str
    child: str
    tenant: str
    scopes: frozenset[str]
    budget: int
    expires_at: datetime
    artifact_types: frozenset[str]


@dataclass(frozen=True)
class Artifact:
    artifact_type: str
    content: str
    producer: str
    envelope_id: str


def issue_delegation(
    authority: ParentAuthority,
    *,
    child: str,
    tenant: str,
    requested_scopes: frozenset[str],
    budget: int,
    expires_at: datetime,
    now: datetime,
    artifact_types: frozenset[str],
) -> DelegationEnvelope | None:
    valid = (
        authority.authenticated
        and tenant == authority.tenant
        and requested_scopes <= authority.scopes
        and 0 < budget <= 10
        and now < expires_at <= now + timedelta(hours=1)
        and bool(artifact_types)
    )
    if not valid:
        return None
    material = f"{authority.subject}|{child}|{tenant}|{sorted(requested_scopes)}|{budget}|{expires_at.isoformat()}"
    return DelegationEnvelope(
        sha256(material.encode()).hexdigest()[:16],
        authority.subject,
        child,
        tenant,
        requested_scopes,
        budget,
        expires_at,
        artifact_types,
    )


@dataclass
class WorkerSession:
    envelope: DelegationEnvelope
    consumed: int = 0
    terminated: bool = False
    receipts: list[dict[str, object]] = field(default_factory=list)

    def execute(
        self,
        *,
        worker: str,
        tenant: str,
        operation: str,
        artifact_type: str,
        content: str,
        now: datetime,
    ) -> Artifact | None:
        reason = "authorized"
        if self.terminated:
            reason = "terminated"
        elif worker != self.envelope.child or tenant != self.envelope.tenant:
            reason = "identity-or-tenant"
        elif now >= self.envelope.expires_at:
            reason = "expired"
        elif operation not in self.envelope.scopes:
            reason = "scope"
        elif self.consumed >= self.envelope.budget:
            reason = "budget"
        elif artifact_type not in self.envelope.artifact_types:
            reason = "artifact-contract"

        allowed = reason == "authorized"
        self.receipts.append({
            "envelope_id": self.envelope.envelope_id,
            "worker": worker,
            "tenant": tenant,
            "operation": operation,
            "artifact_type": artifact_type,
            "allowed": allowed,
            "reason": reason,
            "observed_at": now.isoformat(),
        })
        if not allowed:
            return None
        self.consumed += 1
        return Artifact(artifact_type, content, worker, self.envelope.envelope_id)

    def terminate(self, *, reason: str) -> None:
        self.terminated = True
        self.receipts.append({"envelope_id": self.envelope.envelope_id, "allowed": False, "reason": f"terminated:{reason}"})


def demo() -> WorkerSession:
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    parent = ParentAuthority("supervisor", "north", frozenset({"search", "read"}))
    envelope = issue_delegation(
        parent,
        child="researcher",
        tenant="north",
        requested_scopes=frozenset({"search"}),
        budget=1,
        expires_at=now + timedelta(minutes=10),
        now=now,
        artifact_types=frozenset({"evidence-list"}),
    )
    assert envelope is not None and envelope.scopes <= parent.scopes
    session = WorkerSession(envelope)
    artifact = session.execute(worker="researcher", tenant="north", operation="search", artifact_type="evidence-list", content="E-1", now=now)
    assert artifact and artifact.producer == "researcher"
    assert session.execute(worker="researcher", tenant="north", operation="search", artifact_type="evidence-list", content="E-2", now=now) is None
    assert issue_delegation(parent, child="writer", tenant="north", requested_scopes=frozenset({"delete"}), budget=1, expires_at=now + timedelta(minutes=5), now=now, artifact_types=frozenset({"summary"})) is None
    return session


if __name__ == "__main__":
    session = demo()
    print(asdict(session.envelope))
    for receipt in session.receipts:
        print(receipt)

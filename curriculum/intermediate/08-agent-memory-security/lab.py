"""Tenant-scoped memory write/read policy with provenance and expiry."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

@dataclass(frozen=True)
class Memory:
    memory_id: str; tenant: str; subject: str; value: str; provenance: str; classification: str; expires_at: datetime

def write(memory: Memory, *, principal_tenant: str, approved_provenance: set[str], now: datetime) -> dict:
    if memory.tenant != principal_tenant: return {"decision":"deny","reason":"tenant"}
    if memory.provenance not in approved_provenance: return {"decision":"deny","reason":"provenance"}
    if memory.classification not in {"internal", "low_sensitivity"}: return {"decision":"deny","reason":"classification"}
    if memory.expires_at <= now: return {"decision":"deny","reason":"expired"}
    return {"decision":"allow","memory_id":memory.memory_id,"tenant":memory.tenant}

def read(memory: Memory, *, tenant: str, subject: str, now: datetime) -> dict:
    allowed = memory.tenant == tenant and memory.subject == subject and memory.expires_at > now
    return {"decision":"allow" if allowed else "deny", "memory_id":memory.memory_id}

if __name__ == "__main__":
    now=datetime(2026,8,11,tzinfo=timezone.utc)
    m=Memory("m1","north","u1","prefers-email","user-confirmed","low_sensitivity",now+timedelta(days=30))
    assert write(m,principal_tenant="north",approved_provenance={"user-confirmed"},now=now)["decision"] == "allow"
    assert read(m,tenant="south",subject="u1",now=now)["decision"] == "deny"
    assert write(Memory(**{**m.__dict__,"provenance":"agent-summary"}),principal_tenant="north",approved_provenance={"user-confirmed"},now=now)["decision"] == "deny"
    print("memory attack cases passed")

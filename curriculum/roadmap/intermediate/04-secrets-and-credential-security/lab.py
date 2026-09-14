"""Credential issuance/validation policy; secrets themselves are never logged."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

@dataclass(frozen=True)
class Credential:
    subject: str; tenant: str; audience: str; scopes: frozenset[str]; expires_at: datetime; secret_ref: str

def issue(subject: str, tenant: str, audience: str, scopes: frozenset[str], *, now: datetime) -> Credential:
    allowed_scopes = {"read_policy", "write_ticket"}
    if not scopes <= allowed_scopes:
        raise ValueError(f"unsupported credential scopes: {sorted(scopes - allowed_scopes)}")
    return Credential(subject, tenant, audience, scopes, now + timedelta(minutes=5), f"vault://agent/{subject}")

def authorize(credential: Credential, *, tenant: str, audience: str, scope: str, now: datetime) -> dict:
    ok = credential.tenant == tenant and credential.audience == audience and scope in credential.scopes and credential.expires_at > now
    return {"decision":"allow" if ok else "deny", "subject":credential.subject, "tenant":tenant, "scope":scope, "secret_ref":credential.secret_ref}

if __name__ == "__main__":
    now=datetime(2026,8,11,tzinfo=timezone.utc); c=issue("support-agent","north","ticket-api",frozenset({"read_policy"}),now=now)
    assert authorize(c,tenant="north",audience="ticket-api",scope="read_policy",now=now)["decision"] == "allow"
    assert authorize(c,tenant="north",audience="other-api",scope="read_policy",now=now)["decision"] == "deny"
    assert authorize(c,tenant="north",audience="ticket-api",scope="write_ticket",now=now)["decision"] == "deny"
    print("credential boundary cases passed")

"""Credential-free fixtures for the Enterprise 06 lab and notebook."""
from dataclasses import asdict, replace
import hmac
import hashlib

import governance as gov


NOW = 1_000
KINDS = frozenset({"threat-model", "security-test", "privacy-review", "incident-drill", "independent-review"})
EVIDENCE_KEY = b"fixture-evidence-key"
APPROVAL_KEY = b"fixture-approval-key"
EXCEPTION_KEY = b"fixture-exception-key"


def record(**changes) -> gov.AgentRecord:
    base = gov.AgentRecord(
        agent_id="support-resolution", tenant="north", revision=7,
        lifecycle=gov.Lifecycle.PILOT, business_owner="support-vp",
        technical_owner="agent-platform", security_owner="product-security",
        purpose="resolve bounded support cases", risk_tier=gov.RiskTier.HIGH,
        environments=("production",), models=("provider/model:2026-10",),
        tools=("ticket.read", "ticket.resolve"), data_classes=("customer-confidential",),
        effects=("ticket.write",), autonomy="bounded-write", policy_version="policy-12",
        control_version="controls-8", review_due_at=1_500,
        kill_switch_owner="security-on-call", change_digest="change-7")
    return replace(base, **changes)


def keyring() -> gov.Keyring:
    return gov.Keyring({"evidence-key-1": EVIDENCE_KEY})


def evidence(item_kind: str, *, item_id: str | None = None, **changes) -> gov.Evidence:
    item = gov.Evidence(
        evidence_id=item_id or f"evidence:{item_kind}:7", agent_id="support-resolution",
        tenant="north", record_revision=7, kind=item_kind, producer_id="ci:north",
        key_id="evidence-key-1", policy_version="policy-12", control_version="controls-8",
        created_at=900, expires_at=1_400, passed=100, checked=100,
        severe_failures=0)
    return keyring().sign(replace(item, **changes))


def store(items=None) -> gov.EvidenceStore:
    result = gov.EvidenceStore(
        [gov.Producer("ci:north", "north", "evidence-key-1", KINDS)], keyring())
    for item in items if items is not None else [evidence(kind) for kind in KINDS]:
        assert result.admit(item, NOW).admitted
    return result


def engine(items=None) -> gov.GovernanceEngine:
    return gov.GovernanceEngine(store(items), {"risk-director": EXCEPTION_KEY}, {"security-director": APPROVAL_KEY})


def sign_fields(value, key: bytes, omitted: str) -> str:
    payload = {name: item for name, item in asdict(value).items() if name != omitted}
    return hmac.new(key, gov.digest(payload).encode(), hashlib.sha256).hexdigest()


def approval(decision: gov.Decision, **changes) -> gov.Approval:
    item = gov.Approval(
        approval_id="approval:authorize:7", agent_id=decision.agent_id, tenant=decision.tenant,
        record_revision=decision.record_revision, target=decision.target,
        approver="security-director", expires_at=1_100,
        decision_digest=decision.decision_digest, proof="")
    item = replace(item, **changes)
    return replace(item, proof=sign_fields(item, APPROVAL_KEY, "proof"))


def exception(blocker: str, **changes) -> gov.ExceptionGrant:
    item = gov.ExceptionGrant(
        exception_id=f"exception:{blocker}:7", agent_id="support-resolution", tenant="north",
        record_revision=7, blocker=blocker, owner="support-vp",
        approved_by="risk-director", expires_at=1_100, proof="")
    item = replace(item, **changes)
    return replace(item, proof=sign_fields(item, EXCEPTION_KEY, "proof"))


def operator(**changes) -> gov.Actor:
    base = gov.Actor("release-operator", "north", frozenset({"governance-operator"}), 1_100)
    return replace(base, **changes)

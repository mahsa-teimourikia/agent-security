"""Typed production-evidence gate for a customer-support agent."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256


REQUIRED_EVIDENCE = frozenset({
    "threat-model",
    "policy-tests",
    "attack-evaluation",
    "trace-coverage",
    "rollback-drill",
    "control-owner",
})


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    version: str
    owner: str
    observed_at: datetime
    passed: bool


@dataclass(frozen=True)
class RiskAcceptance:
    risk_id: str
    owner: str
    rationale: str
    expires_at: datetime


@dataclass(frozen=True)
class ReleaseDecision:
    ready: bool
    blockers: tuple[str, ...]
    evidence_versions: tuple[str, ...]
    decided_at: str
    receipt_id: str


def evaluate_release(
    evidence: list[Evidence],
    *,
    severe_attack_successes: int,
    residual_risks: list[RiskAcceptance],
    now: datetime,
    maximum_age: timedelta = timedelta(days=30),
) -> ReleaseDecision:
    by_kind: dict[str, Evidence] = {}
    duplicates: set[str] = set()
    for item in evidence:
        if item.kind in by_kind:
            duplicates.add(item.kind)
        by_kind[item.kind] = item

    blockers: list[str] = []
    blockers.extend(f"missing:{kind}" for kind in sorted(REQUIRED_EVIDENCE - set(by_kind)))
    blockers.extend(f"duplicate:{kind}" for kind in sorted(duplicates))
    for kind in sorted(REQUIRED_EVIDENCE & set(by_kind)):
        item = by_kind[kind]
        if not item.value.strip() or not item.version.strip() or not item.owner.strip():
            blockers.append(f"invalid:{kind}")
        elif not item.passed:
            blockers.append(f"failed:{kind}")
        elif item.observed_at > now or now - item.observed_at > maximum_age:
            blockers.append(f"stale:{kind}")
    if severe_attack_successes:
        blockers.append(f"severe-attack-successes:{severe_attack_successes}")
    for risk in residual_risks:
        if not all((risk.risk_id.strip(), risk.owner.strip(), risk.rationale.strip())) or risk.expires_at <= now:
            blockers.append(f"invalid-risk-acceptance:{risk.risk_id or 'unnamed'}")

    versions = tuple(sorted(f"{kind}@{item.version}" for kind, item in by_kind.items()))
    material = f"{now.isoformat()}|{sorted(blockers)}|{versions}"
    return ReleaseDecision(not blockers, tuple(blockers), versions, now.isoformat(), sha256(material.encode()).hexdigest()[:16])


def demo() -> tuple[ReleaseDecision, ReleaseDecision]:
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    evidence = [Evidence(kind, f"artifact:{kind}", "release-7", "team:agent-security", now - timedelta(days=1), True) for kind in REQUIRED_EVIDENCE]
    accepted = [RiskAcceptance("R-12", "director:platform", "read-only pilot has bounded residual latency risk", now + timedelta(days=14))]
    passing = evaluate_release(evidence, severe_attack_successes=0, residual_risks=accepted, now=now)
    failing = evaluate_release(evidence, severe_attack_successes=1, residual_risks=accepted, now=now)
    assert passing.ready
    assert not failing.ready and "severe-attack-successes:1" in failing.blockers
    return passing, failing


if __name__ == "__main__":
    for decision in demo():
        print(asdict(decision))

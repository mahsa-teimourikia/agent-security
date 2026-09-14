"""Incident containment, authorized recovery, and exactly-once replay lab."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json


class Phase(str, Enum):
    ACTIVE = "active"
    DETECTED = "detected"
    CONTAINED = "contained"
    RECOVERY_PENDING = "recovery_pending"
    RECOVERED = "recovered"


@dataclass(frozen=True)
class Event:
    sequence: int
    kind: str
    detail: str
    actor: str
    observed_at: str
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class RecoveryPlan:
    checkpoint_id: str
    checkpoint_digest: str
    policy_version: str
    credential_version: str
    requested_by: str


@dataclass
class IncidentRun:
    run_id: str
    tenant: str
    policy_version: str
    credential_version: str
    phase: Phase = Phase.ACTIVE
    revoked_capabilities: set[str] = field(default_factory=set)
    committed_actions: set[str] = field(default_factory=set)
    events: list[Event] = field(default_factory=list)
    pending_plan: RecoveryPlan | None = None

    def _record(self, kind: str, detail: str, actor: str, *, now: datetime) -> None:
        previous = self.events[-1].event_hash if self.events else "GENESIS"
        payload = f"{self.run_id}|{len(self.events) + 1}|{kind}|{detail}|{actor}|{now.isoformat()}|{previous}"
        self.events.append(Event(len(self.events) + 1, kind, detail, actor, now.isoformat(), previous, sha256(payload.encode()).hexdigest()))

    def detect(self, signal: str, *, detector: str, now: datetime) -> bool:
        if self.phase is not Phase.ACTIVE or not signal.strip():
            return False
        self.phase = Phase.DETECTED
        self._record("detected", signal, detector, now=now)
        return True

    def contain(self, *, capabilities: set[str], responder: str, now: datetime) -> bool:
        if self.phase is not Phase.DETECTED or not capabilities:
            return False
        self.revoked_capabilities.update(capabilities)
        self.phase = Phase.CONTAINED
        self._record("contained", ",".join(sorted(capabilities)), responder, now=now)
        return True

    def propose_recovery(self, plan: RecoveryPlan, *, now: datetime) -> bool:
        if self.phase is not Phase.CONTAINED:
            return False
        self.pending_plan = plan
        self.phase = Phase.RECOVERY_PENDING
        self._record("recovery-proposed", plan.checkpoint_id, plan.requested_by, now=now)
        return True

    def authorize_recovery(
        self,
        *,
        approver: str,
        expected_checkpoint_digest: str,
        current_policy_version: str,
        current_credential_version: str,
        now: datetime,
    ) -> bool:
        plan = self.pending_plan
        valid = bool(
            self.phase is Phase.RECOVERY_PENDING
            and plan
            and approver.startswith("operator:")
            and approver != plan.requested_by
            and plan.checkpoint_digest == expected_checkpoint_digest
            and plan.policy_version == current_policy_version == self.policy_version
            and plan.credential_version == current_credential_version == self.credential_version
        )
        self._record("recovery-decision", "approved" if valid else "denied", approver, now=now)
        if valid:
            self.phase = Phase.RECOVERED
            self.revoked_capabilities.discard("ticket:write")
        return valid

    def commit_once(self, action_id: str, operation: str, *, now: datetime) -> bool:
        allowed = self.phase is Phase.RECOVERED and "ticket:write" not in self.revoked_capabilities and action_id not in self.committed_actions
        if allowed:
            self.committed_actions.add(action_id)
        self._record("effect", f"{action_id}:{operation}:{'committed' if allowed else 'blocked'}", "application", now=now)
        return allowed

    def verify_event_chain(self) -> bool:
        previous = "GENESIS"
        for event in self.events:
            payload = f"{self.run_id}|{event.sequence}|{event.kind}|{event.detail}|{event.actor}|{event.observed_at}|{previous}"
            if event.previous_hash != previous or event.event_hash != sha256(payload.encode()).hexdigest():
                return False
            previous = event.event_hash
        return True


def checkpoint_digest(state: dict[str, object]) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode()).hexdigest()


def demo() -> IncidentRun:
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    state = {"ticket": "T-7", "operation": "close", "version": 4}
    digest = checkpoint_digest(state)
    run = IncidentRun("run-7", "north", "policy-v4", "credential-v2")
    assert run.detect("unexpected external destination", detector="egress-monitor", now=now)
    assert run.contain(capabilities={"ticket:write", "network:external"}, responder="operator:lee", now=now)
    plan = RecoveryPlan("checkpoint-4", digest, "policy-v4", "credential-v2", "automation:planner")
    assert run.propose_recovery(plan, now=now)
    assert run.authorize_recovery(
        approver="operator:sam",
        expected_checkpoint_digest=digest,
        current_policy_version="policy-v4",
        current_credential_version="credential-v2",
        now=now,
    )
    assert run.commit_once("effect-T-7-close", "close-ticket", now=now)
    assert not run.commit_once("effect-T-7-close", "close-ticket", now=now)
    assert run.verify_event_chain()
    return run


if __name__ == "__main__":
    for event in demo().events:
        print(asdict(event))

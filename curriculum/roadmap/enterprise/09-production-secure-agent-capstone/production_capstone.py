"""Integrated deterministic control plane for the production-agent capstone.

Models, retrieved content, memory, tool output, MCP metadata, and specialist
messages remain proposals or data. This module owns trusted identity, policy,
authorization, approval, effects, durable state, evidence, and release gates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum
import hashlib
import hmac
import json
from typing import Any, Iterable


def _canonical(value: object) -> object:
    if is_dataclass(value):
        return _canonical(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def digest(value: object) -> str:
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"
    IDEMPOTENT = "idempotent"


class GateState(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ActorContext:
    subject: str
    workload_id: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class Document:
    document_id: str
    tenant: str
    subject_id: str
    source_version: str
    content: str
    allowed_uses: frozenset[str]
    fresh_until: int


@dataclass(frozen=True)
class RetrievalResult:
    decision: Decision
    reason: str
    document_ids: tuple[str, ...]
    contents: tuple[str, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class MemoryCandidate:
    candidate_id: str
    tenant: str
    subject_id: str
    kind: str
    value: str
    source_id: str
    source_version: str


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    parent_subject: str
    delegate_workload: str
    tenant: str
    audience: str
    capabilities: frozenset[str]
    policy_version: str
    expires_at: int
    revocation_epoch: int


@dataclass(frozen=True)
class MCPServerRegistration:
    server_id: str
    tenant: str
    digest: str
    tools: frozenset[str]
    expires_at: int
    enabled: bool = True


@dataclass(frozen=True)
class ActionProposal:
    request_id: str
    run_id: str
    operation: str
    resource_id: str
    resource_tenant: str
    logical_operation_id: str
    arguments: dict[str, Any]
    mcp_server_id: str
    mcp_server_digest: str
    control_epoch: int
    proposal_digest: str


def proposal_payload(proposal: ActionProposal) -> dict[str, Any]:
    return {
        key: value
        for key, value in asdict(proposal).items()
        if key != "proposal_digest"
    }


def make_proposal(**values: Any) -> ActionProposal:
    proposal = ActionProposal(proposal_digest="", **values)
    return replace(proposal, proposal_digest=digest(proposal_payload(proposal)))


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    tenant: str
    principal: str
    proposal_digest: str
    operation: str
    resource_id: str
    policy_version: str
    approver: str
    approver_role: str
    issued_at: int
    expires_at: int
    consumed: bool = False
    proof: str = ""


@dataclass(frozen=True)
class DecisionReceipt:
    request_id: str
    decision: Decision
    reason: str
    operation: str
    logical_operation_id: str
    policy_version: str
    control_epoch: int
    evidence_ids: tuple[str, ...]
    effect_id: str = ""


@dataclass(frozen=True)
class Checkpoint:
    checkpoint_id: str
    run_id: str
    tenant: str
    state: dict[str, Any]
    state_digest: str
    policy_version: str
    control_epoch: int
    version: int


@dataclass(frozen=True)
class EvidenceArtifact:
    evidence_id: str
    kind: str
    tenant: str
    subject_digest: str
    producer: str
    policy_version: str
    observed_at: int
    expires_at: int
    authenticated: bool
    result: str
    severe: bool
    details_digest: str


@dataclass(frozen=True)
class ResidualRisk:
    risk_id: str
    owner: str
    decision: str
    expires_at: int
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class EvaluationSummary:
    covered_case_ids: tuple[str, ...]
    total_cases: int
    valid_cases: int
    valid_successes: int
    attack_cases: int
    attacks_safely_blocked: int
    failure_cases: int
    failures_safely_handled: int
    forbidden_outcomes: int
    false_blocks: int
    total_cost_units: int
    successful_compliant_tasks: int

    @property
    def valid_success_rate(self) -> float | None:
        return self.valid_successes / self.valid_cases if self.valid_cases else None

    @property
    def attack_block_rate(self) -> float | None:
        return self.attacks_safely_blocked / self.attack_cases if self.attack_cases else None

    @property
    def failure_safe_rate(self) -> float | None:
        return self.failures_safely_handled / self.failure_cases if self.failure_cases else None

    @property
    def cost_per_successful_compliant_task(self) -> float | None:
        if not self.successful_compliant_tasks:
            return None
        return self.total_cost_units / self.successful_compliant_tasks


@dataclass(frozen=True)
class ReleaseDossier:
    dossier_id: str
    candidate_digest: str
    tenant: str
    architecture_version: str
    policy_version: str
    control_epoch: int
    evidence: tuple[EvidenceArtifact, ...]
    evaluation: EvaluationSummary
    residual_risks: tuple[ResidualRisk, ...]
    requested_decision: str


@dataclass(frozen=True)
class GateReceipt:
    dossier_id: str
    dossier_digest: str
    state: GateState
    reason: str
    missing_kinds: tuple[str, ...]
    invalid_evidence_ids: tuple[str, ...]
    severe_failure_ids: tuple[str, ...]
    policy_version: str
    evaluated_at: int


EFFECT_OPERATIONS = frozenset({"case.update", "refund.issue"})
FORBIDDEN_ARGUMENT_KEYS = frozenset({
    "api_key", "access_token", "secret", "authorization", "credential"
})
REQUIRED_EVIDENCE_KINDS = frozenset({
    "architecture", "threat-model", "invariant-tests", "attack-suite",
    "telemetry", "incident-drill", "recovery-drill", "supply-chain",
    "architecture-review",
})
REQUIRED_CASE_IDS = frozenset({
    "valid-retrieval", "valid-effect", "indirect-injection", "encoded-injection",
    "poisoned-tool-output", "poisoned-memory", "cross-tenant", "credential-misuse", "delegation-escalation",
    "compromised-mcp", "approval-bypass", "approval-replay", "kill-switch",
    "stale-checkpoint", "policy-outage", "unknown-effect",
})


class CapstoneControlPlane:
    """Application-owned boundary for the integrated support-agent workflow."""

    def __init__(
        self,
        *,
        tenant: str,
        policy_version: str,
        receipt_key: bytes,
        documents: Iterable[Document],
        grants: Iterable[DelegationGrant],
        servers: Iterable[MCPServerRegistration],
        policy_available: bool = True,
    ):
        self.tenant = tenant
        self.policy_version = policy_version
        self.receipt_key = receipt_key
        self.policy_available = policy_available
        self.control_epoch = 0
        self.kill_active = False
        self.documents = {item.document_id: item for item in documents}
        self.grants = {item.grant_id: item for item in grants}
        self.servers = {item.server_id: item for item in servers}
        self.approvals: dict[str, ApprovalReceipt] = {}
        self.memory: dict[str, MemoryCandidate] = {}
        self.effects: dict[str, tuple[str, str]] = {}
        self.unknown_effects: dict[str, str] = {}
        self.events: list[dict[str, Any]] = []

    def _event(self, kind: str, **attributes: Any) -> str:
        event = {
            "event_id": f"event:{len(self.events) + 1}",
            "kind": kind,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "control_epoch": self.control_epoch,
            **attributes,
        }
        self.events.append(event)
        return event["event_id"]

    def _signed_approval(self, receipt: ApprovalReceipt) -> ApprovalReceipt:
        payload = {key: value for key, value in asdict(receipt).items() if key != "proof"}
        proof = hmac.new(self.receipt_key, digest(payload).encode(), hashlib.sha256).hexdigest()
        return replace(receipt, proof=proof)

    def _verify_approval(self, receipt: ApprovalReceipt) -> bool:
        expected = self._signed_approval(replace(receipt, proof="")).proof
        return hmac.compare_digest(expected, receipt.proof)

    def retrieve(
        self,
        actor: ActorContext,
        document_ids: Iterable[str],
        *,
        subject_id: str,
        now: int,
    ) -> RetrievalResult:
        if not actor.authenticated or actor.tenant != self.tenant:
            return RetrievalResult(Decision.DENY, "identity-scope", (), (), ())
        if not self.policy_available:
            return RetrievalResult(Decision.UNKNOWN, "policy-unavailable", (), (), ())
        admitted: list[Document] = []
        for document_id in document_ids:
            document = self.documents.get(document_id)
            if (
                document
                and document.tenant == actor.tenant
                and document.subject_id == subject_id
                and document.fresh_until > now
                and "draft" in document.allowed_uses
            ):
                admitted.append(document)
        event_id = self._event(
            "retrieval", actor=actor.subject,
            admitted_document_ids=tuple(item.document_id for item in admitted),
        )
        return RetrievalResult(
            Decision.ALLOW, "authorized-evidence-manifest",
            tuple(item.document_id for item in admitted),
            tuple(item.content for item in admitted),
            (event_id,),
        )

    def admit_memory(self, actor: ActorContext, candidate: MemoryCandidate) -> DecisionReceipt:
        reason = "memory-admitted"
        decision = Decision.ALLOW
        if not actor.authenticated or actor.tenant != self.tenant:
            decision, reason = Decision.DENY, "identity-scope"
        elif candidate.tenant != actor.tenant or candidate.subject_id != actor.subject:
            decision, reason = Decision.DENY, "memory-scope"
        elif candidate.kind in {"approval", "authority", "credential", "policy"}:
            decision, reason = Decision.DENY, "memory-kind-forbidden"
        elif not candidate.source_id or not candidate.source_version:
            decision, reason = Decision.DENY, "memory-provenance"
        if decision is Decision.ALLOW:
            self.memory[candidate.candidate_id] = candidate
        event_id = self._event("memory", actor=actor.subject, decision=decision.value, reason=reason)
        return DecisionReceipt(
            candidate.candidate_id, decision, reason, "memory.write", candidate.candidate_id,
            self.policy_version, self.control_epoch, (event_id,),
        )

    def issue_approval(
        self,
        approver: ActorContext,
        principal: str,
        proposal: ActionProposal,
        *,
        approval_id: str,
        now: int,
        ttl: int = 120,
    ) -> ApprovalReceipt:
        if (
            not approver.authenticated
            or approver.tenant != self.tenant
            or "effect-approver" not in approver.roles
            or approver.subject == principal
            or proposal.resource_tenant != self.tenant
            or proposal.proposal_digest != digest(proposal_payload(proposal))
        ):
            raise PermissionError("approval-not-authorized")
        receipt = ApprovalReceipt(
            approval_id, self.tenant, principal, proposal.proposal_digest,
            proposal.operation, proposal.resource_id, self.policy_version,
            approver.subject, "effect-approver", now, now + ttl,
        )
        signed = self._signed_approval(receipt)
        self.approvals[approval_id] = signed
        return signed

    def activate_kill_switch(self, operator: ActorContext) -> None:
        if (
            not operator.authenticated
            or operator.tenant != self.tenant
            or "incident-commander" not in operator.roles
        ):
            raise PermissionError("kill-switch-not-authorized")
        self.control_epoch += 1
        self.kill_active = True
        self._event("kill-switch", operator=operator.subject)

    def recover(self, operator: ActorContext) -> None:
        if (
            not operator.authenticated
            or operator.tenant != self.tenant
            or "recovery-approver" not in operator.roles
        ):
            raise PermissionError("recovery-not-authorized")
        self.control_epoch += 1
        self.kill_active = False
        self._event("recovery", operator=operator.subject)

    def dispatch(
        self,
        actor: ActorContext,
        proposal: ActionProposal,
        *,
        grant_id: str,
        approval_id: str | None,
        now: int,
        provider_outcome: str = "confirmed",
    ) -> DecisionReceipt:
        decision, reason = Decision.DENY, "denied"
        effect_id = ""
        grant = self.grants.get(grant_id)
        server = self.servers.get(proposal.mcp_server_id)
        argument_keys = {str(key).lower() for key in proposal.arguments}
        existing = self.effects.get(proposal.logical_operation_id)

        if not actor.authenticated or actor.tenant != self.tenant:
            reason = "identity-scope"
        elif not self.policy_available:
            decision, reason = Decision.UNKNOWN, "policy-unavailable"
        elif self.kill_active or proposal.control_epoch != self.control_epoch:
            reason = "control-epoch"
        elif proposal.proposal_digest != digest(proposal_payload(proposal)):
            reason = "proposal-integrity"
        elif proposal.resource_tenant != actor.tenant:
            reason = "cross-tenant"
        elif argument_keys & FORBIDDEN_ARGUMENT_KEYS:
            reason = "credential-in-arguments"
        elif grant is None:
            reason = "grant-missing"
        elif (
            grant.parent_subject != actor.subject
            or grant.delegate_workload != actor.workload_id
            or grant.tenant != actor.tenant
            or grant.audience != "capstone-effect-gateway"
            or grant.policy_version != self.policy_version
            or grant.expires_at <= now
            or grant.revocation_epoch != self.control_epoch
        ):
            reason = "grant-binding"
        elif proposal.operation not in grant.capabilities:
            reason = "capability-escalation"
        elif server is None or not server.enabled or server.tenant != actor.tenant:
            reason = "mcp-server-untrusted"
        elif server.expires_at <= now or server.digest != proposal.mcp_server_digest:
            reason = "mcp-server-integrity"
        elif proposal.operation not in server.tools:
            reason = "mcp-tool-not-allowed"
        elif existing is not None:
            prior_digest, prior_effect_id = existing
            if prior_digest == proposal.proposal_digest:
                decision, reason, effect_id = Decision.IDEMPOTENT, "effect-already-confirmed", prior_effect_id
            else:
                reason = "operation-id-collision"
        elif proposal.logical_operation_id in self.unknown_effects:
            decision, reason = Decision.UNKNOWN, "reconciliation-required"
        else:
            approval = self.approvals.get(approval_id or "")
            if proposal.operation in EFFECT_OPERATIONS and approval is None:
                reason = "approval-required"
            elif proposal.operation in EFFECT_OPERATIONS and (
                not self._verify_approval(approval)
                or approval.consumed
                or approval.expires_at <= now
                or approval.tenant != actor.tenant
                or approval.principal != actor.subject
                or approval.proposal_digest != proposal.proposal_digest
                or approval.operation != proposal.operation
                or approval.resource_id != proposal.resource_id
                or approval.policy_version != self.policy_version
            ):
                reason = "approval-binding"
            elif provider_outcome == "unknown":
                if approval is not None:
                    self.approvals[approval.approval_id] = replace(approval, consumed=True)
                self.unknown_effects[proposal.logical_operation_id] = proposal.proposal_digest
                decision, reason = Decision.UNKNOWN, "provider-outcome-unknown"
            elif provider_outcome != "confirmed":
                decision, reason = Decision.DENY, "provider-rejected"
            else:
                if approval is not None:
                    self.approvals[approval.approval_id] = replace(approval, consumed=True)
                effect_id = f"effect:{proposal.logical_operation_id}"
                self.effects[proposal.logical_operation_id] = (proposal.proposal_digest, effect_id)
                decision, reason = Decision.ALLOW, "effect-confirmed"

        event_id = self._event(
            "dispatch", actor=actor.subject, operation=proposal.operation,
            decision=decision.value, reason=reason,
            logical_operation_id=proposal.logical_operation_id,
        )
        return DecisionReceipt(
            proposal.request_id, decision, reason, proposal.operation,
            proposal.logical_operation_id, self.policy_version, self.control_epoch,
            (event_id,), effect_id,
        )

    def reconcile(self, logical_operation_id: str, *, provider_committed: bool) -> DecisionReceipt:
        proposal_digest = self.unknown_effects.pop(logical_operation_id, "")
        if not proposal_digest:
            decision, reason, effect_id = Decision.DENY, "unknown-operation-missing", ""
        elif provider_committed:
            effect_id = f"effect:{logical_operation_id}"
            self.effects[logical_operation_id] = (proposal_digest, effect_id)
            decision, reason = Decision.ALLOW, "provider-commit-reconciled"
        else:
            decision, reason, effect_id = Decision.DENY, "provider-noncommit-reconciled", ""
        event_id = self._event("reconcile", decision=decision.value, reason=reason)
        return DecisionReceipt(
            f"reconcile:{logical_operation_id}", decision, reason, "reconcile",
            logical_operation_id, self.policy_version, self.control_epoch,
            (event_id,), effect_id,
        )

    def create_checkpoint(self, actor: ActorContext, run_id: str, state: dict[str, Any]) -> Checkpoint:
        if not actor.authenticated or actor.tenant != self.tenant:
            raise PermissionError("checkpoint-scope")
        return Checkpoint(
            f"checkpoint:{run_id}:1", run_id, self.tenant, state, digest(state),
            self.policy_version, self.control_epoch, 1,
        )

    def resume(self, actor: ActorContext, checkpoint: Checkpoint) -> DecisionReceipt:
        decision, reason = Decision.ALLOW, "resume-authorized"
        if not actor.authenticated or actor.tenant != self.tenant or checkpoint.tenant != self.tenant:
            decision, reason = Decision.DENY, "checkpoint-scope"
        elif checkpoint.state_digest != digest(checkpoint.state):
            decision, reason = Decision.DENY, "checkpoint-integrity"
        elif checkpoint.policy_version != self.policy_version:
            decision, reason = Decision.DENY, "checkpoint-policy-stale"
        elif checkpoint.control_epoch != self.control_epoch or self.kill_active:
            decision, reason = Decision.DENY, "checkpoint-control-epoch"
        elif self.unknown_effects:
            decision, reason = Decision.UNKNOWN, "checkpoint-reconciliation-required"
        event_id = self._event("resume", decision=decision.value, reason=reason)
        return DecisionReceipt(
            checkpoint.checkpoint_id, decision, reason, "run.resume", checkpoint.run_id,
            self.policy_version, self.control_epoch, (event_id,),
        )


class ReleaseGate:
    """Independent technical-readiness gate; READY is not deployment approval."""

    def __init__(
        self,
        *,
        authenticated_tenant: str,
        candidate_digest: str,
        policy_version: str,
        control_epoch: int,
    ):
        self.authenticated_tenant = authenticated_tenant
        self.candidate_digest = candidate_digest
        self.policy_version = policy_version
        self.control_epoch = control_epoch

    def evaluate(self, dossier: ReleaseDossier, *, now: int) -> GateReceipt:
        evidence_ids = [item.evidence_id for item in dossier.evidence]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("duplicate-evidence")
        evidence_by_id = {item.evidence_id: item for item in dossier.evidence}
        missing = tuple(sorted(REQUIRED_EVIDENCE_KINDS - {item.kind for item in dossier.evidence}))
        invalid = tuple(sorted(
            item.evidence_id for item in dossier.evidence
            if (
                not item.authenticated
                or item.tenant != self.authenticated_tenant
                or item.subject_digest != self.candidate_digest
                or item.policy_version != self.policy_version
                or item.observed_at > now
                or item.expires_at <= now
                or not item.details_digest
                or item.result not in {"pass", "fail", "unknown"}
            )
        ))
        severe = tuple(sorted(
            item.evidence_id for item in dossier.evidence
            if item.severe and item.result == "fail"
        ))
        invalid_risks = any(
            not risk.owner
            or risk.decision not in {"accept-with-monitoring", "mitigate", "transfer"}
            or risk.expires_at <= now
            or not risk.evidence_ids
            or any(item not in evidence_by_id for item in risk.evidence_ids)
            for risk in dossier.residual_risks
        )
        evaluation = dossier.evaluation
        missing_cases = REQUIRED_CASE_IDS - set(evaluation.covered_case_ids)
        evaluation_incomplete = (
            evaluation.total_cases != len(evaluation.covered_case_ids)
            or len(set(evaluation.covered_case_ids)) != len(evaluation.covered_case_ids)
            or evaluation.valid_cases + evaluation.attack_cases + evaluation.failure_cases
            != evaluation.total_cases
            or evaluation.valid_cases == 0
            or evaluation.attack_cases == 0
            or evaluation.failure_cases == 0
            or not 0 <= evaluation.valid_successes <= evaluation.valid_cases
            or not 0 <= evaluation.attacks_safely_blocked <= evaluation.attack_cases
            or not 0 <= evaluation.failures_safely_handled <= evaluation.failure_cases
            or evaluation.total_cost_units < 0
            or evaluation.successful_compliant_tasks == 0
            or evaluation.successful_compliant_tasks != evaluation.valid_successes
            or bool(missing_cases)
        )
        hard_outcome = evaluation.forbidden_outcomes > 0 or evaluation.false_blocks > 0
        evaluation_blocked = (
            evaluation.valid_success_rate != 1.0
            or evaluation.attack_block_rate != 1.0
            or evaluation.failure_safe_rate != 1.0
        )
        binding_invalid = (
            not dossier.dossier_id
            or not dossier.architecture_version
            or dossier.tenant != self.authenticated_tenant
            or dossier.candidate_digest != self.candidate_digest
            or dossier.policy_version != self.policy_version
            or dossier.control_epoch != self.control_epoch
            or dossier.requested_decision != "approve"
        )

        if severe or hard_outcome or binding_invalid:
            state, reason = GateState.BLOCKED, "non-compensable-release-blocker"
        elif missing or invalid or invalid_risks or evaluation_incomplete:
            state, reason = GateState.INCOMPLETE, "release-evidence-incomplete"
        elif evaluation_blocked:
            state, reason = GateState.BLOCKED, "non-compensable-release-blocker"
        elif any(item.result == "unknown" for item in dossier.evidence):
            state, reason = GateState.INCOMPLETE, "release-evidence-unknown"
        else:
            state, reason = GateState.READY, "technical-readiness-proven"
        return GateReceipt(
            dossier.dossier_id, digest(dossier), state, reason, missing, invalid,
            severe, self.policy_version, now,
        )

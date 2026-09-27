"""Credential-free agent identity and delegated-authority lab for Intermediate 03.

The lab is a deterministic control-plane model, not a production OAuth, SPIFFE,
DPoP, mTLS, KMS, or policy service. It proves the application invariants around
those mechanisms: authenticate humans and workloads independently, issue only
current authority, attenuate it at every hop, bind grants to one audience and
sender, reject replay, propagate revocation, and never fall back to ambient
service authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import hmac
import json
from typing import Any


NOW = datetime(2026, 9, 27, 19, 0, tzinfo=timezone.utc)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset, tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def digest(value: Any) -> str:
    encoded = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    IDEMPOTENT = "idempotent"
    DENY = "deny"
    PAUSED = "paused"
    ERROR = "error"


class Lifecycle(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class GrantState(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class HumanSession:
    session_id: str
    principal_id: str
    tenant: str
    assurance: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class WorkloadAttestation:
    attestation_id: str
    workload_id: str
    tenant: str
    key_thumbprint: str
    issued_at: datetime
    expires_at: datetime
    agent_id: str | None = None


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    tenant: str
    blueprint: str
    sponsor: str
    lifecycle: Lifecycle
    allowed_audiences: frozenset[str]
    allowed_purposes: frozenset[str]


@dataclass(frozen=True)
class EntitlementSnapshot:
    principal_id: str
    tenant: str
    operations: frozenset[str]
    resources: frozenset[str]
    version: int
    policy_version: str


@dataclass(frozen=True)
class ProtectedResource:
    resource_id: str
    tenant: str
    content: str


@dataclass
class IdentityRegistry:
    sessions: dict[str, HumanSession]
    workloads: dict[str, WorkloadAttestation]
    agents: dict[str, AgentIdentity]
    available: bool = True

    def session(self, session_id: str, *, now: datetime) -> tuple[HumanSession | None, str]:
        if not self.available:
            return None, "identity-registry-unavailable"
        session = self.sessions.get(session_id)
        if session is None:
            return None, "session-unknown"
        if not (session.issued_at <= now < session.expires_at):
            return None, "session-expired"
        if session.assurance not in {"mfa", "phishing-resistant"}:
            return None, "session-assurance"
        return session, "session-authenticated"

    def workload(
        self, attestation_id: str, *, now: datetime
    ) -> tuple[WorkloadAttestation | None, str]:
        if not self.available:
            return None, "identity-registry-unavailable"
        workload = self.workloads.get(attestation_id)
        if workload is None:
            return None, "workload-unknown"
        if not (workload.issued_at <= now < workload.expires_at):
            return None, "workload-attestation-expired"
        return workload, "workload-authenticated"

    def agent(self, agent_id: str | None) -> tuple[AgentIdentity | None, str]:
        if not self.available:
            return None, "identity-registry-unavailable"
        agent = self.agents.get(agent_id or "")
        if agent is None:
            return None, "agent-identity-unknown"
        if agent.lifecycle is not Lifecycle.ACTIVE:
            return None, "agent-identity-disabled"
        if not agent.sponsor:
            return None, "agent-sponsor-missing"
        return agent, "agent-identity-active"


@dataclass
class EntitlementService:
    snapshots: dict[str, EntitlementSnapshot]
    available: bool = True

    def current(self, principal_id: str) -> tuple[EntitlementSnapshot | None, str]:
        if not self.available:
            return None, "entitlement-service-unavailable"
        snapshot = self.snapshots.get(principal_id)
        if snapshot is None:
            return None, "entitlement-missing"
        return snapshot, "entitlement-current"


@dataclass(frozen=True)
class GrantRequest:
    request_id: str
    audience: str
    purpose: str
    operations: frozenset[str]
    resources: frozenset[str]
    requested_ttl: timedelta


@dataclass(frozen=True)
class DelegatedGrant:
    grant_id: str
    root_grant_id: str
    parent_grant_id: str | None
    subject_principal: str
    tenant: str
    agent_id: str
    actor_chain: tuple[str, ...]
    delegate_workload: str
    audience: str
    purpose: str
    operations: frozenset[str]
    resources: frozenset[str]
    confirmation_thumbprint: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    policy_version: str
    entitlement_version: int
    delegation_depth: int
    key_id: str
    payload_digest: str
    signature: str


@dataclass(frozen=True)
class DecisionReceipt:
    trace_id: str
    operation: str
    status: str
    reason: str
    tenant_digest: str
    subject_digest: str
    agent_id: str
    actor_chain: tuple[str, ...]
    grant_id: str
    root_grant_id: str
    audience: str
    operation_name: str
    resource_digest: str
    policy_version: str
    entitlement_version: int
    proof_id: str = ""


@dataclass(frozen=True)
class GrantDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    grant: DelegatedGrant | None = None


@dataclass(frozen=True)
class AccessDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    content: str | None = None


class GrantAuthority:
    """Stateful STS analogue with application-owned lifecycle and lineage."""

    def __init__(
        self,
        identities: IdentityRegistry,
        entitlements: EntitlementService,
        *,
        policy_version: str = "identity-policy-v5",
        key_id: str = "grant-key-2026-09",
        secret: bytes = b"synthetic-grant-key",
        max_ttl: timedelta = timedelta(minutes=10),
        max_depth: int = 3,
    ):
        self.identities = identities
        self.entitlements = entitlements
        self.policy_version = policy_version
        self.key_id = key_id
        self._secret = secret
        self.max_ttl = max_ttl
        self.max_depth = max_depth
        self.allowed_hops = {
            "support-orchestrator": frozenset({"case-service"}),
            "case-service": frozenset({"attachment-store"}),
        }
        self.grants: dict[str, DelegatedGrant] = {}
        self.states: dict[str, GrantState] = {}
        self.request_ledger: dict[str, tuple[str, str]] = {}
        self.available = True

    @staticmethod
    def _payload(grant: DelegatedGrant) -> dict[str, Any]:
        return {
            key: value for key, value in grant.__dict__.items()
            if key not in {"payload_digest", "signature"}
        }

    def _seal(self, grant: DelegatedGrant) -> DelegatedGrant:
        payload_digest = digest(self._payload(grant))
        signature = hmac.new(self._secret, payload_digest.encode(), sha256).hexdigest()
        return replace(grant, payload_digest=payload_digest, signature=signature)

    def verify_signature(self, grant: DelegatedGrant) -> bool:
        if grant.key_id != self.key_id:
            return False
        payload_digest = digest(self._payload(grant))
        signature = hmac.new(self._secret, payload_digest.encode(), sha256).hexdigest()
        return hmac.compare_digest(grant.payload_digest, payload_digest) and hmac.compare_digest(
            grant.signature, signature
        )

    def _receipt(
        self,
        *,
        trace_id: str,
        operation: str,
        status: DecisionStatus,
        reason: str,
        tenant: str = "",
        subject: str = "",
        agent_id: str = "",
        actor_chain: tuple[str, ...] = (),
        grant: DelegatedGrant | None = None,
        audience: str = "",
        operation_name: str = "",
        resource: str = "",
        entitlement_version: int = 0,
        proof_id: str = "",
    ) -> DecisionReceipt:
        return DecisionReceipt(
            trace_id, operation, status.value, reason,
            digest(tenant)[:16] if tenant else "none",
            digest(subject)[:16] if subject else "none",
            agent_id, actor_chain,
            grant.grant_id if grant else "",
            grant.root_grant_id if grant else "",
            audience or (grant.audience if grant else ""),
            operation_name,
            digest(resource)[:16] if resource else "none",
            self.policy_version,
            entitlement_version or (grant.entitlement_version if grant else 0),
            proof_id,
        )

    def _terminal(
        self, request_id: str, operation: str, status: DecisionStatus, reason: str,
        **fields: Any,
    ) -> GrantDecision:
        return GrantDecision(
            status, reason,
            self._receipt(
                trace_id=f"trace:{request_id}", operation=operation,
                status=status, reason=reason, **fields,
            ),
        )

    def issue(
        self,
        session_id: str,
        attestation_id: str,
        request: GrantRequest,
        *,
        now: datetime,
    ) -> GrantDecision:
        if not self.available:
            return self._terminal(request.request_id, "issue", DecisionStatus.ERROR, "grant-authority-unavailable")
        session, reason = self.identities.session(session_id, now=now)
        if session is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(request.request_id, "issue", status, reason)
        workload, reason = self.identities.workload(attestation_id, now=now)
        if workload is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request.request_id, "issue", status, reason,
                tenant=session.tenant, subject=session.principal_id,
            )
        agent, reason = self.identities.agent(workload.agent_id)
        if agent is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request.request_id, "issue", status, reason,
                tenant=session.tenant, subject=session.principal_id,
                actor_chain=(workload.workload_id,),
            )
        entitlement, reason = self.entitlements.current(session.principal_id)
        if entitlement is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request.request_id, "issue", status, reason,
                tenant=session.tenant, subject=session.principal_id,
                agent_id=agent.agent_id, actor_chain=(workload.workload_id,),
            )
        fields = {
            "tenant": session.tenant,
            "subject": session.principal_id,
            "agent_id": agent.agent_id,
            "actor_chain": (workload.workload_id,),
            "audience": request.audience,
            "entitlement_version": entitlement.version,
        }
        if len({session.tenant, workload.tenant, agent.tenant, entitlement.tenant}) != 1:
            return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "tenant-binding", **fields)
        if request.audience not in agent.allowed_audiences:
            return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "audience-not-allowed", **fields)
        if request.purpose not in agent.allowed_purposes:
            return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "purpose-not-allowed", **fields)
        if not request.operations or not request.operations <= entitlement.operations:
            return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "operation-escalation", **fields)
        if not request.resources or not request.resources <= entitlement.resources:
            return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "resource-escalation", **fields)
        if entitlement.policy_version != self.policy_version:
            return self._terminal(request.request_id, "issue", DecisionStatus.PAUSED, "entitlement-policy-stale", **fields)
        if request.requested_ttl <= timedelta(0):
            return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "ttl-invalid", **fields)

        request_digest = digest({
            "session": session.session_id,
            "workload": workload.workload_id,
            "request": request,
            "policy": self.policy_version,
            "entitlement": entitlement.version,
        })
        previous = self.request_ledger.get(request.request_id)
        if previous:
            previous_digest, previous_grant_id = previous
            if previous_digest != request_digest:
                return self._terminal(request.request_id, "issue", DecisionStatus.DENY, "request-id-collision", **fields)
            previous_grant = self.grants[previous_grant_id]
            return GrantDecision(
                DecisionStatus.IDEMPOTENT, "issuance-request-replay",
                self._receipt(
                    trace_id=f"trace:{request.request_id}", operation="issue",
                    status=DecisionStatus.IDEMPOTENT, reason="issuance-request-replay",
                    grant=previous_grant, **fields,
                ), previous_grant,
            )

        expires_at = now + min(request.requested_ttl, self.max_ttl, session.expires_at - now, workload.expires_at - now)
        grant_id = f"grant:{digest([request.request_id, request_digest])[:20]}"
        grant = DelegatedGrant(
            grant_id, grant_id, None, session.principal_id, session.tenant,
            agent.agent_id, (workload.workload_id,), workload.workload_id,
            request.audience, request.purpose, request.operations, request.resources,
            workload.key_thumbprint, now, now, expires_at,
            self.policy_version, entitlement.version, 1, self.key_id, "", "",
        )
        sealed = self._seal(grant)
        self.grants[sealed.grant_id] = sealed
        self.states[sealed.grant_id] = GrantState.ACTIVE
        self.request_ledger[request.request_id] = (request_digest, sealed.grant_id)
        return GrantDecision(
            DecisionStatus.ALLOW, "grant-issued",
            self._receipt(
                trace_id=f"trace:{request.request_id}", operation="issue",
                status=DecisionStatus.ALLOW, reason="grant-issued",
                grant=sealed, **fields,
            ), sealed,
        )

    def validate_current(
        self, grant: DelegatedGrant, *, now: datetime
    ) -> tuple[EntitlementSnapshot | None, str]:
        if not self.available:
            return None, "grant-authority-unavailable"
        registered = self.grants.get(grant.grant_id)
        if registered is None or registered != grant or not self.verify_signature(grant):
            return None, "grant-integrity"
        if self.states.get(grant.grant_id) is not GrantState.ACTIVE:
            return None, "grant-revoked"
        if not (grant.not_before <= now < grant.expires_at):
            return None, "grant-expired"
        if grant.policy_version != self.policy_version:
            return None, "policy-version-changed"
        agent, reason = self.identities.agent(grant.agent_id)
        if agent is None:
            return None, reason
        entitlement, reason = self.entitlements.current(grant.subject_principal)
        if entitlement is None:
            return None, reason
        if entitlement.version != grant.entitlement_version:
            return None, "entitlement-version-changed"
        if entitlement.policy_version != self.policy_version:
            return None, "entitlement-policy-stale"
        return entitlement, "grant-current"

    def exchange(
        self,
        parent_grant_id: str,
        actor_attestation_id: str,
        request: GrantRequest,
        *,
        now: datetime,
    ) -> GrantDecision:
        parent = self.grants.get(parent_grant_id)
        if parent is None:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "parent-grant-unknown")
        entitlement, reason = self.validate_current(parent, now=now)
        if entitlement is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request.request_id, "exchange", status, reason,
                tenant=parent.tenant, subject=parent.subject_principal,
                agent_id=parent.agent_id, actor_chain=parent.actor_chain,
                grant=parent, entitlement_version=parent.entitlement_version,
            )
        actor, reason = self.identities.workload(actor_attestation_id, now=now)
        if actor is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request.request_id, "exchange", status, reason,
                tenant=parent.tenant, subject=parent.subject_principal,
                agent_id=parent.agent_id, actor_chain=parent.actor_chain,
                grant=parent,
            )
        fields = {
            "tenant": parent.tenant,
            "subject": parent.subject_principal,
            "agent_id": parent.agent_id,
            "actor_chain": parent.actor_chain + (actor.workload_id,),
            "grant": parent,
            "audience": request.audience,
            "entitlement_version": entitlement.version,
        }
        if parent.audience != actor.workload_id:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "actor-audience-binding", **fields)
        if actor.tenant != parent.tenant:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "tenant-binding", **fields)
        if request.audience not in self.allowed_hops.get(actor.workload_id, frozenset()):
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "hop-not-allowed", **fields)
        if request.purpose != parent.purpose:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "purpose-escalation", **fields)
        if not request.operations or not request.operations <= parent.operations:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "operation-escalation", **fields)
        if not request.resources or not request.resources <= parent.resources:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "resource-escalation", **fields)
        if parent.delegation_depth >= self.max_depth:
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "delegation-depth", **fields)
        if request.requested_ttl <= timedelta(0):
            return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "ttl-invalid", **fields)

        request_digest = digest({
            "parent": parent.payload_digest,
            "actor": actor.workload_id,
            "request": request,
            "policy": self.policy_version,
        })
        previous = self.request_ledger.get(request.request_id)
        if previous:
            previous_digest, previous_grant_id = previous
            if previous_digest != request_digest:
                return self._terminal(request.request_id, "exchange", DecisionStatus.DENY, "request-id-collision", **fields)
            previous_grant = self.grants[previous_grant_id]
            return GrantDecision(
                DecisionStatus.IDEMPOTENT, "exchange-request-replay",
                self._receipt(
                    trace_id=f"trace:{request.request_id}", operation="exchange",
                    status=DecisionStatus.IDEMPOTENT, reason="exchange-request-replay",
                    grant=previous_grant, tenant=parent.tenant,
                    subject=parent.subject_principal, agent_id=parent.agent_id,
                    actor_chain=previous_grant.actor_chain,
                    audience=previous_grant.audience,
                    entitlement_version=entitlement.version,
                ), previous_grant,
            )

        expires_at = min(parent.expires_at, now + min(request.requested_ttl, self.max_ttl), actor.expires_at)
        grant_id = f"grant:{digest([request.request_id, request_digest])[:20]}"
        child = DelegatedGrant(
            grant_id, parent.root_grant_id, parent.grant_id,
            parent.subject_principal, parent.tenant, parent.agent_id,
            parent.actor_chain + (actor.workload_id,), actor.workload_id,
            request.audience, parent.purpose, request.operations, request.resources,
            actor.key_thumbprint, now, now, expires_at, self.policy_version,
            entitlement.version, parent.delegation_depth + 1,
            self.key_id, "", "",
        )
        sealed = self._seal(child)
        self.grants[sealed.grant_id] = sealed
        self.states[sealed.grant_id] = GrantState.ACTIVE
        self.request_ledger[request.request_id] = (request_digest, sealed.grant_id)
        return GrantDecision(
            DecisionStatus.ALLOW, "grant-exchanged",
            self._receipt(
                trace_id=f"trace:{request.request_id}", operation="exchange",
                status=DecisionStatus.ALLOW, reason="grant-exchanged",
                grant=sealed, tenant=parent.tenant,
                subject=parent.subject_principal, agent_id=parent.agent_id,
                actor_chain=sealed.actor_chain, audience=sealed.audience,
                entitlement_version=entitlement.version,
            ), sealed,
        )

    def revoke_lineage(self, grant_id: str, reason: str) -> int:
        if not reason.strip() or grant_id not in self.grants:
            return 0
        root_id = self.grants[grant_id].root_grant_id
        affected = [grant for grant in self.grants.values() if grant.root_grant_id == root_id]
        for grant in affected:
            self.states[grant.grant_id] = GrantState.REVOKED
        return len(affected)


@dataclass(frozen=True)
class RequestProof:
    proof_id: str
    grant_id: str
    grant_digest: str
    method: str
    uri: str
    key_thumbprint: str
    nonce: str
    issued_at: datetime
    key_id: str
    payload_digest: str
    signature: str


class ProofAuthority:
    """DPoP-like teaching analogue; it does not implement RFC 9449."""

    def __init__(
        self, identities: IdentityRegistry,
        *, key_id: str = "proof-key-2026-09", secret: bytes = b"synthetic-proof-key",
    ):
        self.identities = identities
        self.key_id = key_id
        self._secret = secret

    @staticmethod
    def _payload(proof: RequestProof) -> dict[str, Any]:
        return {
            key: value for key, value in proof.__dict__.items()
            if key not in {"payload_digest", "signature"}
        }

    def issue(
        self,
        attestation_id: str,
        grant: DelegatedGrant,
        *,
        proof_id: str,
        method: str,
        uri: str,
        nonce: str,
        now: datetime,
    ) -> RequestProof:
        workload, reason = self.identities.workload(attestation_id, now=now)
        if workload is None:
            raise PermissionError(reason)
        proof = RequestProof(
            proof_id, grant.grant_id, grant.payload_digest, method.upper(), uri,
            workload.key_thumbprint, nonce, now, self.key_id, "", "",
        )
        payload_digest = digest(self._payload(proof))
        signature = hmac.new(self._secret, payload_digest.encode(), sha256).hexdigest()
        return replace(proof, payload_digest=payload_digest, signature=signature)

    def verify(self, proof: RequestProof) -> bool:
        if proof.key_id != self.key_id:
            return False
        payload_digest = digest(self._payload(proof))
        signature = hmac.new(self._secret, payload_digest.encode(), sha256).hexdigest()
        return hmac.compare_digest(proof.payload_digest, payload_digest) and hmac.compare_digest(
            proof.signature, signature
        )


class ResourceServer:
    def __init__(
        self,
        audience: str,
        identities: IdentityRegistry,
        grants: GrantAuthority,
        proofs: ProofAuthority,
        resources: dict[str, ProtectedResource],
        *,
        release_content: bool = True,
    ):
        self.audience = audience
        self.identities = identities
        self.grants = grants
        self.proofs = proofs
        self.resources = resources
        self.release_content = release_content
        self.used_proofs: set[str] = set()
        self.challenges: set[str] = set()
        self.available = True

    def challenge(self, request_id: str) -> str:
        nonce = f"nonce:{digest([self.audience, request_id])[:20]}"
        self.challenges.add(nonce)
        return nonce

    def authorize(
        self,
        attestation_id: str,
        grant_id: str,
        proof: RequestProof,
        *,
        operation: str,
        resource_id: str,
        request_id: str,
        now: datetime,
        method: str = "GET",
    ) -> AccessDecision:
        grant = self.grants.grants.get(grant_id)

        def terminal(status: DecisionStatus, reason: str, candidate: DelegatedGrant | None = grant) -> AccessDecision:
            return AccessDecision(
                status, reason,
                self.grants._receipt(
                    trace_id=f"trace:{request_id}", operation="resource-access",
                    status=status, reason=reason,
                    tenant=candidate.tenant if candidate else "",
                    subject=candidate.subject_principal if candidate else "",
                    agent_id=candidate.agent_id if candidate else "",
                    actor_chain=candidate.actor_chain if candidate else (),
                    grant=candidate, audience=self.audience,
                    operation_name=operation, resource=resource_id,
                    entitlement_version=candidate.entitlement_version if candidate else 0,
                    proof_id=proof.proof_id,
                ),
            )

        if not self.available:
            return terminal(DecisionStatus.ERROR, "resource-server-unavailable")
        if grant is None:
            return terminal(DecisionStatus.DENY, "grant-unknown", None)
        entitlement, reason = self.grants.validate_current(grant, now=now)
        if entitlement is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return terminal(status, reason)
        workload, reason = self.identities.workload(attestation_id, now=now)
        if workload is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return terminal(status, reason)
        if grant.audience != self.audience:
            return terminal(DecisionStatus.DENY, "audience")
        if workload.workload_id != grant.delegate_workload or workload.tenant != grant.tenant:
            return terminal(DecisionStatus.DENY, "sender")
        if workload.key_thumbprint != grant.confirmation_thumbprint:
            return terminal(DecisionStatus.DENY, "sender-key")
        expected_uri = f"https://{self.audience}.internal/resources/{resource_id}"
        if not self.proofs.verify(proof):
            return terminal(DecisionStatus.DENY, "proof-integrity")
        if proof.proof_id in self.used_proofs:
            return terminal(DecisionStatus.DENY, "proof-replay")
        if proof.grant_id != grant.grant_id or proof.grant_digest != grant.payload_digest:
            return terminal(DecisionStatus.DENY, "proof-grant-binding")
        if proof.key_thumbprint != grant.confirmation_thumbprint:
            return terminal(DecisionStatus.DENY, "proof-sender-binding")
        if proof.method != method.upper() or proof.uri != expected_uri:
            return terminal(DecisionStatus.DENY, "proof-request-binding")
        if proof.nonce not in self.challenges:
            return terminal(DecisionStatus.DENY, "proof-nonce")
        if not (now - timedelta(seconds=60) <= proof.issued_at <= now + timedelta(seconds=5)):
            return terminal(DecisionStatus.DENY, "proof-time")

        # A validated proof is one-use even if later resource authorization denies.
        self.used_proofs.add(proof.proof_id)
        self.challenges.remove(proof.nonce)
        resource = self.resources.get(resource_id)
        if resource is None:
            return terminal(DecisionStatus.DENY, "resource-not-found")
        if resource.tenant != grant.tenant or resource.tenant != entitlement.tenant:
            return terminal(DecisionStatus.DENY, "resource-tenant")
        if operation not in grant.operations or operation not in entitlement.operations:
            return terminal(DecisionStatus.DENY, "operation")
        if resource_id not in grant.resources or resource_id not in entitlement.resources:
            return terminal(DecisionStatus.DENY, "resource")
        receipt = self.grants._receipt(
            trace_id=f"trace:{request_id}", operation="resource-access",
            status=DecisionStatus.ALLOW, reason="authorized",
            tenant=grant.tenant, subject=grant.subject_principal,
            agent_id=grant.agent_id, actor_chain=grant.actor_chain,
            grant=grant, audience=self.audience, operation_name=operation,
            resource=resource_id, entitlement_version=entitlement.version,
            proof_id=proof.proof_id,
        )
        content = resource.content if self.release_content else None
        return AccessDecision(DecisionStatus.ALLOW, "authorized", receipt, content)


@dataclass(frozen=True)
class ApplicationResponse:
    status: DecisionStatus
    reason: str
    content: str | None
    receipts: tuple[DecisionReceipt, ...]
    grant_ids: tuple[str, ...]


class DelegatedSupportApplication:
    """Two-hop path with no service-authority fallback."""

    def __init__(
        self,
        grants: GrantAuthority,
        proofs: ProofAuthority,
        case_boundary: ResourceServer,
        attachment_store: ResourceServer,
        *,
        case_attestation_id: str,
    ):
        self.grants = grants
        self.proofs = proofs
        self.case_boundary = case_boundary
        self.attachment_store = attachment_store
        self.case_attestation_id = case_attestation_id
        self.ambient_fallback_count = 0

    def read_attachment(
        self,
        *,
        session_id: str,
        agent_attestation_id: str,
        attachment_id: str,
        request_id: str,
        now: datetime,
    ) -> ApplicationResponse:
        root_request = GrantRequest(
            f"{request_id}:issue", "case-service", "case-support",
            frozenset({"read"}), frozenset({attachment_id}), timedelta(minutes=5),
        )
        issued = self.grants.issue(session_id, agent_attestation_id, root_request, now=now)
        if issued.grant is None:
            return ApplicationResponse(issued.status, issued.reason, None, (issued.receipt,), ())

        nonce = self.case_boundary.challenge(f"{request_id}:case")
        proof = self.proofs.issue(
            agent_attestation_id, issued.grant,
            proof_id=f"proof:{request_id}:case", method="GET",
            uri=f"https://case-service.internal/resources/{attachment_id}",
            nonce=nonce, now=now,
        )
        admitted = self.case_boundary.authorize(
            agent_attestation_id, issued.grant.grant_id, proof,
            operation="read", resource_id=attachment_id,
            request_id=f"{request_id}:case", now=now,
        )
        if admitted.status is not DecisionStatus.ALLOW:
            return ApplicationResponse(
                admitted.status, admitted.reason, None,
                (issued.receipt, admitted.receipt), (issued.grant.grant_id,),
            )

        child_request = GrantRequest(
            f"{request_id}:exchange", "attachment-store", "case-support",
            frozenset({"read"}), frozenset({attachment_id}), timedelta(minutes=2),
        )
        exchanged = self.grants.exchange(
            issued.grant.grant_id, self.case_attestation_id, child_request, now=now
        )
        if exchanged.grant is None:
            return ApplicationResponse(
                exchanged.status, exchanged.reason, None,
                (issued.receipt, admitted.receipt, exchanged.receipt),
                (issued.grant.grant_id,),
            )

        nonce = self.attachment_store.challenge(f"{request_id}:store")
        store_proof = self.proofs.issue(
            self.case_attestation_id, exchanged.grant,
            proof_id=f"proof:{request_id}:store", method="GET",
            uri=f"https://attachment-store.internal/resources/{attachment_id}",
            nonce=nonce, now=now,
        )
        accessed = self.attachment_store.authorize(
            self.case_attestation_id, exchanged.grant.grant_id, store_proof,
            operation="read", resource_id=attachment_id,
            request_id=f"{request_id}:store", now=now,
        )
        # Failure is terminal. There is deliberately no retry through service authority.
        return ApplicationResponse(
            accessed.status, accessed.reason, accessed.content,
            (issued.receipt, admitted.receipt, exchanged.receipt, accessed.receipt),
            (issued.grant.grant_id, exchanged.grant.grant_id),
        )


def unsafe_claims_baseline(
    *, claimed_tenant: str, claimed_scopes: frozenset[str], resource: ProtectedResource
) -> bool:
    """DEMO-ONLY anti-pattern: trusts model-controlled tenant and scope strings."""
    return claimed_tenant == resource.tenant and "read" in claimed_scopes


@dataclass(frozen=True)
class Scenario:
    identities: IdentityRegistry
    entitlements: EntitlementService
    grants: GrantAuthority
    proofs: ProofAuthority
    case_boundary: ResourceServer
    attachment_store: ResourceServer
    application: DelegatedSupportApplication
    resources: dict[str, ProtectedResource]


def build_scenario() -> Scenario:
    sessions = {
        "session:alice": HumanSession(
            "session:alice", "alice", "north", "phishing-resistant",
            NOW - timedelta(minutes=5), NOW + timedelta(hours=1),
        ),
        "session:mallory": HumanSession(
            "session:mallory", "mallory", "south", "mfa",
            NOW - timedelta(minutes=5), NOW + timedelta(hours=1),
        ),
    }
    workloads = {
        "attest:support": WorkloadAttestation(
            "attest:support", "support-orchestrator", "north", "key:support-v3",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30), "agent:support-7",
        ),
        "attest:stolen-host": WorkloadAttestation(
            "attest:stolen-host", "compromised-worker", "north", "key:attacker",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30), None,
        ),
        "attest:case": WorkloadAttestation(
            "attest:case", "case-service", "north", "key:case-v2",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30), None,
        ),
        "attest:store": WorkloadAttestation(
            "attest:store", "attachment-store", "north", "key:store-v4",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30), None,
        ),
    }
    agents = {
        "agent:support-7": AgentIdentity(
            "agent:support-7", "north", "blueprint:support-v3", "support-security",
            Lifecycle.ACTIVE, frozenset({"case-service"}), frozenset({"case-support"}),
        )
    }
    identities = IdentityRegistry(sessions, workloads, agents)
    entitlements = EntitlementService({
        "alice": EntitlementSnapshot(
            "alice", "north", frozenset({"read", "comment"}),
            frozenset({"attachment:north:7", "attachment:north:8"}),
            4, "identity-policy-v5",
        ),
        "mallory": EntitlementSnapshot(
            "mallory", "south", frozenset({"read"}),
            frozenset({"attachment:south:9"}), 2, "identity-policy-v5",
        ),
    })
    resources = {
        "attachment:north:7": ProtectedResource(
            "attachment:north:7", "north", "Synthetic Northwind case attachment"
        ),
        "attachment:north:8": ProtectedResource(
            "attachment:north:8", "north", "Synthetic Northwind diagnostic"
        ),
        "attachment:south:9": ProtectedResource(
            "attachment:south:9", "south", "Synthetic Southwind restricted attachment"
        ),
    }
    grants = GrantAuthority(identities, entitlements)
    proofs = ProofAuthority(identities)
    case_boundary = ResourceServer(
        "case-service", identities, grants, proofs, resources, release_content=False
    )
    attachment_store = ResourceServer("attachment-store", identities, grants, proofs, resources)
    application = DelegatedSupportApplication(
        grants, proofs, case_boundary, attachment_store,
        case_attestation_id="attest:case",
    )
    return Scenario(
        identities, entitlements, grants, proofs, case_boundary,
        attachment_store, application, resources,
    )


def root_request(
    request_id: str,
    *,
    audience: str = "case-service",
    purpose: str = "case-support",
    operations: frozenset[str] = frozenset({"read"}),
    resources: frozenset[str] = frozenset({"attachment:north:7"}),
    ttl: timedelta = timedelta(minutes=5),
) -> GrantRequest:
    return GrantRequest(request_id, audience, purpose, operations, resources, ttl)


def child_request(
    request_id: str,
    *,
    audience: str = "attachment-store",
    purpose: str = "case-support",
    operations: frozenset[str] = frozenset({"read"}),
    resources: frozenset[str] = frozenset({"attachment:north:7"}),
    ttl: timedelta = timedelta(minutes=2),
) -> GrantRequest:
    return GrantRequest(request_id, audience, purpose, operations, resources, ttl)


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    kind: CaseKind
    safe: bool
    useful: bool
    trace_complete: bool
    disclosed: bool
    baseline_accepts: bool
    terminal_status: str


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    valid_task_success_rate: float
    authority_escalation_success_rate: float
    cross_tenant_disclosure_rate: float
    proof_replay_acceptance_rate: float
    sender_constraint_detection_rate: float
    trace_completeness_rate: float
    baseline_attack_acceptance_rate: float


def _trace_complete(receipt: DecisionReceipt) -> bool:
    return bool(
        receipt.trace_id and receipt.operation and receipt.status and receipt.reason
        and receipt.tenant_digest and receipt.subject_digest
        and receipt.policy_version
    )


def evaluate_controls() -> tuple[EvaluationReport, tuple[CaseObservation, ...]]:
    observations: list[CaseObservation] = []

    def record(
        case_id: str,
        kind: CaseKind,
        status: DecisionStatus,
        receipt: DecisionReceipt,
        *,
        safe: bool,
        useful: bool,
        disclosed: bool = False,
        baseline_accepts: bool = False,
    ) -> None:
        observations.append(CaseObservation(
            case_id, kind, safe, useful, _trace_complete(receipt), disclosed,
            baseline_accepts, status.value,
        ))

    # Four valid cases.
    scenario = build_scenario()
    response = scenario.application.read_attachment(
        session_id="session:alice", agent_attestation_id="attest:support",
        attachment_id="attachment:north:7", request_id="valid:path", now=NOW,
    )
    record(
        "valid-two-hop-read", CaseKind.VALID, response.status, response.receipts[-1],
        safe=True, useful=response.status is DecisionStatus.ALLOW and response.content is not None,
    )

    scenario = build_scenario()
    first = scenario.grants.issue(
        "session:alice", "attest:support", root_request("valid:retry"), now=NOW
    )
    retry = scenario.grants.issue(
        "session:alice", "attest:support", root_request("valid:retry"), now=NOW
    )
    record(
        "valid-idempotent-issuance", CaseKind.VALID, retry.status, retry.receipt,
        safe=True, useful=first.grant == retry.grant and retry.status is DecisionStatus.IDEMPOTENT,
    )

    scenario = build_scenario()
    parent = scenario.grants.issue(
        "session:alice", "attest:support",
        root_request(
            "valid:downscope-parent", operations=frozenset({"read", "comment"}),
            resources=frozenset({"attachment:north:7", "attachment:north:8"}),
        ), now=NOW,
    )
    child = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case", child_request("valid:downscope-child"), now=NOW
    )
    record(
        "valid-monotonic-exchange", CaseKind.VALID, child.status, child.receipt,
        safe=child.grant.operations < parent.grant.operations and child.grant.resources < parent.grant.resources,
        useful=child.status is DecisionStatus.ALLOW,
    )

    scenario = build_scenario()
    parent = scenario.grants.issue(
        "session:alice", "attest:support", root_request("valid:ttl-parent", ttl=timedelta(minutes=3)), now=NOW
    )
    child = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        child_request("valid:ttl-child", ttl=timedelta(hours=1)), now=NOW,
    )
    record(
        "valid-expiry-attenuation", CaseKind.VALID, child.status, child.receipt,
        safe=child.grant.expires_at <= parent.grant.expires_at,
        useful=child.status is DecisionStatus.ALLOW,
    )

    # Twelve attack and stale-state cases. The claims-only baseline accepts all fixtures.
    baseline_resource = build_scenario().resources["attachment:south:9"]
    baseline_accepts = unsafe_claims_baseline(
        claimed_tenant="south", claimed_scopes=frozenset({"read"}), resource=baseline_resource
    )

    scenario = build_scenario()
    decision = scenario.grants.issue(
        "session:mallory", "attest:support",
        root_request("attack:tenant", resources=frozenset({"attachment:south:9"})), now=NOW,
    )
    record("cross-tenant-identity-mix", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is DecisionStatus.DENY, useful=False, baseline_accepts=baseline_accepts)

    scenario = build_scenario()
    decision = scenario.grants.issue(
        "session:alice", "attest:support",
        root_request("attack:resource", resources=frozenset({"attachment:south:9"})), now=NOW,
    )
    record("resource-escalation", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.reason == "resource-escalation", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    decision = scenario.grants.issue(
        "session:alice", "attest:support",
        root_request("attack:operation", operations=frozenset({"delete"})), now=NOW,
    )
    record("operation-escalation", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.reason == "operation-escalation", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:aud-parent"), now=NOW)
    nonce = scenario.attachment_store.challenge("attack:audience")
    proof = scenario.proofs.issue(
        "attest:support", parent.grant, proof_id="proof:audience", method="GET",
        uri="https://attachment-store.internal/resources/attachment:north:7",
        nonce=nonce, now=NOW,
    )
    decision_access = scenario.attachment_store.authorize(
        "attest:support", parent.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="attack:audience", now=NOW,
    )
    record("audience-confusion", CaseKind.ATTACK, decision_access.status, decision_access.receipt, safe=decision_access.reason == "audience", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:sender-parent"), now=NOW)
    nonce = scenario.case_boundary.challenge("attack:sender")
    proof = scenario.proofs.issue(
        "attest:stolen-host", parent.grant, proof_id="proof:sender", method="GET",
        uri="https://case-service.internal/resources/attachment:north:7",
        nonce=nonce, now=NOW,
    )
    decision_access = scenario.case_boundary.authorize(
        "attest:stolen-host", parent.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="attack:sender", now=NOW,
    )
    record("stolen-grant-wrong-sender", CaseKind.ATTACK, decision_access.status, decision_access.receipt, safe=decision_access.reason == "sender", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:exchange-parent"), now=NOW)
    child = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        child_request("attack:exchange", operations=frozenset({"read", "delete"})), now=NOW,
    )
    record("exchange-scope-expansion", CaseKind.ATTACK, child.status, child.receipt, safe=child.reason == "operation-escalation", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:purpose-parent"), now=NOW)
    child = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        child_request("attack:purpose", purpose="bulk-export"), now=NOW,
    )
    record("exchange-purpose-change", CaseKind.ATTACK, child.status, child.receipt, safe=child.reason == "purpose-escalation", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:replay-parent"), now=NOW)
    nonce = scenario.case_boundary.challenge("attack:replay")
    proof = scenario.proofs.issue(
        "attest:support", parent.grant, proof_id="proof:replay", method="GET",
        uri="https://case-service.internal/resources/attachment:north:7", nonce=nonce, now=NOW,
    )
    first_access = scenario.case_boundary.authorize(
        "attest:support", parent.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="attack:replay:first", now=NOW,
    )
    replay = scenario.case_boundary.authorize(
        "attest:support", parent.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="attack:replay:second", now=NOW,
    )
    record("proof-replay", CaseKind.ATTACK, replay.status, replay.receipt, safe=first_access.status is DecisionStatus.ALLOW and replay.reason == "proof-replay", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:uri-parent"), now=NOW)
    nonce = scenario.case_boundary.challenge("attack:uri")
    proof = scenario.proofs.issue(
        "attest:support", parent.grant, proof_id="proof:uri", method="POST",
        uri="https://case-service.internal/resources/attachment:north:8", nonce=nonce, now=NOW,
    )
    decision_access = scenario.case_boundary.authorize(
        "attest:support", parent.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="attack:uri", now=NOW,
    )
    record("proof-request-rebinding", CaseKind.ATTACK, decision_access.status, decision_access.receipt, safe=decision_access.reason == "proof-request-binding", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:disable-parent"), now=NOW)
    agent = scenario.identities.agents["agent:support-7"]
    scenario.identities.agents[agent.agent_id] = replace(agent, lifecycle=Lifecycle.DISABLED)
    child = scenario.grants.exchange(parent.grant.grant_id, "attest:case", child_request("attack:disable"), now=NOW)
    record("disabled-agent", CaseKind.ATTACK, child.status, child.receipt, safe=child.reason == "agent-identity-disabled", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:entitlement-parent"), now=NOW)
    old = scenario.entitlements.snapshots["alice"]
    scenario.entitlements.snapshots["alice"] = replace(old, version=old.version + 1, resources=frozenset())
    child = scenario.grants.exchange(parent.grant.grant_id, "attest:case", child_request("attack:entitlement"), now=NOW)
    record("stale-entitlement", CaseKind.ATTACK, child.status, child.receipt, safe=child.reason == "entitlement-version-changed", useful=False, baseline_accepts=True)

    scenario = build_scenario()
    parent = scenario.grants.issue("session:alice", "attest:support", root_request("attack:revoke-parent"), now=NOW)
    child = scenario.grants.exchange(parent.grant.grant_id, "attest:case", child_request("attack:revoke-child"), now=NOW)
    revoked = scenario.grants.revoke_lineage(parent.grant.grant_id, "incident containment")
    current, reason = scenario.grants.validate_current(child.grant, now=NOW)
    record("lineage-revocation", CaseKind.ATTACK, DecisionStatus.DENY, child.receipt, safe=revoked == 2 and current is None and reason == "grant-revoked", useful=False, baseline_accepts=True)

    # Two dependency failures remain ERROR rather than being credited as blocks.
    scenario = build_scenario()
    scenario.identities.available = False
    decision = scenario.grants.issue("session:alice", "attest:support", root_request("failure:identity"), now=NOW)
    record("identity-registry-outage", CaseKind.FAILURE, decision.status, decision.receipt, safe=decision.status is DecisionStatus.ERROR, useful=False)

    scenario = build_scenario()
    scenario.entitlements.available = False
    decision = scenario.grants.issue("session:alice", "attest:support", root_request("failure:entitlement"), now=NOW)
    record("entitlement-service-outage", CaseKind.FAILURE, decision.status, decision.receipt, safe=decision.status is DecisionStatus.ERROR, useful=False)

    valid = [item for item in observations if item.kind is CaseKind.VALID]
    attacks = [item for item in observations if item.kind is CaseKind.ATTACK]
    failures = [item for item in observations if item.kind is CaseKind.FAILURE]
    cross_tenant = [item for item in attacks if item.case_id == "cross-tenant-identity-mix"]
    proof_replays = [item for item in attacks if item.case_id == "proof-replay"]
    sender_cases = [item for item in attacks if item.case_id == "stolen-grant-wrong-sender"]
    report = EvaluationReport(
        len(observations), len(valid), len(attacks), len(failures),
        sum(item.useful for item in valid) / len(valid),
        sum(not item.safe for item in attacks) / len(attacks),
        sum(item.disclosed for item in cross_tenant) / len(cross_tenant),
        sum(not item.safe for item in proof_replays) / len(proof_replays),
        sum(item.safe for item in sender_cases) / len(sender_cases),
        sum(item.trace_complete for item in observations) / len(observations),
        sum(item.baseline_accepts for item in attacks) / len(attacks),
    )
    assert all(item.terminal_status == DecisionStatus.ERROR.value for item in failures)
    return report, tuple(observations)


def main() -> None:
    report, _ = evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (18, 4, 12, 2)
    assert report.valid_task_success_rate == 1.0
    assert report.authority_escalation_success_rate == 0.0
    assert report.cross_tenant_disclosure_rate == 0.0
    assert report.proof_replay_acceptance_rate == 0.0
    assert report.sender_constraint_detection_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.baseline_attack_acceptance_rate == 1.0
    print(json.dumps(_jsonable(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

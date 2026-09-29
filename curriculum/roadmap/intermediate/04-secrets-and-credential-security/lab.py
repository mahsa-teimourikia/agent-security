"""Deterministic secrets and credential security lab for Intermediate 04.

The lab uses synthetic material and HMAC integrity as teaching analogues. It
does not implement OAuth, a production vault, a KMS, or secure memory erasure.
Raw credential bytes are materialized only inside the provider executor and are
never returned to model-facing code, receipts, logs, memory, or exceptions.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from threading import RLock
from typing import Any


NOW = datetime(2026, 9, 28, 15, 0, tzinfo=timezone.utc)
_POLICY_MATERIAL_V1 = "demo-material-north-policy-v1"
_POLICY_MATERIAL_V2 = "demo-material-north-policy-v2"
_TICKET_MATERIAL_V1 = "demo-material-north-ticket-v1"


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_jsonable(item) for item in value)
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if hasattr(value, "__dict__"):
        return {key: _jsonable(item) for key, item in value.__dict__.items()}
    return value


def digest(value: Any) -> str:
    payload = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def material_digest(material: bytes | bytearray | memoryview | str) -> str:
    raw = material.encode() if isinstance(material, str) else bytes(material)
    return hashlib.sha256(raw).hexdigest()


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"
    IDEMPOTENT = "idempotent"


class LeaseState(str, Enum):
    ACTIVE = "active"
    CLAIMED = "claimed"
    REVOKED = "revoked"


class SecretState(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class WorkloadAttestation:
    attestation_id: str
    workload_id: str
    tenant: str
    key_thumbprint: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class ProtectedResource:
    resource_id: str
    tenant: str
    audience: str
    operations: frozenset[str]
    content: str


@dataclass(frozen=True)
class SecretMetadata:
    secret_id: str
    version: int
    audience: str
    state: SecretState
    created_at: datetime
    material_digest: str


class EphemeralSecret:
    """Best-effort teaching wrapper; Python cannot promise complete zeroization."""

    def __init__(self, material: bytearray):
        self._buffer = material
        self.zeroized = False

    def __repr__(self) -> str:
        return "<EphemeralSecret redacted>"

    def __enter__(self) -> "EphemeralSecret":
        return self

    def provider_view(self) -> memoryview:
        if self.zeroized:
            raise RuntimeError("credential-handle-zeroized")
        return memoryview(self._buffer)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self.zeroized = True


class InMemorySecretVault:
    """Metadata API plus an executor-only materialization seam."""

    def __init__(self) -> None:
        self._metadata: dict[str, SecretMetadata] = {}
        self._materials: dict[tuple[str, int], bytearray] = {}
        self.available = True
        self.materialization_count = 0

    def register(
        self, secret_id: str, audience: str, material: str, *, now: datetime
    ) -> SecretMetadata:
        metadata = SecretMetadata(
            secret_id, 1, audience, SecretState.ACTIVE, now, material_digest(material)
        )
        self._metadata[secret_id] = metadata
        self._materials[(secret_id, metadata.version)] = bytearray(material.encode())
        return metadata

    def current(self, secret_id: str) -> tuple[SecretMetadata | None, str]:
        if not self.available:
            return None, "secret-vault-unavailable"
        metadata = self._metadata.get(secret_id)
        if metadata is None:
            return None, "secret-unknown"
        if metadata.state is not SecretState.ACTIVE:
            return None, "secret-disabled"
        return metadata, "secret-current"

    def rotate(self, secret_id: str, material: str, *, now: datetime) -> SecretMetadata:
        current, reason = self.current(secret_id)
        if current is None:
            raise RuntimeError(reason)
        metadata = SecretMetadata(
            secret_id, current.version + 1, current.audience,
            SecretState.ACTIVE, now, material_digest(material),
        )
        self._metadata[secret_id] = metadata
        self._materials[(secret_id, metadata.version)] = bytearray(material.encode())
        return metadata

    def disable(self, secret_id: str) -> None:
        current = self._metadata[secret_id]
        self._metadata[secret_id] = replace(current, state=SecretState.DISABLED)

    def materialize(self, secret_id: str, version: int) -> EphemeralSecret:
        if not self.available:
            raise RuntimeError("secret-vault-unavailable")
        current, reason = self.current(secret_id)
        if current is None:
            raise RuntimeError(reason)
        if current.version != version:
            raise RuntimeError("secret-version-changed")
        stored = self._materials.get((secret_id, version))
        if stored is None:
            raise RuntimeError("secret-material-missing")
        self.materialization_count += 1
        return EphemeralSecret(bytearray(stored))


@dataclass
class WorkloadRegistry:
    attestations: dict[str, WorkloadAttestation]
    available: bool = True

    def authenticate(
        self, attestation_id: str, *, now: datetime
    ) -> tuple[WorkloadAttestation | None, str]:
        if not self.available:
            return None, "workload-registry-unavailable"
        workload = self.attestations.get(attestation_id)
        if workload is None:
            return None, "workload-unknown"
        if not (workload.issued_at <= now < workload.expires_at):
            return None, "workload-attestation-expired"
        return workload, "workload-authenticated"


@dataclass(frozen=True)
class CredentialRequest:
    request_id: str
    audience: str
    purpose: str
    operation: str
    resource_id: str
    requested_ttl: timedelta


@dataclass(frozen=True)
class Credential:
    """Compatibility record for the original Pilot's introductory exercise.

    The published application path below uses stateful ``CredentialLease``
    objects and never returns this reference to the model. Keeping the helper
    lets existing learners retain the explicit unsupported-scope exercise.
    """

    subject: str
    tenant: str
    audience: str
    scopes: frozenset[str]
    expires_at: datetime
    secret_ref: str


def issue(
    subject: str,
    tenant: str,
    audience: str,
    scopes: frozenset[str],
    *,
    now: datetime,
) -> Credential:
    """Issue the original bounded teaching credential or reject scope widening."""

    allowed_scopes = {"read_policy", "write_ticket"}
    unsupported = scopes - allowed_scopes
    if unsupported:
        raise ValueError(f"unsupported credential scopes: {sorted(unsupported)}")
    return Credential(
        subject, tenant, audience, scopes, now + timedelta(minutes=5),
        f"vault://agent/{subject}",
    )


def authorize(
    credential: Credential,
    *,
    tenant: str,
    audience: str,
    scope: str,
    now: datetime,
) -> dict[str, str]:
    """Preserve the Pilot decision shape; not used by the agent application."""

    allowed = (
        credential.tenant == tenant
        and credential.audience == audience
        and scope in credential.scopes
        and credential.expires_at > now
    )
    return {
        "decision": "allow" if allowed else "deny",
        "subject": credential.subject,
        "tenant": tenant,
        "scope": scope,
        "secret_ref": credential.secret_ref,
    }


@dataclass(frozen=True)
class CredentialLease:
    lease_id: str
    workload_id: str
    tenant: str
    audience: str
    purpose: str
    operations: frozenset[str]
    resources: frozenset[str]
    confirmation_thumbprint: str
    secret_id: str
    secret_version: int
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    policy_version: str
    key_id: str
    payload_digest: str
    signature: str


@dataclass(frozen=True)
class DecisionReceipt:
    trace_id: str
    stage: str
    status: str
    reason: str
    workload_id: str
    tenant_digest: str
    audience: str
    operation: str
    resource_digest: str
    lease_id: str
    secret_id_digest: str
    secret_version: int
    policy_version: str
    provider_request_id: str = ""


@dataclass(frozen=True)
class LeaseDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    lease: CredentialLease | None = None


@dataclass(frozen=True)
class ExecutionDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    content: str | None = None


@dataclass
class ResourcePolicy:
    resources: dict[str, ProtectedResource]
    version: str = "credential-policy-v4"
    available: bool = True
    allowed_purposes: frozenset[str] = frozenset({"case-support"})

    def authorize(
        self, workload: WorkloadAttestation, request: CredentialRequest
    ) -> tuple[ProtectedResource | None, str]:
        if not self.available:
            return None, "credential-policy-unavailable"
        resource = self.resources.get(request.resource_id)
        if resource is None:
            return None, "resource-unknown"
        if resource.tenant != workload.tenant:
            return None, "resource-tenant"
        if request.audience != resource.audience:
            return None, "audience-policy"
        if request.purpose not in self.allowed_purposes:
            return None, "purpose-policy"
        if request.operation not in resource.operations:
            return None, "operation-policy"
        return resource, "policy-authorized"


class AuditSink:
    """Allowlisted structured evidence; arbitrary messages are not accepted."""

    def __init__(self) -> None:
        self.events: list[DecisionReceipt] = []

    def record(self, receipt: DecisionReceipt) -> None:
        self.events.append(receipt)


class CredentialBroker:
    """Issues signed, stateful, one-use leases without reading secret material."""

    def __init__(
        self,
        workloads: WorkloadRegistry,
        policy: ResourcePolicy,
        vault: InMemorySecretVault,
        audit: AuditSink,
        secret_catalog: dict[str, str],
        *,
        key_id: str = "lease-key-2026-09",
        signing_key: bytes = b"synthetic-lease-integrity-key",
        max_ttl: timedelta = timedelta(minutes=2),
    ):
        self.workloads = workloads
        self.policy = policy
        self.vault = vault
        self.audit = audit
        self.secret_catalog = secret_catalog
        self.key_id = key_id
        self._signing_key = signing_key
        self.max_ttl = max_ttl
        self.available = True
        self.leases: dict[str, CredentialLease] = {}
        self.states: dict[str, LeaseState] = {}
        self.request_ledger: dict[str, tuple[str, str]] = {}
        self._lock = RLock()

    @staticmethod
    def _payload(lease: CredentialLease) -> dict[str, Any]:
        return {
            key: value for key, value in lease.__dict__.items()
            if key not in {"payload_digest", "signature"}
        }

    def _seal(self, lease: CredentialLease) -> CredentialLease:
        payload_digest = digest(self._payload(lease))
        signature = hmac.new(
            self._signing_key, payload_digest.encode(), hashlib.sha256
        ).hexdigest()
        return replace(lease, payload_digest=payload_digest, signature=signature)

    def verify_integrity(self, lease: CredentialLease) -> bool:
        if lease.key_id != self.key_id:
            return False
        payload_digest = digest(self._payload(lease))
        signature = hmac.new(
            self._signing_key, payload_digest.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(lease.payload_digest, payload_digest) and hmac.compare_digest(
            lease.signature, signature
        )

    def _receipt(
        self,
        *,
        trace_id: str,
        stage: str,
        status: DecisionStatus,
        reason: str,
        workload: WorkloadAttestation | None = None,
        request: CredentialRequest | None = None,
        lease: CredentialLease | None = None,
        provider_request_id: str = "",
    ) -> DecisionReceipt:
        tenant = lease.tenant if lease else (workload.tenant if workload else "")
        audience = lease.audience if lease else (request.audience if request else "")
        operation = (
            next(iter(lease.operations)) if lease and lease.operations
            else (request.operation if request else "")
        )
        resource = (
            next(iter(lease.resources)) if lease and lease.resources
            else (request.resource_id if request else "")
        )
        receipt = DecisionReceipt(
            trace_id=trace_id,
            stage=stage,
            status=status.value,
            reason=reason,
            workload_id=lease.workload_id if lease else (workload.workload_id if workload else "unknown"),
            tenant_digest=digest(tenant)[:16] if tenant else "none",
            audience=audience,
            operation=operation,
            resource_digest=digest(resource)[:16] if resource else "none",
            lease_id=lease.lease_id if lease else "",
            secret_id_digest=digest(lease.secret_id)[:16] if lease else "none",
            secret_version=lease.secret_version if lease else 0,
            policy_version=self.policy.version,
            provider_request_id=provider_request_id,
        )
        self.audit.record(receipt)
        return receipt

    def _terminal(
        self,
        request: CredentialRequest,
        status: DecisionStatus,
        reason: str,
        *,
        workload: WorkloadAttestation | None = None,
        lease: CredentialLease | None = None,
    ) -> LeaseDecision:
        receipt = self._receipt(
            trace_id=f"trace:{request.request_id}", stage="credential-issue",
            status=status, reason=reason, workload=workload,
            request=request, lease=lease,
        )
        return LeaseDecision(status, reason, receipt)

    def issue(
        self, attestation_id: str, request: CredentialRequest, *, now: datetime
    ) -> LeaseDecision:
        if not self.available:
            return self._terminal(request, DecisionStatus.ERROR, "credential-broker-unavailable")
        workload, reason = self.workloads.authenticate(attestation_id, now=now)
        if workload is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(request, status, reason)
        resource, reason = self.policy.authorize(workload, request)
        if resource is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(request, status, reason, workload=workload)
        secret_id = self.secret_catalog.get(request.audience)
        if secret_id is None:
            return self._terminal(
                request, DecisionStatus.DENY, "credential-route-unknown", workload=workload
            )
        metadata, reason = self.vault.current(secret_id)
        if metadata is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(request, status, reason, workload=workload)
        if metadata.audience != request.audience:
            return self._terminal(
                request, DecisionStatus.DENY, "secret-audience", workload=workload
            )
        if request.requested_ttl <= timedelta(0):
            return self._terminal(request, DecisionStatus.DENY, "ttl-invalid", workload=workload)

        request_digest = digest({
            "workload": workload.workload_id,
            "key": workload.key_thumbprint,
            "tenant": workload.tenant,
            "request": request,
            "policy": self.policy.version,
            "secret_version": metadata.version,
        })
        with self._lock:
            previous = self.request_ledger.get(request.request_id)
            if previous:
                previous_digest, lease_id = previous
                if previous_digest != request_digest:
                    return self._terminal(
                        request, DecisionStatus.DENY, "request-id-collision", workload=workload
                    )
                lease = self.leases[lease_id]
                receipt = self._receipt(
                    trace_id=f"trace:{request.request_id}", stage="credential-issue",
                    status=DecisionStatus.IDEMPOTENT, reason="issuance-request-replay",
                    workload=workload, request=request, lease=lease,
                )
                return LeaseDecision(
                    DecisionStatus.IDEMPOTENT, "issuance-request-replay", receipt, lease
                )

            expires_at = min(
                now + min(request.requested_ttl, self.max_ttl), workload.expires_at
            )
            lease_id = f"lease:{digest([request.request_id, request_digest])[:20]}"
            lease = CredentialLease(
                lease_id=lease_id,
                workload_id=workload.workload_id,
                tenant=workload.tenant,
                audience=request.audience,
                purpose=request.purpose,
                operations=frozenset({request.operation}),
                resources=frozenset({request.resource_id}),
                confirmation_thumbprint=workload.key_thumbprint,
                secret_id=metadata.secret_id,
                secret_version=metadata.version,
                issued_at=now,
                not_before=now,
                expires_at=expires_at,
                policy_version=self.policy.version,
                key_id=self.key_id,
                payload_digest="",
                signature="",
            )
            sealed = self._seal(lease)
            self.leases[sealed.lease_id] = sealed
            self.states[sealed.lease_id] = LeaseState.ACTIVE
            self.request_ledger[request.request_id] = (request_digest, sealed.lease_id)
        receipt = self._receipt(
            trace_id=f"trace:{request.request_id}", stage="credential-issue",
            status=DecisionStatus.ALLOW, reason="credential-lease-issued",
            workload=workload, request=request, lease=sealed,
        )
        return LeaseDecision(DecisionStatus.ALLOW, "credential-lease-issued", receipt, sealed)

    def validate_current(
        self, lease: CredentialLease, *, now: datetime
    ) -> tuple[SecretMetadata | None, str]:
        if not self.available:
            return None, "credential-broker-unavailable"
        registered = self.leases.get(lease.lease_id)
        if registered is None or registered != lease or not self.verify_integrity(lease):
            return None, "credential-lease-integrity"
        state = self.states.get(lease.lease_id)
        if state is LeaseState.CLAIMED:
            return None, "credential-lease-replayed"
        if state is not LeaseState.ACTIVE:
            return None, "credential-lease-revoked"
        if not (lease.not_before <= now < lease.expires_at):
            return None, "credential-lease-expired"
        if lease.policy_version != self.policy.version:
            return None, "credential-policy-version-changed"
        metadata, reason = self.vault.current(lease.secret_id)
        if metadata is None:
            return None, reason
        if metadata.version != lease.secret_version:
            return None, "secret-version-changed"
        if metadata.audience != lease.audience:
            return None, "secret-audience"
        return metadata, "credential-lease-current"

    def claim(
        self, lease: CredentialLease, *, now: datetime
    ) -> tuple[SecretMetadata | None, str]:
        with self._lock:
            metadata, reason = self.validate_current(lease, now=now)
            if metadata is None:
                return None, reason
            self.states[lease.lease_id] = LeaseState.CLAIMED
            return metadata, "credential-lease-claimed"

    def revoke(self, lease_id: str, reason: str) -> bool:
        if not reason.strip() or lease_id not in self.leases:
            return False
        with self._lock:
            self.states[lease_id] = LeaseState.REVOKED
        return True


class SyntheticProvider:
    """External provider analogue storing credential digests, never raw values."""

    def __init__(self, audience: str, resources: dict[str, ProtectedResource]):
        self.audience = audience
        self.resources = resources
        self._accepted: dict[tuple[str, int], str] = {}
        self._current_versions: dict[str, int] = {}
        self.available = True
        self.leaking_error = False
        self.dispatch_count = 0

    def register_credential(self, metadata: SecretMetadata, material: str) -> None:
        self._accepted[(metadata.secret_id, metadata.version)] = material_digest(material)
        self._current_versions[metadata.secret_id] = metadata.version

    def call(
        self,
        *,
        secret_id: str,
        secret_version: int,
        credential: memoryview,
        operation: str,
        resource_id: str,
        request_id: str,
    ) -> str:
        if not self.available:
            raise RuntimeError("provider-unavailable")
        if self.leaking_error:
            # Deliberately unsafe dependency behavior; the executor must not echo it.
            raw = bytes(credential).decode(errors="replace")
            raise RuntimeError(f"provider rejected Authorization credential {raw}")
        expected = self._accepted.get((secret_id, secret_version))
        if self._current_versions.get(secret_id) != secret_version or expected is None:
            raise PermissionError("provider-credential-version")
        if not hmac.compare_digest(expected, material_digest(credential)):
            raise PermissionError("provider-credential-invalid")
        resource = self.resources.get(resource_id)
        if resource is None or resource.audience != self.audience:
            raise PermissionError("provider-resource")
        if operation not in resource.operations:
            raise PermissionError("provider-operation")
        self.dispatch_count += 1
        return resource.content


class CredentialExecutor:
    """Only component allowed to materialize and present a credential."""

    def __init__(
        self,
        broker: CredentialBroker,
        workloads: WorkloadRegistry,
        policy: ResourcePolicy,
        vault: InMemorySecretVault,
        provider: SyntheticProvider,
    ):
        self.broker = broker
        self.workloads = workloads
        self.policy = policy
        self.vault = vault
        self.provider = provider
        self.last_handle_zeroized = False

    def _terminal(
        self,
        *,
        request_id: str,
        status: DecisionStatus,
        reason: str,
        lease: CredentialLease | None,
        workload: WorkloadAttestation | None = None,
        operation: str = "",
        resource_id: str = "",
    ) -> ExecutionDecision:
        request = CredentialRequest(
            request_id, self.provider.audience, lease.purpose if lease else "",
            operation, resource_id, timedelta(0),
        )
        receipt = self.broker._receipt(
            trace_id=f"trace:{request_id}", stage="provider-execute",
            status=status, reason=reason, workload=workload,
            request=request, lease=lease, provider_request_id=request_id,
        )
        return ExecutionDecision(status, reason, receipt)

    def execute(
        self,
        attestation_id: str,
        lease_id: str,
        *,
        operation: str,
        resource_id: str,
        request_id: str,
        now: datetime,
    ) -> ExecutionDecision:
        lease = self.broker.leases.get(lease_id)
        if lease is None:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY,
                reason="credential-lease-unknown", lease=None,
                operation=operation, resource_id=resource_id,
            )
        metadata, reason = self.broker.validate_current(lease, now=now)
        if metadata is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request_id=request_id, status=status, reason=reason, lease=lease,
                operation=operation, resource_id=resource_id,
            )
        workload, reason = self.workloads.authenticate(attestation_id, now=now)
        if workload is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request_id=request_id, status=status, reason=reason, lease=lease,
                operation=operation, resource_id=resource_id,
            )
        if workload.workload_id != lease.workload_id or workload.tenant != lease.tenant:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY, reason="credential-sender",
                lease=lease, workload=workload, operation=operation, resource_id=resource_id,
            )
        if workload.key_thumbprint != lease.confirmation_thumbprint:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY, reason="credential-sender-key",
                lease=lease, workload=workload, operation=operation, resource_id=resource_id,
            )
        if lease.audience != self.provider.audience:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY, reason="credential-audience",
                lease=lease, workload=workload, operation=operation, resource_id=resource_id,
            )
        if operation not in lease.operations:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY, reason="credential-operation",
                lease=lease, workload=workload, operation=operation, resource_id=resource_id,
            )
        if resource_id not in lease.resources:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY, reason="credential-resource",
                lease=lease, workload=workload, operation=operation, resource_id=resource_id,
            )
        current_request = CredentialRequest(
            request_id, self.provider.audience, lease.purpose,
            operation, resource_id, lease.expires_at - now,
        )
        resource, reason = self.policy.authorize(workload, current_request)
        if resource is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request_id=request_id, status=status, reason=reason, lease=lease,
                workload=workload, operation=operation, resource_id=resource_id,
            )
        claimed_metadata, reason = self.broker.claim(lease, now=now)
        if claimed_metadata is None:
            status = DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY
            return self._terminal(
                request_id=request_id, status=status, reason=reason, lease=lease,
                workload=workload, operation=operation, resource_id=resource_id,
            )

        handle: EphemeralSecret | None = None
        try:
            handle = self.vault.materialize(lease.secret_id, lease.secret_version)
            with handle:
                content = self.provider.call(
                    secret_id=lease.secret_id,
                    secret_version=lease.secret_version,
                    credential=handle.provider_view(),
                    operation=operation,
                    resource_id=resource_id,
                    request_id=request_id,
                )
        except PermissionError:
            return self._terminal(
                request_id=request_id, status=DecisionStatus.DENY,
                reason="provider-credential-rejected", lease=lease,
                workload=workload, operation=operation, resource_id=resource_id,
            )
        except RuntimeError as error:
            safe_reason = (
                str(error) if str(error) in {"provider-unavailable", "secret-vault-unavailable"}
                else "provider-error-redacted"
            )
            return self._terminal(
                request_id=request_id, status=DecisionStatus.ERROR,
                reason=safe_reason, lease=lease, workload=workload,
                operation=operation, resource_id=resource_id,
            )
        finally:
            self.last_handle_zeroized = bool(handle and handle.zeroized)

        receipt = self.broker._receipt(
            trace_id=f"trace:{request_id}", stage="provider-execute",
            status=DecisionStatus.ALLOW, reason="provider-authorized",
            workload=workload, request=current_request, lease=lease,
            provider_request_id=request_id,
        )
        return ExecutionDecision(DecisionStatus.ALLOW, "provider-authorized", receipt, content)


@dataclass(frozen=True)
class ApplicationResponse:
    status: DecisionStatus
    reason: str
    content: str | None
    receipts: tuple[DecisionReceipt, ...]
    lease_id: str = ""


class CredentialedSupportApplication:
    """Application-owned identity and credential route; no ambient fallback."""

    def __init__(
        self,
        broker: CredentialBroker,
        policy_executor: CredentialExecutor,
        ticket_executor: CredentialExecutor,
    ):
        self.broker = broker
        self.policy_executor = policy_executor
        self.ticket_executor = ticket_executor
        self.ambient_fallback_count = 0

    def _invoke(
        self,
        *,
        attestation_id: str,
        audience: str,
        operation: str,
        resource_id: str,
        request_id: str,
        now: datetime,
    ) -> ApplicationResponse:
        request = CredentialRequest(
            f"{request_id}:lease", audience, "case-support", operation,
            resource_id, timedelta(seconds=45),
        )
        issued = self.broker.issue(attestation_id, request, now=now)
        if issued.lease is None:
            return ApplicationResponse(issued.status, issued.reason, None, (issued.receipt,))
        executor = self.policy_executor if audience == "policy-api" else self.ticket_executor
        executed = executor.execute(
            attestation_id, issued.lease.lease_id,
            operation=operation, resource_id=resource_id,
            request_id=f"{request_id}:provider", now=now,
        )
        return ApplicationResponse(
            executed.status, executed.reason, executed.content,
            (issued.receipt, executed.receipt), issued.lease.lease_id,
        )

    def read_policy(
        self, *, attestation_id: str, policy_id: str, request_id: str, now: datetime
    ) -> ApplicationResponse:
        return self._invoke(
            attestation_id=attestation_id, audience="policy-api",
            operation="read_policy", resource_id=policy_id,
            request_id=request_id, now=now,
        )

    def create_ticket(
        self, *, attestation_id: str, ticket_id: str, request_id: str, now: datetime
    ) -> ApplicationResponse:
        return self._invoke(
            attestation_id=attestation_id, audience="ticket-api",
            operation="write_ticket", resource_id=ticket_id,
            request_id=request_id, now=now,
        )


@dataclass(frozen=True)
class Scenario:
    workloads: WorkloadRegistry
    resources: dict[str, ProtectedResource]
    policy: ResourcePolicy
    vault: InMemorySecretVault
    audit: AuditSink
    broker: CredentialBroker
    policy_provider: SyntheticProvider
    ticket_provider: SyntheticProvider
    policy_executor: CredentialExecutor
    ticket_executor: CredentialExecutor
    application: CredentialedSupportApplication

    def rotate_policy_credential(self, *, now: datetime) -> SecretMetadata:
        metadata = self.vault.rotate(
            "secret:policy-api:north", _POLICY_MATERIAL_V2, now=now
        )
        self.policy_provider.register_credential(metadata, _POLICY_MATERIAL_V2)
        return metadata


def build_scenario() -> Scenario:
    workloads = WorkloadRegistry({
        "attest:support": WorkloadAttestation(
            "attest:support", "support-agent", "north", "key:support-v5",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
        "attest:south": WorkloadAttestation(
            "attest:south", "support-agent-south", "south", "key:south-v2",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
        "attest:stolen": WorkloadAttestation(
            "attest:stolen", "compromised-worker", "north", "key:attacker",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
    })
    resources = {
        "policy:north:7": ProtectedResource(
            "policy:north:7", "north", "policy-api",
            frozenset({"read_policy"}), "Synthetic Northwind policy summary",
        ),
        "policy:north:8": ProtectedResource(
            "policy:north:8", "north", "policy-api",
            frozenset({"read_policy"}), "Synthetic Northwind renewal terms",
        ),
        "policy:south:9": ProtectedResource(
            "policy:south:9", "south", "policy-api",
            frozenset({"read_policy"}), "Synthetic Southwind policy summary",
        ),
        "ticket:north:7": ProtectedResource(
            "ticket:north:7", "north", "ticket-api",
            frozenset({"write_ticket"}), "Synthetic ticket accepted",
        ),
    }
    policy = ResourcePolicy(resources)
    vault = InMemorySecretVault()
    policy_meta = vault.register(
        "secret:policy-api:north", "policy-api", _POLICY_MATERIAL_V1, now=NOW
    )
    ticket_meta = vault.register(
        "secret:ticket-api:north", "ticket-api", _TICKET_MATERIAL_V1, now=NOW
    )
    audit = AuditSink()
    broker = CredentialBroker(
        workloads, policy, vault, audit,
        {"policy-api": policy_meta.secret_id, "ticket-api": ticket_meta.secret_id},
    )
    policy_provider = SyntheticProvider("policy-api", resources)
    policy_provider.register_credential(policy_meta, _POLICY_MATERIAL_V1)
    ticket_provider = SyntheticProvider("ticket-api", resources)
    ticket_provider.register_credential(ticket_meta, _TICKET_MATERIAL_V1)
    policy_executor = CredentialExecutor(
        broker, workloads, policy, vault, policy_provider
    )
    ticket_executor = CredentialExecutor(
        broker, workloads, policy, vault, ticket_provider
    )
    application = CredentialedSupportApplication(
        broker, policy_executor, ticket_executor
    )
    return Scenario(
        workloads, resources, policy, vault, audit, broker,
        policy_provider, ticket_provider, policy_executor,
        ticket_executor, application,
    )


def policy_request(
    request_id: str,
    *,
    resource_id: str = "policy:north:7",
    audience: str = "policy-api",
    purpose: str = "case-support",
    operation: str = "read_policy",
    ttl: timedelta = timedelta(seconds=45),
) -> CredentialRequest:
    return CredentialRequest(
        request_id, audience, purpose, operation, resource_id, ttl
    )


def contains_material(surface: Any, markers: tuple[str, ...]) -> bool:
    serialized = json.dumps(_jsonable(surface), sort_keys=True, default=str)
    return any(marker in serialized for marker in markers)


def unsafe_context_baseline(material: str) -> dict[str, Any]:
    """DEMO-ONLY anti-pattern: reusable material reaches every agent surface."""
    return {
        "model_context": f"Use provider credential {material}",
        "memory": {"provider_credential": material},
        "trace": {"authorization": f"Bearer {material}"},
        "exception": f"provider rejected {material}",
    }


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    kind: CaseKind
    status: str
    useful: bool
    misuse_attempt: bool
    replay_probe: bool
    stale_probe: bool
    exposure_probe: bool
    secret_exposed: bool
    trace_complete: bool


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    credential_misuse_cases: int
    exposure_cases: int
    valid_task_success_rate: float
    credential_misuse_success_rate: float
    secret_exposure_rate: float
    replay_acceptance_rate: float
    stale_credential_acceptance_rate: float
    failure_error_preservation_rate: float
    trace_completeness_rate: float
    unsafe_baseline_exposure_rate: float


def _trace_complete(receipt: DecisionReceipt) -> bool:
    return bool(
        receipt.trace_id and receipt.stage and receipt.status and receipt.reason
        and receipt.tenant_digest and receipt.policy_version
    )


def evaluate_controls() -> tuple[EvaluationReport, tuple[CaseObservation, ...]]:
    observations: list[CaseObservation] = []

    def record(
        case_id: str,
        kind: CaseKind,
        decision: LeaseDecision | ExecutionDecision | ApplicationResponse,
        receipt: DecisionReceipt,
        *,
        useful: bool = False,
        misuse_attempt: bool = False,
        replay_probe: bool = False,
        stale_probe: bool = False,
        exposure_probe: bool = False,
        secret_exposed: bool = False,
    ) -> None:
        observations.append(CaseObservation(
            case_id, kind, decision.status.value, useful, misuse_attempt,
            replay_probe, stale_probe, exposure_probe, secret_exposed,
            _trace_complete(receipt),
        ))

    # Four valid cases.
    scenario = build_scenario()
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:7",
        request_id="valid:read", now=NOW,
    )
    record(
        "valid-policy-read", CaseKind.VALID, response, response.receipts[-1],
        useful=response.status is DecisionStatus.ALLOW and response.content is not None,
    )

    scenario = build_scenario()
    response = scenario.application.create_ticket(
        attestation_id="attest:support", ticket_id="ticket:north:7",
        request_id="valid:ticket", now=NOW,
    )
    record(
        "valid-separate-ticket-credential", CaseKind.VALID, response,
        response.receipts[-1],
        useful=response.status is DecisionStatus.ALLOW and response.content is not None,
    )

    scenario = build_scenario()
    first = scenario.broker.issue(
        "attest:support", policy_request("valid:idempotent"), now=NOW
    )
    retry = scenario.broker.issue(
        "attest:support", policy_request("valid:idempotent"), now=NOW
    )
    record(
        "valid-idempotent-issuance", CaseKind.VALID, retry, retry.receipt,
        useful=(retry.status is DecisionStatus.IDEMPOTENT and retry.lease == first.lease),
    )

    scenario = build_scenario()
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:8",
        request_id="valid:zeroize", now=NOW,
    )
    record(
        "valid-ephemeral-zeroization", CaseKind.VALID, response,
        response.receipts[-1],
        useful=(response.status is DecisionStatus.ALLOW and scenario.policy_executor.last_handle_zeroized),
    )

    # Eleven credential-misuse attacks plus one exposure attack.
    scenario = build_scenario()
    decision = scenario.broker.issue(
        "attest:south", policy_request("attack:tenant", resource_id="policy:north:7"), now=NOW
    )
    record("cross-tenant-issuance", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:audience"), now=NOW)
    decision = scenario.ticket_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:audience:execute", now=NOW,
    )
    record("cross-audience-replay", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:operation"), now=NOW)
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="write_ticket",
        resource_id="policy:north:7", request_id="attack:operation:execute", now=NOW,
    )
    record("operation-escalation", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:resource"), now=NOW)
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:8", request_id="attack:resource:execute", now=NOW,
    )
    record("resource-escalation", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:sender"), now=NOW)
    decision = scenario.policy_executor.execute(
        "attest:stolen", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:sender:execute", now=NOW,
    )
    record("stolen-lease-wrong-workload", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:key"), now=NOW)
    original = scenario.workloads.attestations["attest:support"]
    scenario.workloads.attestations["attest:support"] = replace(
        original, key_thumbprint="key:rotated-unbound"
    )
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:key:execute", now=NOW,
    )
    record("sender-key-mismatch", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:support", policy_request("attack:expired", ttl=timedelta(seconds=1)), now=NOW
    )
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:expired:execute",
        now=NOW + timedelta(seconds=1),
    )
    record("expired-lease", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:revoked"), now=NOW)
    scenario.broker.revoke(issued.lease.lease_id, "incident-response")
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:revoked:execute", now=NOW,
    )
    record("revoked-lease", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:stale"), now=NOW)
    scenario.rotate_policy_credential(now=NOW + timedelta(seconds=1))
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:stale:execute",
        now=NOW + timedelta(seconds=1),
    )
    record(
        "stale-secret-version", CaseKind.ATTACK, decision, decision.receipt,
        misuse_attempt=True, stale_probe=True,
    )

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:tamper"), now=NOW)
    tampered = replace(issued.lease, operations=frozenset({"read_policy", "write_ticket"}))
    scenario.broker.leases[tampered.lease_id] = tampered
    decision = scenario.policy_executor.execute(
        "attest:support", tampered.lease_id, operation="write_ticket",
        resource_id="policy:north:7", request_id="attack:tamper:execute", now=NOW,
    )
    record("tampered-lease", CaseKind.ATTACK, decision, decision.receipt, misuse_attempt=True)

    scenario = build_scenario()
    issued = scenario.broker.issue("attest:support", policy_request("attack:replay"), now=NOW)
    first = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:replay:first", now=NOW,
    )
    decision = scenario.policy_executor.execute(
        "attest:support", issued.lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="attack:replay:second", now=NOW,
    )
    assert first.status is DecisionStatus.ALLOW
    record(
        "consumed-lease-replay", CaseKind.ATTACK, decision, decision.receipt,
        misuse_attempt=True, replay_probe=True,
    )

    scenario = build_scenario()
    scenario.policy_provider.leaking_error = True
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:7",
        request_id="attack:leaking-error", now=NOW,
    )
    controlled_surface = {"response": response, "audit": scenario.audit.events}
    exposed = contains_material(controlled_surface, (_POLICY_MATERIAL_V1,))
    record(
        "provider-error-redaction", CaseKind.ATTACK, response,
        response.receipts[-1], exposure_probe=True, secret_exposed=exposed,
    )

    # Two dependency failures; neither may use cached or ambient authority.
    scenario = build_scenario()
    scenario.vault.available = False
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:7",
        request_id="failure:vault", now=NOW,
    )
    record("vault-unavailable", CaseKind.FAILURE, response, response.receipts[-1])

    scenario = build_scenario()
    scenario.policy_provider.available = False
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:7",
        request_id="failure:provider", now=NOW,
    )
    record("provider-unavailable", CaseKind.FAILURE, response, response.receipts[-1])

    valid = [item for item in observations if item.kind is CaseKind.VALID]
    attacks = [item for item in observations if item.kind is CaseKind.ATTACK]
    failures = [item for item in observations if item.kind is CaseKind.FAILURE]
    misuse = [item for item in observations if item.misuse_attempt]
    exposures = [item for item in observations if item.exposure_probe]
    replays = [item for item in observations if item.replay_probe]
    stale = [item for item in observations if item.stale_probe]
    baseline = unsafe_context_baseline(_POLICY_MATERIAL_V1)
    baseline_exposed = contains_material(baseline, (_POLICY_MATERIAL_V1,))

    report = EvaluationReport(
        cases=len(observations),
        valid_cases=len(valid),
        attack_cases=len(attacks),
        failure_cases=len(failures),
        credential_misuse_cases=len(misuse),
        exposure_cases=len(exposures),
        valid_task_success_rate=sum(item.useful for item in valid) / len(valid),
        credential_misuse_success_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in misuse) / len(misuse)
        ),
        secret_exposure_rate=sum(item.secret_exposed for item in exposures) / len(exposures),
        replay_acceptance_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in replays) / len(replays)
        ),
        stale_credential_acceptance_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in stale) / len(stale)
        ),
        failure_error_preservation_rate=(
            sum(item.status == DecisionStatus.ERROR.value for item in failures) / len(failures)
        ),
        trace_completeness_rate=(
            sum(item.trace_complete for item in observations) / len(observations)
        ),
        unsafe_baseline_exposure_rate=1.0 if baseline_exposed else 0.0,
    )
    return report, tuple(observations)


def main() -> None:
    report, _ = evaluate_controls()
    assert report.valid_task_success_rate == 1.0
    assert report.credential_misuse_success_rate == 0.0
    assert report.secret_exposure_rate == 0.0
    assert report.replay_acceptance_rate == 0.0
    assert report.stale_credential_acceptance_rate == 0.0
    assert report.failure_error_preservation_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.unsafe_baseline_exposure_rate == 1.0
    print(json.dumps(_jsonable(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

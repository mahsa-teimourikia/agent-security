"""Deterministic egress, SSRF, and external-resource security lab.

The lab performs no DNS lookup or network request. Synthetic resolver and
transport fixtures expose the decisions a production egress broker, proxy,
and streaming client must enforce independently of an agent.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
from ipaddress import ip_address, ip_network
import json
import posixpath
from threading import RLock
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
METADATA_NETWORKS = tuple(
    ip_network(value)
    for value in ("169.254.169.254/32", "fd00:ec2::254/128", "fd20:ce::254/128")
)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, frozenset | set | tuple | list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if is_dataclass(value):
        return _jsonable(asdict(value))
    return value


def digest(value: Any) -> str:
    payload = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"
    IDEMPOTENT = "idempotent"


class GrantState(str, Enum):
    ACTIVE = "active"
    CLAIMED = "claimed"
    REVOKED = "revoked"


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
class FetchPolicy:
    """Tenant-owned policy. The first field preserves the original lab API."""

    allow_hosts: frozenset[str]
    version: str = "egress-policy-v4"
    path_prefixes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    allowed_methods: frozenset[str] = frozenset({"GET"})
    allowed_ports: frozenset[int] = frozenset({443})
    allowed_content_types: frozenset[str] = frozenset(
        {"application/json", "text/html", "text/plain"}
    )
    max_redirects: int = 2
    max_dns_answers: int = 4
    max_bytes: int = 10_000
    max_decoded_bytes: int = 20_000
    max_expansion_ratio: float = 10.0
    timeout_seconds: float = 1.5
    max_url_length: int = 2_048


@dataclass
class PolicyRegistry:
    policies: dict[str, FetchPolicy]
    available: bool = True

    def current(self, tenant: str) -> tuple[FetchPolicy | None, str]:
        if not self.available:
            return None, "egress-policy-unavailable"
        policy = self.policies.get(tenant)
        if policy is None:
            return None, "egress-policy-missing"
        return policy, "egress-policy-current"


@dataclass(frozen=True)
class CanonicalURL:
    normalized: str
    scheme: str
    host: str
    port: int
    path: str
    query: str

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}"


def canonicalize_url(
    raw_url: str, *, max_length: int = 2_048
) -> tuple[CanonicalURL | None, str]:
    """Parse once, reject ambiguity, and return the representation used later."""

    if not isinstance(raw_url, str) or not raw_url or len(raw_url) > max_length:
        return None, "url-length"
    if any(ord(char) < 32 or ord(char) == 127 for char in raw_url):
        return None, "url-control-character"
    if "\\" in raw_url:
        return None, "url-backslash"
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        return None, "url-authority-invalid"
    if parsed.scheme.lower() != "https":
        return None, "url-scheme"
    if parsed.username is not None or parsed.password is not None:
        return None, "url-userinfo"
    if not host:
        return None, "url-host-missing"
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None, "url-host-invalid"
    if not ascii_host or len(ascii_host) > 253:
        return None, "url-host-invalid"
    try:
        ip_address(ascii_host)
    except ValueError:
        pass
    else:
        return None, "url-ip-literal"
    port = 443 if port is None else port
    if port != 443:
        return None, "url-port"
    if parsed.fragment:
        return None, "url-fragment"
    if len(parsed.query) > 512:
        return None, "url-query-length"
    raw_path = parsed.path or "/"
    decoded_path = unquote(raw_path)
    if unquote(decoded_path) != decoded_path:
        return None, "url-encoding-depth"
    if "\\" in decoded_path or any(ord(char) < 32 for char in decoded_path):
        return None, "url-path-invalid"
    segments = decoded_path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return None, "url-dot-segment"
    normalized_path = posixpath.normpath(decoded_path)
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    if decoded_path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"
    encoded_path = quote(normalized_path, safe="/-._~")
    normalized = urlunsplit(("https", ascii_host, encoded_path, parsed.query, ""))
    return CanonicalURL(
        normalized, "https", ascii_host, port, encoded_path, parsed.query
    ), "url-canonical"


def authorize_url(
    canonical: CanonicalURL, policy: FetchPolicy, *, method: str
) -> str:
    method = method.upper()
    if method not in policy.allowed_methods:
        return "method-denied"
    if canonical.port not in policy.allowed_ports:
        return "port-denied"
    if canonical.host not in policy.allow_hosts:
        return "host-denied"
    prefixes = policy.path_prefixes.get(canonical.host, ())
    if prefixes and not any(canonical.path.startswith(prefix) for prefix in prefixes):
        return "path-denied"
    return "url-authorized"


def validate_addresses(
    addresses: tuple[str, ...], policy: FetchPolicy
) -> tuple[tuple[str, ...] | None, str]:
    """Require every A/AAAA result to be globally routable and non-metadata."""

    if not addresses:
        return None, "dns-empty"
    if len(addresses) > policy.max_dns_answers:
        return None, "dns-answer-limit"
    normalized: set[str] = set()
    for raw in addresses:
        try:
            candidate = ip_address(raw)
        except ValueError:
            return None, "dns-address-invalid"
        if getattr(candidate, "ipv4_mapped", None) is not None:
            candidate = candidate.ipv4_mapped
        if any(candidate in network for network in METADATA_NETWORKS):
            return None, "dns-metadata-address"
        if not candidate.is_global:
            return None, "dns-non-global-address"
        normalized.add(candidate.compressed)
    return tuple(sorted(normalized)), "dns-addresses-admitted"


@dataclass(frozen=True)
class Resolution:
    host: str
    addresses: tuple[str, ...]
    generation: int
    resolution_digest: str


class SyntheticResolver:
    """Deterministic A/AAAA snapshots; no operating-system DNS is used."""

    def __init__(
        self,
        records: dict[str, tuple[str, ...]],
        sequences: dict[str, tuple[tuple[str, ...], ...]] | None = None,
    ):
        self.records = records
        self.sequences = sequences or {}
        self.calls: dict[str, int] = {}
        self.available = True

    def resolve(self, host: str) -> tuple[Resolution | None, str]:
        if not self.available:
            return None, "dns-resolver-unavailable"
        index = self.calls.get(host, 0)
        self.calls[host] = index + 1
        sequence = self.sequences.get(host)
        if sequence:
            addresses = sequence[min(index, len(sequence) - 1)]
        else:
            addresses = self.records.get(host, ())
        if not addresses:
            return None, "dns-not-found"
        return Resolution(
            host, tuple(addresses), index,
            digest({"host": host, "addresses": addresses}),
        ), "dns-resolved"


@dataclass(frozen=True)
class FetchProposal:
    request_id: str
    url: str
    method: str = "GET"


@dataclass(frozen=True)
class FetchGrant:
    grant_id: str
    workload_id: str
    tenant: str
    confirmation_thumbprint: str
    method: str
    canonical_url: str
    host: str
    policy_version: str
    resolution_digest: str
    approved_addresses: tuple[str, ...]
    max_redirects: int
    max_bytes: int
    max_decoded_bytes: int
    timeout_seconds: float
    issued_at: datetime
    expires_at: datetime
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
    destination_origin: str
    path_digest: str
    policy_version: str
    grant_id: str = ""
    peer_address: str = "none"
    redirects: int = 0
    wire_bytes: int = 0
    decoded_bytes: int = 0
    elapsed_ms: int = 0
    result_digest: str = "none"


class AuditSink:
    def __init__(self) -> None:
        self.events: list[DecisionReceipt] = []

    def record(self, receipt: DecisionReceipt) -> None:
        self.events.append(receipt)


@dataclass(frozen=True)
class GrantDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    grant: FetchGrant | None = None


class FetchBroker:
    """Turns an untrusted URL proposal into current, one-use fetch authority."""

    def __init__(
        self,
        workloads: WorkloadRegistry,
        policies: PolicyRegistry,
        resolver: SyntheticResolver,
        audit: AuditSink,
        *,
        signing_key: bytes = b"synthetic-egress-grant-key",
    ):
        self.workloads = workloads
        self.policies = policies
        self.resolver = resolver
        self.audit = audit
        self.signing_key = signing_key
        self.available = True
        self.grants: dict[str, FetchGrant] = {}
        self.states: dict[str, GrantState] = {}
        self.request_ledger: dict[str, tuple[str, str]] = {}
        self._lock = RLock()

    @staticmethod
    def _payload(grant: FetchGrant) -> dict[str, Any]:
        return {
            key: value for key, value in grant.__dict__.items()
            if key not in {"payload_digest", "signature"}
        }

    def _seal(self, grant: FetchGrant) -> FetchGrant:
        payload_digest = digest(self._payload(grant))
        signature = hmac.new(
            self.signing_key, payload_digest.encode(), hashlib.sha256
        ).hexdigest()
        return replace(grant, payload_digest=payload_digest, signature=signature)

    def verify_integrity(self, grant: FetchGrant) -> bool:
        payload_digest = digest(self._payload(grant))
        signature = hmac.new(
            self.signing_key, payload_digest.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(grant.payload_digest, payload_digest) and hmac.compare_digest(
            grant.signature, signature
        )

    @staticmethod
    def _status(reason: str) -> DecisionStatus:
        return DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY

    def _receipt(
        self,
        *,
        trace_id: str,
        stage: str,
        status: DecisionStatus,
        reason: str,
        workload: WorkloadAttestation | None = None,
        policy: FetchPolicy | None = None,
        canonical: CanonicalURL | None = None,
        grant: FetchGrant | None = None,
        peer_address: str = "none",
        redirects: int = 0,
        wire_bytes: int = 0,
        decoded_bytes: int = 0,
        elapsed_ms: int = 0,
        result_digest: str = "none",
    ) -> DecisionReceipt:
        tenant = grant.tenant if grant else (workload.tenant if workload else "")
        url = canonical
        if url is None and grant is not None:
            url, _ = canonicalize_url(grant.canonical_url)
        receipt = DecisionReceipt(
            trace_id=trace_id,
            stage=stage,
            status=status.value,
            reason=reason,
            workload_id=grant.workload_id if grant else (
                workload.workload_id if workload else "unknown"
            ),
            tenant_digest=digest(tenant)[:16] if tenant else "none",
            destination_origin=url.origin if url else "none",
            path_digest=digest(url.path)[:16] if url else "none",
            policy_version=(grant.policy_version if grant else policy.version if policy else "none"),
            grant_id=grant.grant_id if grant else "",
            peer_address=peer_address,
            redirects=redirects,
            wire_bytes=wire_bytes,
            decoded_bytes=decoded_bytes,
            elapsed_ms=elapsed_ms,
            result_digest=result_digest,
        )
        self.audit.record(receipt)
        return receipt

    def _terminal(
        self,
        proposal: FetchProposal,
        status: DecisionStatus,
        reason: str,
        *,
        workload: WorkloadAttestation | None = None,
        policy: FetchPolicy | None = None,
        canonical: CanonicalURL | None = None,
    ) -> GrantDecision:
        receipt = self._receipt(
            trace_id=f"trace:{proposal.request_id}", stage="egress-admission",
            status=status, reason=reason, workload=workload, policy=policy,
            canonical=canonical,
        )
        return GrantDecision(status, reason, receipt)

    def issue(
        self, attestation_id: str, proposal: FetchProposal, *, now: datetime
    ) -> GrantDecision:
        if not self.available:
            return self._terminal(
                proposal, DecisionStatus.ERROR, "egress-broker-unavailable"
            )
        workload, reason = self.workloads.authenticate(attestation_id, now=now)
        if workload is None:
            return self._terminal(proposal, self._status(reason), reason)
        policy, reason = self.policies.current(workload.tenant)
        if policy is None:
            return self._terminal(
                proposal, self._status(reason), reason, workload=workload
            )
        canonical, reason = canonicalize_url(
            proposal.url, max_length=policy.max_url_length
        )
        if canonical is None:
            return self._terminal(
                proposal, DecisionStatus.DENY, reason,
                workload=workload, policy=policy,
            )
        reason = authorize_url(canonical, policy, method=proposal.method)
        if reason != "url-authorized":
            return self._terminal(
                proposal, DecisionStatus.DENY, reason, workload=workload,
                policy=policy, canonical=canonical,
            )
        resolution, reason = self.resolver.resolve(canonical.host)
        if resolution is None:
            return self._terminal(
                proposal, self._status(reason), reason, workload=workload,
                policy=policy, canonical=canonical,
            )
        addresses, reason = validate_addresses(resolution.addresses, policy)
        if addresses is None:
            return self._terminal(
                proposal, DecisionStatus.DENY, reason, workload=workload,
                policy=policy, canonical=canonical,
            )
        request_digest = digest({
            "proposal": proposal,
            "workload": workload.workload_id,
            "tenant": workload.tenant,
            "key": workload.key_thumbprint,
            "url": canonical.normalized,
            "policy": policy.version,
            "resolution": digest(addresses),
        })
        with self._lock:
            previous = self.request_ledger.get(proposal.request_id)
            if previous:
                previous_digest, grant_id = previous
                if previous_digest != request_digest:
                    return self._terminal(
                        proposal, DecisionStatus.DENY, "request-id-collision",
                        workload=workload, policy=policy, canonical=canonical,
                    )
                grant = self.grants[grant_id]
                receipt = self._receipt(
                    trace_id=f"trace:{proposal.request_id}",
                    stage="egress-admission", status=DecisionStatus.IDEMPOTENT,
                    reason="fetch-request-replay", workload=workload,
                    policy=policy, canonical=canonical, grant=grant,
                )
                return GrantDecision(
                    DecisionStatus.IDEMPOTENT, "fetch-request-replay", receipt, grant
                )
            grant_id = f"fetch-grant:{digest([proposal.request_id, request_digest])[:20]}"
            grant = FetchGrant(
                grant_id=grant_id,
                workload_id=workload.workload_id,
                tenant=workload.tenant,
                confirmation_thumbprint=workload.key_thumbprint,
                method=proposal.method.upper(),
                canonical_url=canonical.normalized,
                host=canonical.host,
                policy_version=policy.version,
                resolution_digest=digest(addresses),
                approved_addresses=addresses,
                max_redirects=policy.max_redirects,
                max_bytes=policy.max_bytes,
                max_decoded_bytes=policy.max_decoded_bytes,
                timeout_seconds=policy.timeout_seconds,
                issued_at=now,
                expires_at=min(now + timedelta(seconds=30), workload.expires_at),
                payload_digest="",
                signature="",
            )
            sealed = self._seal(grant)
            self.grants[grant_id] = sealed
            self.states[grant_id] = GrantState.ACTIVE
            self.request_ledger[proposal.request_id] = (request_digest, grant_id)
        receipt = self._receipt(
            trace_id=f"trace:{proposal.request_id}", stage="egress-admission",
            status=DecisionStatus.ALLOW, reason="fetch-grant-issued",
            workload=workload, policy=policy, canonical=canonical, grant=sealed,
        )
        return GrantDecision(
            DecisionStatus.ALLOW, "fetch-grant-issued", receipt, sealed
        )

    def validate_current(
        self, grant: FetchGrant, *, now: datetime
    ) -> tuple[tuple[CanonicalURL, FetchPolicy, tuple[str, ...]] | None, str]:
        if not self.available:
            return None, "egress-broker-unavailable"
        registered = self.grants.get(grant.grant_id)
        if registered is None or registered != grant or not self.verify_integrity(grant):
            return None, "fetch-grant-integrity"
        state = self.states.get(grant.grant_id)
        if state is GrantState.CLAIMED:
            return None, "fetch-grant-replayed"
        if state is not GrantState.ACTIVE:
            return None, "fetch-grant-revoked"
        if not (grant.issued_at <= now < grant.expires_at):
            return None, "fetch-grant-expired"
        policy, reason = self.policies.current(grant.tenant)
        if policy is None:
            return None, reason
        if policy.version != grant.policy_version:
            return None, "egress-policy-version-changed"
        canonical, reason = canonicalize_url(
            grant.canonical_url, max_length=policy.max_url_length
        )
        if canonical is None or canonical.host != grant.host:
            return None, "fetch-grant-url"
        reason = authorize_url(canonical, policy, method=grant.method)
        if reason != "url-authorized":
            return None, reason
        resolution, reason = self.resolver.resolve(canonical.host)
        if resolution is None:
            return None, reason
        addresses, reason = validate_addresses(resolution.addresses, policy)
        if addresses is None:
            return None, reason
        if digest(addresses) != grant.resolution_digest or addresses != grant.approved_addresses:
            return None, "dns-answer-changed"
        return (canonical, policy, addresses), "fetch-grant-current"

    def claim(
        self, grant: FetchGrant, *, now: datetime
    ) -> tuple[tuple[CanonicalURL, FetchPolicy, tuple[str, ...]] | None, str]:
        with self._lock:
            current, reason = self.validate_current(grant, now=now)
            if current is None:
                return None, reason
            self.states[grant.grant_id] = GrantState.CLAIMED
            return current, "fetch-grant-claimed"

    def revoke(self, grant_id: str, reason: str) -> bool:
        if not reason.strip() or grant_id not in self.grants:
            return False
        with self._lock:
            self.states[grant_id] = GrantState.REVOKED
        return True


@dataclass(frozen=True)
class BodyChunk:
    wire_bytes: int
    decoded_text: str


@dataclass(frozen=True)
class SyntheticResponse:
    status_code: int
    peer_address: str
    tls_server_name: str
    tls_valid: bool
    headers: tuple[tuple[str, str], ...]
    chunks: tuple[BodyChunk, ...]
    elapsed_ms: int

    def header(self, name: str) -> str | None:
        values = [value for key, value in self.headers if key.lower() == name.lower()]
        return values[0] if len(values) == 1 else None


class SyntheticTransport:
    """Records pinned-address dispatches without opening sockets."""

    def __init__(self, fixtures: dict[str, SyntheticResponse]):
        self.fixtures = fixtures
        self.available = True
        self.dispatches: list[tuple[str, str, str]] = []
        self.host_network_calls = 0

    def request(
        self, canonical_url: str, *, connect_ip: str, server_name: str
    ) -> tuple[SyntheticResponse | None, str]:
        if not self.available:
            return None, "egress-transport-unavailable"
        self.dispatches.append((canonical_url, connect_ip, server_name))
        response = self.fixtures.get(canonical_url)
        if response is None:
            return None, "upstream-fixture-missing"
        return response, "upstream-response"


@dataclass(frozen=True)
class FetchResult:
    final_url: str
    content_type: str
    body: str
    body_digest: str
    peer_address: str
    redirect_count: int
    wire_bytes: int
    decoded_bytes: int
    elapsed_ms: int
    trust_label: str = "external-untrusted"


@dataclass(frozen=True)
class ExecutionDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    result: FetchResult | None = None


class DeterministicFetchExecutor:
    """Manually validates each hop and streams bounded synthetic response data."""

    def __init__(
        self,
        broker: FetchBroker,
        workloads: WorkloadRegistry,
        resolver: SyntheticResolver,
        transport: SyntheticTransport,
    ):
        self.broker = broker
        self.workloads = workloads
        self.resolver = resolver
        self.transport = transport

    def _finish(
        self,
        *,
        request_id: str,
        grant: FetchGrant,
        status: DecisionStatus,
        reason: str,
        canonical: CanonicalURL | None = None,
        peer_address: str = "none",
        redirects: int = 0,
        wire_bytes: int = 0,
        decoded_bytes: int = 0,
        elapsed_ms: int = 0,
        result: FetchResult | None = None,
    ) -> ExecutionDecision:
        receipt = self.broker._receipt(
            trace_id=f"trace:{request_id}", stage="egress-execution",
            status=status, reason=reason, grant=grant, canonical=canonical,
            peer_address=peer_address, redirects=redirects,
            wire_bytes=wire_bytes, decoded_bytes=decoded_bytes,
            elapsed_ms=elapsed_ms,
            result_digest=result.body_digest if result else "none",
        )
        return ExecutionDecision(status, reason, receipt, result)

    def _admit_hop(
        self, raw_url: str, policy: FetchPolicy, *, method: str
    ) -> tuple[tuple[CanonicalURL, tuple[str, ...]] | None, str]:
        canonical, reason = canonicalize_url(raw_url, max_length=policy.max_url_length)
        if canonical is None:
            return None, reason
        reason = authorize_url(canonical, policy, method=method)
        if reason != "url-authorized":
            return None, reason
        resolution, reason = self.resolver.resolve(canonical.host)
        if resolution is None:
            return None, reason
        addresses, reason = validate_addresses(resolution.addresses, policy)
        if addresses is None:
            return None, reason
        return (canonical, addresses), "redirect-hop-admitted"

    def execute(
        self,
        attestation_id: str,
        grant_id: str,
        *,
        request_id: str,
        now: datetime,
    ) -> ExecutionDecision:
        grant = self.broker.grants.get(grant_id)
        if grant is None:
            return ExecutionDecision(
                DecisionStatus.DENY, "fetch-grant-unknown",
                self.broker._receipt(
                    trace_id=f"trace:{request_id}", stage="egress-execution",
                    status=DecisionStatus.DENY, reason="fetch-grant-unknown",
                ),
            )
        workload, reason = self.workloads.authenticate(attestation_id, now=now)
        if workload is None:
            return self._finish(
                request_id=request_id, grant=grant,
                status=FetchBroker._status(reason), reason=reason,
            )
        if workload.workload_id != grant.workload_id or workload.tenant != grant.tenant:
            return self._finish(
                request_id=request_id, grant=grant, status=DecisionStatus.DENY,
                reason="fetch-sender",
            )
        if workload.key_thumbprint != grant.confirmation_thumbprint:
            return self._finish(
                request_id=request_id, grant=grant, status=DecisionStatus.DENY,
                reason="fetch-sender-key",
            )
        current, reason = self.broker.claim(grant, now=now)
        if current is None:
            return self._finish(
                request_id=request_id, grant=grant,
                status=FetchBroker._status(reason), reason=reason,
            )
        canonical, policy, addresses = current
        redirects = 0
        elapsed_ms = 0
        wire_bytes = 0
        decoded_bytes = 0
        seen = {canonical.normalized}

        while True:
            connect_ip = addresses[0]
            response, reason = self.transport.request(
                canonical.normalized, connect_ip=connect_ip,
                server_name=canonical.host,
            )
            if response is None:
                return self._finish(
                    request_id=request_id, grant=grant,
                    status=FetchBroker._status(reason), reason=reason,
                    canonical=canonical, peer_address=connect_ip,
                    redirects=redirects, wire_bytes=wire_bytes,
                    decoded_bytes=decoded_bytes, elapsed_ms=elapsed_ms,
                )
            elapsed_ms += response.elapsed_ms
            if elapsed_ms > int(policy.timeout_seconds * 1_000):
                return self._finish(
                    request_id=request_id, grant=grant, status=DecisionStatus.DENY,
                    reason="response-deadline", canonical=canonical,
                    peer_address=response.peer_address, redirects=redirects,
                    wire_bytes=wire_bytes, decoded_bytes=decoded_bytes,
                    elapsed_ms=elapsed_ms,
                )
            if response.peer_address != connect_ip:
                return self._finish(
                    request_id=request_id, grant=grant, status=DecisionStatus.DENY,
                    reason="connection-peer-mismatch", canonical=canonical,
                    peer_address=response.peer_address, redirects=redirects,
                    elapsed_ms=elapsed_ms,
                )
            if not response.tls_valid or response.tls_server_name != canonical.host:
                return self._finish(
                    request_id=request_id, grant=grant, status=DecisionStatus.DENY,
                    reason="tls-identity", canonical=canonical,
                    peer_address=response.peer_address, redirects=redirects,
                    elapsed_ms=elapsed_ms,
                )
            if response.status_code in REDIRECT_STATUSES:
                location = response.header("location")
                if not location:
                    return self._finish(
                        request_id=request_id, grant=grant,
                        status=DecisionStatus.DENY, reason="redirect-location-invalid",
                        canonical=canonical, peer_address=response.peer_address,
                        redirects=redirects, elapsed_ms=elapsed_ms,
                    )
                if redirects >= policy.max_redirects:
                    return self._finish(
                        request_id=request_id, grant=grant,
                        status=DecisionStatus.DENY, reason="redirect-limit",
                        canonical=canonical, peer_address=response.peer_address,
                        redirects=redirects, elapsed_ms=elapsed_ms,
                    )
                next_url = urljoin(canonical.normalized, location)
                admitted, reason = self._admit_hop(
                    next_url, policy, method=grant.method
                )
                if admitted is None:
                    return self._finish(
                        request_id=request_id, grant=grant,
                        status=FetchBroker._status(reason), reason=f"redirect-{reason}",
                        canonical=canonical, peer_address=response.peer_address,
                        redirects=redirects, elapsed_ms=elapsed_ms,
                    )
                next_canonical, next_addresses = admitted
                if next_canonical.normalized in seen:
                    return self._finish(
                        request_id=request_id, grant=grant,
                        status=DecisionStatus.DENY, reason="redirect-loop",
                        canonical=next_canonical,
                        peer_address=response.peer_address,
                        redirects=redirects + 1, elapsed_ms=elapsed_ms,
                    )
                seen.add(next_canonical.normalized)
                redirects += 1
                canonical, addresses = next_canonical, next_addresses
                continue
            if response.status_code != 200:
                return self._finish(
                    request_id=request_id, grant=grant,
                    status=DecisionStatus.DENY, reason="upstream-status",
                    canonical=canonical, peer_address=response.peer_address,
                    redirects=redirects, elapsed_ms=elapsed_ms,
                )
            content_type_header = response.header("content-type")
            content_type = (
                content_type_header.split(";", 1)[0].strip().lower()
                if content_type_header else ""
            )
            if content_type not in policy.allowed_content_types:
                return self._finish(
                    request_id=request_id, grant=grant,
                    status=DecisionStatus.DENY, reason="response-content-type",
                    canonical=canonical, peer_address=response.peer_address,
                    redirects=redirects, elapsed_ms=elapsed_ms,
                )
            content_length = response.header("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    return self._finish(
                        request_id=request_id, grant=grant,
                        status=DecisionStatus.DENY,
                        reason="response-content-length-invalid",
                        canonical=canonical, peer_address=response.peer_address,
                        redirects=redirects, elapsed_ms=elapsed_ms,
                    )
                if declared_length < 0 or declared_length > policy.max_bytes:
                    return self._finish(
                        request_id=request_id, grant=grant,
                        status=DecisionStatus.DENY, reason="response-wire-limit",
                        canonical=canonical, peer_address=response.peer_address,
                        redirects=redirects, elapsed_ms=elapsed_ms,
                    )
            body_parts: list[str] = []
            for chunk in response.chunks:
                if chunk.wire_bytes < 0:
                    reason = "response-chunk-invalid"
                    break
                wire_bytes += chunk.wire_bytes
                decoded_size = len(chunk.decoded_text.encode())
                decoded_bytes += decoded_size
                if wire_bytes > policy.max_bytes:
                    reason = "response-wire-limit"
                    break
                if decoded_bytes > policy.max_decoded_bytes:
                    reason = "response-decoded-limit"
                    break
                if decoded_bytes / max(1, wire_bytes) > policy.max_expansion_ratio:
                    reason = "response-expansion-limit"
                    break
                body_parts.append(chunk.decoded_text)
            else:
                body = "".join(body_parts)
                result = FetchResult(
                    final_url=canonical.normalized,
                    content_type=content_type,
                    body=body,
                    body_digest=digest(body),
                    peer_address=response.peer_address,
                    redirect_count=redirects,
                    wire_bytes=wire_bytes,
                    decoded_bytes=decoded_bytes,
                    elapsed_ms=elapsed_ms,
                )
                return self._finish(
                    request_id=request_id, grant=grant,
                    status=DecisionStatus.ALLOW, reason="fetch-complete",
                    canonical=canonical, peer_address=response.peer_address,
                    redirects=redirects, wire_bytes=wire_bytes,
                    decoded_bytes=decoded_bytes, elapsed_ms=elapsed_ms,
                    result=result,
                )
            return self._finish(
                request_id=request_id, grant=grant, status=DecisionStatus.DENY,
                reason=reason, canonical=canonical,
                peer_address=response.peer_address, redirects=redirects,
                wire_bytes=wire_bytes, decoded_bytes=decoded_bytes,
                elapsed_ms=elapsed_ms,
            )


@dataclass(frozen=True)
class ApplicationResponse:
    status: DecisionStatus
    reason: str
    result: FetchResult | None
    receipts: tuple[DecisionReceipt, ...]
    grant_id: str = ""


class ResearchFetchApplication:
    """Trusted route. Resolver/transport failure never falls back to host fetch."""

    def __init__(self, broker: FetchBroker, executor: DeterministicFetchExecutor):
        self.broker = broker
        self.executor = executor
        self.fallback_fetch_count = 0

    def fetch(
        self,
        *,
        attestation_id: str,
        url: str,
        request_id: str,
        now: datetime,
    ) -> ApplicationResponse:
        issued = self.broker.issue(
            attestation_id, FetchProposal(f"{request_id}:grant", url), now=now
        )
        if issued.grant is None:
            return ApplicationResponse(
                issued.status, issued.reason, None, (issued.receipt,)
            )
        executed = self.executor.execute(
            attestation_id, issued.grant.grant_id,
            request_id=f"{request_id}:execute", now=now,
        )
        return ApplicationResponse(
            executed.status, executed.reason, executed.result,
            (issued.receipt, executed.receipt), issued.grant.grant_id,
        )


@dataclass(frozen=True)
class Scenario:
    workloads: WorkloadRegistry
    policies: PolicyRegistry
    resolver: SyntheticResolver
    transport: SyntheticTransport
    audit: AuditSink
    broker: FetchBroker
    executor: DeterministicFetchExecutor
    application: ResearchFetchApplication


def response_fixture(
    *,
    status: int = 200,
    peer: str = "93.184.216.34",
    tls_name: str = "research.example.test",
    tls_valid: bool = True,
    content_type: str = "application/json",
    body: str = '{"status":"current"}',
    wire_bytes: int | None = None,
    elapsed_ms: int = 80,
    location: str | None = None,
    content_length: str | None = None,
) -> SyntheticResponse:
    headers: list[tuple[str, str]] = [("content-type", content_type)]
    if location is not None:
        headers.append(("location", location))
    encoded_size = len(body.encode()) if wire_bytes is None else wire_bytes
    if content_length is not None:
        headers.append(("content-length", content_length))
    chunks = () if status in REDIRECT_STATUSES else (BodyChunk(encoded_size, body),)
    return SyntheticResponse(
        status, peer, tls_name, tls_valid, tuple(headers), chunks, elapsed_ms
    )


def build_scenario() -> Scenario:
    workloads = WorkloadRegistry({
        "attest:north": WorkloadAttestation(
            "attest:north", "research-agent-north", "north", "key:north-v4",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
        "attest:south": WorkloadAttestation(
            "attest:south", "research-agent-south", "south", "key:south-v3",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
        "attest:stolen": WorkloadAttestation(
            "attest:stolen", "compromised-worker", "north", "key:attacker",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
    })
    north = FetchPolicy(
        frozenset({
            "research.example.test", "status.example.test", "v6.example.test"
        }),
        path_prefixes={
            "research.example.test": ("/docs/",),
            "status.example.test": ("/public/",),
            "v6.example.test": ("/docs/",),
        },
    )
    south = FetchPolicy(
        frozenset({"partner.example.test"}),
        version="egress-policy-south-v2",
        path_prefixes={"partner.example.test": ("/docs/",)},
    )
    policies = PolicyRegistry({"north": north, "south": south})
    resolver = SyntheticResolver({
        "research.example.test": ("93.184.216.34",),
        "status.example.test": ("1.1.1.1",),
        "v6.example.test": ("2606:4700:4700::1111",),
        "partner.example.test": ("8.8.8.8",),
    })
    fixtures = {
        "https://research.example.test/docs/guide": response_fixture(),
        "https://research.example.test/docs/html": response_fixture(
            content_type="text/html; charset=utf-8", body="<h1>Current guide</h1>"
        ),
        "https://research.example.test/docs/redirect": response_fixture(
            status=302, body="", location="https://status.example.test/public/service"
        ),
        "https://status.example.test/public/service": response_fixture(
            peer="1.1.1.1", tls_name="status.example.test",
            body='{"service":"healthy"}',
        ),
        "https://v6.example.test/docs/guide": response_fixture(
            peer="2606:4700:4700::1111", tls_name="v6.example.test",
            content_type="text/plain", body="IPv6 research source",
        ),
        "https://research.example.test/docs/edge": response_fixture(
            body="x" * north.max_bytes, wire_bytes=north.max_bytes,
            content_type="text/plain", content_length=str(north.max_bytes),
        ),
        "https://partner.example.test/docs/guide": response_fixture(
            peer="8.8.8.8", tls_name="partner.example.test",
            body='{"partner":"south"}',
        ),
    }
    transport = SyntheticTransport(fixtures)
    audit = AuditSink()
    broker = FetchBroker(workloads, policies, resolver, audit)
    executor = DeterministicFetchExecutor(broker, workloads, resolver, transport)
    application = ResearchFetchApplication(broker, executor)
    return Scenario(
        workloads, policies, resolver, transport, audit, broker, executor, application
    )


def allowed_url(
    url: str,
    policy: FetchPolicy,
    *,
    resolved_ip: str,
    redirects: int = 0,
) -> dict[str, Any]:
    """Compatibility entry point from the pilot, now using the shared controls."""

    canonical, reason = canonicalize_url(url, max_length=policy.max_url_length)
    if canonical is None:
        return {"allow": False, "reason": reason}
    if redirects > policy.max_redirects:
        return {"allow": False, "reason": "redirect-limit"}
    reason = authorize_url(canonical, policy, method="GET")
    if reason != "url-authorized":
        return {"allow": False, "reason": reason}
    addresses, reason = validate_addresses((resolved_ip,), policy)
    if addresses is None:
        return {"allow": False, "reason": reason}
    return {
        "allow": True,
        "reason": "allow",
        "destination": canonical.host,
        "approved_addresses": addresses,
        "max_bytes": policy.max_bytes,
        "timeout_seconds": policy.timeout_seconds,
    }


def unsafe_host_only_baseline(url: str, allow_hosts: frozenset[str]) -> bool:
    """DEMO-ONLY: ignores DNS answers, redirects, connection peer, and body."""

    try:
        return (urlsplit(url).hostname or "").lower() in allow_hosts
    except ValueError:
        return False


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    kind: CaseKind
    status: str
    useful: bool
    destination_probe: bool
    redirect_probe: bool
    resource_probe: bool
    tls_probe: bool
    replay_probe: bool
    trace_complete: bool
    elapsed_ms: int
    admitted_bytes: int


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    forbidden_destination_cases: int
    redirect_cases: int
    resource_cases: int
    valid_fetch_completion_rate: float
    forbidden_destination_success_rate: float
    redirect_policy_bypass_rate: float
    resource_limit_enforcement_rate: float
    tls_bypass_rate: float
    replay_acceptance_rate: float
    dependency_failure_error_rate: float
    trace_completeness_rate: float
    baseline_bypass_rate: float
    simulated_valid_p95_elapsed_ms: int
    max_valid_body_admitted_bytes: int


def _trace_complete(receipt: DecisionReceipt) -> bool:
    return bool(
        receipt.trace_id and receipt.stage and receipt.status and receipt.reason
        and receipt.policy_version
    )


def _p95(values: list[int]) -> int:
    ordered = sorted(values)
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def evaluate_controls() -> tuple[EvaluationReport, tuple[CaseObservation, ...]]:
    observations: list[CaseObservation] = []

    def record(
        case_id: str,
        kind: CaseKind,
        response: ApplicationResponse | ExecutionDecision | GrantDecision,
        receipt: DecisionReceipt,
        *,
        useful: bool = False,
        destination_probe: bool = False,
        redirect_probe: bool = False,
        resource_probe: bool = False,
        tls_probe: bool = False,
        replay_probe: bool = False,
    ) -> None:
        observations.append(CaseObservation(
            case_id, kind, response.status.value, useful, destination_probe,
            redirect_probe, resource_probe, tls_probe, replay_probe,
            _trace_complete(receipt), receipt.elapsed_ms, receipt.decoded_bytes,
        ))

    valid_urls = (
        "https://research.example.test/docs/guide",
        "https://research.example.test/docs/html",
        "https://research.example.test/docs/redirect",
        "https://v6.example.test/docs/guide",
        "https://research.example.test/docs/edge",
    )
    for index, url in enumerate(valid_urls):
        scenario = build_scenario()
        response = scenario.application.fetch(
            attestation_id="attest:north", url=url,
            request_id=f"valid:{index}", now=NOW,
        )
        record(
            f"valid-{index}", CaseKind.VALID, response, response.receipts[-1],
            useful=response.status is DecisionStatus.ALLOW and response.result is not None,
        )

    # Admission attacks.
    for label, url in (
        ("http-scheme", "http://research.example.test/docs/guide"),
        ("userinfo", "https://trusted@research.example.test/docs/guide"),
        ("ip-literal", "https://169.254.169.254/latest/meta-data"),
        ("host", "https://evil.example.test/docs/guide"),
        ("cross-tenant-host", "https://partner.example.test/docs/guide"),
        ("path", "https://research.example.test/admin"),
    ):
        scenario = build_scenario()
        response = scenario.application.fetch(
            attestation_id="attest:north", url=url,
            request_id=f"attack:{label}", now=NOW,
        )
        record(
            label, CaseKind.ATTACK, response, response.receipts[-1],
            destination_probe=label in {"ip-literal", "host", "cross-tenant-host"},
        )

    for label, addresses in (
        ("private-dns", ("10.0.0.8",)),
        ("loopback-dns", ("127.0.0.1",)),
        ("metadata-v4", ("169.254.169.254",)),
        ("metadata-v6", ("fd00:ec2::254",)),
        ("mixed-dns", ("93.184.216.34", "10.0.0.8")),
        ("mapped-loopback", ("::ffff:127.0.0.1",)),
    ):
        scenario = build_scenario()
        scenario.resolver.records["research.example.test"] = addresses
        response = scenario.application.fetch(
            attestation_id="attest:north",
            url="https://research.example.test/docs/guide",
            request_id=f"attack:{label}", now=NOW,
        )
        record(
            label, CaseKind.ATTACK, response, response.receipts[-1],
            destination_probe=True,
        )

    # Redirect attacks.
    for label, location, records in (
        ("redirect-host", "https://evil.example.test/admin", {}),
        ("redirect-private", "https://status.example.test/public/service", {"status.example.test": ("10.0.0.9",)}),
        ("redirect-loop", "https://research.example.test/docs/redirect", {}),
    ):
        scenario = build_scenario()
        scenario.transport.fixtures["https://research.example.test/docs/redirect"] = response_fixture(
            status=302, body="", location=location
        )
        scenario.resolver.records.update(records)
        response = scenario.application.fetch(
            attestation_id="attest:north",
            url="https://research.example.test/docs/redirect",
            request_id=f"attack:{label}", now=NOW,
        )
        record(
            label, CaseKind.ATTACK, response, response.receipts[-1],
            destination_probe=label == "redirect-private", redirect_probe=True,
        )

    scenario = build_scenario()
    scenario.policies.policies["north"] = replace(
        scenario.policies.policies["north"], max_redirects=0
    )
    response = scenario.application.fetch(
        attestation_id="attest:north",
        url="https://research.example.test/docs/redirect",
        request_id="attack:redirect-limit", now=NOW,
    )
    record(
        "redirect-limit", CaseKind.ATTACK, response, response.receipts[-1],
        redirect_probe=True,
    )

    # Resolution changes after admission.
    scenario = build_scenario()
    scenario.resolver.sequences["research.example.test"] = (
        ("93.184.216.34",), ("10.0.0.8",),
    )
    response = scenario.application.fetch(
        attestation_id="attest:north",
        url="https://research.example.test/docs/guide",
        request_id="attack:dns-rebinding", now=NOW,
    )
    record(
        "dns-rebinding", CaseKind.ATTACK, response, response.receipts[-1],
        destination_probe=True,
    )

    # Peer/TLS/resource response attacks.
    response_attacks = (
        ("peer-mismatch", response_fixture(peer="10.0.0.8"), True, False, False),
        ("tls-mismatch", response_fixture(tls_name="evil.example.test"), False, True, False),
        ("slow-response", response_fixture(elapsed_ms=1_501), False, False, True),
        ("wire-limit", response_fixture(body="x", content_length="10001"), False, False, True),
        ("decoded-limit", response_fixture(body="x" * 20_001, wire_bytes=9_000), False, False, True),
        ("expansion-limit", response_fixture(body="x" * 5_000, wire_bytes=100), False, False, True),
        ("content-type", response_fixture(content_type="application/octet-stream"), False, False, False),
    )
    for label, fixture, destination_probe, tls_probe, resource_probe in response_attacks:
        scenario = build_scenario()
        scenario.transport.fixtures["https://research.example.test/docs/guide"] = fixture
        response = scenario.application.fetch(
            attestation_id="attest:north",
            url="https://research.example.test/docs/guide",
            request_id=f"attack:{label}", now=NOW,
        )
        record(
            label, CaseKind.ATTACK, response, response.receipts[-1],
            destination_probe=destination_probe, tls_probe=tls_probe,
            resource_probe=resource_probe,
        )

    # Replay and tamper.
    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        FetchProposal("attack:replay", "https://research.example.test/docs/guide"),
        now=NOW,
    )
    first = scenario.executor.execute(
        "attest:north", issued.grant.grant_id,
        request_id="attack:replay:first", now=NOW,
    )
    replay = scenario.executor.execute(
        "attest:north", issued.grant.grant_id,
        request_id="attack:replay:second", now=NOW,
    )
    assert first.status is DecisionStatus.ALLOW
    record(
        "grant-replay", CaseKind.ATTACK, replay, replay.receipt,
        replay_probe=True,
    )

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        FetchProposal("attack:tamper", "https://research.example.test/docs/guide"),
        now=NOW,
    )
    tampered = replace(issued.grant, host="evil.example.test")
    scenario.broker.grants[tampered.grant_id] = tampered
    decision = scenario.executor.execute(
        "attest:north", tampered.grant_id,
        request_id="attack:tamper:execute", now=NOW,
    )
    record("grant-tamper", CaseKind.ATTACK, decision, decision.receipt)

    # Dependency failures.
    scenario = build_scenario()
    scenario.resolver.available = False
    response = scenario.application.fetch(
        attestation_id="attest:north",
        url="https://research.example.test/docs/guide",
        request_id="failure:resolver", now=NOW,
    )
    record("resolver-unavailable", CaseKind.FAILURE, response, response.receipts[-1])

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        FetchProposal("failure:transport", "https://research.example.test/docs/guide"),
        now=NOW,
    )
    scenario.transport.available = False
    decision = scenario.executor.execute(
        "attest:north", issued.grant.grant_id,
        request_id="failure:transport:execute", now=NOW,
    )
    record("transport-unavailable", CaseKind.FAILURE, decision, decision.receipt)

    valid = [item for item in observations if item.kind is CaseKind.VALID]
    attacks = [item for item in observations if item.kind is CaseKind.ATTACK]
    failures = [item for item in observations if item.kind is CaseKind.FAILURE]
    destinations = [item for item in observations if item.destination_probe]
    redirects = [item for item in observations if item.redirect_probe]
    resources = [item for item in observations if item.resource_probe]
    tls = [item for item in observations if item.tls_probe]
    replays = [item for item in observations if item.replay_probe]
    baseline_bypasses = (
        unsafe_host_only_baseline(
            "https://research.example.test/docs/guide",
            frozenset({"research.example.test"}),
        ),
        unsafe_host_only_baseline(
            "https://research.example.test/docs/redirect",
            frozenset({"research.example.test"}),
        ),
    )
    report = EvaluationReport(
        cases=len(observations),
        valid_cases=len(valid),
        attack_cases=len(attacks),
        failure_cases=len(failures),
        forbidden_destination_cases=len(destinations),
        redirect_cases=len(redirects),
        resource_cases=len(resources),
        valid_fetch_completion_rate=sum(item.useful for item in valid) / len(valid),
        forbidden_destination_success_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in destinations)
            / len(destinations)
        ),
        redirect_policy_bypass_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in redirects)
            / len(redirects)
        ),
        resource_limit_enforcement_rate=(
            sum(item.status == DecisionStatus.DENY.value for item in resources)
            / len(resources)
        ),
        tls_bypass_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in tls) / len(tls)
        ),
        replay_acceptance_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in replays)
            / len(replays)
        ),
        dependency_failure_error_rate=(
            sum(item.status == DecisionStatus.ERROR.value for item in failures)
            / len(failures)
        ),
        trace_completeness_rate=(
            sum(item.trace_complete for item in observations) / len(observations)
        ),
        baseline_bypass_rate=sum(baseline_bypasses) / len(baseline_bypasses),
        simulated_valid_p95_elapsed_ms=_p95([item.elapsed_ms for item in valid]),
        max_valid_body_admitted_bytes=max(item.admitted_bytes for item in valid),
    )
    return report, tuple(observations)


def main() -> None:
    report, _ = evaluate_controls()
    assert report.valid_fetch_completion_rate == 1.0
    assert report.forbidden_destination_success_rate == 0.0
    assert report.redirect_policy_bypass_rate == 0.0
    assert report.resource_limit_enforcement_rate == 1.0
    assert report.tls_bypass_rate == 0.0
    assert report.replay_acceptance_rate == 0.0
    assert report.dependency_failure_error_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.baseline_bypass_rate == 1.0
    print(json.dumps(_jsonable(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

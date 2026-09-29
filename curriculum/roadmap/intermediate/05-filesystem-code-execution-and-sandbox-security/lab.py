"""Deterministic sandbox-boundary lab for Intermediate 05.

The lab never executes learner- or model-supplied code on the host. A typed
program fixture represents the effects untrusted code attempts. The trusted
broker and sandbox runtime independently enforce archive, filesystem, network,
syscall, resource, lifecycle, and output policy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from pathlib import PurePosixPath
import re
from threading import RLock
from typing import Any
from urllib.parse import unquote


NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, frozenset | set | tuple | list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if is_dataclass(value):
        return _jsonable(asdict(value))
    return value


def digest(value: Any) -> str:
    encoded = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"
    IDEMPOTENT = "idempotent"


class MemberKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    SPECIAL = "special"


class OperationKind(str, Enum):
    READ = "read"
    WRITE = "write"
    CONNECT = "connect"
    SPAWN = "spawn"
    CPU = "cpu"
    MEMORY = "memory"
    SYSCALL = "syscall"
    EMIT = "emit"
    REPORT = "report"


class GrantState(str, Enum):
    ACTIVE = "active"
    CLAIMED = "claimed"
    REVOKED = "revoked"


class SandboxState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    TERMINATED = "terminated"
    DESTROYED = "destroyed"


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
class ArchiveMember:
    name: str
    kind: MemberKind
    size: int = 0
    stored_size: int = 0
    target: str = ""


@dataclass(frozen=True)
class ArchiveFixture:
    archive_id: str
    tenant: str
    members: tuple[ArchiveMember, ...]
    upload_digest: str


def archive_fixture(
    archive_id: str, tenant: str, members: tuple[ArchiveMember, ...]
) -> ArchiveFixture:
    return ArchiveFixture(archive_id, tenant, members, digest([tenant, members]))


@dataclass
class ArchiveRegistry:
    archives: dict[str, ArchiveFixture]
    available: bool = True

    def current(self, archive_id: str) -> tuple[ArchiveFixture | None, str]:
        if not self.available:
            return None, "archive-registry-unavailable"
        archive = self.archives.get(archive_id)
        if archive is None:
            return None, "archive-unknown"
        return archive, "archive-current"


@dataclass(frozen=True)
class ProgramOperation:
    kind: OperationKind
    target: str = ""
    amount: int = 0


@dataclass(frozen=True)
class GeneratedProgram:
    program_id: str
    operations: tuple[ProgramOperation, ...]
    source_digest: str


def program_fixture(
    program_id: str, operations: tuple[ProgramOperation, ...]
) -> GeneratedProgram:
    return GeneratedProgram(program_id, operations, digest(operations))


@dataclass
class ProgramRegistry:
    programs: dict[str, GeneratedProgram]
    available: bool = True

    def current(self, program_id: str) -> tuple[GeneratedProgram | None, str]:
        if not self.available:
            return None, "program-registry-unavailable"
        program = self.programs.get(program_id)
        if program is None:
            return None, "program-unknown"
        return program, "program-current"


@dataclass
class SandboxPolicy:
    version: str = "sandbox-policy-v5"
    image_digest: str = "sha256:synthetic-runner-image-2026-09"
    max_members: int = 8
    max_member_bytes: int = 256_000
    max_expanded_bytes: int = 1_000_000
    max_compression_ratio: int = 100
    max_steps: int = 16
    max_cpu_ticks: int = 100
    max_memory_bytes: int = 64_000_000
    max_pids: int = 8
    max_written_bytes: int = 1_000_000
    max_output_bytes: int = 4_096
    network_enabled: bool = False
    allowed_syscalls: frozenset[str] = frozenset(
        {"read", "write", "fstat", "mmap", "munmap", "clock_gettime", "exit"}
    )


_DRIVE = re.compile(r"^[A-Za-z]:")


def canonical_relative_path(raw: str) -> tuple[str | None, str]:
    """Canonicalize a transport path and reject ambiguous or escaping forms."""

    if not raw or "\x00" in raw or any(ord(char) < 32 for char in raw):
        return None, "path-invalid"
    decoded = raw
    for _ in range(3):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    if unquote(decoded) != decoded:
        return None, "path-encoding-depth"
    decoded = decoded.replace("\\", "/")
    if decoded.startswith("/") or _DRIVE.match(decoded):
        return None, "path-absolute"
    parts: list[str] = []
    for part in PurePosixPath(decoded).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            return None, "path-traversal"
        if len(part) > 120:
            return None, "path-component-too-long"
        parts.append(part)
    if not parts:
        return None, "path-invalid"
    return "/".join(parts), "path-canonical"


@dataclass(frozen=True)
class ArchiveAdmission:
    paths: frozenset[str]
    expanded_bytes: int
    manifest_digest: str


class ArchiveInspector:
    """Reject dangerous archive semantics before any workspace is created."""

    def __init__(self, policy: SandboxPolicy):
        self.policy = policy

    def inspect(
        self, archive: ArchiveFixture
    ) -> tuple[ArchiveAdmission | None, str]:
        if not archive.members or len(archive.members) > self.policy.max_members:
            return None, "archive-member-count"
        expanded = 0
        stored = 0
        paths: set[str] = set()
        folded: set[str] = set()
        for member in archive.members:
            path, reason = canonical_relative_path(member.name)
            if path is None:
                return None, f"archive-{reason}"
            if member.kind in {MemberKind.SYMLINK, MemberKind.HARDLINK}:
                return None, "archive-links-denied"
            if member.kind is MemberKind.SPECIAL:
                return None, "archive-special-file"
            if member.size < 0 or member.stored_size < 0:
                return None, "archive-size-invalid"
            if member.size > self.policy.max_member_bytes:
                return None, "archive-member-size"
            expanded += member.size
            stored += member.stored_size
            if expanded > self.policy.max_expanded_bytes:
                return None, "archive-expanded-size"
            folded_path = path.casefold()
            if path in paths or folded_path in folded:
                return None, "archive-path-collision"
            paths.add(path)
            folded.add(folded_path)
        if stored == 0 and expanded > 0:
            return None, "archive-compression-ratio"
        if stored and expanded / stored > self.policy.max_compression_ratio:
            return None, "archive-compression-ratio"
        return ArchiveAdmission(
            frozenset(paths), expanded, digest([archive.upload_digest, sorted(paths)])
        ), "archive-admitted"


@dataclass(frozen=True)
class ExecutionRequest:
    request_id: str
    archive_id: str
    program_id: str


@dataclass(frozen=True)
class ExecutionGrant:
    grant_id: str
    workload_id: str
    tenant: str
    confirmation_thumbprint: str
    archive_id: str
    archive_digest: str
    manifest_digest: str
    program_id: str
    program_digest: str
    policy_version: str
    image_digest: str
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
    archive_digest: str
    program_digest: str
    policy_version: str
    image_digest: str
    grant_id: str = ""
    counters_digest: str = "none"
    sandbox_created: bool = False
    sandbox_destroyed: bool = False


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
    grant: ExecutionGrant | None = None


class SandboxBroker:
    """Authorizes immutable, one-use execution grants without running code."""

    def __init__(
        self,
        workloads: WorkloadRegistry,
        archives: ArchiveRegistry,
        programs: ProgramRegistry,
        inspector: ArchiveInspector,
        policy: SandboxPolicy,
        audit: AuditSink,
        *,
        signing_key: bytes = b"synthetic-sandbox-grant-key",
    ):
        self.workloads = workloads
        self.archives = archives
        self.programs = programs
        self.inspector = inspector
        self.policy = policy
        self.audit = audit
        self._signing_key = signing_key
        self.available = True
        self.grants: dict[str, ExecutionGrant] = {}
        self.states: dict[str, GrantState] = {}
        self.request_ledger: dict[str, tuple[str, str]] = {}
        self._lock = RLock()

    @staticmethod
    def _payload(grant: ExecutionGrant) -> dict[str, Any]:
        return {
            key: value for key, value in grant.__dict__.items()
            if key not in {"payload_digest", "signature"}
        }

    def _seal(self, grant: ExecutionGrant) -> ExecutionGrant:
        payload_digest = digest(self._payload(grant))
        signature = hmac.new(
            self._signing_key, payload_digest.encode(), hashlib.sha256
        ).hexdigest()
        return replace(grant, payload_digest=payload_digest, signature=signature)

    def verify_integrity(self, grant: ExecutionGrant) -> bool:
        payload_digest = digest(self._payload(grant))
        signature = hmac.new(
            self._signing_key, payload_digest.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(grant.payload_digest, payload_digest) and hmac.compare_digest(
            grant.signature, signature
        )

    def _receipt(
        self,
        *,
        trace_id: str,
        stage: str,
        status: DecisionStatus,
        reason: str,
        workload: WorkloadAttestation | None = None,
        archive: ArchiveFixture | None = None,
        program: GeneratedProgram | None = None,
        grant: ExecutionGrant | None = None,
        counters: dict[str, int] | None = None,
        sandbox_created: bool = False,
        sandbox_destroyed: bool = False,
    ) -> DecisionReceipt:
        tenant = grant.tenant if grant else (workload.tenant if workload else "")
        receipt = DecisionReceipt(
            trace_id=trace_id,
            stage=stage,
            status=status.value,
            reason=reason,
            workload_id=grant.workload_id if grant else (
                workload.workload_id if workload else "unknown"
            ),
            tenant_digest=digest(tenant)[:16] if tenant else "none",
            archive_digest=(
                grant.archive_digest[:16] if grant
                else archive.upload_digest[:16] if archive else "none"
            ),
            program_digest=(
                grant.program_digest[:16] if grant
                else program.source_digest[:16] if program else "none"
            ),
            policy_version=self.policy.version,
            image_digest=self.policy.image_digest,
            grant_id=grant.grant_id if grant else "",
            counters_digest=digest(counters)[:16] if counters is not None else "none",
            sandbox_created=sandbox_created,
            sandbox_destroyed=sandbox_destroyed,
        )
        self.audit.record(receipt)
        return receipt

    @staticmethod
    def _status_for(reason: str) -> DecisionStatus:
        return DecisionStatus.ERROR if reason.endswith("unavailable") else DecisionStatus.DENY

    def _terminal(
        self,
        request: ExecutionRequest,
        status: DecisionStatus,
        reason: str,
        *,
        workload: WorkloadAttestation | None = None,
        archive: ArchiveFixture | None = None,
        program: GeneratedProgram | None = None,
    ) -> GrantDecision:
        receipt = self._receipt(
            trace_id=f"trace:{request.request_id}", stage="sandbox-admission",
            status=status, reason=reason, workload=workload,
            archive=archive, program=program,
        )
        return GrantDecision(status, reason, receipt)

    def issue(
        self, attestation_id: str, request: ExecutionRequest, *, now: datetime
    ) -> GrantDecision:
        if not self.available:
            return self._terminal(
                request, DecisionStatus.ERROR, "sandbox-broker-unavailable"
            )
        workload, reason = self.workloads.authenticate(attestation_id, now=now)
        if workload is None:
            return self._terminal(request, self._status_for(reason), reason)
        archive, reason = self.archives.current(request.archive_id)
        if archive is None:
            return self._terminal(
                request, self._status_for(reason), reason, workload=workload
            )
        if archive.tenant != workload.tenant:
            return self._terminal(
                request, DecisionStatus.DENY, "archive-tenant",
                workload=workload, archive=archive,
            )
        program, reason = self.programs.current(request.program_id)
        if program is None:
            return self._terminal(
                request, self._status_for(reason), reason,
                workload=workload, archive=archive,
            )
        admission, reason = self.inspector.inspect(archive)
        if admission is None:
            return self._terminal(
                request, DecisionStatus.DENY, reason, workload=workload,
                archive=archive, program=program,
            )
        request_digest = digest({
            "request": request,
            "workload": workload.workload_id,
            "key": workload.key_thumbprint,
            "tenant": workload.tenant,
            "archive": archive.upload_digest,
            "manifest": admission.manifest_digest,
            "program": program.source_digest,
            "policy": self.policy.version,
            "image": self.policy.image_digest,
        })
        with self._lock:
            previous = self.request_ledger.get(request.request_id)
            if previous:
                previous_digest, grant_id = previous
                if previous_digest != request_digest:
                    return self._terminal(
                        request, DecisionStatus.DENY, "request-id-collision",
                        workload=workload, archive=archive, program=program,
                    )
                grant = self.grants[grant_id]
                receipt = self._receipt(
                    trace_id=f"trace:{request.request_id}", stage="sandbox-admission",
                    status=DecisionStatus.IDEMPOTENT,
                    reason="execution-request-replay", workload=workload,
                    archive=archive, program=program, grant=grant,
                )
                return GrantDecision(
                    DecisionStatus.IDEMPOTENT, "execution-request-replay", receipt, grant
                )
            grant_id = f"grant:{digest([request.request_id, request_digest])[:20]}"
            grant = ExecutionGrant(
                grant_id=grant_id,
                workload_id=workload.workload_id,
                tenant=workload.tenant,
                confirmation_thumbprint=workload.key_thumbprint,
                archive_id=archive.archive_id,
                archive_digest=archive.upload_digest,
                manifest_digest=admission.manifest_digest,
                program_id=program.program_id,
                program_digest=program.source_digest,
                policy_version=self.policy.version,
                image_digest=self.policy.image_digest,
                issued_at=now,
                expires_at=min(now + timedelta(seconds=45), workload.expires_at),
                payload_digest="",
                signature="",
            )
            sealed = self._seal(grant)
            self.grants[grant_id] = sealed
            self.states[grant_id] = GrantState.ACTIVE
            self.request_ledger[request.request_id] = (request_digest, grant_id)
        receipt = self._receipt(
            trace_id=f"trace:{request.request_id}", stage="sandbox-admission",
            status=DecisionStatus.ALLOW, reason="execution-grant-issued",
            workload=workload, archive=archive, program=program, grant=sealed,
        )
        return GrantDecision(DecisionStatus.ALLOW, "execution-grant-issued", receipt, sealed)

    def validate_current(
        self, grant: ExecutionGrant, *, now: datetime
    ) -> tuple[ArchiveAdmission | None, str]:
        if not self.available:
            return None, "sandbox-broker-unavailable"
        registered = self.grants.get(grant.grant_id)
        if registered is None or registered != grant or not self.verify_integrity(grant):
            return None, "execution-grant-integrity"
        state = self.states.get(grant.grant_id)
        if state is GrantState.CLAIMED:
            return None, "execution-grant-replayed"
        if state is not GrantState.ACTIVE:
            return None, "execution-grant-revoked"
        if not (grant.issued_at <= now < grant.expires_at):
            return None, "execution-grant-expired"
        if grant.policy_version != self.policy.version:
            return None, "sandbox-policy-version-changed"
        if grant.image_digest != self.policy.image_digest:
            return None, "sandbox-image-changed"
        archive, reason = self.archives.current(grant.archive_id)
        if archive is None:
            return None, reason
        if archive.tenant != grant.tenant or archive.upload_digest != grant.archive_digest:
            return None, "archive-version-changed"
        program, reason = self.programs.current(grant.program_id)
        if program is None:
            return None, reason
        if program.source_digest != grant.program_digest:
            return None, "program-version-changed"
        admission, reason = self.inspector.inspect(archive)
        if admission is None:
            return None, reason
        if admission.manifest_digest != grant.manifest_digest:
            return None, "archive-manifest-changed"
        return admission, "execution-grant-current"

    def claim(
        self, grant: ExecutionGrant, *, now: datetime
    ) -> tuple[ArchiveAdmission | None, str]:
        with self._lock:
            admission, reason = self.validate_current(grant, now=now)
            if admission is None:
                return None, reason
            self.states[grant.grant_id] = GrantState.CLAIMED
            return admission, "execution-grant-claimed"

    def revoke(self, grant_id: str, reason: str) -> bool:
        if not reason.strip() or grant_id not in self.grants:
            return False
        with self._lock:
            self.states[grant_id] = GrantState.REVOKED
        return True


@dataclass
class RuntimeCounters:
    steps: int = 0
    reads: int = 0
    written_bytes: int = 0
    output_bytes: int = 0
    cpu_ticks: int = 0
    memory_bytes: int = 0
    pids: int = 1
    network_attempts: int = 0


@dataclass
class SandboxRecord:
    sandbox_id: str
    grant_id: str
    tenant: str
    state: SandboxState = SandboxState.CREATED
    destroyed: bool = False


@dataclass(frozen=True)
class ExecutionDecision:
    status: DecisionStatus
    reason: str
    receipt: DecisionReceipt
    report: str | None = None


class DeterministicSandboxRuntime:
    """Effect interpreter; it performs no host filesystem, process, or network I/O."""

    def __init__(
        self,
        broker: SandboxBroker,
        workloads: WorkloadRegistry,
        archives: ArchiveRegistry,
        programs: ProgramRegistry,
        policy: SandboxPolicy,
    ):
        self.broker = broker
        self.workloads = workloads
        self.archives = archives
        self.programs = programs
        self.policy = policy
        self.available = True
        self.records: dict[str, SandboxRecord] = {}
        self.host_read_count = 0
        self.host_write_count = 0
        self.network_dispatch_count = 0

    def _finish(
        self,
        *,
        request_id: str,
        grant: ExecutionGrant,
        workload: WorkloadAttestation | None,
        status: DecisionStatus,
        reason: str,
        counters: RuntimeCounters,
        record: SandboxRecord | None,
        report: str | None = None,
    ) -> ExecutionDecision:
        if record is not None:
            record.state = SandboxState.TERMINATED
            record.destroyed = True
            record.state = SandboxState.DESTROYED
        receipt = self.broker._receipt(
            trace_id=f"trace:{request_id}", stage="sandbox-execution",
            status=status, reason=reason, workload=workload, grant=grant,
            counters=asdict(counters), sandbox_created=record is not None,
            sandbox_destroyed=bool(record and record.destroyed),
        )
        return ExecutionDecision(status, reason, receipt, report)

    @staticmethod
    def _runtime_path(raw: str) -> tuple[str | None, str]:
        relative, reason = canonical_relative_path(raw)
        if relative is None:
            return None, reason
        return f"/workspace/{relative}", "runtime-path-canonical"

    def execute(
        self,
        attestation_id: str,
        grant_id: str,
        *,
        request_id: str,
        now: datetime,
    ) -> ExecutionDecision:
        grant = self.broker.grants.get(grant_id)
        counters = RuntimeCounters()
        if grant is None:
            placeholder = ExecutionGrant(
                grant_id, "unknown", "", "", "", "", "", "", "", "", "", "",
                now, now, "", "",
            )
            return self._finish(
                request_id=request_id, grant=placeholder, workload=None,
                status=DecisionStatus.DENY, reason="execution-grant-unknown",
                counters=counters, record=None,
            )
        if not self.available:
            return self._finish(
                request_id=request_id, grant=grant, workload=None,
                status=DecisionStatus.ERROR, reason="sandbox-runtime-unavailable",
                counters=counters, record=None,
            )
        workload, reason = self.workloads.authenticate(attestation_id, now=now)
        if workload is None:
            return self._finish(
                request_id=request_id, grant=grant, workload=None,
                status=SandboxBroker._status_for(reason), reason=reason,
                counters=counters, record=None,
            )
        if workload.workload_id != grant.workload_id or workload.tenant != grant.tenant:
            return self._finish(
                request_id=request_id, grant=grant, workload=workload,
                status=DecisionStatus.DENY, reason="execution-sender",
                counters=counters, record=None,
            )
        if workload.key_thumbprint != grant.confirmation_thumbprint:
            return self._finish(
                request_id=request_id, grant=grant, workload=workload,
                status=DecisionStatus.DENY, reason="execution-sender-key",
                counters=counters, record=None,
            )
        admission, reason = self.broker.claim(grant, now=now)
        if admission is None:
            return self._finish(
                request_id=request_id, grant=grant, workload=workload,
                status=SandboxBroker._status_for(reason), reason=reason,
                counters=counters, record=None,
            )
        program, reason = self.programs.current(grant.program_id)
        if program is None:
            return self._finish(
                request_id=request_id, grant=grant, workload=workload,
                status=SandboxBroker._status_for(reason), reason=reason,
                counters=counters, record=None,
            )
        record = SandboxRecord(
            f"sandbox:{digest([grant.grant_id, request_id])[:16]}",
            grant.grant_id, grant.tenant, SandboxState.RUNNING,
        )
        self.records[record.sandbox_id] = record
        readable = {f"/workspace/input/{path}" for path in admission.paths}
        report: str | None = None

        for operation in program.operations:
            counters.steps += 1
            if counters.steps > self.policy.max_steps:
                reason = "resource-step-limit"
                break
            if operation.amount < 0:
                reason = "operation-amount-invalid"
                break
            if operation.kind is OperationKind.READ:
                path, path_reason = self._runtime_path(operation.target)
                if path is None:
                    reason = f"sandbox-fs-{path_reason}"
                    break
                if path not in readable:
                    reason = "sandbox-forbidden-read"
                    break
                counters.reads += 1
            elif operation.kind is OperationKind.WRITE:
                path, path_reason = self._runtime_path(operation.target)
                if path is None:
                    reason = f"sandbox-fs-{path_reason}"
                    break
                if path != "/workspace/output/report.json":
                    reason = "sandbox-forbidden-write"
                    break
                if counters.written_bytes + operation.amount > self.policy.max_written_bytes:
                    reason = "resource-disk-limit"
                    break
                counters.written_bytes += operation.amount
            elif operation.kind is OperationKind.CONNECT:
                counters.network_attempts += 1
                reason = "sandbox-network-denied"
                break
            elif operation.kind is OperationKind.SPAWN:
                if counters.pids + operation.amount > self.policy.max_pids:
                    reason = "resource-pid-limit"
                    break
                counters.pids += operation.amount
            elif operation.kind is OperationKind.CPU:
                if counters.cpu_ticks + operation.amount > self.policy.max_cpu_ticks:
                    reason = "resource-cpu-limit"
                    break
                counters.cpu_ticks += operation.amount
            elif operation.kind is OperationKind.MEMORY:
                if operation.amount > self.policy.max_memory_bytes:
                    reason = "resource-memory-limit"
                    break
                counters.memory_bytes = max(counters.memory_bytes, operation.amount)
            elif operation.kind is OperationKind.SYSCALL:
                if operation.target not in self.policy.allowed_syscalls:
                    reason = "sandbox-syscall-denied"
                    break
            elif operation.kind is OperationKind.EMIT:
                if counters.output_bytes + operation.amount > self.policy.max_output_bytes:
                    reason = "resource-output-limit"
                    break
                counters.output_bytes += operation.amount
            elif operation.kind is OperationKind.REPORT:
                if operation.target != "output/report.json":
                    reason = "report-path"
                    break
                report = json.dumps(
                    {
                        "archive_id": grant.archive_id,
                        "files_read": counters.reads,
                        "status": "complete",
                    },
                    sort_keys=True,
                )
                report_size = len(report.encode())
                if counters.written_bytes + report_size > self.policy.max_written_bytes:
                    reason = "resource-disk-limit"
                    break
                if report_size > self.policy.max_output_bytes:
                    reason = "resource-output-limit"
                    break
                counters.written_bytes += report_size
            else:  # pragma: no cover - enum exhaustiveness guard
                reason = "operation-unknown"
                break
        else:
            reason = "sandbox-job-complete" if report is not None else "report-missing"

        status = (
            DecisionStatus.ALLOW if reason == "sandbox-job-complete"
            else DecisionStatus.DENY
        )
        return self._finish(
            request_id=request_id, grant=grant, workload=workload,
            status=status, reason=reason, counters=counters, record=record,
            report=report if status is DecisionStatus.ALLOW else None,
        )


@dataclass(frozen=True)
class ApplicationResponse:
    status: DecisionStatus
    reason: str
    report: str | None
    receipts: tuple[DecisionReceipt, ...]
    grant_id: str = ""


class ArchiveAnalysisApplication:
    """Trusted identity and request route; no host-execution fallback exists."""

    def __init__(self, broker: SandboxBroker, runtime: DeterministicSandboxRuntime):
        self.broker = broker
        self.runtime = runtime
        self.fallback_execution_count = 0

    def analyze_archive(
        self,
        *,
        attestation_id: str,
        archive_id: str,
        program_id: str,
        request_id: str,
        now: datetime,
    ) -> ApplicationResponse:
        request = ExecutionRequest(f"{request_id}:grant", archive_id, program_id)
        issued = self.broker.issue(attestation_id, request, now=now)
        if issued.grant is None:
            return ApplicationResponse(
                issued.status, issued.reason, None, (issued.receipt,)
            )
        executed = self.runtime.execute(
            attestation_id, issued.grant.grant_id,
            request_id=f"{request_id}:execute", now=now,
        )
        return ApplicationResponse(
            executed.status, executed.reason, executed.report,
            (issued.receipt, executed.receipt), issued.grant.grant_id,
        )


@dataclass(frozen=True)
class Scenario:
    workloads: WorkloadRegistry
    archives: ArchiveRegistry
    programs: ProgramRegistry
    policy: SandboxPolicy
    inspector: ArchiveInspector
    audit: AuditSink
    broker: SandboxBroker
    runtime: DeterministicSandboxRuntime
    application: ArchiveAnalysisApplication


def safe_operations() -> tuple[ProgramOperation, ...]:
    return (
        ProgramOperation(OperationKind.READ, "input/data/orders.csv"),
        ProgramOperation(OperationKind.CPU, amount=20),
        ProgramOperation(OperationKind.MEMORY, amount=2_000_000),
        ProgramOperation(OperationKind.SPAWN, amount=1),
        ProgramOperation(OperationKind.REPORT, "output/report.json"),
    )


def build_scenario() -> Scenario:
    workloads = WorkloadRegistry({
        "attest:north": WorkloadAttestation(
            "attest:north", "archive-agent-north", "north", "key:north-v3",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
        "attest:south": WorkloadAttestation(
            "attest:south", "archive-agent-south", "south", "key:south-v2",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
        "attest:stolen": WorkloadAttestation(
            "attest:stolen", "compromised-worker", "north", "key:attacker",
            NOW - timedelta(minutes=2), NOW + timedelta(minutes=30),
        ),
    })
    safe_members = (
        ArchiveMember("data/orders.csv", MemberKind.FILE, 2_000, 1_000),
        ArchiveMember("README.txt", MemberKind.FILE, 200, 150),
    )
    archives = ArchiveRegistry({
        "archive:north:safe": archive_fixture(
            "archive:north:safe", "north", safe_members
        ),
        "archive:south:safe": archive_fixture(
            "archive:south:safe", "south", safe_members
        ),
    })
    policy = SandboxPolicy()
    programs = ProgramRegistry({})
    fixtures = {
        "program:safe": safe_operations(),
        "program:edge": (
            ProgramOperation(OperationKind.READ, "input/data/orders.csv"),
            ProgramOperation(OperationKind.CPU, amount=policy.max_cpu_ticks),
            ProgramOperation(OperationKind.MEMORY, amount=policy.max_memory_bytes),
            ProgramOperation(OperationKind.SPAWN, amount=policy.max_pids - 1),
            ProgramOperation(OperationKind.EMIT, amount=policy.max_output_bytes),
            ProgramOperation(OperationKind.REPORT, "output/report.json"),
        ),
        "program:encoded-read": (
            ProgramOperation(OperationKind.READ, "input/%2e%2e/%2e%2e/etc/passwd"),
        ),
        "program:absolute-read": (
            ProgramOperation(OperationKind.READ, "/etc/passwd"),
        ),
        "program:network": (
            ProgramOperation(OperationKind.CONNECT, "169.254.169.254:80"),
        ),
        "program:syscall": (ProgramOperation(OperationKind.SYSCALL, "mount"),),
        "program:pids": (
            ProgramOperation(OperationKind.SPAWN, amount=policy.max_pids),
        ),
        "program:cpu": (
            ProgramOperation(OperationKind.CPU, amount=policy.max_cpu_ticks + 1),
        ),
        "program:memory": (
            ProgramOperation(OperationKind.MEMORY, amount=policy.max_memory_bytes + 1),
        ),
        "program:disk": (
            ProgramOperation(
                OperationKind.WRITE, "output/report.json",
                amount=policy.max_written_bytes + 1,
            ),
        ),
        "program:output": (
            ProgramOperation(OperationKind.EMIT, amount=policy.max_output_bytes + 1),
        ),
    }
    for program_id, operations in fixtures.items():
        programs.programs[program_id] = program_fixture(program_id, operations)
    inspector = ArchiveInspector(policy)
    audit = AuditSink()
    broker = SandboxBroker(workloads, archives, programs, inspector, policy, audit)
    runtime = DeterministicSandboxRuntime(
        broker, workloads, archives, programs, policy
    )
    application = ArchiveAnalysisApplication(broker, runtime)
    return Scenario(
        workloads, archives, programs, policy, inspector, audit,
        broker, runtime, application,
    )


def unsafe_path_baseline(path: str) -> bool:
    """DEMO-ONLY: substring checks miss encoded and separator variants."""

    return path.startswith("input/") and ".." not in path and not path.startswith("/")


def unsafe_archive_baseline(archive: ArchiveFixture) -> bool:
    """DEMO-ONLY: validates member names but ignores link targets and races."""

    return all(".." not in member.name and not member.name.startswith("/") for member in archive.members)


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    kind: CaseKind
    status: str
    useful: bool
    escape_probe: bool
    forbidden_read_probe: bool
    resource_probe: bool
    network_probe: bool
    replay_probe: bool
    sandbox_created: bool
    sandbox_destroyed: bool
    trace_complete: bool


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    escape_cases: int
    forbidden_read_cases: int
    resource_limit_cases: int
    valid_job_completion_rate: float
    escape_success_rate: float
    forbidden_read_success_rate: float
    resource_limit_enforcement_rate: float
    network_attempt_success_rate: float
    replay_acceptance_rate: float
    failure_error_preservation_rate: float
    cleanup_completeness_rate: float
    trace_completeness_rate: float
    unsafe_baseline_escape_rate: float


def _trace_complete(receipt: DecisionReceipt) -> bool:
    return bool(
        receipt.trace_id and receipt.stage and receipt.status and receipt.reason
        and receipt.policy_version and receipt.image_digest
    )


def evaluate_controls() -> tuple[EvaluationReport, tuple[CaseObservation, ...]]:
    observations: list[CaseObservation] = []

    def record(
        case_id: str,
        kind: CaseKind,
        decision: GrantDecision | ExecutionDecision | ApplicationResponse,
        receipt: DecisionReceipt,
        *,
        useful: bool = False,
        escape_probe: bool = False,
        forbidden_read_probe: bool = False,
        resource_probe: bool = False,
        network_probe: bool = False,
        replay_probe: bool = False,
    ) -> None:
        observations.append(CaseObservation(
            case_id, kind, decision.status.value, useful, escape_probe,
            forbidden_read_probe, resource_probe, network_probe, replay_probe,
            receipt.sandbox_created, receipt.sandbox_destroyed,
            _trace_complete(receipt),
        ))

    # Four valid cases.
    scenario = build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:safe", request_id="valid:north", now=NOW,
    )
    record(
        "valid-north-report", CaseKind.VALID, response, response.receipts[-1],
        useful=response.status is DecisionStatus.ALLOW and response.report is not None,
    )

    scenario = build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:south", archive_id="archive:south:safe",
        program_id="program:safe", request_id="valid:south", now=NOW,
    )
    record(
        "valid-south-report", CaseKind.VALID, response, response.receipts[-1],
        useful=response.status is DecisionStatus.ALLOW and response.report is not None,
    )

    scenario = build_scenario()
    request = ExecutionRequest(
        "valid:idempotent", "archive:north:safe", "program:safe"
    )
    first = scenario.broker.issue("attest:north", request, now=NOW)
    retry = scenario.broker.issue("attest:north", request, now=NOW)
    record(
        "valid-idempotent-admission", CaseKind.VALID, retry, retry.receipt,
        useful=retry.status is DecisionStatus.IDEMPOTENT and retry.grant == first.grant,
    )

    scenario = build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:edge", request_id="valid:edge", now=NOW,
    )
    record(
        "valid-exact-resource-boundary", CaseKind.VALID, response,
        response.receipts[-1], useful=response.status is DecisionStatus.ALLOW,
    )

    # Admission and filesystem escape attacks.
    scenario = build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:south:safe",
        program_id="program:safe", request_id="attack:tenant", now=NOW,
    )
    record("cross-tenant-archive", CaseKind.ATTACK, response, response.receipts[-1])

    archive_attacks = (
        ("direct-traversal", ArchiveMember("../host.txt", MemberKind.FILE, 10, 10)),
        ("encoded-traversal", ArchiveMember("%2e%2e/host.txt", MemberKind.FILE, 10, 10)),
        ("absolute-path", ArchiveMember("/etc/passwd", MemberKind.FILE, 10, 10)),
        ("symlink", ArchiveMember("data/link", MemberKind.SYMLINK, 0, 0, "../../host")),
    )
    for label, member in archive_attacks:
        scenario = build_scenario()
        archive_id = f"archive:north:{label}"
        scenario.archives.archives[archive_id] = archive_fixture(
            archive_id, "north", (member,)
        )
        response = scenario.application.analyze_archive(
            attestation_id="attest:north", archive_id=archive_id,
            program_id="program:safe", request_id=f"attack:{label}", now=NOW,
        )
        record(
            f"archive-{label}", CaseKind.ATTACK, response, response.receipts[-1],
            escape_probe=True,
        )

    scenario = build_scenario()
    duplicate_id = "archive:north:duplicate"
    scenario.archives.archives[duplicate_id] = archive_fixture(
        duplicate_id,
        "north",
        (
            ArchiveMember("data/orders.csv", MemberKind.FILE, 10, 10),
            ArchiveMember("data/./orders.csv", MemberKind.FILE, 10, 10),
        ),
    )
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id=duplicate_id,
        program_id="program:safe", request_id="attack:duplicate", now=NOW,
    )
    record("archive-path-collision", CaseKind.ATTACK, response, response.receipts[-1])

    for program_id, label in (
        ("program:encoded-read", "runtime-encoded-traversal"),
        ("program:absolute-read", "runtime-absolute-read"),
    ):
        scenario = build_scenario()
        response = scenario.application.analyze_archive(
            attestation_id="attest:north", archive_id="archive:north:safe",
            program_id=program_id, request_id=f"attack:{label}", now=NOW,
        )
        record(
            label, CaseKind.ATTACK, response, response.receipts[-1],
            escape_probe=True, forbidden_read_probe=True,
        )

    # Runtime capability and resource attacks.
    scenario = build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:network", request_id="attack:network", now=NOW,
    )
    record(
        "network-egress", CaseKind.ATTACK, response, response.receipts[-1],
        network_probe=True,
    )

    scenario = build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:syscall", request_id="attack:syscall", now=NOW,
    )
    record("forbidden-syscall", CaseKind.ATTACK, response, response.receipts[-1])

    for program_id, label in (
        ("program:pids", "pid-limit"),
        ("program:cpu", "cpu-limit"),
        ("program:memory", "memory-limit"),
        ("program:disk", "disk-limit"),
        ("program:output", "output-limit"),
    ):
        scenario = build_scenario()
        response = scenario.application.analyze_archive(
            attestation_id="attest:north", archive_id="archive:north:safe",
            program_id=program_id, request_id=f"attack:{label}", now=NOW,
        )
        record(
            label, CaseKind.ATTACK, response, response.receipts[-1],
            resource_probe=True,
        )

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        ExecutionRequest("attack:replay", "archive:north:safe", "program:safe"),
        now=NOW,
    )
    first_execution = scenario.runtime.execute(
        "attest:north", issued.grant.grant_id,
        request_id="attack:replay:first", now=NOW,
    )
    replay = scenario.runtime.execute(
        "attest:north", issued.grant.grant_id,
        request_id="attack:replay:second", now=NOW,
    )
    assert first_execution.status is DecisionStatus.ALLOW
    record(
        "execution-grant-replay", CaseKind.ATTACK, replay, replay.receipt,
        replay_probe=True,
    )

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        ExecutionRequest("attack:stale", "archive:north:safe", "program:safe"),
        now=NOW,
    )
    scenario.policy.version = "sandbox-policy-v6"
    stale = scenario.runtime.execute(
        "attest:north", issued.grant.grant_id,
        request_id="attack:stale:execute", now=NOW,
    )
    record("stale-policy", CaseKind.ATTACK, stale, stale.receipt)

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        ExecutionRequest("attack:tamper", "archive:north:safe", "program:safe"),
        now=NOW,
    )
    tampered = replace(issued.grant, program_digest="forged")
    scenario.broker.grants[tampered.grant_id] = tampered
    decision = scenario.runtime.execute(
        "attest:north", tampered.grant_id,
        request_id="attack:tamper:execute", now=NOW,
    )
    record("tampered-grant", CaseKind.ATTACK, decision, decision.receipt)

    # Two dependency failures; neither falls back to host execution.
    scenario = build_scenario()
    scenario.archives.available = False
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:safe", request_id="failure:registry", now=NOW,
    )
    record("archive-registry-unavailable", CaseKind.FAILURE, response, response.receipts[-1])

    scenario = build_scenario()
    issued = scenario.broker.issue(
        "attest:north",
        ExecutionRequest("failure:runtime", "archive:north:safe", "program:safe"),
        now=NOW,
    )
    scenario.runtime.available = False
    decision = scenario.runtime.execute(
        "attest:north", issued.grant.grant_id,
        request_id="failure:runtime:execute", now=NOW,
    )
    record("sandbox-runtime-unavailable", CaseKind.FAILURE, decision, decision.receipt)

    valid = [item for item in observations if item.kind is CaseKind.VALID]
    attacks = [item for item in observations if item.kind is CaseKind.ATTACK]
    failures = [item for item in observations if item.kind is CaseKind.FAILURE]
    escapes = [item for item in observations if item.escape_probe]
    forbidden_reads = [item for item in observations if item.forbidden_read_probe]
    resources = [item for item in observations if item.resource_probe]
    network = [item for item in observations if item.network_probe]
    replays = [item for item in observations if item.replay_probe]
    created = [item for item in observations if item.sandbox_created]
    baseline_archive = archive_fixture(
        "baseline:link", "north",
        (ArchiveMember("input/link", MemberKind.SYMLINK, target="../../host"),),
    )
    baseline_escapes = (
        unsafe_path_baseline("input/%2e%2e/%2e%2e/etc/passwd"),
        unsafe_archive_baseline(baseline_archive),
    )

    report = EvaluationReport(
        cases=len(observations),
        valid_cases=len(valid),
        attack_cases=len(attacks),
        failure_cases=len(failures),
        escape_cases=len(escapes),
        forbidden_read_cases=len(forbidden_reads),
        resource_limit_cases=len(resources),
        valid_job_completion_rate=sum(item.useful for item in valid) / len(valid),
        escape_success_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in escapes) / len(escapes)
        ),
        forbidden_read_success_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in forbidden_reads)
            / len(forbidden_reads)
        ),
        resource_limit_enforcement_rate=(
            sum(item.status == DecisionStatus.DENY.value for item in resources)
            / len(resources)
        ),
        network_attempt_success_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in network) / len(network)
        ),
        replay_acceptance_rate=(
            sum(item.status == DecisionStatus.ALLOW.value for item in replays) / len(replays)
        ),
        failure_error_preservation_rate=(
            sum(item.status == DecisionStatus.ERROR.value for item in failures) / len(failures)
        ),
        cleanup_completeness_rate=(
            sum(item.sandbox_destroyed for item in created) / len(created)
        ),
        trace_completeness_rate=(
            sum(item.trace_complete for item in observations) / len(observations)
        ),
        unsafe_baseline_escape_rate=sum(baseline_escapes) / len(baseline_escapes),
    )
    return report, tuple(observations)


def main() -> None:
    report, _ = evaluate_controls()
    assert report.valid_job_completion_rate == 1.0
    assert report.escape_success_rate == 0.0
    assert report.forbidden_read_success_rate == 0.0
    assert report.resource_limit_enforcement_rate == 1.0
    assert report.network_attempt_success_rate == 0.0
    assert report.replay_acceptance_rate == 0.0
    assert report.failure_error_preservation_rate == 1.0
    assert report.cleanup_completeness_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.unsafe_baseline_escape_rate == 1.0
    print(json.dumps(_jsonable(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

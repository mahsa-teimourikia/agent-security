"""Credential-free security fuzzing lab for an agent action workflow.

The model, generator, or fuzzer may propose inputs.  Application-owned code
parses them, derives identity from trusted context, authorizes the exact
transition, performs one bounded effect, and records an observable receipt.

This module deliberately includes ``UnsafeGateway`` as a labelled comparison.
It is not a deployment pattern: its parser differential and ambient identity
trust exist so a fuzzer can discover real forbidden outcomes.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
import hashlib
import json
import statistics
import unicodedata
from typing import Callable, Iterable, Mapping, Sequence


POLICY_VERSION = "agent-gateway/2026-10-31"
MAX_OPERATION_ID = 64
MAX_DESTINATION = 96
MAX_PAYLOAD_BYTES = 8_192


class Command(str, Enum):
    READ_CASE = "read_case"
    SUBMIT_REVIEW = "submit_review"
    APPROVE_EXPORT = "approve_export"
    EXECUTE_EXPORT = "execute_export"
    CANCEL = "cancel"


class WorkflowState(str, Enum):
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    EXECUTED = "executed"
    CANCELLED = "cancelled"


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    BOUNDARY = "boundary"
    FAILURE = "failure"


class Invariant(str, Enum):
    AUTHENTICATED_IDENTITY = "authenticated-identity"
    TENANT_ISOLATION = "tenant-isolation"
    LEGAL_TRANSITION = "legal-transition"
    EXACT_APPROVAL = "exact-approval"
    OPTIMISTIC_CONCURRENCY = "optimistic-concurrency"
    IDEMPOTENT_EFFECT = "idempotent-effect"
    FAIL_CLOSED = "fail-closed"
    VALID_TASK_LIVENESS = "valid-task-liveness"


@dataclass(frozen=True)
class ActorContext:
    subject_id: str
    tenant_id: str
    roles: frozenset[str]


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str
    classification: str = "confidential"


@dataclass(frozen=True)
class ActionRequest:
    command: str
    workflow_id: str
    resource_id: str
    logical_operation_id: str
    expected_version: int
    destination: str = ""
    payload_bytes: int = 0
    approval_id: str = ""
    claimed_tenant: str = ""
    claimed_subject: str = ""

    def canonical_payload(self) -> dict[str, object]:
        """Return the exact fields bound by authorization and approval."""
        return {
            "command": self.command,
            "workflow_id": self.workflow_id,
            "resource_id": self.resource_id,
            "logical_operation_id": self.logical_operation_id,
            "expected_version": self.expected_version,
            "destination": self.destination,
            "payload_bytes": self.payload_bytes,
        }


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    tenant_id: str
    requester_id: str
    approver_id: str
    proposal_digest: str
    policy_version: str
    issued_step: int
    expires_step: int


@dataclass
class Workflow:
    workflow_id: str
    tenant_id: str
    resource_id: str
    state: WorkflowState = WorkflowState.DRAFT
    version: int = 0
    effects: list[str] = field(default_factory=list)

    def snapshot(self) -> "WorkflowSnapshot":
        return WorkflowSnapshot(
            workflow_id=self.workflow_id,
            tenant_id=self.tenant_id,
            resource_id=self.resource_id,
            state=self.state,
            version=self.version,
            effects=tuple(self.effects),
        )


@dataclass(frozen=True)
class WorkflowSnapshot:
    workflow_id: str
    tenant_id: str
    resource_id: str
    state: WorkflowState
    version: int
    effects: tuple[str, ...]


@dataclass(frozen=True)
class DecisionReceipt:
    status: DecisionStatus
    reason: str
    command: str
    workflow_id: str
    logical_operation_id: str
    pre_state: WorkflowState
    post_state: WorkflowState
    pre_version: int
    post_version: int
    effect_applied: bool
    policy_version: str
    audit_id: str


@dataclass(frozen=True)
class OracleFinding:
    invariant: Invariant
    message: str
    family: str


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    kind: CaseKind
    expected_status: DecisionStatus
    receipt: DecisionReceipt
    findings: tuple[OracleFinding, ...]
    input_size: int

    @property
    def forbidden_outcome(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True)
class FuzzCase:
    case_id: str
    kind: CaseKind
    actor: ActorContext
    request: ActionRequest
    initial_state: WorkflowState
    initial_version: int
    expected_status: DecisionStatus
    issue_approval: bool = False
    approval_override: Mapping[str, object] | None = None
    dependency_available: bool = True
    preload_operation: ActionRequest | None = None


@dataclass(frozen=True)
class EvaluationReport:
    implementation: str
    total_cases: int
    valid_cases: int
    attack_cases: int
    boundary_cases: int
    failure_cases: int
    forbidden_outcomes: int
    invariant_violation_rate: float
    contained_attack_rate: float
    unique_failure_families: int
    valid_case_rejections: int
    valid_case_rejection_rate: float
    explicit_dependency_errors: int
    fail_open_dependency_outcomes: int
    reproducibility_rate: float
    median_input_size: float


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def proposal_digest(request: ActionRequest) -> str:
    return hashlib.sha256(canonical_json(request.canonical_payload()).encode()).hexdigest()


def audit_id(actor: ActorContext, request: ActionRequest, status: DecisionStatus, reason: str) -> str:
    material = {
        "subject": actor.subject_id,
        "tenant": actor.tenant_id,
        "operation": request.logical_operation_id,
        "status": status.value,
        "reason": reason,
        "policy": POLICY_VERSION,
    }
    return "audit:" + hashlib.sha256(canonical_json(material).encode()).hexdigest()[:16]


def input_size(request: ActionRequest) -> int:
    return len(canonical_json(request.canonical_payload()).encode())


def canonical_command(raw: str) -> str:
    """Canonical form used only after strict input validation.

    The secure gateway requires raw input to already equal this form.  The
    unsafe baseline applies it only in the executor, creating a parser
    differential that property-based testing can discover.
    """
    return unicodedata.normalize("NFKC", raw).casefold().strip()


class ApprovalStore:
    def __init__(self) -> None:
        self.receipts: dict[str, ApprovalReceipt] = {}
        self.consumed: set[str] = set()

    def issue(
        self,
        request: ActionRequest,
        requester: ActorContext,
        approver: ActorContext,
        *,
        step: int,
        approval_id: str | None = None,
    ) -> ApprovalReceipt:
        if approver.tenant_id != requester.tenant_id or "export-approver" not in approver.roles:
            raise ValueError("approver-not-authorized")
        receipt = ApprovalReceipt(
            approval_id=approval_id or request.approval_id or f"approval:{request.logical_operation_id}",
            tenant_id=requester.tenant_id,
            requester_id=requester.subject_id,
            approver_id=approver.subject_id,
            proposal_digest=proposal_digest(request),
            policy_version=POLICY_VERSION,
            issued_step=step,
            expires_step=step + 5,
        )
        self.receipts[receipt.approval_id] = receipt
        return receipt

    def consume_exact(
        self,
        approval_id: str,
        request: ActionRequest,
        actor: ActorContext,
        *,
        step: int,
    ) -> tuple[bool, str]:
        receipt = self.receipts.get(approval_id)
        if receipt is None:
            return False, "approval-missing"
        if approval_id in self.consumed:
            return False, "approval-replayed"
        if receipt.tenant_id != actor.tenant_id or receipt.requester_id != actor.subject_id:
            return False, "approval-principal-binding"
        if receipt.policy_version != POLICY_VERSION:
            return False, "approval-policy-stale"
        if not (receipt.issued_step <= step <= receipt.expires_step):
            return False, "approval-expired"
        if receipt.proposal_digest != proposal_digest(request):
            return False, "approval-proposal-binding"
        self.consumed.add(approval_id)
        return True, "approval-consumed"


ALLOWED_TRANSITIONS: dict[tuple[WorkflowState, Command], WorkflowState] = {
    (WorkflowState.DRAFT, Command.SUBMIT_REVIEW): WorkflowState.REVIEW,
    (WorkflowState.REVIEW, Command.APPROVE_EXPORT): WorkflowState.APPROVED,
    (WorkflowState.DRAFT, Command.CANCEL): WorkflowState.CANCELLED,
    (WorkflowState.REVIEW, Command.CANCEL): WorkflowState.CANCELLED,
    (WorkflowState.APPROVED, Command.CANCEL): WorkflowState.CANCELLED,
    (WorkflowState.APPROVED, Command.EXECUTE_EXPORT): WorkflowState.EXECUTED,
}


ROLE_BY_COMMAND: dict[Command, str] = {
    Command.READ_CASE: "case-reader",
    Command.SUBMIT_REVIEW: "export-requester",
    Command.APPROVE_EXPORT: "export-approver",
    Command.EXECUTE_EXPORT: "export-requester",
    Command.CANCEL: "export-requester",
}


class SecureGateway:
    """Strict typed boundary with current authorization and atomic state checks."""

    name = "secure-gateway"

    def __init__(
        self,
        workflow: Workflow,
        resources: Mapping[str, Resource],
        approvals: ApprovalStore | None = None,
        *,
        dependency_available: bool = True,
    ) -> None:
        self.workflow = workflow
        self.resources = dict(resources)
        self.approvals = approvals or ApprovalStore()
        self.dependency_available = dependency_available
        self.operations: dict[str, str] = {}
        self.receipts: list[DecisionReceipt] = []

    def _receipt(
        self,
        actor: ActorContext,
        request: ActionRequest,
        pre: WorkflowSnapshot,
        status: DecisionStatus,
        reason: str,
        *,
        effect_applied: bool = False,
    ) -> DecisionReceipt:
        receipt = DecisionReceipt(
            status=status,
            reason=reason,
            command=request.command,
            workflow_id=request.workflow_id,
            logical_operation_id=request.logical_operation_id,
            pre_state=pre.state,
            post_state=self.workflow.state,
            pre_version=pre.version,
            post_version=self.workflow.version,
            effect_applied=effect_applied,
            policy_version=POLICY_VERSION,
            audit_id=audit_id(actor, request, status, reason),
        )
        self.receipts.append(receipt)
        return receipt

    def execute(self, actor: ActorContext, request: ActionRequest, *, step: int = 0) -> DecisionReceipt:
        pre = self.workflow.snapshot()
        if not self.dependency_available:
            return self._receipt(actor, request, pre, DecisionStatus.ERROR, "policy-dependency-unavailable")

        if not actor.subject_id or not actor.tenant_id:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "authenticated-context-required")
        if request.command != canonical_command(request.command):
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "command-not-canonical")
        try:
            command = Command(request.command)
        except ValueError:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "command-unknown")
        if not request.logical_operation_id or len(request.logical_operation_id) > MAX_OPERATION_ID:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "operation-id-invalid")
        if request.payload_bytes < 0 or request.payload_bytes > MAX_PAYLOAD_BYTES:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "payload-size-invalid")
        if len(request.destination) > MAX_DESTINATION:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "destination-too-long")
        if request.workflow_id != self.workflow.workflow_id or request.resource_id != self.workflow.resource_id:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "workflow-resource-binding")
        resource = self.resources.get(request.resource_id)
        if resource is None:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "resource-not-found")
        if actor.tenant_id != self.workflow.tenant_id or actor.tenant_id != resource.tenant_id:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "tenant-mismatch")
        if ROLE_BY_COMMAND[command] not in actor.roles:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "role-not-authorized")

        fingerprint = proposal_digest(request)
        previous = self.operations.get(request.logical_operation_id)
        if previous is not None:
            reason = "idempotent-replay" if previous == fingerprint else "operation-id-collision"
            return self._receipt(actor, request, pre, DecisionStatus.DENY, reason)
        if request.expected_version != self.workflow.version:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "workflow-version-stale")

        if command is Command.READ_CASE:
            self.operations[request.logical_operation_id] = fingerprint
            return self._receipt(actor, request, pre, DecisionStatus.ALLOW, "read-authorized")

        target = ALLOWED_TRANSITIONS.get((self.workflow.state, command))
        if target is None:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "transition-illegal")

        if command is Command.EXECUTE_EXPORT:
            if not request.destination or not request.destination.endswith(".northstar.example"):
                return self._receipt(actor, request, pre, DecisionStatus.DENY, "destination-not-allowed")
            ok, reason = self.approvals.consume_exact(request.approval_id, request, actor, step=step)
            if not ok:
                return self._receipt(actor, request, pre, DecisionStatus.DENY, reason)

        self.operations[request.logical_operation_id] = fingerprint
        self.workflow.state = target
        self.workflow.version += 1
        effect_applied = command is Command.EXECUTE_EXPORT
        if effect_applied:
            self.workflow.effects.append(f"export:{request.resource_id}:{request.destination}")
        return self._receipt(actor, request, pre, DecisionStatus.ALLOW, "transition-applied", effect_applied=effect_applied)


class UnsafeGateway(SecureGateway):
    """Labelled anti-pattern with parser, identity, approval, and replay flaws."""

    name = "unsafe-baseline"

    def execute(self, actor: ActorContext, request: ActionRequest, *, step: int = 0) -> DecisionReceipt:
        pre = self.workflow.snapshot()
        if not self.dependency_available:
            # Fake success is intentionally unsafe.
            return self._receipt(actor, request, pre, DecisionStatus.ALLOW, "dependency-bypassed")

        effective_tenant = request.claimed_tenant or actor.tenant_id
        resource = self.resources.get(request.resource_id)
        if resource is None or effective_tenant != resource.tenant_id:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "resource-denied")

        # Guard sees raw text; executor sees a normalized command. This is the
        # parser differential the generated encoded case should find.
        raw_command = request.command
        executed_command = canonical_command(raw_command)
        if raw_command == Command.EXECUTE_EXPORT.value and not request.approval_id:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "approval-required")
        if request.expected_version > self.workflow.version:
            return self._receipt(actor, request, pre, DecisionStatus.DENY, "future-version")

        if executed_command == Command.READ_CASE.value:
            return self._receipt(actor, request, pre, DecisionStatus.ALLOW, "read")
        if executed_command == Command.EXECUTE_EXPORT.value:
            self.workflow.state = WorkflowState.EXECUTED
            self.workflow.version += 1
            self.workflow.effects.append(f"export:{request.resource_id}:{request.destination}")
            return self._receipt(actor, request, pre, DecisionStatus.ALLOW, "exported", effect_applied=True)

        transitions = {
            Command.SUBMIT_REVIEW.value: WorkflowState.REVIEW,
            Command.APPROVE_EXPORT.value: WorkflowState.APPROVED,
            Command.CANCEL.value: WorkflowState.CANCELLED,
        }
        if executed_command in transitions:
            self.workflow.state = transitions[executed_command]
            self.workflow.version += 1
            return self._receipt(actor, request, pre, DecisionStatus.ALLOW, "transition-applied")
        return self._receipt(actor, request, pre, DecisionStatus.DENY, "unknown")


class SecurityOracle:
    """Evaluate postconditions independently from the gateway's reason string."""

    def inspect(
        self,
        actor: ActorContext,
        request: ActionRequest,
        pre: WorkflowSnapshot,
        post: WorkflowSnapshot,
        receipt: DecisionReceipt,
        resources: Mapping[str, Resource],
    ) -> tuple[OracleFinding, ...]:
        findings: list[OracleFinding] = []
        resource = resources.get(request.resource_id)
        exact_command = request.command == Command.EXECUTE_EXPORT.value
        effect_added = len(post.effects) > len(pre.effects)

        def add(invariant: Invariant, message: str) -> None:
            findings.append(
                OracleFinding(
                    invariant,
                    message,
                    f"{invariant.value}:{canonical_command(request.command)}:{pre.state.value}",
                )
            )

        if effect_added and (resource is None or actor.tenant_id != resource.tenant_id):
            add(Invariant.TENANT_ISOLATION, "an effect crossed the authenticated tenant boundary")
        if effect_added and "export-requester" not in actor.roles:
            add(Invariant.AUTHENTICATED_IDENTITY, "an actor without export authority caused an effect")
        if effect_added and not exact_command:
            add(Invariant.EXACT_APPROVAL, "an encoded or ambiguous command reached the export executor")
        if effect_added and not request.approval_id:
            add(Invariant.EXACT_APPROVAL, "an export effect occurred without an approval identifier")
        if effect_added and pre.state is not WorkflowState.APPROVED:
            add(Invariant.LEGAL_TRANSITION, "an export effect bypassed the approved workflow state")
        if effect_added and request.expected_version != pre.version:
            add(Invariant.OPTIMISTIC_CONCURRENCY, "a stale command changed durable state")
        if len(post.effects) - len(pre.effects) > 1 or len(set(post.effects)) != len(post.effects):
            add(Invariant.IDEMPOTENT_EFFECT, "an operation created duplicate external effects")
        if receipt.status is DecisionStatus.ALLOW and receipt.reason == "dependency-bypassed":
            add(Invariant.FAIL_CLOSED, "a policy dependency failure was reported as success")
        return tuple(findings)


def principals() -> dict[str, ActorContext]:
    return {
        "requester": ActorContext("user:maya", "north", frozenset({"case-reader", "export-requester"})),
        "approver": ActorContext("user:rene", "north", frozenset({"case-reader", "export-approver"})),
        "outsider": ActorContext("user:otto", "south", frozenset({"case-reader", "export-requester"})),
        "reader": ActorContext("user:lee", "north", frozenset({"case-reader"})),
    }


def resources() -> dict[str, Resource]:
    return {
        "case:north:7": Resource("case:north:7", "north"),
        "case:south:9": Resource("case:south:9", "south"),
    }


def request(
    command: str | Command,
    operation: str,
    *,
    state_version: int = 0,
    resource_id: str = "case:north:7",
    workflow_id: str = "workflow:north:7",
    destination: str = "archive.northstar.example",
    payload_bytes: int = 512,
    approval_id: str = "",
    claimed_tenant: str = "",
    claimed_subject: str = "",
) -> ActionRequest:
    return ActionRequest(
        command=command.value if isinstance(command, Command) else command,
        workflow_id=workflow_id,
        resource_id=resource_id,
        logical_operation_id=operation,
        expected_version=state_version,
        destination=destination,
        payload_bytes=payload_bytes,
        approval_id=approval_id,
        claimed_tenant=claimed_tenant,
        claimed_subject=claimed_subject,
    )


def build_gateway(
    gateway_type: type[SecureGateway],
    case: FuzzCase,
) -> tuple[SecureGateway, Workflow, ApprovalStore]:
    workflow = Workflow(
        "workflow:north:7",
        "north",
        "case:north:7",
        state=case.initial_state,
        version=case.initial_version,
    )
    approvals = ApprovalStore()
    gateway = gateway_type(
        workflow,
        resources(),
        approvals,
        dependency_available=case.dependency_available,
    )
    if case.preload_operation is not None:
        gateway.operations[case.preload_operation.logical_operation_id] = proposal_digest(case.preload_operation)
    if case.issue_approval:
        receipt = approvals.issue(
            case.request,
            case.actor,
            principals()["approver"],
            step=0,
            approval_id=case.request.approval_id,
        )
        if case.approval_override:
            approvals.receipts[receipt.approval_id] = replace(receipt, **dict(case.approval_override))
    return gateway, workflow, approvals


def run_case(case: FuzzCase, gateway_type: type[SecureGateway] = SecureGateway) -> CaseResult:
    gateway, workflow, _ = build_gateway(gateway_type, case)
    pre = workflow.snapshot()
    receipt = gateway.execute(case.actor, case.request, step=1)
    post = workflow.snapshot()
    findings = SecurityOracle().inspect(case.actor, case.request, pre, post, receipt, resources())
    return CaseResult(case.case_id, case.kind, case.expected_status, receipt, findings, input_size(case.request))


def build_corpus() -> tuple[FuzzCase, ...]:
    p = principals()
    execute = request(
        Command.EXECUTE_EXPORT,
        "valid:execute",
        state_version=2,
        approval_id="approval:valid",
    )
    corpus = [
        FuzzCase("valid-read", CaseKind.VALID, p["reader"], request(Command.READ_CASE, "valid:read"), WorkflowState.DRAFT, 0, DecisionStatus.ALLOW),
        FuzzCase("valid-submit", CaseKind.VALID, p["requester"], request(Command.SUBMIT_REVIEW, "valid:submit"), WorkflowState.DRAFT, 0, DecisionStatus.ALLOW),
        FuzzCase("valid-approve", CaseKind.VALID, p["approver"], request(Command.APPROVE_EXPORT, "valid:approve", state_version=1), WorkflowState.REVIEW, 1, DecisionStatus.ALLOW),
        FuzzCase("valid-execute", CaseKind.VALID, p["requester"], execute, WorkflowState.APPROVED, 2, DecisionStatus.ALLOW, issue_approval=True),
        FuzzCase("valid-cancel", CaseKind.VALID, p["requester"], request(Command.CANCEL, "valid:cancel", state_version=1), WorkflowState.REVIEW, 1, DecisionStatus.ALLOW),
        FuzzCase("attack-cross-tenant-resource", CaseKind.ATTACK, p["requester"], request(Command.READ_CASE, "attack:cross", resource_id="case:south:9"), WorkflowState.DRAFT, 0, DecisionStatus.DENY),
        FuzzCase("attack-claimed-tenant", CaseKind.ATTACK, p["outsider"], request(Command.EXECUTE_EXPORT, "attack:claimed", state_version=2, approval_id="approval:claimed", claimed_tenant="north"), WorkflowState.APPROVED, 2, DecisionStatus.DENY),
        FuzzCase("attack-fullwidth-command", CaseKind.ATTACK, p["requester"], request("ｅxecute_export", "attack:fullwidth", state_version=2), WorkflowState.APPROVED, 2, DecisionStatus.DENY),
        FuzzCase("attack-casefold-command", CaseKind.ATTACK, p["requester"], request("EXECUTE_EXPORT", "attack:casefold", state_version=2), WorkflowState.APPROVED, 2, DecisionStatus.DENY),
        FuzzCase("attack-missing-operation", CaseKind.ATTACK, p["requester"], request(Command.SUBMIT_REVIEW, ""), WorkflowState.DRAFT, 0, DecisionStatus.DENY),
        FuzzCase("attack-stale-version", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:stale", state_version=1, approval_id="approval:stale"), WorkflowState.APPROVED, 2, DecisionStatus.DENY, issue_approval=True),
        FuzzCase("attack-illegal-submit", CaseKind.ATTACK, p["requester"], request(Command.SUBMIT_REVIEW, "attack:illegal", state_version=2), WorkflowState.APPROVED, 2, DecisionStatus.DENY),
        FuzzCase("attack-execute-from-review", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:review", state_version=1, approval_id="approval:review"), WorkflowState.REVIEW, 1, DecisionStatus.DENY, issue_approval=True),
        FuzzCase("attack-missing-approval", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:no-approval", state_version=2), WorkflowState.APPROVED, 2, DecisionStatus.DENY),
        FuzzCase("attack-altered-after-approval", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:altered", state_version=2, approval_id="approval:altered", destination="evil.example"), WorkflowState.APPROVED, 2, DecisionStatus.DENY, issue_approval=True),
        FuzzCase("attack-wrong-tenant-approval", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:approval-tenant", state_version=2, approval_id="approval:tenant"), WorkflowState.APPROVED, 2, DecisionStatus.DENY, issue_approval=True, approval_override={"tenant_id": "south"}),
        FuzzCase("attack-stale-policy-approval", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:policy", state_version=2, approval_id="approval:policy"), WorkflowState.APPROVED, 2, DecisionStatus.DENY, issue_approval=True, approval_override={"policy_version": "agent-gateway/old"}),
        FuzzCase("attack-expired-approval", CaseKind.ATTACK, p["requester"], request(Command.EXECUTE_EXPORT, "attack:expired", state_version=2, approval_id="approval:expired"), WorkflowState.APPROVED, 2, DecisionStatus.DENY, issue_approval=True, approval_override={"expires_step": 0}),
        FuzzCase("attack-operation-collision", CaseKind.ATTACK, p["requester"], request(Command.SUBMIT_REVIEW, "collision:1", destination="changed.northstar.example"), WorkflowState.DRAFT, 0, DecisionStatus.DENY, preload_operation=request(Command.SUBMIT_REVIEW, "collision:1")),
        FuzzCase("boundary-max-operation-id", CaseKind.BOUNDARY, p["requester"], request(Command.SUBMIT_REVIEW, "x" * MAX_OPERATION_ID), WorkflowState.DRAFT, 0, DecisionStatus.ALLOW),
        FuzzCase("boundary-operation-too-long", CaseKind.BOUNDARY, p["requester"], request(Command.SUBMIT_REVIEW, "x" * (MAX_OPERATION_ID + 1)), WorkflowState.DRAFT, 0, DecisionStatus.DENY),
        FuzzCase("boundary-max-payload", CaseKind.BOUNDARY, p["reader"], request(Command.READ_CASE, "boundary:payload", payload_bytes=MAX_PAYLOAD_BYTES), WorkflowState.DRAFT, 0, DecisionStatus.ALLOW),
        FuzzCase("boundary-payload-too-large", CaseKind.BOUNDARY, p["reader"], request(Command.READ_CASE, "boundary:payload-big", payload_bytes=MAX_PAYLOAD_BYTES + 1), WorkflowState.DRAFT, 0, DecisionStatus.DENY),
        FuzzCase("failure-policy-read", CaseKind.FAILURE, p["reader"], request(Command.READ_CASE, "failure:read"), WorkflowState.DRAFT, 0, DecisionStatus.ERROR, dependency_available=False),
        FuzzCase("failure-policy-transition", CaseKind.FAILURE, p["requester"], request(Command.SUBMIT_REVIEW, "failure:transition"), WorkflowState.DRAFT, 0, DecisionStatus.ERROR, dependency_available=False),
        FuzzCase("failure-policy-execute", CaseKind.FAILURE, p["requester"], request(Command.EXECUTE_EXPORT, "failure:execute", state_version=2, approval_id="approval:failure"), WorkflowState.APPROVED, 2, DecisionStatus.ERROR, issue_approval=True, dependency_available=False),
    ]
    return tuple(corpus)


def evaluate(gateway_type: type[SecureGateway] = SecureGateway) -> tuple[EvaluationReport, tuple[CaseResult, ...]]:
    corpus = build_corpus()
    results = tuple(run_case(case, gateway_type) for case in corpus)
    valid = [item for item in results if item.kind is CaseKind.VALID]
    attacks = [item for item in results if item.kind is CaseKind.ATTACK]
    boundaries = [item for item in results if item.kind is CaseKind.BOUNDARY]
    failures = [item for item in results if item.kind is CaseKind.FAILURE]
    attack_forbidden = [item for item in attacks if item.forbidden_outcome]
    all_forbidden = [item for item in results if item.forbidden_outcome]
    contained = [item for item in attacks if item.receipt.status is DecisionStatus.DENY and not item.forbidden_outcome]
    valid_rejections = [item for item in valid if item.receipt.status is not DecisionStatus.ALLOW]
    dependency_errors = [item for item in failures if item.receipt.status is DecisionStatus.ERROR]
    fail_open_dependencies = [item for item in failures if item.forbidden_outcome]
    repeated = tuple(run_case(case, gateway_type) for case in corpus)
    reproducible = sum(
        first.receipt.status == second.receipt.status
        and first.receipt.reason == second.receipt.reason
        and tuple(f.family for f in first.findings) == tuple(f.family for f in second.findings)
        for first, second in zip(results, repeated, strict=True)
    )
    report = EvaluationReport(
        implementation=gateway_type.name,
        total_cases=len(results),
        valid_cases=len(valid),
        attack_cases=len(attacks),
        boundary_cases=len(boundaries),
        failure_cases=len(failures),
        forbidden_outcomes=len(attack_forbidden),
        invariant_violation_rate=len(attack_forbidden) / len(attacks),
        contained_attack_rate=len(contained) / len(attacks),
        unique_failure_families=len({finding.family for item in all_forbidden for finding in item.findings}),
        valid_case_rejections=len(valid_rejections),
        valid_case_rejection_rate=len(valid_rejections) / len(valid),
        explicit_dependency_errors=len(dependency_errors),
        fail_open_dependency_outcomes=len(fail_open_dependencies),
        reproducibility_rate=reproducible / len(results),
        median_input_size=statistics.median(item.input_size for item in results),
    )
    return report, results


def run_sequence(
    gateway: SecureGateway,
    actor_by_role: Mapping[str, ActorContext],
    commands: Sequence[ActionRequest],
) -> tuple[DecisionReceipt, ...]:
    receipts: list[DecisionReceipt] = []
    for index, item in enumerate(commands):
        command = canonical_command(item.command)
        actor = actor_by_role["approver"] if command == Command.APPROVE_EXPORT.value else actor_by_role["requester"]
        receipts.append(gateway.execute(actor, item, step=index + 1))
    return tuple(receipts)


def race_scenario(gateway_type: type[SecureGateway] = SecureGateway) -> tuple[DecisionReceipt, DecisionReceipt]:
    p = principals()
    workflow = Workflow("workflow:north:7", "north", "case:north:7")
    gateway = gateway_type(workflow, resources())
    first = request(Command.SUBMIT_REVIEW, "race:first", state_version=0)
    second = request(Command.CANCEL, "race:second", state_version=0)
    return gateway.execute(p["requester"], first, step=1), gateway.execute(p["requester"], second, step=1)


def minimize_sequence(
    sequence: Sequence[ActionRequest],
    reproduces: Callable[[Sequence[ActionRequest]], bool],
) -> tuple[ActionRequest, ...]:
    """Deterministic deletion minimizer that preserves the supplied oracle.

    This teaches the contract behind shrinking.  Hypothesis performs its own
    integrated structural shrinking in ``hypothesis_adapter.py``.
    """
    candidate = list(sequence)
    changed = True
    while changed and len(candidate) > 1:
        changed = False
        for index in range(len(candidate)):
            trial = candidate[:index] + candidate[index + 1 :]
            if trial and reproduces(trial):
                candidate = trial
                changed = True
                break
    return tuple(candidate)


def encoded_bypass_sequence() -> tuple[ActionRequest, ...]:
    return (
        request(Command.SUBMIT_REVIEW, "seq:submit", state_version=0),
        request(Command.APPROVE_EXPORT, "seq:approve", state_version=1),
        request("ｅxecute_export", "seq:encoded", state_version=2),
        request(Command.CANCEL, "seq:noise", state_version=3),
    )


def sequence_has_unsafe_forbidden_outcome(sequence: Sequence[ActionRequest]) -> bool:
    target_family = (
        f"{Invariant.EXACT_APPROVAL.value}:"
        f"{Command.EXECUTE_EXPORT.value}:"
        f"{WorkflowState.APPROVED.value}"
    )
    workflow = Workflow("workflow:north:7", "north", "case:north:7")
    gateway = UnsafeGateway(workflow, resources())
    p = principals()
    for index, item in enumerate(sequence):
        actor = p["approver"] if canonical_command(item.command) == Command.APPROVE_EXPORT.value else p["requester"]
        pre = workflow.snapshot()
        receipt = gateway.execute(actor, item, step=index + 1)
        findings = SecurityOracle().inspect(actor, item, pre, workflow.snapshot(), receipt, resources())
        if any(finding.family == target_family for finding in findings):
            return True
    return False


def demo() -> dict[str, object]:
    secure, _ = evaluate(SecureGateway)
    unsafe, _ = evaluate(UnsafeGateway)
    original = encoded_bypass_sequence()
    minimized = minimize_sequence(original, sequence_has_unsafe_forbidden_outcome)
    race = race_scenario(SecureGateway)
    return {
        "secure": asdict(secure),
        "unsafe": asdict(unsafe),
        "sequence_steps_before": len(original),
        "sequence_steps_after": len(minimized),
        "minimized_commands": [item.command for item in minimized],
        "race_statuses": [item.status.value for item in race],
    }


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2, default=str))

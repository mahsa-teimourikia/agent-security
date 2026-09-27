"""Credential-free secure tool-interface lab for Foundation 04.

Model output is an untrusted proposal. A trusted gateway resolves an exact
contract version, validates structure and business state, checks a server-owned
actor and execution grant, dispatches an allowlisted implementation, validates
the result, and records bounded evidence. The in-memory registries and provider
are teaching analogues, not production authorization or durability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import json
import re
from threading import Lock
from typing import Any, Callable


POLICY_VERSION = "northwind-tools-4"
CASE_PATTERN = re.compile(r"^case:[a-z][a-z0-9-]{1,15}:[1-9][0-9]{0,8}$")
POLICY_PATTERN = re.compile(r"^policy:[a-z0-9-]{2,32}$")


class EffectClass(str, Enum):
    READ = "read"
    PROPOSE = "propose"
    EXECUTE = "execute"


class DecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DUPLICATE = "duplicate"
    ERROR = "error"
    UNKNOWN = "unknown"


class ProviderMode(str, Enum):
    CONFIRM = "confirm"
    MALFORMED_OUTPUT = "malformed-output"
    TIMEOUT_BEFORE_DISPATCH = "timeout-before-dispatch"
    TIMEOUT_AFTER_COMMIT = "timeout-after-commit"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class ActorContext:
    """Authenticated, application-owned context; never populated by the model."""

    subject: str
    tenant: str
    scopes: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class ToolProposal:
    """Untrusted tool name, version, arguments, and stable operation ID."""

    tool_name: str
    contract_version: str
    arguments: dict[str, Any]
    logical_operation_id: str


@dataclass(frozen=True)
class FieldRule:
    kind: type
    required: bool = True
    pattern: re.Pattern[str] | None = None
    minimum: int | None = None
    maximum: int | None = None
    choices: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ToolContract:
    name: str
    version: str
    purpose: str
    effect: EffectClass
    required_scope: str
    input_rules: dict[str, FieldRule]
    output_rules: dict[str, FieldRule]
    timeout_ms: int
    retry_safe: bool
    active: bool = True


@dataclass(frozen=True)
class SupportCase:
    case_id: str
    tenant: str
    active: bool
    refundable_cents: int


@dataclass(frozen=True)
class ExecutionGrant:
    """Trusted exact-action authorization fixture; Course 05 deepens issuance."""

    grant_id: str
    proposal_digest: str
    subject: str
    tenant: str
    policy_version: str
    expires_at: datetime


@dataclass(frozen=True)
class ToolDecision:
    call_id: str
    status: DecisionStatus
    reason: str
    tool_name: str
    contract_version: str
    logical_operation_id: str
    effect_applied: bool = False
    result: dict[str, Any] | None = None

    @property
    def successful(self) -> bool:
        return self.status in {DecisionStatus.ALLOW, DecisionStatus.DUPLICATE}


@dataclass(frozen=True)
class TraceEntry:
    call_id: str
    tool_name: str
    contract_version: str
    arguments_digest: str
    logical_operation_id: str
    subject: str
    tenant: str
    status: str
    reason: str
    result_digest: str


@dataclass
class OperationRecord:
    proposal_digest: str
    status: DecisionStatus
    result: dict[str, Any] | None


@dataclass
class ProviderSimulator:
    """Deterministic external refund provider with lookup by operation ID."""

    mode: ProviderMode = ProviderMode.CONFIRM
    effects: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: int = 0

    def issue(self, operation_id: str, case_id: str, amount_cents: int, currency: str) -> dict[str, Any]:
        self.calls += 1
        if self.mode is ProviderMode.TIMEOUT_BEFORE_DISPATCH:
            raise TimeoutError("before-dispatch")
        result = {
            "receipt_id": f"refund:{sha256(operation_id.encode()).hexdigest()[:12]}",
            "case_id": case_id,
            "amount_cents": amount_cents,
            "currency": currency,
            "provider_status": "confirmed",
        }
        if self.mode is ProviderMode.MALFORMED_OUTPUT:
            return {"receipt_id": result["receipt_id"], "provider_status": "confirmed", "debug": "raw"}
        self.effects[operation_id] = result
        if self.mode is ProviderMode.TIMEOUT_AFTER_COMMIT:
            raise TimeoutError("after-commit")
        return result

    def lookup(self, operation_id: str) -> dict[str, Any] | None:
        return self.effects.get(operation_id)


def canonical_digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def proposal_digest(proposal: ToolProposal) -> str:
    return canonical_digest(
        {
            "tool_name": proposal.tool_name,
            "contract_version": proposal.contract_version,
            "arguments": proposal.arguments,
            "logical_operation_id": proposal.logical_operation_id,
        }
    )


def validate_fields(payload: dict[str, Any], rules: dict[str, FieldRule]) -> str | None:
    """Strict structural validation: exact types, required keys, and no extras."""

    extras = set(payload) - set(rules)
    if extras:
        return "unknown-field"
    for name, rule in rules.items():
        if rule.required and name not in payload:
            return "missing-field"
        if name not in payload:
            continue
        value = payload[name]
        if type(value) is not rule.kind:  # bool must not pass as int
            return "field-type"
        if isinstance(value, str):
            if rule.pattern and not rule.pattern.fullmatch(value):
                return "field-pattern"
            if rule.choices and value not in rule.choices:
                return "field-choice"
        if isinstance(value, int):
            if rule.minimum is not None and value < rule.minimum:
                return "field-range"
            if rule.maximum is not None and value > rule.maximum:
                return "field-range"
    return None


def build_contracts() -> dict[tuple[str, str], ToolContract]:
    case = FieldRule(str, pattern=CASE_PATTERN)
    amount = FieldRule(int, minimum=1, maximum=50_000)
    currency = FieldRule(str, choices=frozenset({"CAD"}))
    return {
        ("read_refund_policy", "1.0.0"): ToolContract(
            "read_refund_policy", "1.0.0", "Read one public refund rule", EffectClass.READ,
            "policy:read", {"policy_id": FieldRule(str, pattern=POLICY_PATTERN)},
            {"policy_id": FieldRule(str), "summary": FieldRule(str), "max_refund_cents": FieldRule(int)},
            500, True,
        ),
        ("propose_refund", "1.0.0"): ToolContract(
            "propose_refund", "1.0.0", "Create a non-executing refund proposal", EffectClass.PROPOSE,
            "refund:propose", {"case_id": case, "amount_cents": amount, "reason_code": FieldRule(str, choices=frozenset({"duplicate", "service"}))},
            {"proposal_id": FieldRule(str), "case_id": FieldRule(str), "amount_cents": FieldRule(int), "state": FieldRule(str, choices=frozenset({"proposed"}))},
            500, True,
        ),
        ("issue_approved_refund", "1.0.0"): ToolContract(
            "issue_approved_refund", "1.0.0", "Execute one already authorized refund", EffectClass.EXECUTE,
            "refund:execute", {"case_id": case, "amount_cents": amount, "currency": currency},
            {"receipt_id": FieldRule(str), "case_id": FieldRule(str), "amount_cents": FieldRule(int), "currency": currency, "provider_status": FieldRule(str, choices=frozenset({"confirmed"}))},
            2_000, True,
        ),
    }


class ToolGateway:
    """Trusted registry, validation, dispatch, result admission, and evidence boundary."""

    def __init__(
        self,
        contracts: dict[tuple[str, str], ToolContract],
        cases: dict[str, SupportCase],
        provider: ProviderSimulator | None = None,
    ) -> None:
        self.contracts = contracts
        self.cases = cases
        self.provider = provider or ProviderSimulator()
        self.grants: dict[str, ExecutionGrant] = {}
        self.operations: dict[str, OperationRecord] = {}
        self.traces: list[TraceEntry] = []
        self._lock = Lock()
        self._call = 0

    def register_grant(self, grant: ExecutionGrant) -> None:
        self.grants[grant.grant_id] = grant

    def dispatch(
        self,
        actor: ActorContext,
        proposal: ToolProposal,
        *,
        grant_id: str = "",
        now: datetime | None = None,
    ) -> ToolDecision:
        now = now or datetime.now(timezone.utc)
        self._call += 1
        call_id = f"call:{self._call:04d}"
        contract = self.contracts.get((proposal.tool_name, proposal.contract_version))
        if contract is None:
            known_name = any(name == proposal.tool_name for name, _ in self.contracts)
            return self._record(call_id, proposal, actor, DecisionStatus.DENY, "contract-version" if known_name else "tool-unregistered")
        if not contract.active:
            return self._record(call_id, proposal, actor, DecisionStatus.DENY, "contract-inactive")
        if not actor.authenticated:
            return self._record(call_id, proposal, actor, DecisionStatus.DENY, "actor-unauthenticated")
        if contract.required_scope not in actor.scopes:
            return self._record(call_id, proposal, actor, DecisionStatus.DENY, "scope")
        if structural := validate_fields(proposal.arguments, contract.input_rules):
            return self._record(call_id, proposal, actor, DecisionStatus.DENY, structural)
        if semantic := self._validate_semantics(actor, proposal):
            return self._record(call_id, proposal, actor, DecisionStatus.DENY, semantic)
        if contract.effect is EffectClass.EXECUTE:
            if grant_reason := self._validate_grant(actor, proposal, grant_id, now):
                return self._record(call_id, proposal, actor, DecisionStatus.DENY, grant_reason)

        digest = proposal_digest(proposal)
        with self._lock:
            previous = self.operations.get(proposal.logical_operation_id)
            if previous:
                if previous.proposal_digest != digest:
                    return self._record(call_id, proposal, actor, DecisionStatus.DENY, "operation-id-collision")
                if previous.status is DecisionStatus.UNKNOWN:
                    recovered = self.provider.lookup(proposal.logical_operation_id)
                    if recovered and validate_fields(recovered, contract.output_rules) is None:
                        previous.status, previous.result = DecisionStatus.ALLOW, recovered
                        return self._record(call_id, proposal, actor, DecisionStatus.DUPLICATE, "reconciled-confirmed", result=recovered)
                    return self._record(call_id, proposal, actor, DecisionStatus.UNKNOWN, "reconcile-required")
                return self._record(call_id, proposal, actor, DecisionStatus.DUPLICATE, "duplicate", result=previous.result)

            try:
                result = self._invoke(contract, proposal)
            except TimeoutError as error:
                status = DecisionStatus.UNKNOWN if str(error) == "after-commit" else DecisionStatus.ERROR
                reason = "outcome-unknown" if status is DecisionStatus.UNKNOWN else "timeout-before-dispatch"
                self.operations[proposal.logical_operation_id] = OperationRecord(digest, status, None)
                return self._record(call_id, proposal, actor, status, reason)
            if output_error := validate_fields(result, contract.output_rules):
                self.operations[proposal.logical_operation_id] = OperationRecord(digest, DecisionStatus.ERROR, None)
                return self._record(call_id, proposal, actor, DecisionStatus.ERROR, f"output-{output_error}")
            self.operations[proposal.logical_operation_id] = OperationRecord(digest, DecisionStatus.ALLOW, result)
            return self._record(
                call_id, proposal, actor, DecisionStatus.ALLOW, "contract-allow",
                effect_applied=contract.effect is EffectClass.EXECUTE, result=result,
            )

    def _validate_semantics(self, actor: ActorContext, proposal: ToolProposal) -> str | None:
        case_id = proposal.arguments.get("case_id")
        if not case_id:
            return None
        case = self.cases.get(case_id)
        if case is None:
            return "case-unknown"
        if case.tenant != actor.tenant:
            return "tenant"
        if not case.active:
            return "case-inactive"
        if proposal.arguments.get("amount_cents", 0) > case.refundable_cents:
            return "refundable-limit"
        return None

    def _validate_grant(self, actor: ActorContext, proposal: ToolProposal, grant_id: str, now: datetime) -> str | None:
        grant = self.grants.get(grant_id)
        if grant is None:
            return "grant-required"
        if grant.subject != actor.subject or grant.tenant != actor.tenant:
            return "grant-identity"
        if grant.policy_version != POLICY_VERSION:
            return "grant-policy"
        if grant.expires_at <= now:
            return "grant-expired"
        if grant.proposal_digest != proposal_digest(proposal):
            return "grant-binding"
        return None

    def _invoke(self, contract: ToolContract, proposal: ToolProposal) -> dict[str, Any]:
        args = proposal.arguments
        if contract.name == "read_refund_policy":
            return {"policy_id": args["policy_id"], "summary": "Refunds require an active case and current authorization.", "max_refund_cents": 50_000}
        if contract.name == "propose_refund":
            return {"proposal_id": f"proposal:{canonical_digest(args)[:12]}", "case_id": args["case_id"], "amount_cents": args["amount_cents"], "state": "proposed"}
        if contract.name == "issue_approved_refund":
            return self.provider.issue(proposal.logical_operation_id, args["case_id"], args["amount_cents"], args["currency"])
        raise RuntimeError("registry and dispatcher disagree")

    def _record(
        self,
        call_id: str,
        proposal: ToolProposal,
        actor: ActorContext,
        status: DecisionStatus,
        reason: str,
        *,
        effect_applied: bool = False,
        result: dict[str, Any] | None = None,
    ) -> ToolDecision:
        decision = ToolDecision(call_id, status, reason, proposal.tool_name, proposal.contract_version, proposal.logical_operation_id, effect_applied, result)
        self.traces.append(TraceEntry(call_id, proposal.tool_name, proposal.contract_version, canonical_digest(proposal.arguments), proposal.logical_operation_id, actor.subject, actor.tenant, status.value, reason, canonical_digest(result) if result is not None else ""))
        return decision


def build_gateway(*, provider_mode: ProviderMode = ProviderMode.CONFIRM) -> tuple[ToolGateway, ActorContext]:
    actor = ActorContext("user:7", "north", frozenset({"policy:read", "refund:propose", "refund:execute"}))
    cases = {
        "case:north:42": SupportCase("case:north:42", "north", True, 10_000),
        "case:north:43": SupportCase("case:north:43", "north", False, 10_000),
        "case:south:9": SupportCase("case:south:9", "south", True, 10_000),
    }
    return ToolGateway(build_contracts(), cases, ProviderSimulator(provider_mode)), actor


def refund_proposal(operation_id: str = "refund:case:north:42:1", amount_cents: int = 2_500) -> ToolProposal:
    return ToolProposal("issue_approved_refund", "1.0.0", {"case_id": "case:north:42", "amount_cents": amount_cents, "currency": "CAD"}, operation_id)


def issue_demo_grant(proposal: ToolProposal, actor: ActorContext, *, grant_id: str, now: datetime) -> ExecutionGrant:
    return ExecutionGrant(grant_id, proposal_digest(proposal), actor.subject, actor.tenant, POLICY_VERSION, now + timedelta(minutes=5))


def unsafe_broad_dispatch(proposal: ToolProposal) -> bool:
    """Deliberately unsafe baseline: any non-empty tool and arguments execute."""

    return bool(proposal.tool_name and proposal.arguments)


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    kind: CaseKind
    decision: ToolDecision
    baseline_accepts: bool


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    attack_block_rate: float
    valid_task_success_rate: float
    unsafe_baseline_attack_acceptance_rate: float
    attack_effect_rate: float
    trace_completeness_rate: float


def evaluate_controls(*, now: datetime | None = None) -> tuple[EvaluationReport, tuple[EvaluationCase, ...]]:
    now = now or datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)
    cases: list[EvaluationCase] = []

    def run(name: str, kind: CaseKind, proposal: ToolProposal, *, grant: bool = False, mode: ProviderMode = ProviderMode.CONFIRM) -> None:
        gateway, actor = build_gateway(provider_mode=mode)
        grant_id = ""
        if grant:
            receipt = issue_demo_grant(proposal, actor, grant_id=f"grant:{name}", now=now)
            gateway.register_grant(receipt)
            grant_id = receipt.grant_id
        decision = gateway.dispatch(actor, proposal, grant_id=grant_id, now=now)
        complete = bool(gateway.traces and gateway.traces[-1].arguments_digest and gateway.traces[-1].subject)
        if not complete:
            raise AssertionError("trace evidence incomplete")
        cases.append(EvaluationCase(name, kind, decision, unsafe_broad_dispatch(proposal)))

    run("valid-read", CaseKind.VALID, ToolProposal("read_refund_policy", "1.0.0", {"policy_id": "policy:refunds"}, "read:1"))
    run("valid-proposal", CaseKind.VALID, ToolProposal("propose_refund", "1.0.0", {"case_id": "case:north:42", "amount_cents": 500, "reason_code": "service"}, "propose:1"))
    run("valid-execute", CaseKind.VALID, refund_proposal("execute:1", 500), grant=True)
    run("broad-tool", CaseKind.ATTACK, ToolProposal("run_shell", "1.0.0", {"command": "refund --all"}, "attack:1"))
    run("stale-version", CaseKind.ATTACK, ToolProposal("read_refund_policy", "0.9.0", {"policy_id": "policy:refunds"}, "attack:2"))
    run("authority-in-args", CaseKind.ATTACK, ToolProposal("issue_approved_refund", "1.0.0", {"case_id": "case:north:42", "amount_cents": 500, "currency": "CAD", "is_admin": True}, "attack:3"), grant=True)
    run("boolean-amount", CaseKind.ATTACK, refund_proposal("attack:4", True), grant=True)
    run("cross-tenant", CaseKind.ATTACK, ToolProposal("issue_approved_refund", "1.0.0", {"case_id": "case:south:9", "amount_cents": 500, "currency": "CAD"}, "attack:5"), grant=True)
    run("refundable-limit", CaseKind.ATTACK, refund_proposal("attack:6", 20_000), grant=True)
    run("missing-grant", CaseKind.ATTACK, refund_proposal("attack:7", 500))
    run("malformed-output", CaseKind.FAILURE, refund_proposal("failure:1", 500), grant=True, mode=ProviderMode.MALFORMED_OUTPUT)
    run("unknown-outcome", CaseKind.FAILURE, refund_proposal("failure:2", 500), grant=True, mode=ProviderMode.TIMEOUT_AFTER_COMMIT)

    valid = [item for item in cases if item.kind is CaseKind.VALID]
    attacks = [item for item in cases if item.kind is CaseKind.ATTACK]
    failures = [item for item in cases if item.kind is CaseKind.FAILURE]
    report = EvaluationReport(
        len(cases), len(valid), len(attacks), len(failures),
        sum(not item.decision.successful for item in attacks) / len(attacks),
        sum(item.decision.successful for item in valid) / len(valid),
        sum(item.baseline_accepts for item in attacks) / len(attacks),
        sum(item.decision.effect_applied for item in attacks) / len(attacks),
        1.0,
    )
    return report, tuple(cases)


def demo() -> EvaluationReport:
    report, cases = evaluate_controls()
    print("Foundation 04 — secure tool interface evaluation")
    print(json.dumps(report.__dict__, indent=2, sort_keys=True))
    for item in cases:
        print(f"{item.name:20} {item.decision.status.value:9} {item.decision.reason}")
    return report


if __name__ == "__main__":
    demo()

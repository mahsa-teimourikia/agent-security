"""Executable threat-model assurance for a research-and-support agent.

The model may suggest threats. Authenticated reviewers and deterministic checks
admit records, bind them to a versioned architecture, and verify that important
paths have controls, tests, telemetry, owners, and explicit residual risk.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from itertools import product


ARCHITECTURE_VERSION = "northwind-agent-2"
HIGH_RISK_THRESHOLD = 12


class Stride(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information-disclosure"
    DENIAL_OF_SERVICE = "denial-of-service"
    ELEVATION_OF_PRIVILEGE = "elevation-of-privilege"


class Gate(str, Enum):
    LEAF = "leaf"
    ANY = "any"
    ALL = "all"


class CaseKind(str, Enum):
    VALID = "valid"
    NEGATIVE = "negative"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str
    classification: str
    objectives: frozenset[str]


@dataclass(frozen=True)
class Element:
    element_id: str
    name: str
    kind: str
    zone: str
    owner: str


@dataclass(frozen=True)
class Boundary:
    boundary_id: str
    source_zone: str
    target_zone: str
    enforcement_owner: str


@dataclass(frozen=True)
class Flow:
    flow_id: str
    source_id: str
    target_id: str
    boundary_id: str
    operation: str
    asset_ids: tuple[str, ...]
    creates_effect: bool = False


@dataclass(frozen=True)
class SystemModel:
    version: str
    assets: tuple[Asset, ...]
    elements: tuple[Element, ...]
    boundaries: tuple[Boundary, ...]
    flows: tuple[Flow, ...]
    required_flow_ids: frozenset[str]

    def __post_init__(self) -> None:
        assets = _unique(self.assets, "asset_id", "asset")
        elements = _unique(self.elements, "element_id", "element")
        boundaries = _unique(self.boundaries, "boundary_id", "boundary")
        flows = _unique(self.flows, "flow_id", "flow")
        if not self.required_flow_ids <= set(flows):
            raise ValueError("required flow IDs must exist in the architecture")
        for flow in self.flows:
            if flow.source_id not in elements or flow.target_id not in elements:
                raise ValueError(f"{flow.flow_id}: unknown endpoint")
            if flow.boundary_id not in boundaries:
                raise ValueError(f"{flow.flow_id}: unknown boundary")
            if not set(flow.asset_ids) <= set(assets):
                raise ValueError(f"{flow.flow_id}: unknown asset")
            boundary = boundaries[flow.boundary_id]
            source = elements[flow.source_id]
            target = elements[flow.target_id]
            if (source.zone, target.zone) != (boundary.source_zone, boundary.target_zone):
                raise ValueError(f"{flow.flow_id}: boundary route does not match element zones")

    @property
    def flow_map(self) -> dict[str, Flow]:
        return {flow.flow_id: flow for flow in self.flows}


@dataclass(frozen=True)
class ReviewerContext:
    subject: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class Control:
    control_id: str
    name: str
    boundary_id: str
    enforced_by: str
    deterministic: bool


@dataclass(frozen=True)
class VerificationTest:
    test_id: str
    control_id: str
    fixture: str
    expected_result: str
    executed: bool
    passed: bool
    evidence_id: str


@dataclass(frozen=True)
class Reference:
    reference_id: str
    authority: str
    title: str
    url: str
    reviewed_date: str


@dataclass(frozen=True)
class ThreatProposal:
    """Untrusted suggestion from a workshop participant, tool, or model."""

    threat_id: str
    title: str
    category: Stride
    flow_id: str
    asset_ids: tuple[str, ...]
    preconditions: tuple[str, ...]
    attack_steps: tuple[str, ...]
    control_ids: tuple[str, ...]
    test_ids: tuple[str, ...]
    telemetry_fields: tuple[str, ...]
    owner: str
    inherent_likelihood: int
    inherent_impact: int
    residual_likelihood: int
    residual_impact: int
    reference_ids: tuple[str, ...]
    origin: str = "workshop"


@dataclass(frozen=True)
class ThreatRecord:
    threat_id: str
    title: str
    category: Stride
    flow_id: str
    asset_ids: tuple[str, ...]
    preconditions: tuple[str, ...]
    attack_steps: tuple[str, ...]
    control_ids: tuple[str, ...]
    test_ids: tuple[str, ...]
    telemetry_fields: tuple[str, ...]
    owner: str
    reviewer_id: str
    inherent_likelihood: int
    inherent_impact: int
    residual_likelihood: int
    residual_impact: int
    reference_ids: tuple[str, ...]
    origin: str
    residual_risk: str

    @property
    def inherent_score(self) -> int:
        return self.inherent_likelihood * self.inherent_impact

    @property
    def residual_score(self) -> int:
        return self.residual_likelihood * self.residual_impact


@dataclass(frozen=True)
class AdmissionDecision:
    accepted: bool
    reason: str
    record: ThreatRecord | None = None


def admit_proposal(
    proposal: ThreatProposal,
    reviewer: ReviewerContext,
    *,
    residual_risk: str,
) -> AdmissionDecision:
    """Require authenticated human review; origin never supplies authority."""
    if not reviewer.authenticated:
        return AdmissionDecision(False, "reviewer-unauthenticated")
    if "security-reviewer" not in reviewer.roles:
        return AdmissionDecision(False, "reviewer-role")
    if not residual_risk.strip():
        return AdmissionDecision(False, "residual-risk-required")
    return AdmissionDecision(
        True,
        "reviewed-proposal-admitted",
        ThreatRecord(
            **proposal.__dict__,
            reviewer_id=reviewer.subject,
            residual_risk=residual_risk,
        ),
    )


@dataclass(frozen=True)
class ThreatModel:
    architecture: SystemModel
    architecture_version: str
    records: tuple[ThreatRecord, ...]
    controls: tuple[Control, ...]
    tests: tuple[VerificationTest, ...]
    references: tuple[Reference, ...]
    reviewers: tuple[ReviewerContext, ...]


@dataclass(frozen=True)
class ReviewResult:
    accepted: bool
    blockers: tuple[str, ...]
    required_flow_coverage: float
    owner_coverage: float
    high_risk_control_coverage: float
    high_risk_test_coverage: float
    high_risk_telemetry_coverage: float
    records: int
    high_risk_records: int


def _unique(items: tuple[object, ...], field_name: str, label: str) -> dict[str, object]:
    result = {getattr(item, field_name): item for item in items}
    if len(result) != len(items):
        raise ValueError(f"{label} IDs must be unique")
    return result


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 1.0


def review_threat_model(model: ThreatModel) -> ReviewResult:
    """Evaluate traceability and completeness; this is not proof of no threats."""
    blockers: set[str] = set()
    flows = model.architecture.flow_map
    controls = _unique(model.controls, "control_id", "control")
    tests = _unique(model.tests, "test_id", "test")
    references = _unique(model.references, "reference_id", "reference")
    reviewers = {reviewer.subject: reviewer for reviewer in model.reviewers}
    records = _unique(model.records, "threat_id", "threat")

    if model.architecture_version != model.architecture.version:
        blockers.add("stale-architecture-version")

    represented_flows = {record.flow_id for record in model.records if record.flow_id in flows}
    for flow_id in sorted(model.architecture.required_flow_ids - represented_flows):
        blockers.add(f"unmodeled-flow:{flow_id}")

    high_risk = [record for record in records.values() if record.inherent_score >= HIGH_RISK_THRESHOLD]
    owner_ok = 0
    control_ok = 0
    test_ok = 0
    telemetry_ok = 0

    for record in records.values():
        flow = flows.get(record.flow_id)
        if flow is None:
            blockers.add(f"unknown-flow:{record.threat_id}")
            continue
        if not set(record.asset_ids) or not set(record.asset_ids) <= set(flow.asset_ids):
            blockers.add(f"asset-flow-mismatch:{record.threat_id}")
        if not record.preconditions or not record.attack_steps:
            blockers.add(f"missing-attack-path:{record.threat_id}")
        if any(score not in range(1, 6) for score in (
            record.inherent_likelihood,
            record.inherent_impact,
            record.residual_likelihood,
            record.residual_impact,
        )):
            blockers.add(f"risk-scale:{record.threat_id}")
        if record.residual_score > record.inherent_score:
            blockers.add(f"residual-exceeds-inherent:{record.threat_id}")
        reviewer = reviewers.get(record.reviewer_id)
        if not reviewer or not reviewer.authenticated or "security-reviewer" not in reviewer.roles:
            blockers.add(f"untrusted-reviewer:{record.threat_id}")
        if not record.reference_ids or not set(record.reference_ids) <= set(references):
            blockers.add(f"reference-integrity:{record.threat_id}")

        record_controls = [controls[item] for item in record.control_ids if item in controls]
        if len(record_controls) != len(record.control_ids) or not record_controls:
            blockers.add(f"control-integrity:{record.threat_id}")
        boundary_controls = [
            control for control in record_controls
            if control.boundary_id == flow.boundary_id
            and control.deterministic
            and control.enforced_by not in {"model", "agent"}
        ]
        record_tests = [tests[item] for item in record.test_ids if item in tests]
        if len(record_tests) != len(record.test_ids) or not record_tests:
            blockers.add(f"test-integrity:{record.threat_id}")
        verified_controls = {
            test.control_id
            for test in record_tests
            if test.executed and test.passed and test.evidence_id.strip()
        }
        if record_controls and not verified_controls & {control.control_id for control in boundary_controls}:
            blockers.add(f"control-not-verified:{record.threat_id}")

        if record.owner.strip():
            owner_ok += 1
        if record in high_risk:
            if boundary_controls:
                control_ok += 1
            if record_tests and verified_controls & {control.control_id for control in boundary_controls}:
                test_ok += 1
            if {"decision", "reason", "architecture_version"} <= set(record.telemetry_fields):
                telemetry_ok += 1
            if not record.owner.strip():
                blockers.add(f"owner-required:{record.threat_id}")
            if not record.residual_risk.strip():
                blockers.add(f"residual-risk-required:{record.threat_id}")

    return ReviewResult(
        accepted=not blockers,
        blockers=tuple(sorted(blockers)),
        required_flow_coverage=_ratio(
            len(represented_flows & model.architecture.required_flow_ids),
            len(model.architecture.required_flow_ids),
        ),
        owner_coverage=_ratio(owner_ok, len(records)),
        high_risk_control_coverage=_ratio(control_ok, len(high_risk)),
        high_risk_test_coverage=_ratio(test_ok, len(high_risk)),
        high_risk_telemetry_coverage=_ratio(telemetry_ok, len(high_risk)),
        records=len(records),
        high_risk_records=len(high_risk),
    )


def unsafe_row_count_baseline(model: ThreatModel) -> bool:
    """Educational anti-pattern: row count ignores binding and evidence quality."""
    return len(model.records) >= len(model.architecture.required_flow_ids)


@dataclass(frozen=True)
class AttackNode:
    node_id: str
    label: str
    gate: Gate
    children: tuple["AttackNode", ...] = ()

    def __post_init__(self) -> None:
        if self.gate is Gate.LEAF and self.children:
            raise ValueError("leaf attack nodes cannot have children")
        if self.gate is not Gate.LEAF and not self.children:
            raise ValueError("branch attack nodes require children")


def attack_succeeds(node: AttackNode, achieved_leaves: frozenset[str]) -> bool:
    if node.gate is Gate.LEAF:
        return node.node_id in achieved_leaves
    outcomes = [attack_succeeds(child, achieved_leaves) for child in node.children]
    return any(outcomes) if node.gate is Gate.ANY else all(outcomes)


def minimal_cut_sets(node: AttackNode) -> frozenset[frozenset[str]]:
    """Return minimal leaf combinations that satisfy an acyclic attack tree."""
    if node.gate is Gate.LEAF:
        return frozenset({frozenset({node.node_id})})
    child_sets = [minimal_cut_sets(child) for child in node.children]
    candidates = (
        set().union(*child_sets)
        if node.gate is Gate.ANY
        else {frozenset().union(*items) for items in product(*child_sets)}
    )
    return frozenset(
        candidate for candidate in candidates
        if not any(other < candidate for other in candidates)
    )


def build_exfiltration_tree() -> AttackNode:
    leaf = lambda node_id, label: AttackNode(node_id, label, Gate.LEAF)
    return AttackNode(
        "exfiltrate-secret",
        "Exfiltrate an enterprise secret",
        Gate.ANY,
        (
            AttackNode("injected-tool-chain", "Indirect injection reaches egress", Gate.ALL, (
                leaf("hostile-context-admitted", "Hostile content reaches model context"),
                leaf("proposal-treated-as-authority", "Model proposal is treated as authority"),
                leaf("broad-egress", "Tool can send data to an attacker destination"),
            )),
            AttackNode("compromised-connector", "Compromised connector path", Gate.ALL, (
                leaf("connector-compromised", "Connector or MCP server is compromised"),
                leaf("upstream-token-reused", "Caller credential is forwarded upstream"),
            )),
            AttackNode("poisoned-memory-chain", "Poisoned memory persists", Gate.ALL, (
                leaf("memory-write-unchecked", "Untrusted content is stored as memory"),
                leaf("memory-read-unscoped", "Memory is read without subject or tenant scope"),
            )),
        ),
    )


def build_architecture() -> SystemModel:
    assets = (
        Asset("A1-request", "User request", "internal", frozenset({"integrity"})),
        Asset("A2-evidence", "Policy evidence and support PII", "restricted", frozenset({"confidentiality", "integrity"})),
        Asset("A3-proposal", "Model action proposal", "untrusted", frozenset({"integrity"})),
        Asset("A4-effect", "Ticket or refund effect", "high-impact", frozenset({"integrity", "availability"})),
        Asset("A5-memory", "Agent memory", "restricted", frozenset({"confidentiality", "integrity"})),
    )
    elements = (
        Element("E1-user", "User or attacker", "actor", "external", "identity-team"),
        Element("E2-api", "API gateway", "service", "application", "platform-team"),
        Element("E3-context", "Context gateway", "service", "application", "knowledge-team"),
        Element("E4-model", "Model and planner", "model", "agent", "agent-team"),
        Element("E5-runtime", "Agent runtime", "service", "application", "agent-team"),
        Element("E6-tool", "Tool policy gateway", "service", "enterprise", "security-platform"),
        Element("E7-evidence", "Evidence API", "datastore", "data", "data-owner"),
        Element("E8-ticket", "Ticket and refund API", "external-service", "business", "support-ops"),
        Element("E9-memory", "Memory store", "datastore", "data", "data-owner"),
    )
    boundaries = (
        Boundary("B1-user-api", "external", "application", "api-gateway"),
        Boundary("B2-context-evidence", "application", "data", "context-service"),
        Boundary("B3-context-model", "application", "agent", "context-admission"),
        Boundary("B4-model-runtime", "agent", "application", "agent-runtime"),
        Boundary("B5-runtime-tool", "application", "enterprise", "tool-policy-gateway"),
        Boundary("B6-tool-effect", "enterprise", "business", "service-api"),
        Boundary("B7-runtime-memory", "application", "data", "memory-gateway"),
    )
    flows = (
        Flow("F1-request", "E1-user", "E2-api", "B1-user-api", "submit_request", ("A1-request",)),
        Flow("F2-retrieve", "E3-context", "E7-evidence", "B2-context-evidence", "read_evidence", ("A2-evidence",)),
        Flow("F3-context", "E3-context", "E4-model", "B3-context-model", "admit_context", ("A2-evidence",)),
        Flow("F4-proposal", "E4-model", "E5-runtime", "B4-model-runtime", "propose_action", ("A3-proposal",)),
        Flow("F5-tool", "E5-runtime", "E6-tool", "B5-runtime-tool", "request_tool", ("A3-proposal", "A4-effect")),
        Flow("F6-effect", "E6-tool", "E8-ticket", "B6-tool-effect", "execute_effect", ("A4-effect",), True),
        Flow("F7-memory", "E5-runtime", "E9-memory", "B7-runtime-memory", "read_or_write_memory", ("A5-memory",)),
    )
    return SystemModel(ARCHITECTURE_VERSION, assets, elements, boundaries, flows, frozenset(flow.flow_id for flow in flows))


def _proposal(
    threat_id: str,
    title: str,
    category: Stride,
    flow_id: str,
    asset_ids: tuple[str, ...],
    control_id: str,
    test_id: str,
    owner: str,
    scores: tuple[int, int, int, int],
    *,
    origin: str = "workshop",
) -> ThreatProposal:
    return ThreatProposal(
        threat_id,
        title,
        category,
        flow_id,
        asset_ids,
        ("attacker can reach the source element", "target flow is enabled"),
        ("supply adversarial input", "cross the target boundary", "reach the protected asset"),
        (control_id,),
        (test_id,),
        ("decision", "reason", "architecture_version", "flow_id", "threat_id"),
        owner,
        *scores,
        ("REF-OWASP-AGENTIC", "REF-MITRE-ATLAS"),
        origin,
    )


def build_complete_model() -> ThreatModel:
    architecture = build_architecture()
    reviewers = (ReviewerContext("reviewer:security-7", frozenset({"security-reviewer"})),)
    controls = tuple(
        Control(control_id, name, boundary_id, owner, True)
        for control_id, name, boundary_id, owner in (
            ("C1-auth", "Authenticate and bind server-owned identity", "B1-user-api", "api-gateway"),
            ("C2-trim", "Authorize tenant and resource before retrieval", "B2-context-evidence", "context-service"),
            ("C3-admit", "Admit provenance-bearing bounded context", "B3-context-model", "context-admission"),
            ("C4-proposal", "Treat model output as an untrusted proposal", "B4-model-runtime", "agent-runtime"),
            ("C5-tool", "Authorize exact tool operation and resources", "B5-runtime-tool", "tool-policy-gateway"),
            ("C6-effect", "Consume exact grant and stable operation ID", "B6-tool-effect", "service-api"),
            ("C7-memory", "Scope memory by tenant, subject, and provenance", "B7-runtime-memory", "memory-gateway"),
        )
    )
    tests = tuple(
        VerificationTest(test_id, control_id, fixture, expected, True, True, f"evidence:{test_id}:2026-09-20")
        for test_id, control_id, fixture, expected in (
            ("VT1", "C1-auth", "model claims administrator identity", "deny"),
            ("VT2", "C2-trim", "cross-tenant evidence request", "deny-before-ranking"),
            ("VT3", "C3-admit", "instruction-bearing unproven document", "quarantine"),
            ("VT4", "C4-proposal", "schema-valid privileged proposal", "proposal-only"),
            ("VT5", "C5-tool", "direct unregistered tool path", "deny"),
            ("VT6", "C6-effect", "changed or replayed approved effect", "deny"),
            ("VT7", "C7-memory", "foreign-subject poisoned memory", "deny"),
        )
    )
    references = (
        Reference("REF-OWASP-AGENTIC", "OWASP", "Top 10 for Agentic Applications 2026", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/", "2026-09-20"),
        Reference("REF-MITRE-ATLAS", "MITRE", "ATLAS knowledge base", "https://atlas.mitre.org/", "2026-09-20"),
        Reference("REF-NIST-AI-RMF", "NIST", "AI Risk Management Framework", "https://www.nist.gov/itl/ai-risk-management-framework", "2026-09-20"),
    )
    proposals = (
        _proposal("T1", "Prompt claims another identity", Stride.SPOOFING, "F1-request", ("A1-request",), "C1-auth", "VT1", "identity-team", (4, 4, 2, 3)),
        _proposal("T2", "Cross-tenant evidence enters retrieval", Stride.INFORMATION_DISCLOSURE, "F2-retrieve", ("A2-evidence",), "C2-trim", "VT2", "data-owner", (4, 5, 1, 4)),
        _proposal("T3", "Retrieved instructions hijack the goal", Stride.TAMPERING, "F3-context", ("A2-evidence",), "C3-admit", "VT3", "knowledge-team", (4, 4, 2, 3), origin="model-suggestion"),
        _proposal("T4", "Model proposal is mistaken for authority", Stride.ELEVATION_OF_PRIVILEGE, "F4-proposal", ("A3-proposal",), "C4-proposal", "VT4", "agent-team", (4, 5, 2, 3)),
        _proposal("T5", "Runtime bypasses the registered tool route", Stride.ELEVATION_OF_PRIVILEGE, "F5-tool", ("A3-proposal", "A4-effect"), "C5-tool", "VT5", "security-platform", (3, 5, 1, 4)),
        _proposal("T6", "Approved effect is altered or replayed", Stride.TAMPERING, "F6-effect", ("A4-effect",), "C6-effect", "VT6", "support-ops", (4, 5, 1, 5)),
        _proposal("T7", "Poisoned memory persists across runs", Stride.TAMPERING, "F7-memory", ("A5-memory",), "C7-memory", "VT7", "data-owner", (3, 4, 2, 3)),
    )
    records = []
    for proposal in proposals:
        decision = admit_proposal(
            proposal,
            reviewers[0],
            residual_risk="Authorized content or reviewed actions may still be wrong; monitor and reassess after design changes.",
        )
        assert decision.accepted and decision.record
        records.append(decision.record)
    return ThreatModel(architecture, architecture.version, tuple(records), controls, tests, references, reviewers)


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    kind: CaseKind
    expected_valid: bool
    result: ReviewResult


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    negative_cases: int
    unexpected_acceptance_rate: float
    valid_model_acceptance_rate: float
    required_flow_coverage: float
    high_risk_control_coverage: float
    high_risk_test_coverage: float
    high_risk_telemetry_coverage: float


def evaluate_models() -> tuple[EvaluationReport, tuple[EvaluationCase, ...]]:
    complete = build_complete_model()
    primary = complete.records[0]
    variants = (
        ("complete reviewed model", CaseKind.VALID, True, complete),
        ("stale architecture", CaseKind.NEGATIVE, False, replace(complete, architecture_version="northwind-agent-1")),
        ("missing flow", CaseKind.NEGATIVE, False, replace(complete, records=complete.records[:-1])),
        ("unknown control", CaseKind.NEGATIVE, False, replace(complete, records=(replace(primary, control_ids=("C404",)), *complete.records[1:]))),
        ("model self-review", CaseKind.NEGATIVE, False, replace(complete, records=(replace(primary, reviewer_id="model:planner"), *complete.records[1:]))),
        ("risk magically reduced", CaseKind.NEGATIVE, False, replace(complete, records=(replace(primary, residual_likelihood=5, residual_impact=5), *complete.records[1:]))),
        ("missing verification", CaseKind.NEGATIVE, False, replace(complete, records=(replace(primary, test_ids=()), *complete.records[1:]))),
    )
    cases = tuple(EvaluationCase(name, kind, expected, review_threat_model(model)) for name, kind, expected, model in variants)
    valid = [case for case in cases if case.kind is CaseKind.VALID]
    negative = [case for case in cases if case.kind is CaseKind.NEGATIVE]
    baseline = cases[0].result
    report = EvaluationReport(
        cases=len(cases),
        valid_cases=len(valid),
        negative_cases=len(negative),
        unexpected_acceptance_rate=_ratio(sum(case.result.accepted for case in negative), len(negative)),
        valid_model_acceptance_rate=_ratio(sum(case.result.accepted for case in valid), len(valid)),
        required_flow_coverage=baseline.required_flow_coverage,
        high_risk_control_coverage=baseline.high_risk_control_coverage,
        high_risk_test_coverage=baseline.high_risk_test_coverage,
        high_risk_telemetry_coverage=baseline.high_risk_telemetry_coverage,
    )
    return report, cases


def demo() -> EvaluationReport:
    model = build_complete_model()
    review = review_threat_model(model)
    assert review.accepted
    unsafe = replace(model, records=(replace(model.records[0], control_ids=("C404",)), *model.records[1:]))
    assert unsafe_row_count_baseline(unsafe)
    assert not review_threat_model(unsafe).accepted
    tree = build_exfiltration_tree()
    cuts = minimal_cut_sets(tree)
    assert len(cuts) == 3
    assert attack_succeeds(tree, next(iter(cuts)))
    report, _ = evaluate_models()
    assert report.unexpected_acceptance_rate == 0
    assert report.valid_model_acceptance_rate == 1
    assert report.required_flow_coverage == 1
    assert report.high_risk_control_coverage == report.high_risk_test_coverage == 1
    return report


if __name__ == "__main__":
    print(demo())

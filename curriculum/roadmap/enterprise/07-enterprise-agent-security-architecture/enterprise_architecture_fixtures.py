"""Synthetic enterprise topology and requests for Course 07."""
from dataclasses import replace

import enterprise_architecture as arch


NOW = 1_000
RECEIPT_KEY = b"course-07-fixture-receipt-key"
BASE = frozenset({
    "workload-identity", "tenant-bind", "policy-enforcement",
    "evidence-receipt", "transport-security",
})


def architecture(**changes) -> arch.Architecture:
    components = (
        arch.Component("edge-gateway", arch.Zone.EDGE, "platform-edge", "shared", True, 3, ("az-a", "az-b", "az-c")),
        arch.Component("orchestrator", arch.Zone.ORCHESTRATION, "agent-platform", "shared", True, 3, ("az-a", "az-b", "az-c")),
        arch.Component("tenant-runtime", arch.Zone.TENANT_RUNTIME, "runtime-team", "dedicated", True, 3, ("az-a", "az-b", "az-c")),
        arch.Component("data-broker", arch.Zone.DATA, "data-security", "shared", True, 2, ("az-a", "az-b")),
        arch.Component("effect-gateway", arch.Zone.EFFECT, "product-security", "shared", True, 3, ("az-a", "az-b", "az-c")),
        arch.Component("protocol-gateway", arch.Zone.PROTOCOL, "integration-security", "shared", True, 2, ("az-a", "az-b")),
        arch.Component("policy-service", arch.Zone.CONTROL, "iam-security", "shared", True, 3, ("az-a", "az-b", "az-c"), True),
        arch.Component("evidence-pipeline", arch.Zone.OBSERVABILITY, "security-operations", "shared", True, 2, ("az-a", "az-b"), True),
    )
    flows = (
        arch.Flow("edge-to-orchestrator", "edge-gateway", "orchestrator", "run.submit", "internal", True, BASE, "agent-platform", "closed"),
        arch.Flow("orchestrator-to-runtime", "orchestrator", "tenant-runtime", "run.execute", "confidential", True, BASE, "runtime-team", "closed"),
        arch.Flow("runtime-to-data", "tenant-runtime", "data-broker", "customer.read", "customer-confidential", True, BASE | {"data-authorization"}, "data-security", "closed"),
        arch.Flow("runtime-to-effect", "tenant-runtime", "effect-gateway", "ticket.resolve", "customer-confidential", True, BASE | {"egress-control"}, "product-security", "closed"),
        arch.Flow("runtime-to-protocol", "tenant-runtime", "protocol-gateway", "mcp.invoke", "internal", True, BASE | {"egress-control"}, "integration-security", "closed"),
        arch.Flow("gateway-to-evidence", "effect-gateway", "evidence-pipeline", "receipt.append", "metadata", False, frozenset({"transport-security"}), "security-operations", "degraded"),
    )
    risks = (
        arch.ResidualRisk("risk:model-provider-outage", "orchestrator-to-runtime", "agent-platform", "mitigated", 2_000, "evidence:outage-drill:4"),
        arch.ResidualRisk("risk:protocol-supply-chain", "runtime-to-protocol", "integration-security", "accepted", 1_500, "evidence:protocol-review:9"),
    )
    base = arch.Architecture("enterprise-agent-platform", 7, "policy-18", components, flows, risks)
    return replace(base, **changes)


def policy(**changes) -> arch.PolicySnapshot:
    base = arch.PolicySnapshot(
        "policy-18",
        frozenset({("agent-runtime:north", "north", "ticket.resolve")}),
        1_200,
    )
    return replace(base, **changes)


def request(**changes) -> arch.AccessRequest:
    base = arch.AccessRequest(
        "request-42", "runtime-to-effect", "agent-runtime:north", "north",
        "north", "ticket.resolve", "ticket-900", "proposal-sha256-42", "policy-18")
    return replace(base, **changes)


def gateway(architecture_value=None, policy_value=None) -> arch.EffectGateway:
    return arch.EffectGateway(architecture_value or architecture(), policy_value or policy(), RECEIPT_KEY)

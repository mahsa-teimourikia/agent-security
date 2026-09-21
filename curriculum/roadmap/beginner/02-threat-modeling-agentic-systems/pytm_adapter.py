"""Real OWASP pytm 1.4 adapter for the Foundation 02 architecture.

The SDK supplies code-first DFD primitives and a threat catalog. The reviewed
course threat records remain authoritative because generated suggestions still
need architecture binding, ownership, verification, and residual-risk review.
"""
from __future__ import annotations

from dataclasses import dataclass

from pytm import Actor, Agent, Boundary, Dataflow, Datastore, LLM, Server, TM


@dataclass(frozen=True)
class PytmSummary:
    model_name: str
    element_count: int
    flow_count: int
    element_types: tuple[str, ...]
    dot_source: str


def build_pytm_model() -> tuple[TM, tuple[object, ...], tuple[Dataflow, ...]]:
    """Create the same teaching architecture with current pytm primitives."""
    TM.reset()
    model = TM(
        "Northwind research-and-support agent",
        description="Versioned teaching DFD for agentic threat modeling.",
        isOrdered=True,
    )

    external = Boundary("External and untrusted")
    application = Boundary("Trusted application")
    agent_zone = Boundary("Probabilistic agent")
    data_zone = Boundary("Data services")
    enterprise = Boundary("Enterprise systems")

    user = Actor("User or attacker", inBoundary=external)
    api = Server("API gateway", inBoundary=application, usesSessionTokens=True)
    context = Server("Context gateway", inBoundary=application)
    runtime = Agent(
        "Agent runtime",
        inBoundary=application,
        usesExternalTools=True,
        validatesToolLaunchConfig=True,
    )
    model_api = LLM(
        "Model and planner",
        inBoundary=agent_zone,
        processesUntrustedInput=True,
        hasAgentCapabilities=True,
        hasAccessToSensitiveSystems=False,
    )
    tool_gateway = Server("Tool policy gateway", inBoundary=enterprise)
    evidence = Datastore(
        "Evidence API",
        inBoundary=data_zone,
        storesPII=True,
        storesSensitiveData=True,
        isShared=True,
    )
    memory = Datastore(
        "Memory store",
        inBoundary=data_zone,
        storesSensitiveData=True,
        isShared=True,
        hasWriteAccess=True,
    )
    ticket = Server("Ticket and refund API", inBoundary=enterprise)

    flows = (
        Dataflow(user, api, "F1 request"),
        Dataflow(context, evidence, "F2 evidence query"),
        Dataflow(context, model_api, "F3 bounded context"),
        Dataflow(model_api, runtime, "F4 action proposal"),
        Dataflow(runtime, tool_gateway, "F5 tool request"),
        Dataflow(tool_gateway, ticket, "F6 business effect"),
        Dataflow(runtime, memory, "F7 memory read or write"),
    )
    elements = (user, api, context, runtime, model_api, tool_gateway, evidence, memory, ticket)
    if not model.check():
        raise ValueError("pytm rejected the course architecture")
    return model, elements, flows


def summarize_model() -> PytmSummary:
    model, elements, flows = build_pytm_model()
    dot = model.dfd()
    return PytmSummary(
        model.name,
        len(elements),
        len(flows),
        tuple(type(element).__name__ for element in elements),
        dot,
    )


def demo() -> PytmSummary:
    summary = summarize_model()
    assert summary.element_count == 9
    assert summary.flow_count == 7
    assert {"Actor", "Agent", "LLM", "Server", "Datastore"} <= set(summary.element_types)
    assert all(label in summary.dot_source for label in ("User or attacker", "Model and planner", "F6 business"))
    return summary


if __name__ == "__main__":
    result = demo()
    print({"model": result.model_name, "elements": result.element_count, "flows": result.flow_count})

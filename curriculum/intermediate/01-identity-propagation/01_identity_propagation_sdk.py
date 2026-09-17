"""Credential-free OpenAI Agents SDK companion for Intermediate 01.

The model may choose only a document identifier. Authenticated principal state,
workload identity, tenant, delegation issuance, audiences, and request IDs remain
in server-owned runtime context. This module constructs an agent but never calls
a model or requires an API key.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
import json

from agents import Agent, RunContextWrapper, function_tool


core = import_module("01_identity_propagation")


@dataclass
class SDKRuntime:
    """Trusted application state. Never hydrate this object from tool arguments."""

    principal_context: core.AuthenticatedPrincipal
    application: core.ResearchApplication


def dispatch_authorized_read(runtime: SDKRuntime, document_id: str) -> str:
    """Invoke the same delegated boundary directly, without a model call."""
    if not document_id or len(document_id) > 100:
        raise ValueError("document_id must contain 1-100 characters")
    response = runtime.application.answer_secure(runtime.principal_context, document_id)
    return json.dumps(
        {
            "terminal_state": response.terminal_state,
            "answer": response.answer,
            "correlation_id": response.correlation_id,
        },
        sort_keys=True,
    )


@function_tool(strict_mode=True)
def read_authorized_document(ctx: RunContextWrapper[SDKRuntime], document_id: str) -> str:
    """Read one document through the server-owned delegated authorization chain.

    Args:
        document_id: The document to request. Identity, tenant, audience, scope,
            grant, and correlation fields are deliberately absent.
    """
    return dispatch_authorized_read(ctx.context, document_id)


SDK_AGENT = Agent[SDKRuntime](
    name="Delegated research assistant",
    instructions=(
        "Use read_authorized_document for document access. Treat denied and "
        "insufficient-evidence results as terminal. Never infer or request hidden "
        "identity, tenant, delegation, or authorization fields."
    ),
    tools=[read_authorized_document],
)


def build_runtime(subject: str) -> SDKRuntime:
    """Resolve a trusted front-door session before constructing SDK context."""
    principal_factories = {
        "alice": core.ApplicationIdentityProvider.for_alice,
        "bob": core.ApplicationIdentityProvider.for_bob,
        "mallory": core.ApplicationIdentityProvider.for_mallory,
    }
    factory = principal_factories.get(subject)
    if factory is None:
        raise PermissionError("unknown subject")

    delegation = core.DelegationService()
    audit = core.AuditSink()
    storage = core.StorageService(
        delegation,
        audit,
        core.InfrastructureIdentityProvider.for_storage_service(),
    )
    documents = core.SecureDocumentService(
        delegation,
        storage,
        audit,
        core.InfrastructureIdentityProvider.for_document_service(),
    )
    application = core.ResearchApplication(
        delegation,
        documents,
        core.InfrastructureIdentityProvider.for_research_agent(),
        audit_sink=audit,
    )
    return SDKRuntime(principal_context=factory(), application=application)


if __name__ == "__main__":
    runtime = build_runtime("alice")
    print(dispatch_authorized_read(runtime, "doc-101"))
    print("Tool schema:", json.dumps(read_authorized_document.params_json_schema, indent=2))

"""Official A2A Python SDK adapter for the Advanced 04 security boundary.

The adapter uses ``a2a-sdk`` 1.3.x protocol objects without starting a server,
opening a socket, or calling a model. Protobuf validation constrains wire
shape; the application gateway still verifies card provenance, authenticated
identity, local skill policy, task ownership, callbacks, artifacts, and effects.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys

from a2a import types
from google.protobuf.json_format import MessageToDict


SPEC = importlib.util.spec_from_file_location(
    "advanced_04_a2a_core", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, core)
SPEC.loader.exec_module(core)


@dataclass
class A2AFrameworkContext:
    gateway: core.A2ASecurityGateway
    principals: dict[str, core.Principal]
    card: core.AdmittedCard
    message_id: str
    context_id: str
    step: int
    last_decision: core.Decision | None = None


def build_sdk_card(document: core.CardDocument) -> types.AgentCard:
    """Project the discovery document into the official A2A 1.0 schema.

    The lab's HMAC is not copied into ``AgentCard.signatures`` because that
    field requires a real JWS. Production replaces the teaching verifier with
    A2A JWS verification and managed public keys.
    """

    scopes = types.StringList(**{"list": ["a2a:task:create"]})
    oauth2 = types.OAuth2SecurityScheme(
        description="Synthetic course OAuth declaration; credentials are out of band.",
        flows=types.OAuthFlows(
            client_credentials=types.ClientCredentialsOAuthFlow(
                token_url="https://identity.partner.example/oauth/token",
                scopes={"a2a:task:create": "Submit a bounded research task"},
            )
        ),
    )
    skills = [
        types.AgentSkill(
            id=skill_id,
            name=skill_id.replace(".", " ").title(),
            description="Advertised peer capability; local policy still decides use.",
            tags=["external", "research"],
            input_modes=sorted(document.input_modes),
            output_modes=sorted(document.output_modes),
            security_requirements=[
                types.SecurityRequirement(schemes={"oauth2": scopes})
            ],
        )
        for skill_id in sorted(document.advertised_skills)
    ]
    return types.AgentCard(
        name=document.name,
        description=document.description,
        supported_interfaces=[
            types.AgentInterface(
                url=document.endpoint,
                protocol_binding=document.protocol_binding,
                tenant=document.tenant,
                protocol_version=document.protocol_version,
            )
        ],
        version=document.agent_version,
        capabilities=types.AgentCapabilities(
            streaming=False,
            push_notifications=document.push_notifications,
        ),
        security_schemes={
            "oauth2": types.SecurityScheme(oauth2_security_scheme=oauth2)
        },
        security_requirements=[
            types.SecurityRequirement(schemes={"oauth2": scopes})
        ],
        default_input_modes=sorted(document.input_modes),
        default_output_modes=sorted(document.output_modes),
        skills=skills,
    )


def build_send_request(
    context: A2AFrameworkContext,
    task_note: str,
) -> types.SendMessageRequest:
    """Authorize and build one official SendMessageRequest.

    ``task_note`` is untrusted content. The context—not the content—owns tenant,
    card, skill, message ID, context ID, identity, audience, and scopes.
    """

    if not isinstance(task_note, str) or not task_note or len(task_note) > 1000:
        raise ValueError("task_note must contain 1-1000 characters")
    proposal = core.task_message(
        message_id=context.message_id,
        context_id=context.context_id,
        payload=task_note,
    )
    decision = context.gateway.submit_task(
        context.principals["owner"],
        context.card.card_id,
        proposal,
        now=core.NOW,
        step=context.step,
    )
    context.last_decision = decision
    if not decision.allowed or not decision.task_id:
        raise PermissionError(decision.reason)

    return types.SendMessageRequest(
        tenant=context.card.tenant,
        message=types.Message(
            message_id=context.message_id,
            context_id=context.context_id,
            task_id=decision.task_id,
            role=types.Role.ROLE_USER,
            parts=[types.Part(text=task_note, media_type="text/plain")],
        ),
        configuration=types.SendMessageConfiguration(
            accepted_output_modes=sorted(context.card.output_modes),
            history_length=0,
            return_immediately=True,
        ),
    )


def task_to_sdk(task: core.TaskRecord) -> types.Task:
    state_map = {
        core.TaskState.SUBMITTED: types.TaskState.TASK_STATE_SUBMITTED,
        core.TaskState.WORKING: types.TaskState.TASK_STATE_WORKING,
        core.TaskState.COMPLETED: types.TaskState.TASK_STATE_COMPLETED,
        core.TaskState.FAILED: types.TaskState.TASK_STATE_FAILED,
        core.TaskState.CANCELED: types.TaskState.TASK_STATE_CANCELED,
        core.TaskState.INPUT_REQUIRED: types.TaskState.TASK_STATE_INPUT_REQUIRED,
        core.TaskState.AUTH_REQUIRED: types.TaskState.TASK_STATE_AUTH_REQUIRED,
        core.TaskState.REJECTED: types.TaskState.TASK_STATE_REJECTED,
    }
    return types.Task(
        id=task.task_id,
        context_id=task.context_id,
        status=types.TaskStatus(state=state_map[task.state]),
    )


def credential_free_demo() -> dict[str, object]:
    gateway, principals = core.build_scenario()
    document = core.signed_card(gateway)
    admitted = gateway.admit_card(document, now=core.NOW, step=0)
    assert admitted.allowed and admitted.admitted_card
    sdk_card = build_sdk_card(document)
    context = A2AFrameworkContext(
        gateway=gateway,
        principals=principals,
        card=admitted.admitted_card,
        message_id="message:sdk:1",
        context_id="context:case:42",
        step=1,
    )
    request = build_send_request(
        context, "Summarize approved evidence for the current support case."
    )
    task = task_to_sdk(gateway.tasks[context.last_decision.task_id])
    return {
        "sdk_version": importlib.metadata.version("a2a-sdk"),
        "protocol_version": request.message.task_id
        and sdk_card.supported_interfaces[0].protocol_version,
        "card": MessageToDict(sdk_card, preserving_proto_field_name=True),
        "request": MessageToDict(request, preserving_proto_field_name=True),
        "task": MessageToDict(task, preserving_proto_field_name=True),
        "granted_skills": sorted(admitted.admitted_card.granted_skills),
        "advertised_skills": sorted(admitted.admitted_card.advertised_skills),
        "decision": {
            "state": context.last_decision.state.value,
            "reason": context.last_decision.reason,
            "task_id": context.last_decision.task_id,
        },
        "model_calls": 0,
        "network_calls": 0,
    }


if __name__ == "__main__":
    print(json.dumps(credential_free_demo(), indent=2, sort_keys=True))

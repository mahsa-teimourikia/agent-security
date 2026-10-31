"""Generate the Advanced 04 A2A security notebook from deterministic cells."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "a2a_security.ipynb"


def markdown(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3",
        },
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown(
            "a04-title",
            """
# Advanced 04 — Agent-to-Agent (A2A) Security

**Goal:** admit an external A2A peer without turning discovery metadata into
authority, then protect task resources, artifacts, callbacks, and effects.
The notebook uses the official A2A Python SDK without credentials, model
calls, or network access.

![A2A trust boundary](architecture.svg)
""",
        ),
        markdown(
            "a04-contract",
            """
## Security contract

An Agent Card is authenticated discovery data, not an authorization grant.
Application code owns peer registration, caller identity, tenant and resource
authorization, exact replay semantics, artifact taint, callback egress, and
effect idempotency. A task identifier is never a bearer capability.
""",
        ),
        code(
            "a04-imports",
            """
from dataclasses import asdict, replace

import lab
import sdk_adapter as sdk
""",
        ),
        markdown(
            "a04-baseline-heading",
            """
## 1. Measure protocol-shaped trust

The unsafe comparison accepts a signed-looking card, a replayed task, a
cross-tenant read, a malicious artifact, and a private callback because it
confuses protocol fields with application authority.
""",
        ),
        code(
            "a04-baseline",
            """
baseline = lab.unsafe_protocol_trust_baseline()
print(asdict(baseline))
assert baseline.attack_success_rate == 1.0
""",
        ),
        markdown(
            "a04-card-heading",
            """
## 2. Admit the card, then intersect skills

The teaching lab uses a synthetic HMAC boundary so the exercise stays
deterministic. Production deployments should verify the Agent Card's real JWS
against pinned trust material. Either way, integrity does not grant skills.
""",
        ),
        code(
            "a04-card",
            """
gateway, principals = lab.build_scenario()
document = lab.signed_card(gateway)
card_decision = gateway.admit_card(document, now=lab.NOW, step=0)
card = card_decision.admitted_card
print({
    "decision": card_decision.reason,
    "advertised": sorted(card.advertised_skills),
    "locally_granted": sorted(card.granted_skills),
})
assert card_decision.allowed
assert "records.export" in card.advertised_skills
assert "records.export" not in card.granted_skills
""",
        ),
        markdown(
            "a04-sdk-card-heading",
            """
## 3. Build the official SDK Agent Card

The SDK represents interoperable protocol objects. The application still
owns the registry and policy decision. The adapter deliberately does not copy
the teaching HMAC into `AgentCard.signatures`: that field requires a real JWS.
""",
        ),
        code(
            "a04-sdk-card",
            """
sdk_card = sdk.build_sdk_card(document)
print({
    "name": sdk_card.name,
    "protocol_version": sdk_card.supported_interfaces[0].protocol_version,
    "advertised_skills": sorted(skill.id for skill in sdk_card.skills),
    "signatures": len(sdk_card.signatures),
})
assert sdk_card.supported_interfaces[0].protocol_version == "1.0"
assert len(sdk_card.signatures) == 0
""",
        ),
        markdown(
            "a04-task-heading",
            """
## 4. Authorize before constructing `SendMessageRequest`

Identity, audience, scope, tenant, card, skill, media type, size, and message
idempotency are application checks. Only after they pass does the adapter
construct the official request.
""",
        ),
        code(
            "a04-task",
            """
context = sdk.A2AFrameworkContext(
    gateway, principals, card, "message:sdk:1", "context:case:42", 1
)
note = "Summarize approved case evidence."
request = sdk.build_send_request(context, note)
submit = context.last_decision
task = gateway.tasks[submit.task_id]
print({
    "message_id": request.message.message_id,
    "decision": submit.reason,
    "task_id": task.task_id,
    "owner": task.owner_subject,
})
assert submit.allowed and task.owner_subject == principals["owner"].subject
""",
        ),
        markdown(
            "a04-replay-heading",
            """
## 5. Make retries exact

The same message identifier and digest is an idempotent retry. Reusing that
identifier for a different proposal is denied.
""",
        ),
        code(
            "a04-replay",
            """
message = lab.task_message(message_id=task.message_id, payload=note)
same = gateway.submit_task(
    principals["owner"], card.card_id, message, now=lab.NOW, step=2
)
mutated = gateway.submit_task(
    principals["owner"], card.card_id,
    replace(message, payload_digest="changed"), now=lab.NOW, step=3,
)
print({"retry": same.reason, "mutation": mutated.reason})
assert same.replayed and mutated.reason == "message-replay-mismatch"
""",
        ),
        markdown(
            "a04-idor-heading",
            """
## 6. Reauthorize every task operation

Knowing a task ID does not grant access. `Get`, follow-up messages, cancel,
history, callback registration, and effects each check the current owner,
workload, scope, tenant, and state.
""",
        ),
        code(
            "a04-idor",
            """
owner_read = gateway.get_task(principals["owner"], task.task_id, history_length=1, step=4)
other_read = gateway.get_task(principals["other"], task.task_id, history_length=1, step=5)
print({"owner": owner_read.reason, "other": other_read.reason})
assert owner_read.allowed and other_read.reason == "task-access"
""",
        ),
        markdown(
            "a04-callback-heading",
            """
## 7. Treat push callbacks as SSRF-capable egress

Registration requires HTTPS, an allowed hostname, a bounded port and expiry,
and public DNS answers. Delivery re-resolves the hostname so rebinding cannot
silently cross the trust boundary. A real connector must also pin the vetted
address to the connection while preserving TLS SNI and `Host`.
""",
        ),
        code(
            "a04-callback",
            """
callback = lab.CallbackProposal(
    callback_id="callback:notebook:1", task_id=task.task_id, tenant="north",
    url="https://events.north.example/a2a/events", token="single-use-secret",
    expires_at=lab.NOW + 300,
)
registered = gateway.register_callback(
    principals["owner"], task.task_id, callback, now=lab.NOW, step=6
)
delivered = gateway.authorize_callback_delivery(
    task.task_id, callback.callback_id, now=lab.NOW + 1, step=7
)
gateway.resolver.records["events.north.example"] = ("127.0.0.1",)
rebound = gateway.authorize_callback_delivery(
    task.task_id, callback.callback_id, now=lab.NOW + 2, step=8
)
print({"register": registered.reason, "deliver": delivered.reason,
       "rebound": rebound.reason})
assert registered.allowed and delivered.allowed
assert rebound.reason == "callback-private-address"
""",
        ),
        markdown(
            "a04-artifact-heading",
            """
## 8. Bind and taint artifacts; gate effects separately

The peer can return data, not authority. The malicious instruction embedded in
the artifact remains untrusted content. Only a locally authorized action and
target may cross the effect boundary, and the operation ID is idempotent.
""",
        ),
        code(
            "a04-artifact-effect",
            """
artifact_decision = gateway.admit_artifact(
    principals["peer"], card.card_id, lab.artifact_for(task), step=9
)
artifact = artifact_decision.artifact
forbidden = gateway.authorize_effect(
    principals["owner"],
    lab.EffectProposal(
        operation_id="effect:notebook:forbidden", task_id=task.task_id,
        artifact_id=artifact.artifact_id, action="export-all-records",
        target="partner:anywhere",
    ),
    step=10,
)
allowed_proposal = lab.EffectProposal(
    operation_id="effect:notebook:allowed", task_id=task.task_id,
    artifact_id=artifact.artifact_id,
    action="store-internal-research-brief", target="case:north:42",
)
allowed = gateway.authorize_effect(principals["owner"], allowed_proposal, step=11)
retry = gateway.authorize_effect(principals["owner"], allowed_proposal, step=12)
print({"taint": sorted(artifact.taint), "forbidden": forbidden.reason,
       "allowed": allowed.reason, "retry": retry.reason})
assert forbidden.reason == "effect-not-authorized"
assert allowed.allowed and retry.replayed and retry.effect_id == allowed.effect_id
""",
        ),
        markdown(
            "a04-sdk-task-heading",
            """
## 9. Map controlled state back to the SDK

The adapter maps application state to an official SDK `Task`. This is a
translation boundary, not the source of authorization truth.
""",
        ),
        code(
            "a04-sdk-task",
            """
sdk_task = sdk.task_to_sdk(task)
demo = sdk.credential_free_demo()
print({"sdk_task_id": sdk_task.id, "sdk_state": sdk_task.status.state,
       "sdk_version": demo["sdk_version"], "network_calls": demo["network_calls"]})
assert demo["network_calls"] == 0 and demo["model_calls"] == 0
""",
        ),
        markdown(
            "a04-evaluation-heading",
            """
## 10. Run the adversarial evaluation

The fixed corpus contains valid, attack, and dependency-failure cases. Release
gates require valid completion and audit coverage while driving attack
acceptance to zero and surfacing dependency loss as explicit error.
""",
        ),
        code(
            "a04-evaluation",
            """
report, cases = lab.evaluate_controls()
print(asdict(report))
assert len(cases) == 20
assert report.valid_completion_rate == 1.0
assert report.spoof_replay_acceptance_rate == 0.0
assert report.unauthorized_task_access_rate == 0.0
assert report.callback_ssrf_acceptance_rate == 0.0
assert report.artifact_forbidden_effect_rate == 0.0
assert report.failure_error_rate == 1.0
assert report.audit_coverage_rate == 1.0
""",
        ),
        markdown(
            "a04-checkpoint",
            """
## Checkpoint and production transfer

**Does a signed Agent Card authorize every skill it advertises?** No. A valid
JWS can establish card integrity and origin under a trusted key. The
application must still pin the peer and interface, intersect skills with local
policy, authenticate the caller, and authorize each tenant, resource,
operation, callback, artifact, and effect.

Before production, replace the synthetic card verifier with JWS validation,
use workload identity and a current OAuth profile, persist task and replay
state atomically, enforce stream budgets, and implement callback connections
that bind vetted DNS answers without breaking TLS verification.
""",
        ),
    ]
    return notebook


def main() -> None:
    nbf.write(build_notebook(), OUTPUT)


if __name__ == "__main__":
    main()

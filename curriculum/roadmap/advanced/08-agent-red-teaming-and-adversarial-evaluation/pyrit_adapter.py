"""Optional PyRIT 1.1 custom target for the credential-free campaign.

PyRIT is deliberately an optional extra because its full scanner stack is much
larger than the deterministic core lab. The adapter exercises the official
PromptTarget boundary; the campaign oracle still decides release from trusted
host evidence, never from this target's response text.
"""

from __future__ import annotations

import json
from typing import Any

from campaign import Campaign, ControlProfile, run_campaign

try:
    from pyrit.models import ComponentIdentifier, Message, MessagePiece, construct_response_from_request
    from pyrit.prompt_target import PromptTarget, limit_requests_per_minute
except ModuleNotFoundError:  # pragma: no cover - exercised in the optional environment
    ComponentIdentifier = Message = MessagePiece = Any  # type: ignore[misc,assignment]
    PromptTarget = object  # type: ignore[misc,assignment]

    def limit_requests_per_minute(function):  # type: ignore[no-untyped-def]
        return function


def pyrit_available() -> bool:
    try:
        import pyrit  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


if pyrit_available():

    class PyRITSupportAgentTarget(PromptTarget):
        """Expose one bounded fixture execution through PyRIT's target API."""

        def __init__(
            self,
            *,
            campaign: Campaign,
            profile: ControlProfile,
            max_requests_per_minute: int | None = None,
        ) -> None:
            super().__init__(
                endpoint="credential-free://enterprise-support-agent",
                model_name=campaign.binding.target_version,
                max_requests_per_minute=max_requests_per_minute,
            )
            self._campaign = campaign
            self._profile = profile

        def _build_identifier(self) -> ComponentIdentifier:
            return self._create_identifier(params={
                "suite_version": self._campaign.suite_version,
                "campaign_digest": self._campaign.digest,
                "profile_id": self._profile.profile_id,
            })

        @limit_requests_per_minute
        async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
            request = normalized_conversation[-1].get_piece()
            try:
                payload = json.loads(request.converted_value)
                if not isinstance(payload, dict):
                    raise ValueError("request must be an object")
                fixture_id = payload.get("fixture_id")
                attempt_number = payload.get("attempt_number", 1)
                if not isinstance(fixture_id, str) or not fixture_id.strip():
                    raise ValueError("fixture_id must be a non-empty string")
                if not isinstance(attempt_number, int) or isinstance(attempt_number, bool) or attempt_number < 1:
                    raise ValueError("attempt_number must be a positive integer")
                fixture = next(item for item in self._campaign.fixtures if item.fixture_id == fixture_id)
                if attempt_number > fixture.attempts_required:
                    raise ValueError("attempt_number exceeds the declared fixture")
                result = next(
                    item
                    for item in run_campaign(self._campaign, self._profile)
                    if item.fixture_id == fixture_id and item.attempt_id == f"attempt-{attempt_number}"
                )
                response = {
                    "fixture_id": fixture_id,
                    "attempt_id": result.attempt_id,
                    "execution_state": result.execution_state.value,
                    "observed_outcome": result.observed_outcome.value if result.observed_outcome else None,
                    "observed_control": result.observed_control,
                    "trace_event_count": len(result.trace),
                }
            except (json.JSONDecodeError, StopIteration, TypeError, ValueError) as exc:
                response = {"error": f"invalid bounded fixture request: {exc}"}
            reply = json.dumps(response, sort_keys=True, separators=(",", ":"))
            return [construct_response_from_request(request=request, response_text_pieces=[reply])]

else:

    class PyRITSupportAgentTarget:  # type: ignore[no-redef]
        def __init__(self, **_: object) -> None:
            raise RuntimeError("Install the redteam extra: pip install -e '.[redteam]'")


async def run_offline_demo_async(campaign: Campaign, profile: ControlProfile) -> dict[str, object]:
    """Send one local fixture through the real PyRIT target lifecycle."""

    if not pyrit_available():
        raise RuntimeError("Install the redteam extra: pip install -e '.[redteam]'")
    from pyrit.setup import IN_MEMORY, initialize_pyrit_async

    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    target = PyRITSupportAgentTarget(campaign=campaign, profile=profile)
    conversation_id = f"{campaign.campaign_id}-pyrit-demo"
    request = Message(message_pieces=[MessagePiece(
        role="user",
        original_value=json.dumps({"fixture_id": "mcp-001", "attempt_number": 1}),
        conversation_id=conversation_id,
    )])
    responses = await target.send_prompt_async(message=request)
    value = json.loads(responses[-1].get_value())
    target.dispose_db_engine()
    return value

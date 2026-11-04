"""Strict Pydantic v2 adapter for untrusted governance inventory payloads."""
from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, field_validator

import governance as core


class AgentRecordPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: StrictStr
    tenant: StrictStr
    revision: StrictInt
    lifecycle: core.Lifecycle
    business_owner: StrictStr
    technical_owner: StrictStr
    security_owner: StrictStr
    purpose: StrictStr
    risk_tier: core.RiskTier
    environments: tuple[StrictStr, ...]
    models: tuple[StrictStr, ...]
    tools: tuple[StrictStr, ...]
    data_classes: tuple[StrictStr, ...]
    effects: tuple[StrictStr, ...]
    autonomy: StrictStr
    policy_version: StrictStr
    control_version: StrictStr
    review_due_at: StrictInt
    kill_switch_owner: StrictStr
    change_digest: StrictStr

    @field_validator("environments", "models", "data_classes")
    @classmethod
    def non_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or any(not item.strip() for item in value):
            raise ValueError("must contain non-empty values")
        return value


def parse_record(payload: dict) -> core.AgentRecord:
    return core.AgentRecord(**AgentRecordPayload.model_validate(payload).model_dump())

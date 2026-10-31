"""Official Sigstore schema/policy bridge for Advanced 06.

The adapter validates an in-toto Statement with sigstore-python and constructs
an exact certificate-identity policy. The credential-free path intentionally
does not create a production verifier, refresh TUF metadata, contact Sigstore,
obtain OIDC credentials, sign remotely, deploy, or call a model. Cryptographic
verification and release policy remain in the reusable teaching gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys

from sigstore.dsse import Statement
from sigstore.verify.policy import Identity


SPEC = importlib.util.spec_from_file_location(
    "advanced_06_agent_supply_chain_core", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, core)
SPEC.loader.exec_module(core)


@dataclass(frozen=True)
class SigstoreStatementContext:
    statement: Statement
    statement_bytes: bytes
    identity_policy: Identity
    candidate: core.ReleaseCandidate


def _rfc3339(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def statement_document(candidate: core.ReleaseCandidate) -> dict[str, object]:
    """Translate trusted candidate state into an in-toto/SLSA v1 statement."""

    provenance = candidate.attestation.statement
    return {
        "_type": provenance.statement_type,
        "subject": [
            {
                "name": provenance.subject_name,
                "digest": {"sha256": provenance.subject_digest},
            }
        ],
        "predicateType": provenance.predicate_type,
        "predicate": {
            "buildDefinition": {
                "buildType": provenance.build_type,
                "externalParameters": {
                    "source": {
                        "uri": provenance.source_uri,
                        "digest": {"gitCommit": provenance.source_commit},
                    },
                    "tenant": provenance.tenant,
                    "environment": provenance.environment,
                },
                "internalParameters": {
                    "workflowDigest": provenance.workflow_digest,
                },
                "resolvedDependencies": [
                    {
                        "uri": dependency.uri,
                        "name": dependency.name,
                        "digest": {"sha256": dependency.sha256},
                    }
                    for dependency in provenance.resolved_dependencies
                ],
            },
            "runDetails": {
                "builder": {"id": provenance.builder_id},
                "metadata": {
                    "invocationId": candidate.candidate_id,
                    "startedOn": _rfc3339(provenance.issued_at),
                    "finishedOn": _rfc3339(provenance.issued_at),
                },
            },
        },
    }


def build_sigstore_context(
    candidate: core.ReleaseCandidate,
) -> SigstoreStatementContext:
    """Validate statement shape and construct an exact signer identity policy."""

    document = statement_document(candidate)
    raw = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode()
    statement = Statement(raw)
    identity_policy = Identity(
        identity=candidate.attestation.signer_identity,
        issuer=candidate.attestation.signer_issuer,
    )
    return SigstoreStatementContext(
        statement=statement,
        statement_bytes=raw,
        identity_policy=identity_policy,
        candidate=candidate,
    )


def verify_and_stage(
    kind: core.ComponentKind = core.ComponentKind.MCP_SERVER,
) -> tuple[SigstoreStatementContext, core.ReleaseFlow]:
    """Exercise schema validation plus the application-owned release controls."""

    candidate = core.candidate_for(kind, candidate_id=f"sdk:{kind.value}")
    context = build_sigstore_context(candidate)
    gate, principals, _ = core.build_scenario()
    verification = gate.verify_candidate(
        principals["verifier"], candidate, now=core.NOW, step=0
    )
    if not verification.allowed or not verification.verified:
        raise PermissionError(verification.reason)
    canary = gate.start_canary(
        principals["deployer"],
        verification.verified.verification_id,
        f"deployment:sdk:{kind.value}",
        now=core.NOW + 1,
        step=1,
    )
    if not canary.allowed or not canary.deployment:
        raise PermissionError(canary.reason)
    promotion = gate.promote(
        principals["deployer"],
        core.PromotionProposal(
            f"promotion:sdk:{kind.value}",
            canary.deployment.deployment_id,
            verification.verified.verification_id,
            "north",
            "production",
            core.healthy_observation(canary.deployment, suffix="sdk"),
        ),
        now=core.NOW + 12,
        step=2,
    )
    if not promotion.allowed:
        raise PermissionError(promotion.reason)
    return context, core.ReleaseFlow(
        gate, principals, verification, canary, promotion
    )


def credential_free_demo() -> dict[str, object]:
    context, flow = verify_and_stage()
    document = json.loads(context.statement_bytes)
    return {
        "sigstore_version": importlib.metadata.version("sigstore"),
        "slsa_version": core.SLSA_VERSION,
        "statement_type": document["_type"],
        "predicate_type": document["predicateType"],
        "subject_digest": document["subject"][0]["digest"]["sha256"],
        "artifact_digest": context.candidate.artifact.digest,
        "builder_id": document["predicate"]["runDetails"]["builder"]["id"],
        "signer_identity": context.candidate.attestation.signer_identity,
        "verification_reason": flow.verification.reason,
        "promotion_reason": flow.promotion.reason,
        "stage": flow.promotion.deployment.stage.value,
        "network_calls": 0,
        "oidc_credentials": 0,
        "model_calls": 0,
    }


if __name__ == "__main__":
    print(credential_free_demo())

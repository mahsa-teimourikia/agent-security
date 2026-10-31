"""Generate the Advanced 06 agent supply-chain notebook deterministically."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "agent_supply_chain_security.ipynb"


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
            "a06-title",
            """
# Advanced 06 — Agent Supply-Chain Security

**Goal:** activate an agent component only after a trusted release gate verifies
its immutable identity, authenticated provenance, expected source/builder,
least-privilege manifest, dependency inventory, risk evidence, rollout state,
and exact recovery path.

The notebook uses real Ed25519 verification and the official Sigstore Python
SDK without OIDC credentials, model calls, deployments, or network access.

![Agent supply-chain verification, rollout, and recovery](architecture.svg)
""",
        ),
        markdown(
            "a06-contract",
            """
## Security contract

A digest proves equality to bytes, a signature authenticates a key, provenance
describes production, and an SBOM describes inventory. None independently
authorizes deployment. Application-owned policy binds them to one component,
tenant, environment, capability set, candidate, canary, and recovery state.
""",
        ),
        code(
            "a06-imports",
            """
from dataclasses import asdict, replace
import base64
import json

import lab
import sdk_adapter as sdk
""",
        ),
        markdown(
            "a06-baseline-heading",
            """
## 1. Quantify a presence-check baseline

The unsafe comparison sees metadata but rarely verifies it, leaves most
components mutable, misses provenance attacks, releases forbidden candidates,
and has no exact recovery capability.
""",
        ),
        code(
            "a06-baseline",
            """
baseline = lab.unsafe_supply_chain_baseline()
print(asdict(baseline))
print({
    "verified_coverage": baseline.verified_artifact_coverage,
    "unpinned_rate": baseline.unpinned_component_rate,
    "provenance_detection": baseline.provenance_failure_detection_rate,
    "forbidden_release_rate": baseline.forbidden_release_rate,
    "median_rollback_seconds": baseline.median_rollback_seconds,
})
assert baseline.forbidden_release_rate == 1.0
""",
        ),
        markdown(
            "a06-candidate-heading",
            """
## 2. Inspect one exact release candidate

The MCP server candidate contains bytes, a least-privilege manifest, signed
provenance, dependency inventory, and scan evidence. All fields are claims until
the verifier resolves and checks their binding.
""",
        ),
        code(
            "a06-candidate",
            """
gate, principals, candidates = lab.build_scenario()
candidate = replace(
    candidates[lab.ComponentKind.MCP_SERVER],
    candidate_id="notebook:mcp-server:2.4.0",
)
print({
    "component": candidate.manifest.component_id,
    "artifact_digest": candidate.artifact.digest,
    "artifact_ref": candidate.manifest.artifact_ref,
    "capabilities": sorted(candidate.manifest.capabilities),
    "dependencies": [item.uri for item in candidate.manifest.dependencies],
    "signer": candidate.attestation.signer_identity,
    "builder": candidate.attestation.statement.builder_id,
})
assert candidate.manifest.artifact_ref == f"sha256:{candidate.artifact.digest}"
""",
        ),
        markdown(
            "a06-verify-heading",
            """
## 3. Verify cryptography and policy independently

The gate computes the digest, verifies the Ed25519 signature, then evaluates
statement/predicate, signer/issuer, subject, builder, source, workflow,
materials, scope, lifecycle, capabilities, inventory, scan, revocation, and
replay policy. The receipt contains identifiers and reasons—not artifact bytes
or signature material.
""",
        ),
        code(
            "a06-verify",
            """
verification = gate.verify_candidate(
    principals["verifier"], candidate, now=lab.NOW, step=0
)
print(asdict(verification.receipt))
print(asdict(verification.verified))
assert verification.allowed and verification.reason == "candidate-verified"
serialized_receipt = json.dumps(asdict(verification.receipt), default=str)
assert candidate.artifact.content.decode() not in serialized_receipt
assert candidate.attestation.signature not in serialized_receipt
""",
        ),
        markdown(
            "a06-sigstore-heading",
            """
## 4. Validate the official Sigstore statement shape

Sigstore Python validates the in-toto Statement schema and constructs an exact
certificate identity/issuer policy. The application must still verify the
bundle and evaluate local release policy; the lab never uses `UnsafeNoOp`.
""",
        ),
        code(
            "a06-sigstore",
            """
sigstore_context = sdk.build_sigstore_context(candidate)
statement = json.loads(sigstore_context.statement_bytes)
print(json.dumps(statement, indent=2))
assert statement["_type"] == lab.IN_TOTO_STATEMENT_TYPE
assert statement["predicateType"] == lab.SLSA_PROVENANCE_TYPE
assert statement["subject"][0]["digest"]["sha256"] == candidate.artifact.digest
""",
        ),
        markdown(
            "a06-substitution-heading",
            """
## 5. Reject mutable references and artifact substitution

A valid name and version are not immutable identity. Changing the bytes after
metadata generation must fail the local digest check before deployment.
""",
        ),
        code(
            "a06-substitution",
            """
for name, mutated in {
    "mutable-reference": replace(
        candidate,
        candidate_id="notebook:mutable",
        manifest=replace(candidate.manifest, artifact_ref="registry.example/mcp:latest"),
    ),
    "substituted-bytes": replace(
        candidate,
        candidate_id="notebook:substitution",
        artifact=replace(candidate.artifact, content=b"malicious payload"),
    ),
}.items():
    local_gate, local_principals, _ = lab.build_scenario()
    result = local_gate.verify_candidate(
        local_principals["verifier"], mutated, now=lab.NOW, step=1
    )
    print(name, result.state.value, result.reason)
    assert not result.allowed
""",
        ),
        markdown(
            "a06-provenance-attack-heading",
            """
## 6. Distinguish signature failure from semantic provenance failure

Changing a signed field without resigning fails cryptography. To test semantic
policy, the fixture resigns a changed statement with its known teaching key;
the valid signature is then denied because the builder or source is not allowed.
""",
        ),
        code(
            "a06-provenance-attack",
            """
for name, changes in {
    "wrong-builder": {"builder_id": "https://runner.attacker.example"},
    "mutable-source-ref": {"source_commit": "refs/heads/main"},
    "wrong-workflow": {"workflow_digest": "0" * 64},
}.items():
    local_gate, local_principals, _ = lab.build_scenario()
    changed_statement = replace(candidate.attestation.statement, **changes)
    changed = lab.resign(
        replace(candidate, candidate_id=f"notebook:{name}"), changed_statement
    )
    result = local_gate.verify_candidate(
        local_principals["verifier"], changed, now=lab.NOW, step=2
    )
    print(name, result.state.value, result.reason)
    assert not result.allowed
""",
        ),
        markdown(
            "a06-signature-heading",
            """
## 7. Reject a forged signature even when the metadata looks correct

Schema validity and plausible provenance are not authentication.
""",
        ),
        code(
            "a06-signature",
            """
local_gate, local_principals, _ = lab.build_scenario()
forged = replace(
    candidate,
    candidate_id="notebook:forged-signature",
    attestation=replace(
        candidate.attestation,
        signature=base64.b64encode(b"0" * 64).decode(),
    ),
)
forged_result = local_gate.verify_candidate(
    local_principals["verifier"], forged, now=lab.NOW, step=3
)
print(forged_result.state.value, forged_result.reason)
assert forged_result.reason == "attestation-signature"
""",
        ),
        markdown(
            "a06-manifest-heading",
            """
## 8. Keep signed requests from widening authority

The manifest may be authentic and still request an unauthorized capability.
Inventory and risk evidence must also bind the exact root digest and full
dependency set.
""",
        ),
        code(
            "a06-manifest",
            """
mutations = {
    "capability-widening": replace(
        candidate,
        candidate_id="notebook:widen",
        manifest=replace(
            candidate.manifest,
            capabilities=candidate.manifest.capabilities | {"records.export"},
        ),
    ),
    "incomplete-inventory": replace(
        candidate,
        candidate_id="notebook:inventory",
        inventory=replace(candidate.inventory, complete=False, components=()),
    ),
    "critical-finding": replace(
        candidate,
        candidate_id="notebook:risk",
        scan=replace(candidate.scan, critical_findings=1),
    ),
}
for name, mutated in mutations.items():
    local_gate, local_principals, _ = lab.build_scenario()
    result = local_gate.verify_candidate(
        local_principals["verifier"], mutated, now=lab.NOW, step=4
    )
    print(name, result.state.value, result.reason)
    assert not result.allowed
""",
        ),
        markdown(
            "a06-canary-heading",
            """
## 9. Stage before activation

Verification yields a bounded release record. A separate deployer uses its ID
to start a canary. Production is unchanged until a later promotion succeeds.
""",
        ),
        code(
            "a06-canary",
            """
canary = gate.start_canary(
    principals["deployer"], verification.verified.verification_id,
    "deployment:notebook:mcp", now=lab.NOW + 1, step=5,
)
print(asdict(canary.deployment))
assert canary.allowed and canary.deployment.stage is lab.DeploymentStage.CANARY
assert gate.current_digests[verification.verified.component_id] == canary.deployment.previous_digest
""",
        ),
        markdown(
            "a06-promotion-heading",
            """
## 10. Bind promotion to sufficient healthy observations

A timer is not health evidence. Too few samples stop promotion. The accepted
observation binds the exact deployment and digest, has a valid window, and
reports bounded errors with no forbidden actions or provenance failures.
""",
        ),
        code(
            "a06-promotion",
            """
insufficient = replace(
    lab.healthy_observation(canary.deployment, suffix="insufficient"),
    sample_count=20,
)
stopped = gate.promote(
    principals["deployer"],
    lab.PromotionProposal(
        "promotion:notebook:insufficient", canary.deployment.deployment_id,
        verification.verified.verification_id, "north", "production", insufficient,
    ),
    now=lab.NOW + 12, step=6,
)
print(stopped.state.value, stopped.reason)
assert stopped.state is lab.DecisionState.STOP

healthy = lab.healthy_observation(canary.deployment, suffix="healthy")
promotion = gate.promote(
    principals["deployer"],
    lab.PromotionProposal(
        "promotion:notebook:healthy", canary.deployment.deployment_id,
        verification.verified.verification_id, "north", "production", healthy,
    ),
    now=lab.NOW + 12, step=7,
)
print(promotion.state.value, promotion.reason, promotion.deployment.stage.value)
assert promotion.allowed
""",
        ),
        markdown(
            "a06-rollback-heading",
            """
## 11. Recover by exact digest and consume authority once

The health monitor issues a short-lived guard binding incident, failed digest,
and retained target. The deployer restores that target; replay is denied.
""",
        ),
        code(
            "a06-rollback",
            """
issued = gate.issue_rollback_guard(
    principals["monitor"], promotion.deployment.deployment_id,
    "incident:notebook", "guard:notebook", now=lab.NOW + 20, step=8,
)
rollback = gate.consume_rollback(
    principals["deployer"], issued.rollback_guard.guard_id,
    now=lab.NOW + 32, step=9,
)
replay = gate.consume_rollback(
    principals["deployer"], issued.rollback_guard.guard_id,
    now=lab.NOW + 33, step=10,
)
print(asdict(rollback.rollback))
print("replay", replay.state.value, replay.reason)
assert rollback.rollback.restored_digest == promotion.deployment.previous_digest
assert rollback.rollback.duration_seconds == 12
assert replay.reason == "rollback-guard-consumed"
""",
        ),
        markdown(
            "a06-failure-heading",
            """
## 12. Fail explicitly when verification infrastructure is unavailable

The gate never converts trust-store, policy, verifier, inventory, or rollout
outage into an unsigned release or direct production activation.
""",
        ),
        code(
            "a06-failure",
            """
failed_gate, failed_principals, failed_candidates = lab.build_scenario()
failed_gate.trust_store_available = False
failure = failed_gate.verify_candidate(
    failed_principals["verifier"],
    replace(
        failed_candidates[lab.ComponentKind.MCP_SERVER],
        candidate_id="notebook:trust-failure",
    ),
    now=lab.NOW, step=11,
)
print(failure.state.value, failure.reason)
assert failure.state is lab.DecisionState.ERROR
assert failure.reason == "trust-store-unavailable"
""",
        ),
        markdown(
            "a06-evaluation-heading",
            """
## 13. Evaluate exact populations and denominators

The controlled suite contains five valid releases, fourteen attacks, three
dependency failures, and two recovery cases. Safety metrics are reported beside
valid completion so a deny-all design cannot look successful.
""",
        ),
        code(
            "a06-evaluation",
            """
report, cases = lab.evaluate_controls()
print(asdict(report))
print({category: sum(case.category == category for case in cases)
       for category in ("valid", "attack", "failure", "recovery")})
assert (report.valid_cases, report.attack_cases,
        report.failure_cases, report.recovery_cases) == (5, 14, 3, 2)
assert report.valid_deployment_completion_rate == 1.0
assert report.forbidden_release_rate == 0.0
assert report.provenance_failure_detection_rate == 1.0
assert report.rollback_success_rate == 1.0
""",
        ),
        markdown(
            "a06-production",
            """
## Production upgrade

Replace local keys and state with Sigstore bundle verification, exact identity
policy, TUF-distributed roots, registry quarantine, protected and isolated
builders, signed SLSA provenance, signed CycloneDX/SPDX inventory, current risk
and VEX policy, transactional replay/deployment state, cluster/application
admission, independently sourced telemetry, replicated known-good artifacts,
and unknown-outcome reconciliation. Test root rotation, signer compromise,
registry substitution, stale evidence, concurrent promotion/revocation/rollback,
and emergency procedures before production use.

## Checkpoint

Does the presence of provenance prove an agent component is acceptable? **No.**
Authenticate the provenance, bind it to the locally computed digest, and compare
signer, issuer, source, builder, workflow, materials, scope, lifecycle,
capabilities, inventory, risk, revocation and rollout state with independent
current policy. Accepted provenance yields a release capability, not automatic
production activation.
""",
        ),
    ]
    return notebook


def main() -> None:
    nbf.write(build_notebook(), OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()

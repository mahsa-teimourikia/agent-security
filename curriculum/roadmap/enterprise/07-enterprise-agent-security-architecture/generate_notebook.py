"""Generate the Enterprise 07 notebook deterministically."""
from pathlib import Path
import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "enterprise_security_architecture.ipynb"


def md(cell_id: str, source: str):
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
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        md("e07-title", """
# Enterprise 07 — Enterprise Agent Security Architecture

**Goal:** prove that every authority-changing path is mediated, owned,
resilient, observable, and enforced again at the protected resource or effect.

![Mediated enterprise agent architecture](architecture.svg)

This notebook is deterministic, credential-free, and makes no external calls.
"""),
        md("e07-thesis", """
## Security thesis

A diagram, internal network, workload name, schema, model recommendation, or
upstream policy result is not authority. The effect owner must authenticate
current identity, bind tenant/capability, evaluate policy, and emit evidence.
"""),
        code("e07-imports", """
from dataclasses import asdict
import json

import enterprise_architecture as arch
import enterprise_architecture_fixtures as fx
from enterprise_architecture_otel import DecisionTelemetry
import lab

architecture = fx.architecture()
print({"architecture": architecture.architecture_id, "version": architecture.version})
"""),
        md("e07-topology", """
## 1. Evaluate the authority graph

Count required control slots, owners, unmediated paths, critical failure points,
and residual risks. A component named “gateway” earns no credit by itself.
"""),
        code("e07-topology-run", """
report = arch.evaluate_architecture(architecture, fx.NOW)
print(json.dumps(asdict(report), indent=2))
assert report.release_ready
assert report.control_coverage == report.owner_coverage == 1.0
"""),
        md("e07-allow", """
## 2. Enforce at the effect boundary

Authenticated principal and tenant come from application state. The gateway
checks the exact flow, capability, resource tenant, proposal digest, and policy.
"""),
        code("e07-allow-run", """
gateway = fx.gateway()
allowed = gateway.decide(fx.request(), fx.NOW)
print(asdict(allowed))
assert allowed.state is arch.DecisionState.ALLOW
assert gateway.verify(allowed)
"""),
        md("e07-tenant", """
## 3. Reject cross-tenant scope

Changing proposed content cannot widen authenticated tenant authority.
"""),
        code("e07-tenant-run", """
cross_tenant = gateway.decide(
    fx.request(request_id="request-cross", resource_tenant="south"), fx.NOW)
print(asdict(cross_tenant))
assert cross_tenant.reason == "cross-tenant"
"""),
        md("e07-bypass", """
## 4. Expose a direct bypass

Remove policy enforcement from the runtime-to-effect flow. Both architecture
review and runtime enforcement detect the unmediated path.
"""),
        code("e07-bypass-run", """
weak = lab.without_control(architecture, "runtime-to-effect", "policy-enforcement")
weak_report = arch.evaluate_architecture(weak, fx.NOW)
bypass = fx.gateway(architecture_value=weak).decide(fx.request(), fx.NOW)
print({"paths": weak_report.unmediated_paths, "decision": bypass.reason})
assert weak_report.unmediated_paths == ("runtime-to-effect",)
assert bypass.reason == "unmediated-path"
"""),
        md("e07-spof", """
## 5. Detect correlated “redundancy”

Replicas in one failure domain are still one control-plane failure point.
"""),
        code("e07-spof-run", """
from dataclasses import replace
components = tuple(
    replace(item, replicas=3, failure_domains=("az-a", "az-a", "az-a"))
    if item.component_id == "policy-service" else item
    for item in architecture.components)
fragile = arch.evaluate_architecture(replace(architecture, components=components), fx.NOW)
print(fragile.single_points_of_failure)
assert "policy-service" in fragile.single_points_of_failure
"""),
        md("e07-outage", """
## 6. Preserve dependency uncertainty

Policy-service failure is not permission. Consequential work remains UNKNOWN
and needs reconciliation or a separately governed degraded-mode contract.
"""),
        code("e07-outage-run", """
unknown = fx.gateway(policy_value=fx.policy(available=False)).decide(
    fx.request(request_id="request-outage"), fx.NOW)
print(asdict(unknown))
assert unknown.state is arch.DecisionState.UNKNOWN
"""),
        md("e07-otel", """
## 7. Emit minimized OpenTelemetry evidence

The real SDK records IDs, versions, decision, reason, and receipt digest—never
prompt or customer content. Spans are evidence, not authorization.
"""),
        code("e07-otel-run", """
telemetry = DecisionTelemetry()
for receipt in (allowed, cross_tenant, bypass, unknown):
    telemetry.emit(receipt)
spans = telemetry.finished()
print(dict(spans[0].attributes))
assert len(spans) == 4
assert all("prompt" not in key for span in spans for key in span.attributes)
"""),
        md("e07-eval", """
## 8. Evaluate distinct populations

Report valid allows, forbidden allows, cross-tenant rejections, bypass
rejections, and dependency uncertainty with their own denominators.
"""),
        code("e07-eval-run", """
evaluation = lab.evaluate_controls()
print(json.dumps(asdict(evaluation), indent=2))
assert evaluation.unsafe_allows == 0
assert evaluation.valid_allow_rate == 1.0
assert evaluation.cross_tenant_rejection_rate == 1.0
assert evaluation.unmediated_path_rejection_rate == 1.0
assert evaluation.dependency_unknown_rate == 1.0
"""),
        md("e07-checkpoint", """
## Checkpoint

The orchestrator checks a user and approves `ticket.resolve`. The effect gateway
has mTLS but receives a shared service identity and trusts the ticket tenant in
the model's arguments. Is the architecture adequately authorized?

**Expected reasoning:** No. mTLS authenticates the shared peer, not delegated
user/tenant scope or ticket ownership. The effect boundary must derive trusted
identity, bind the exact capability and resource tenant, evaluate current policy,
and record/verify the outcome independently of model arguments.
"""),
    ]
    return notebook


if __name__ == "__main__":
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")

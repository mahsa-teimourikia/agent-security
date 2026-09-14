"""Regenerate the five hardened published-course notebooks deterministically."""
from pathlib import Path
import nbformat as nbf


COURSES = {
    "curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.ipynb": {
        "title": "Intermediate 02 — MCP Gateway Security",
        "intro": "Authorize MCP calls independently of discovery and model output. The lab proves server trust, identity binding, token audience, scope, exact schemas, quotas, and non-passthrough.",
        "module": "02_mcp_gateway.py",
        "setup": "ns = runpy.run_path('02_mcp_gateway.py')\nGateway, ClientIdentity, AccessToken, ToolSpec, ToolCall = (ns[name] for name in ('Gateway', 'ClientIdentity', 'AccessToken', 'ToolSpec', 'ToolCall'))\nnow = datetime(2026, 9, 12, tzinfo=timezone.utc)\ngateway = Gateway({'research-mcp-v1': {'search_policy': ToolSpec('search_policy', 'policy:search', frozenset({'query'}))}}, per_subject_limit=2)\nidentity = ClientIdentity('research-agent', 'north')\ntoken = AccessToken('research-agent', 'north', 'mcp-gateway', frozenset({'policy:search'}), now + timedelta(minutes=5), 'opaque-7')\nsafe = ToolCall('research-mcp-v1', 'search_policy', {'query': 'retention'})",
        "safe": "allowed = gateway.dispatch(identity, token, safe, now=now)\nassert allowed['status'] == 'allow'\nallowed",
        "attack": "attacks = [\n gateway.dispatch(identity, AccessToken('research-agent','north','other-api',token.scopes,token.expires_at,'opaque-8'), safe, now=now),\n gateway.dispatch(identity, token, ToolCall('evil-mcp','search_policy',{'query':'x'}), now=now),\n gateway.dispatch(identity, token, ToolCall('research-mcp-v1','search_policy',{'query':'x','admin':'true'}), now=now),\n]\n[(r['status'], r['receipt'].reason) for r in attacks]",
        "checks": "assert [r['receipt'].reason for r in attacks] == ['token-audience', 'untrusted-server', 'argument-schema']\nassert 'opaque-7' not in repr(allowed)\nassert all(r['receipt'].decision == 'deny' for r in attacks)",
        "metrics": "from collections import Counter\nCounter(receipt.reason for receipt in gateway.receipts)",
        "failure": "bypass = gateway.dispatch(identity, token, safe, now=now)\nassert bypass['status'] == 'allow'\nlimited = gateway.dispatch(identity, token, safe, now=now)\nassert limited['receipt'].reason == 'rate-limit'\nlimited",
        "production": "Production replacement: authenticated workload identity, OAuth resource indicators, separate upstream tokens, TLS, egress policy, durable quotas, protected receipts, revocation, and incident ownership. Tool results remain untrusted after an allowed call.",
    },
    "curriculum/intermediate/03-incident-recovery/03_incident_recovery.ipynb": {
        "title": "Intermediate 03 — Incident Response and Recovery",
        "intro": "Move a suspicious agent run through detection, containment, independently authorized recovery, and exactly-once replay while preserving a verifiable chronology.",
        "module": "03_incident_recovery.py",
        "setup": "ns = runpy.run_path('03_incident_recovery.py')\nIncidentRun, RecoveryPlan, checkpoint_digest = (ns[name] for name in ('IncidentRun','RecoveryPlan','checkpoint_digest'))\nnow = datetime(2026, 9, 12, tzinfo=timezone.utc)\nstate = {'ticket':'T-7','operation':'close','version':4}\ndigest = checkpoint_digest(state)\nrun = IncidentRun('run-7','north','policy-v4','credential-v2')",
        "safe": "assert run.detect('unexpected egress', detector='egress-monitor', now=now)\nassert run.contain(capabilities={'ticket:write','network:external'}, responder='operator:lee', now=now)\nassert run.propose_recovery(RecoveryPlan('checkpoint-4',digest,'policy-v4','credential-v2','automation:planner'), now=now)\nrun.phase.value",
        "attack": "denied = run.authorize_recovery(approver='automation:planner', expected_checkpoint_digest=digest, current_policy_version='policy-v4', current_credential_version='credential-v2', now=now)\nassert not denied\nassert run.phase.value == 'recovery_pending'",
        "checks": "approved = run.authorize_recovery(approver='operator:sam', expected_checkpoint_digest=digest, current_policy_version='policy-v4', current_credential_version='credential-v2', now=now)\nassert approved and run.verify_event_chain()\nassert run.commit_once('effect-T-7-close','close-ticket',now=now)\nassert not run.commit_once('effect-T-7-close','close-ticket',now=now)",
        "metrics": "{'events': len(run.events), 'chain_valid': run.verify_event_chain(), 'duplicate_effects': 0, 'phase': run.phase.value}",
        "failure": "tampered = list(run.events)\noriginal = run.events[0]\nrun.events[0] = type(original)(original.sequence, original.kind, 'changed', original.actor, original.observed_at, original.previous_hash, original.event_hash)\nassert not run.verify_event_chain()\nrun.events = tampered",
        "production": "Production replacement: protected append-only audit, authenticated responders, distributed revocation, provider idempotency, encrypted evidence, tested rollback, affected-party handling, and explicit incident ownership.",
    },
    "curriculum/advanced/01-attack-evaluation/01_attack_evaluation.ipynb": {
        "title": "Advanced 01 — Agent Security Attack Evaluation",
        "intro": "Combine versioned adversarial and valid-task cases without hiding severe failures or utility burdens inside a single average.",
        "module": "01_attack_evaluation.py",
        "setup": "ns = runpy.run_path('01_attack_evaluation.py')\nAttackCase, CaseResult, Severity, evaluate = (ns[name] for name in ('AttackCase','CaseResult','Severity','evaluate'))\ncases = [AttackCase('inj-1','goal-hijack',Severity.HIGH,True,'action-policy'), AttackCase('scope-1','privilege-abuse',Severity.CRITICAL,True,'scope-pdp'), AttackCase('valid-1','normal-task',Severity.LOW,False,'scope-pdp')]",
        "safe": "safe = [CaseResult('inj-1',True,True,'action-policy'), CaseResult('scope-1',True,True,'scope-pdp'), CaseResult('valid-1',False,True,'scope-pdp')]\nreport = evaluate(cases,safe,suite_version='agent-attacks-1.0')\nassert report.ready\nreport",
        "attack": "unsafe = [safe[0], CaseResult('scope-1',False,True,'scope-pdp'), safe[2]]\nfailed = evaluate(cases,unsafe,suite_version='agent-attacks-1.0')\nassert not failed.ready and failed.severe_attack_successes == 1\nfailed",
        "checks": "missing = evaluate(cases,safe[:-1],suite_version='agent-attacks-1.0')\nassert 'missing:valid-1' in missing.blockers\nassert missing.case_coverage == 2/3",
        "metrics": "{'attack_success_rate': failed.attack_success_rate, 'severe_attack_successes': failed.severe_attack_successes, 'false_block_rate': failed.false_block_rate, 'trace_coverage': failed.trace_coverage}",
        "failure": "false_block = [safe[0],safe[1],CaseResult('valid-1',True,True,'scope-pdp')]\nutility_failure = evaluate(cases,false_block,suite_version='agent-attacks-1.0')\nassert any(item.startswith('false-block-rate:') for item in utility_failure.blockers)",
        "production": "Production replacement: protected versioned suites, representative environments, severity review, statistically appropriate confidence, utility metrics, durable result provenance, and non-averaged severe blockers.",
    },
    "curriculum/advanced/02-multi-agent-security/02_multi_agent_security.ipynb": {
        "title": "Advanced 02 — Multi-Agent Delegation Security",
        "intro": "Attenuate authority across a supervisor-worker boundary and prove tenant, scope, budget, lifetime, identity, and artifact contracts at use time.",
        "module": "02_multi_agent_security.py",
        "setup": "ns = runpy.run_path('02_multi_agent_security.py')\nParentAuthority, WorkerSession, issue_delegation = (ns[name] for name in ('ParentAuthority','WorkerSession','issue_delegation'))\nnow = datetime(2026,9,12,tzinfo=timezone.utc)\nparent = ParentAuthority('supervisor','north',frozenset({'search','read'}))\nenvelope = issue_delegation(parent, child='researcher', tenant='north', requested_scopes=frozenset({'search'}), budget=1, expires_at=now+timedelta(minutes=10), now=now, artifact_types=frozenset({'evidence-list'}))\nassert envelope and envelope.scopes <= parent.scopes\nsession = WorkerSession(envelope)",
        "safe": "artifact = session.execute(worker='researcher',tenant='north',operation='search',artifact_type='evidence-list',content='E-1',now=now)\nassert artifact and artifact.envelope_id == envelope.envelope_id\nartifact",
        "attack": "assert session.execute(worker='researcher',tenant='north',operation='search',artifact_type='evidence-list',content='E-2',now=now) is None\nassert session.receipts[-1]['reason'] == 'budget'",
        "checks": "escalation = issue_delegation(parent, child='writer', tenant='north', requested_scopes=frozenset({'delete'}), budget=1, expires_at=now+timedelta(minutes=5), now=now, artifact_types=frozenset({'summary'}))\nassert escalation is None",
        "metrics": "{'issued_scope': sorted(envelope.scopes), 'parent_scope': sorted(parent.scopes), 'budget_consumed': session.consumed, 'denials': sum(not r['allowed'] for r in session.receipts)}",
        "failure": "session.terminate(reason='suspected compromise')\nassert session.execute(worker='researcher',tenant='north',operation='search',artifact_type='evidence-list',content='E-3',now=now) is None\nassert session.receipts[-1]['reason'] == 'terminated'",
        "production": "Production replacement: authenticated issuer, integrity-protected and replay-resistant envelopes, revocation, workload identity, independent budgets, queue isolation, typed artifact validation, privacy-aware traces, and kill-switch drills.",
    },
    "curriculum/advanced/03-production-gate/03_production_gate.ipynb": {
        "title": "Advanced 03 — Governance and Production Readiness",
        "intro": "Validate typed, owned, fresh evidence and issue a release decision that cannot average away severe failures.",
        "module": "03_production_gate.py",
        "setup": "ns = runpy.run_path('03_production_gate.py')\nEvidence, RiskAcceptance, REQUIRED_EVIDENCE, evaluate_release = (ns[name] for name in ('Evidence','RiskAcceptance','REQUIRED_EVIDENCE','evaluate_release'))\nnow = datetime(2026,9,12,tzinfo=timezone.utc)\nevidence = [Evidence(kind,f'artifact:{kind}','release-7','team:agent-security',now-timedelta(days=1),True) for kind in REQUIRED_EVIDENCE]\nrisks = [RiskAcceptance('R-12','director:platform','bounded read-only pilot latency risk',now+timedelta(days=14))]",
        "safe": "decision = evaluate_release(evidence,severe_attack_successes=0,residual_risks=risks,now=now)\nassert decision.ready and not decision.blockers\ndecision",
        "attack": "severe = evaluate_release(evidence,severe_attack_successes=1,residual_risks=risks,now=now)\nassert not severe.ready and 'severe-attack-successes:1' in severe.blockers\nsevere",
        "checks": "stale = list(evidence)\nstale[0] = Evidence(stale[0].kind,stale[0].value,stale[0].version,stale[0].owner,now-timedelta(days=60),True)\nstale_decision = evaluate_release(stale,severe_attack_successes=0,residual_risks=risks,now=now)\nassert any(item.startswith('stale:') for item in stale_decision.blockers)",
        "metrics": "{'ready': decision.ready, 'evidence_count': len(evidence), 'version_bindings': decision.evidence_versions, 'receipt_id': decision.receipt_id}",
        "failure": "expired = [RiskAcceptance('R-12','director:platform','risk still exists',now-timedelta(seconds=1))]\nexpired_decision = evaluate_release(evidence,severe_attack_successes=0,residual_risks=expired,now=now)\nassert not expired_decision.ready",
        "production": "Production replacement: authenticated evidence producers, protected history, branch and environment controls, staged deployment, monitored rollback, kill switches, accountable exceptions, and periodic reapproval after material change.",
    },
}


def notebook(spec: dict[str, str]) -> nbf.NotebookNode:
    nb = nbf.v4.new_notebook()
    nb["metadata"]["kernelspec"] = {"display_name": "Python 3", "language": "python", "name": "python3"}
    nb["metadata"]["language_info"] = {"name": "python", "version": "3.11"}
    cells = [
        nbf.v4.new_markdown_cell(f"# {spec['title']}\n\n{spec['intro']}"),
        nbf.v4.new_markdown_cell("## 1. Load the course lab\n\nThe notebook imports the reusable course module rather than copying its security logic."),
        nbf.v4.new_code_cell("import runpy\nfrom datetime import datetime, timedelta, timezone\n" + spec["setup"]),
        nbf.v4.new_markdown_cell("## 2. Establish the safe baseline\n\nObserve the trusted inputs and the decision evidence before injecting failures."),
        nbf.v4.new_code_cell(spec["safe"]),
        nbf.v4.new_markdown_cell("## 3. Inject an attack\n\nChange one security-relevant boundary and keep the rest of the fixture stable."),
        nbf.v4.new_code_cell(spec["attack"]),
        nbf.v4.new_markdown_cell("## 4. Attempt a bypass\n\nThe assertions below make the security property executable and regression-testable."),
        nbf.v4.new_code_cell(spec["checks"]),
        nbf.v4.new_markdown_cell("## 5. Evaluate observable outcomes\n\nUse explicit denominators or counts. Private model reasoning is neither required nor recorded."),
        nbf.v4.new_code_cell(spec["metrics"]),
        nbf.v4.new_markdown_cell("## 6. Exercise a second failure mode"),
        nbf.v4.new_code_cell(spec["failure"]),
        nbf.v4.new_markdown_cell("## 7. Production replacement\n\n" + spec["production"]),
        nbf.v4.new_markdown_cell("## Checkpoint\n\nExplain which trusted component enforces the invariant, what evidence proves the decision, and what residual risk remains."),
    ]
    for index, cell in enumerate(cells):
        cell["id"] = f"cell-{index:02d}"
    nb["cells"] = cells
    return nb


for relative, spec in COURSES.items():
    path = Path(relative)
    nbf.write(notebook(spec), path)
    print(f"generated {path}")

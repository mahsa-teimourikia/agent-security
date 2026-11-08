# Course Map

Canonical navigation for the published Agent Security curriculum. The
[Learning Hub](https://mahsa-teimourikia.github.io/agent-security/) is the
interactive learner experience, while the
[36-course syllabus](curriculum/README.md) records the complete sequence and
practical focus of every current course.

## Current 36-course sequence

All four tracks have passed the publication gate. Every course has a substantive
chapter, credential-free reusable lab, executable notebook, focused tests, and
a Learning Hub checkpoint.

| Track | Course IDs | Published courses | Syllabus |
|---|---|---:|---|
| Foundation | F01–F07 | 7 | [Architecture, threat modeling, invariants, tools, authorization, injection, and evidence](curriculum/README.md#foundation-sequence-seven-published) |
| State and execution | I01–I10 | 10 | [Memory, durable state, identity, credentials, sandboxing, egress, RAG, MCP, and human review](curriculum/README.md#intermediate-sequence-ten-published-topics) |
| Distributed adversaries | A01–A10 | 10 | [Delegation, cross-agent attacks, protocols, supply chain, testing, assurance, and hunting](curriculum/README.md#advanced-sequence-ten-published-topics) |
| Enterprise operations | E01–E09 | 9 | [Long-running agents, revocation, incidents, recovery, governance, architecture, and capstone](curriculum/README.md#production--enterprise-sequence-nine-published-topics) |

Course numbers restart at `01` within each track. The `F`, `I`, `A`, and `E`
prefixes provide globally unique Learning Hub identifiers.

## Compact legacy path

The original nine-course path remains published for learners who want a shorter
route through the core controls. Current course A01 reuses the mature
multi-agent delegation lesson from this path; the roadmap alias does not create
a duplicate course.

### Beginner

| # | Module | Theory | Lab | Notebook |
|---|---|---|---|---|
| 01 | Security Foundations and Tool Policy | [README](curriculum/beginner/01-tool-policy/README.md) | [01_tool_policy.py](curriculum/beginner/01-tool-policy/01_tool_policy.py) | [01_tool_policy.ipynb](curriculum/beginner/01-tool-policy/01_tool_policy.ipynb) |
| 02 | Prompt Injection and Untrusted Content | [README](curriculum/beginner/02-prompt-injection/README.md) | [02_prompt_injection.py](curriculum/beginner/02-prompt-injection/02_prompt_injection.py) | [02_prompt_injection.ipynb](curriculum/beginner/02-prompt-injection/02_prompt_injection.ipynb) |
| 03 | Secure Research Agent | [README](curriculum/beginner/03-secure-research-agent/README.md) | [03_secure_research_agent.py](curriculum/beginner/03-secure-research-agent/03_secure_research_agent.py) | [03_secure_research_agent.ipynb](curriculum/beginner/03-secure-research-agent/03_secure_research_agent.ipynb) |

### Intermediate

| # | Module | Theory | Lab | Notebook |
|---|---|---|---|---|
| 01 | Identity Propagation and Memory Security | [README](curriculum/intermediate/01-identity-propagation/README.md) | [01_identity_propagation.py](curriculum/intermediate/01-identity-propagation/01_identity_propagation.py) | [01_identity_propagation.ipynb](curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb) |
| 02 | MCP Gateway Security | [README](curriculum/intermediate/02-mcp-gateway/README.md) | [02_mcp_gateway.py](curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.py) | [02_mcp_gateway.ipynb](curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.ipynb) |
| 03 | Incident Response and Recovery | [README](curriculum/intermediate/03-incident-recovery/README.md) | [03_incident_recovery.py](curriculum/intermediate/03-incident-recovery/03_incident_recovery.py) | [03_incident_recovery.ipynb](curriculum/intermediate/03-incident-recovery/03_incident_recovery.ipynb) |

### Advanced

| # | Module | Theory | Lab | Notebook |
|---|---|---|---|---|
| 01 | Security Attack Evaluation | [README](curriculum/advanced/01-attack-evaluation/README.md) | [01_attack_evaluation.py](curriculum/advanced/01-attack-evaluation/01_attack_evaluation.py) | [01_attack_evaluation.ipynb](curriculum/advanced/01-attack-evaluation/01_attack_evaluation.ipynb) |
| 02 | Multi-Agent Delegation and Security | [README](curriculum/advanced/02-multi-agent-security/README.md) | [02_multi_agent_security.py](curriculum/advanced/02-multi-agent-security/02_multi_agent_security.py) | [02_multi_agent_security.ipynb](curriculum/advanced/02-multi-agent-security/02_multi_agent_security.ipynb) |
| 03 | Governance and Production Readiness | [README](curriculum/advanced/03-production-gate/README.md) | [03_production_gate.py](curriculum/advanced/03-production-gate/03_production_gate.py) | [03_production_gate.ipynb](curriculum/advanced/03-production-gate/03_production_gate.ipynb) |

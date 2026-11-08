# Agent Security Learning Hub

A comprehensive, source-linked curriculum for securing AI agents, agentic workflows, tools, memory, protocols, and multi-agent systems.

## Start with the Learning Hub

**[Open the Agent Security Learning Hub →](https://mahsa-teimourikia.github.io/agent-security/)**

The Hub presents the complete 36-course curriculum across Foundation, State and
Execution, Distributed Adversaries, and Enterprise Operations, alongside the
compact original path. Every published lesson follows **Learn → Lab →
Checkpoint**, links to a credential-free notebook and reusable Python lab, uses
a focused checkpoint, and records completion locally in the browser.

### Knowledge check

Ready to test your understanding? Take the interactive [Agent Security Knowledge Check](https://mahsa-teimourikia.github.io/agent-security/quiz/) after completing the lessons. It includes multi-select questions, explanations, scoring, and retry support.

## Current 36-course curriculum

All courses in the expanded sequence have passed the publication gate. Use the
[complete syllabus](curriculum/README.md) for the course-by-course focus and the
[course map](COURSE_MAP.md) for navigation between the current and compact
paths.

| Track | IDs | Courses | Focus |
|---|---|---:|---|
| [Foundation](curriculum/README.md#foundation-sequence-seven-published) | F01–F07 | 7 | boundaries, threat models, invariants, narrow tools, authorization, injection, and evidence security |
| [State and execution](curriculum/README.md#intermediate-sequence-ten-published-topics) | I01–I10 | 10 | memory, durable state, identity, credentials, sandboxing, egress, RAG, MCP, and human review |
| [Distributed adversaries](curriculum/README.md#advanced-sequence-ten-published-topics) | A01–A10 | 10 | delegation, cross-agent attacks, cascading failures, protocols, supply chain, testing, assurance, and hunting |
| [Enterprise operations](curriculum/README.md#production--enterprise-sequence-nine-published-topics) | E01–E09 | 9 | long-running agents, revocation, incidents, forensics, release gates, governance, architecture, and capstone |

## Compact original path

The original nine-course path remains published for learners who want a shorter
route through the core controls. Its README chapters, reusable labs, and
notebooks are linked in the [course map](COURSE_MAP.md#compact-legacy-path).

| Level | Courses | Focus |
|---|---:|---|
| Beginner | 3 | tool policy, prompt injection containment, and secure research |
| Intermediate | 3 | identity propagation, MCP gateway security, and incident recovery |
| Advanced | 3 | attack evaluation, multi-agent delegation, and production readiness |

## Running locally

The core labs use deterministic fixtures and have a credential-free path. No API keys or cloud services are required.

```bash
# Run Lesson 01 scenario evaluation
python3 curriculum/beginner/01-tool-policy/01_tool_policy.py

# Run focused tests
python3 -m pytest -q

# Compile all Python
python3 -m compileall -q curriculum tests

# Run the guided notebook
jupyter notebook curriculum/beginner/01-tool-policy/01_tool_policy.ipynb

# Execute every credential-free notebook as CI does
python3 scripts/execute-notebooks.py --timeout 90
```

## Security references

- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [OWASP Securing Agentic Applications Guide](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [Google Secure AI Framework](https://cloud.google.com/use-cases/secure-ai-framework)
- [MCP Security Best Practices 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [NSA MCP Security Design Considerations](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/)
- [Microsoft Agent Safety](https://learn.microsoft.com/en-us/agent-framework/agents/safety)
- [OpenAI Agents SDK human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)

Learning with One+i · responsible AI, real-world impact — [oneplusi.io](https://oneplusi.io)

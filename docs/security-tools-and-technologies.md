# Security tools and technologies

There is no single “agent security product.” Secure systems combine controls at different layers and keep enforcement in application code. Choose the smallest set that produces evidence for your threat model; do not add a scanner or guardrail as a substitute for authorization.

## Tooling map

| Layer | What it solves | Prominent options | Selection notes |
| --- | --- | --- | --- |
| Policy and orchestration | State transitions, approvals, retries, and stop conditions | [LangGraph](https://langchain-ai.github.io/langgraph/), [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) | Keep policy nodes deterministic; model output should be a proposal, not permission. |
| Prompt and output guardrails | Validate topics, schemas, PII, and unsafe outputs | [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo-guardrails/), [Guardrails AI](https://www.guardrailsai.com/docs) | Use layered checks and fail closed for high-impact actions; test bypasses. |
| Red teaming and vulnerability scanning | Discover injection, leakage, jailbreak, and hallucination weaknesses | [Microsoft PyRIT](https://microsoft.github.io/PyRIT/), [garak](https://reference.garak.ai/en/latest/), [Giskard](https://docs.giskard.ai/en/stable/) | Keep attack fixtures versioned and map every finding to a mitigation and owner. |
| Evaluation and regression | Turn controls into repeatable release gates | [DeepEval](https://deepeval.com/docs/getting-started), [OpenAI Evals](https://github.com/openai/evals) | Assert security properties such as no unauthorized tool call, not only answer quality. |
| Tracing and observability | Explain trajectories, tool calls, cost, and policy decisions | [OpenTelemetry](https://opentelemetry.io/docs/), [Langfuse](https://langfuse.com/docs), [Arize Phoenix](https://phoenix.arize.com/) | Redact prompts and secrets; propagate correlation IDs across delegated agents. |
| Identity and secrets | Bind actions to a principal and protect credentials | [OAuth 2.0](https://oauth.net/2/), [SPIFFE/SPIRE](https://spiffe.io/docs/latest/spiffe-about/overview/), [Vault](https://developer.hashicorp.com/vault/docs) | Use short-lived, down-scoped credentials; never put provider keys in prompts or memory. |
| Privacy and data loss prevention | Detect, minimize, and redact sensitive data | [Microsoft Presidio](https://microsoft.github.io/presidio/), [OpenTelemetry Collector processors](https://opentelemetry.io/docs/collector/) | Define retention and tenant boundaries before choosing detectors. |
| Protocol and tool boundaries | Secure tool discovery, schemas, transport, and egress | [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices), [OWASP MCP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [MCP Inspector](https://github.com/modelcontextprotocol/inspector) | Discovery is not trust. Authenticate servers and validate every call. |
| Runtime isolation | Limit filesystem, network, and code-execution blast radius | [gVisor](https://gvisor.dev/docs/), [Firecracker](https://firecracker-microvm.github.io/), [Wasm](https://webassembly.org/docs/security/) | Assume a tool can be compromised; isolate side effects and enforce resource budgets. |

## Recommended adoption sequence

1. Write the threat model and action classification first: read-only, reversible, or irreversible.
2. Implement identity, authorization, tool schemas, budgets, approval gates, and a kill switch in code.
3. Add traces for principal, tenant, policy decision, tool, outcome, and correlation ID—with redaction.
4. Add deterministic regression tests, then run PyRIT or garak against realistic attack fixtures.
5. Add guardrails where they reduce a measured risk; document false positives, bypass tests, and fallback behavior.
6. Exercise incident response and rollback before enabling autonomy in production.

## Research foundations

- [Indirect Prompt Injections: Top Ten Threats and Mitigations](https://arxiv.org/abs/2302.12173) — threat model for instructions embedded in retrieved content.
- [Ignore Previous Prompt: Attack Techniques For Language Models](https://arxiv.org/abs/2211.09527) — early systematic analysis of prompt injection.
- [Tensor Trust: Interpreting and Protecting Large Language Models](https://arxiv.org/abs/2308.02377) — empirical study of instruction-hierarchy attacks.
- [ToolEmu: Identifying the Risks of LM Agents with an LM-Emulated Sandbox](https://arxiv.org/abs/2309.15817) — evaluating tool-using agents in a sandbox.
- [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses](https://arxiv.org/abs/2406.13352) — benchmark for realistic agent prompt-injection defenses.
- [Garak: A Framework for Security Probing Large Language Models](https://arxiv.org/abs/2406.11036) and [PyRIT](https://arxiv.org/abs/2410.02828) — open-source red-team approaches.
- [A Survey on Large Language Model based Autonomous Agents](https://arxiv.org/abs/2308.11432) — useful background on agent architecture and failure surfaces.

## Practical decision rule

For a low-risk read-only assistant, start with application authorization, schema validation, redacted tracing, and regression fixtures. For an agent that can change records or spend money, add short-lived identity, human approval, runtime isolation, attack evaluation, and a rehearsed rollback. A tool is appropriate only when it closes a specific gap and its output can be tested.

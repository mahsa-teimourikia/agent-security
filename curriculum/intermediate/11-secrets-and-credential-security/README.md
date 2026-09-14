# 11 — Secrets and Credential Security

<!-- roadmap-status -->
> **Roadmap status: Pilot.** Some executable evidence exists; the remaining gate is listed in the Learning Hub and review plan.

## Learning objectives

Keep secret material outside context, memory, and traces; issue short-lived,
tenant-scoped, audience-bound credentials; and prove a tool cannot reuse a token
for another service or broader action.

## Threat model

Secrets leak through prompts, retrieval, memory, logs, exceptions, environment
inheritance, and broad token forwarding. A credential is authority, so a model
must never select its own scope, audience, or lifetime.

## Practical lab

Run `python curriculum/intermediate/11-secrets-and-credential-security/lab.py`.
It returns a vault reference rather than secret material, accepts only the bound
tenant/audience/scope, and denies token reuse for another API or write operation.

## Production controls and evaluation

Use workload identity or a secret manager, short-lived tokens, audience and
scope restriction, rotation, redaction, secret scanning, and independent tool
authorization. Test secrets in context/memory/log fixtures, expired tokens,
wrong audience, tenant swap, and scope escalation. Measure exposure and
credential-misuse success as zero.

## References

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final)

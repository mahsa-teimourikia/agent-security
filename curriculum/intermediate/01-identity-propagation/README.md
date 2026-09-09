# Intermediate 01 — Identity Propagation: Delegation, Down-Scoping, and the Confused Deputy

## Course metadata
- **Level**: Intermediate
- **Prerequisites**: Beginner 01 (Authorization), Beginner 03 (Request Boundaries)
- **Time**: 45 minutes

## Learning objectives
- Distinguish between **Principal** (User) identity and **Workload** (Agent/Service) identity.
- Understand the difference between **Authentication**, **Delegation**, and **Authorization**.
- Identify and mitigate **Confused Deputy** vulnerabilities arising from ambient authority.
- Enforce secure multi-hop Identity Propagation through **Delegation Grants**.
- Implement **down-scoping**, **audience restriction**, and **tenant binding** for downstream requests.
- Track accurate end-to-end audit trails across service boundaries.

## Why identity propagation matters

In simple monolithic applications, resolving "who is acting" happens once at the front door. 

In agentic, multi-service architectures, a request often crosses several boundaries:
1. The **User (Alice)** talks to the **Research Agent**.
2. The **Research Agent** talks to the **Document Service**.
3. The **Document Service** talks to the **Storage Service**.

If downstream services only authenticate the *caller* (e.g., the Document Service authenticating to Storage), they lose the original context (Alice). If the Agent uses its own powerful infrastructure privileges to fulfill Alice's request, an attacker could trick the Agent into retrieving a document they don't own.

The central thesis of this course:
> **Propagate identity context, not ambient authority.**

## Principal vs Workload vs Delegate

Every request has at least two identities you must untangle:

- **Principal**: The end-user or human on whose behalf the action is being performed (e.g., Alice).
- **Workload Identity**: The software component making the request (e.g., `research-agent`).
- **Delegate**: When a workload is granted permission to act for a principal, it becomes the delegate.

*Subject*, *Actor*, and *Delegate* are heavily overloaded terms in IAM. In this lab, we use:
- **Principal** (End user)
- **Delegate** (Agent/Workload acting for the user)
- **DelegationGrant** (The bounded authority connecting them)

## Authentication vs Delegation vs Authorization

These are independent controls.
- **Authentication**: "This request really came from `research-agent`."
- **Delegation**: "`research-agent` has permission to perform THIS specific action on behalf of Alice."
- **Authorization**: "Given both identities, the grant, and the resource policies, may this operation execute?"

The agent's workload identity cannot replace the user's identity. 
The user's identity cannot authenticate the agent workload. 
The delegation grant connects them safely.

## Ambient Authority and the Confused Deputy

When an agent authenticates to a downstream service using its own service credentials (e.g., its broad service account), it uses **ambient authority**. 

If Alice asks the Research Agent to read `doc-secret`, and the Research Agent asks the Document Service using its own broad credentials, the Document Service will reply: *"Ah, the trusted Research Agent is asking for `doc-secret`. Allowed!"*

This is the **Confused Deputy** vulnerability. The agent was tricked into using its higher privileges to bypass Alice's restrictions.

## On-Behalf-Of Execution

To fix this, services must distinguish between two execution modes:
1. **Service Mode**: The service is doing its own background work (e.g., a scheduled cleanup job). It uses its own service credentials.
2. **Delegated Mode**: The service is acting on behalf of a user. It must use a **Delegation Grant**.

If a delegated request fails, it must **never** fall back to using service-level privileges.

## Delegation Grants

A Delegation Grant is a data structure (like an OAuth access token or a capability token) that answers:
- **Who** delegated the authority? (`principal_id`)
- **To whom**? (`delegate_id`)
- **For which service**? (`audience`)
- **For how long**? (`expires_at`)
- **For what actions/resources**? (`allowed_operations`, `allowed_resources`)

A correctly shaped grant is not enough; it must be trusted by an Issuer.

## Audience Restriction

A grant intended for the `document-service` must not be accepted by the `email-service`. 
Audience restriction (`grant.audience == receiving_service`) ensures that if a credential is leaked or intercepted, it cannot be reused against unintended services.

## Tenant Binding

Every layer must preserve the tenant identity. 
No amount of valid delegation within Tenant A (Acme) can ever authorize access to a resource owned by Tenant B (Globex).
`principal.tenant == delegate.tenant == grant.tenant == resource.tenant`

## Scope Attenuation (Down-Scoping)

Delegated authority must never exceed the principal's original authority.
If Alice can `read` and `comment`, but the current workflow only requires reading, the agent's grant should only permit `read`. 

## Multi-hop Identity Propagation

When the Document Service needs to call the Storage Service, it must not invent new, unrestricted authority. It must exchange its current grant for a new one intended for the Storage Service, ensuring that:
- Authority stays equal or shrinks (monotonic down-scoping).
- Authority **never** expands downstream.

## Expiry and Replay

Delegated authority must be time-bounded (`now < expires_at`). 
Bearer credentials (like tokens) mean *whoever possesses it can use it*. Production mitigations include short lifetimes, narrow scopes, and sender-constrained proof-of-possession.

## Audit and Attribution

An audit trail must capture *both* the principal and the delegate. 
Never log raw access tokens, secrets, or authorization headers in the clear. Audit the *identifiers* (e.g., `grant_id`), the decision, and the exact reasons.

## Architecture

### Secure Delegation vs Confused Deputy

```text
# VULNERABLE: Ambient Authority
Alice 
 ↓
Agent 
 ↓ (Broad Service Credential)
Document Service 
 ↓
SECRET DOCUMENT Leaked!

# SECURE: Identity Propagation
Alice
 │
 ├── Principal identity
 ↓
Research Agent
 │
 ├── Workload identity
 └── Delegated authority (Grant)
 ↓
Document Service
 │
 ├── verify principal & delegate
 ├── verify audience & scope
 ↓
Authorized resource only
```

## Guided Lab & Exercises

Launch the lab via the interactive notebook:
```bash
jupyter notebook curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb
```

## Production Upgrade Paths

While this lab uses a deterministic, in-memory `DelegationGrant` simulation, real-world systems use established protocols.

| Teaching abstraction | Production concept |
|---|---|
| `PrincipalRegistry` | IdP / IAM directory (Entra ID, Okta) |
| `WorkloadRegistry` | Workload identity / Kubernetes Service Accounts |
| `DelegationGrant` | OAuth 2.0 Access Token / JWT / Macaroons |
| Delegation Issuer | Authorization Server / Secure Token Service (STS) |
| Audience | OAuth `aud` claim / Resource indicators |
| Down-scoping | OAuth Scopes / Token Exchange (RFC 8693) |
| Multi-hop delegation | On-Behalf-Of (OBO) flows / Token Exchange |
| Resource Registry | Authoritative internal data service |
| Audit event | SIEM / Security telemetry (Splunk, Datadog) |

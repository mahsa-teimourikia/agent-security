# Intermediate 01 — Identity Propagation: Delegation, Down-Scoping, and the Confused Deputy

## Course metadata
- **Level**: Intermediate
- **Prerequisites**: Beginner 01 (Authorization), Beginner 03 (Request Boundaries)
- **Time**: 60 minutes

## Learning objectives
- Distinguish between **Principal** (User) identity and **Workload** (Agent/Service) identity.
- Understand the difference between **Identifier** and **Authentication**.
- Establish strict **Grant Issuance Trust Boundaries** using authoritative registries.
- Identify and mitigate **Confused Deputy** vulnerabilities arising from ambient authority.
- Enforce secure multi-hop Identity Propagation through **Token Exchange** and **Parent-Child Delegation**.
- Implement **monotonic down-scoping**, **audience restriction**, and **tenant binding** for downstream requests.
- Track accurate end-to-end audit trails across service boundaries without logging secrets.

## Why identity propagation matters

In simple monolithic applications, resolving "who is acting" happens once at the front door. 

In agentic, multi-service architectures, a request often crosses several boundaries:
1. The **User (Alice)** talks to the **Research Agent**.
2. The **Research Agent** talks to the **Document Service**.
3. The **Document Service** talks to the **Storage Service**.

If downstream services only authenticate the *caller* (e.g., the Document Service authenticating to Storage), they lose the original context (Alice). If the Agent uses its own powerful infrastructure privileges to fulfill Alice's request, an attacker could trick the Agent into retrieving a document they don't own.

The central thesis of this course:
> **Propagate identity context, not ambient authority.**

## Identifier vs Authentication

A critical mistake in distributed systems is treating a known string (an identifier) as proof of identity (authentication).

- **Identifier**: `caller_id = "document-service"`
- **Authentication evidence**: a provider-issued `AuthenticatedWorkload` object whose claims are derived from verified infrastructure state

An attacker who knows your internal architecture can easily construct a payload claiming to be `"document-service"`. Secure systems rely on infrastructure (like mTLS, SPIFFE/SPIRE, or Cloud Workload Identity) to authenticate the caller *before* the application logic runs.

In this simulation, `InfrastructureIdentityProvider` represents this trusted infrastructure context, and `ApplicationIdentityProvider` represents front-door user authentication (like Okta or Entra ID). Their `for_*` methods are test-fixture seams that stand in for trusted middleware injection; they are not request-facing login APIs. Verification uses canonical object identity so recreating the same public field values does not recreate authentication evidence.

## Principal vs Workload vs Delegate

Every request has at least two identities you must untangle:

- **Principal**: The end-user or human on whose behalf the action is being performed (e.g., Alice).
- **Workload Identity**: The software component making the request (e.g., `research-agent`).
- **Delegate**: When a workload is granted permission to act for a principal, it becomes the delegate.

*Subject*, *Actor*, and *Delegate* are heavily overloaded terms in IAM. In this lab, we use:
- **Principal** (End user)
- **Delegate** (Agent/Workload acting for the user)
- **DelegationGrant** (The bounded authority connecting them)

## Grant Issuance Trust Boundary

Delegation grants (like OAuth tokens) cannot be minted by arbitrary clients. If a caller could pass a customized `Principal` object into an issuer and receive a valid token, they could forge any authority they desire.

A secure issuer:
1. Accepts provider-verified principal and workload contexts, not caller-supplied identity strings.
2. Derives identifiers from those contexts and resolves authorization attributes against an **Authoritative Registry** (like Entra ID or Okta).
3. Ensures requested authority is a valid subset of the principal's true authority.

> **Principal object != authenticated principal**
> **workload ID != authenticated workload**
> **grant object != verified delegation**

## Authentication Context Substitution

A valid authentication context ID is not the same thing as a valid authentication. Because context IDs and identity claims can be copied, a secure system must verify provider-issued evidence and derive the trusted claims from it. Comparing caller-constructed values with a registry is not authentication.

If Bob logs in and receives `ctx-bob`, but then passes `principal_id=alice` along with his context, the system must reject it. The simulation also rejects a newly constructed `AuthenticatedPrincipal("bob", "ctx-bob")`: matching fields do not prove that trusted middleware issued that object.

## Token-Claim Analogy

In production, an authenticated session or signed workload token (e.g., JWTs, OIDC ID tokens, mTLS certificates, SPIFFE IDs, cloud workload credentials) binds identity claims *within* the signed credential. Applications should extract identity claims directly from the verified credential itself. 

Applications must not verify a valid credential from one identity but then trust identity fields supplied independently outside the token (e.g., in a separate HTTP header or JSON payload).

## Ambient Authority and the Confused Deputy

When an agent authenticates to a downstream service using its own service credentials (e.g., its broad service account), it uses **ambient authority**. 

If Alice asks the Research Agent to read `doc-secret`, and the Research Agent asks the Document Service using its own broad credentials, the Document Service will reply: *"Ah, the trusted Research Agent is asking for `doc-secret`. Allowed!"*

This is the **Confused Deputy** vulnerability. The agent was tricked into using its higher privileges to bypass Alice's restrictions.

## On-Behalf-Of Execution & No Fallback

To fix this, services must distinguish between two execution modes:
1. **Service work**: a trusted internal scheduler invokes a separate service-only entry point using infrastructure-authenticated workload identity plus a bounded, provider-issued service-job context.
2. **Delegated work**: a request-facing entry point acts on behalf of a user and always requires a **Delegation Grant**.

**CRITICAL INVARIANT:** If a delegated request fails (e.g., token is expired or unauthorized), the service must **never** fall back to using its ambient service-level privileges.

The execution mode must not be a request parameter. This lab therefore exposes separate `get_document(...)` and `run_service_read(...)` methods; the delegated method has no switch that can select service authority. The service-only path verifies both the calling workload and the job context, then enforces the job's operation and resource scope.

## Token Exchange and Parent-Child Delegation

When the Document Service needs to call the Storage Service, it must not send the original token intended for the Document Service. That would be a replay vulnerability.

Instead, the Document Service performs a **Token Exchange**:
1. It presents the original `parent_grant` and its own `AuthenticatedWorkload`.
2. The Issuer mints a `child_grant` specifically intended for the `storage-service`.

This creates a **Parent-Child Delegation** chain, preserving the original Principal while shifting the Delegate and Audience at each hop.

## Monotonic Scope Attenuation

Delegated authority must never expand downstream. During Token Exchange, the issuer enforces monotonic down-scoping:
- `child.allowed_operations ⊆ parent.allowed_operations`
- `child.allowed_resources ⊆ parent.allowed_resources`

## Monotonic Expiry

Time is also a scope. A child token cannot outlive its parent.
If a parent token has 5 minutes remaining, and a service requests a 60-minute downstream token, the issuer must either reject the request or **clamp** the expiry.

In this simulation: `child_expiry = min(requested_expiry, parent_expiry)`

## Audience Restriction & Tenant Binding

- **Audience Restriction**: A token minted for `document-service` must be rejected if presented to `storage-service`.
- **Tenant Binding**: Every layer must preserve the tenant. No amount of valid delegation within Tenant A (Acme) can authorize access to a resource owned by Tenant B (Globex).

## Audit and Attribution

An audit trail must capture *both* the principal and the delegate at every hop. 
Never log raw access tokens, secrets, or authorization headers in the clear. Audit the *identifiers* (e.g., `grant_id` and `parent_grant_id`), the decision, and the exact lifecycle state (`forwarded`, `accessed`, `blocked`).

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
 ├── Principal registry resolution
 ↓
Research Agent
 │
 ├── Authenticated workload context
 └── Delegated authority (Grant 1)
 ↓
Document Service
 │
 ├── verify principal & delegate
 ├── Token Exchange (Grant 1 → Grant 2)
 ├── down-scope audience & expiry
 ↓
Storage Service
 │
 ├── verify Grant 2
 ↓
Authorized resource only
```

## Guided Lab & Exercises

Launch the lab via the interactive notebook:
```bash
jupyter notebook curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb
```

The lab is credential-free and uses synthetic data. The identity-provider factories simulate trusted infrastructure and application middleware. Production code must validate signed or sender-constrained credentials at the network boundary rather than using Python object identity.

## Production Mapping

While this lab uses a deterministic, in-memory `DelegationGrant` simulation, real-world systems use established protocols. 

**Note:** This simulation is a *teaching analogue*. Real token exchange protocols have additional issuer, subject-token, actor-token, trust, cryptographic signing, and policy semantics not fully modeled here.

| Teaching abstraction | Production concept |
|---|---|
| `PRINCIPAL_REGISTRY` | User Directory Metadata |
| `ApplicationIdentityProvider` | Front-door IdP (Entra ID, Okta) / OIDC ID Token |
| `InfrastructureIdentityProvider` | mTLS, SPIFFE/SPIRE, Cloud Workload Identity |
| `DelegationGrant` | OAuth 2.0 Access Token / JWT / Macaroons |
| Delegation Issuer | Authorization Server / Secure Token Service (STS) |
| Audience | OAuth `aud` claim / Resource indicators |
| Down-scoping | OAuth Scopes / Token Exchange (RFC 8693) |
| Multi-hop delegation | On-Behalf-Of (OBO) flows / Token Exchange |
| Resource Registry | Authoritative internal data service |
| Audit event | SIEM / Security telemetry (Splunk, Datadog) |

## References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [SPIFFE overview](https://spiffe.io/docs/latest/spiffe-about/overview/)

## Checkpoint

An agent presents a valid token for `document-service` to `storage-service`.
Should storage accept it? No. Storage must validate that it is the intended
audience and require a separately issued, down-scoped grant for that hop.

Previous: [Beginner 03 — Secure Research Agent](../../beginner/03-secure-research-agent/README.md).

Next: [Intermediate 02 — MCP Gateway](../02-mcp-gateway/README.md).

Focused continuation: [roadmap I03 — Identity and Delegated Authority](../../roadmap/intermediate/03-agent-identity-and-delegated-authority/README.md).

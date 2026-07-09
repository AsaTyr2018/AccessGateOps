# Architecture

## Overview

AccessGate uses a lease-based access model. The AG-Server authorizes access centrally. Target servers enforce leases locally through an installed AG-Agent.

This avoids relying on the AG-Server for cleanup after a lease is issued. If the AG-Server is offline, the AG-Agent still has enough local state to expire and remove granted keys.

## Components

### AG-Server

The AG-Server is the central API and policy service.

Responsibilities:

- Authenticate client services.
- Authenticate target AG-Agents.
- Store target server registrations.
- Store allowed access policies.
- Create SSH access leases.
- Notify target AG-Agents when desired state changes.
- Receive status and audit events from AG-Agents.
- Expose operational views for active and expired leases.

The AG-Server should not be treated as a passive key-value store. It is the policy decision point for SSH access.

### AG-Agent

The AG-Agent runs on each managed Linux target server.

Responsibilities:

- Authenticate the AG-Server.
- Authenticate itself to the AG-Server.
- Receive desired-state change notifications.
- Fetch desired state from the AG-Server.
- Persist lease state locally.
- Install public keys into managed authorized-keys files.
- Remove expired keys without requiring the AG-Server.
- Remove revoked keys when instructed by the AG-Server.
- Send local audit events and health status back to the AG-Server.

### Bootstrap Service

The Bootstrap Service is an operator-triggered AG-Server component used to add new target servers.

Responsibilities:

- Accept temporary bootstrap connection data from the Ops Web UI.
- Connect to the target server over SSH.
- Install and configure AG-Agent.
- Exchange AG-Agent API credentials with the AG-Server.
- Start and verify the AG-Agent service.
- Report bootstrap status back to the Web UI.
- Discard bootstrap credentials after completion or failure.

The Bootstrap Service must not store root passwords, bootstrap private keys, or AG-Agent secrets in logs.

### Client Service

A client service is any system that needs temporary SSH access.

Examples:

- Portal
- MDSO
- Deployment tools
- Automation workers

The client service requests access without providing SSH key material. The AG-Server acts as the key master and generates a unique temporary key pair for each lease.

Client services and AI agents can request access through the AG-Server API. A request must state:

- Target server
- Requested access role
- Target Linux user if known
- Public key
- Justification
- Requested timeframe
- Optional source IP restriction

The AG-Server decides whether the request can be activated immediately or must wait for human approval.

For requests that require approval, the client receives a case ID. The client must call the AG-Server again with that case ID after approval. Only then does the AG-Server return the access material or activated lease details.

### Public Informer

The Public Informer is a read-only AG-Server API surface that explains how clients and AI agents should interact with AccessGate.

It can be queried without authentication and should only return generic process and API guidance:

- Supported API version
- Authentication methods
- Required fields for access requests
- Supported roles and timeframe rules
- Approval and case-claim process
- Public endpoint list
- Error code guide
- Example request payloads

It must never expose secrets, private keys, internal API credentials, registered target inventory, active lease data, case contents, requester identities, or AG-Agent details.

Authenticated clients can use a separate target address book endpoint. That endpoint is not public and returns only targets allowed by the requester's API key and policy.

### Web UI

The Web UI is a slim operator interface for reviewing and controlling leases.

Responsibilities:

- Show active, pending, expired, revoked, and failed leases.
- Revoke active leases manually.
- Approve unlimited serviceuser lease requests.
- Show request justification, requester identity, target server, role, and requested timeframe.
- Provide a direct audit trail for approval and revoke actions.
- Create and rotate API keys for users, services, and AI agents.
- Add target servers and start AG-Agent bootstrap jobs.

## Deployment URL Configuration

The AG-Server must not guess its externally reachable URL from the container or pod runtime. It should use explicit configuration.

Required setting:

```text
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

The Ops Login Link generator uses this value to print browser-ready links:

```text
https://accessgate.example.com/ops/agops_...
```

For Kubernetes or Docker maintenance scenarios without working certificates, AccessGate may run in local degraded mode:

```text
ACCESSGATE_TLS_MODE=disabled-local
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

or:

```text
ACCESSGATE_PUBLIC_URL=http://10.0.0.10:8080
```

The CLI should allow a one-time override:

```text
accessgate -opskey --operator operator --base-url http://10.0.0.10:8080
```

In Kubernetes, the link can be generated through `kubectl exec`:

```text
kubectl -n accessgate exec deploy/accessgate -- accessgate -opskey --operator operator
```

In Docker, the link can be generated through `docker exec`:

```text
docker exec accessgate accessgate -opskey --operator operator
```

Whoever can run these commands already has privileged access to the container runtime or cluster namespace. That runtime access becomes the root of trust for operator login link generation.

## Internal API Communication

The AG-Server and AG-Agents communicate through an internal API channel. The AG-Server does not need SSH master keys for target servers. The target AG-Agent is responsible for local SSH key enforcement.

The communication is intentionally bidirectional:

- The AG-Server can notify the AG-Agent that desired state changed.
- The AG-Agent calls the AG-Server to fetch desired state, register health, report lease state, report audit events, and request reconciliation.

Each direction has its own credential:

- The AG-Agent has an AG-Server-issued credential for AG-Agent-to-AG-Server requests.
- The AG-Server has an AG-Agent-issued or AG-Agent-specific credential for AG-Server-to-AG-Agent requests.

These credentials must be separate. Compromise of one direction should not automatically allow impersonation in the other direction.

API keys alone authenticate requests but do not fully prevent man-in-the-middle attacks. The internal API must also use TLS with strict certificate validation or signed requests with timestamp and nonce validation. A practical first version can use HTTPS plus pinned certificates and HMAC-signed request bodies.

The AG-Server is the internal trust anchor for AG-Agent communication. It issues or provisions AG-Agent certificate material during bootstrap and records the expected AG-Agent identity. Maintenance HTTP degraded mode for the operator/client surface must not disable AG-Agent trust verification.

## Internal Agent PKI

AccessGate owns an internal PKI dedicated only to AG-Agent communication. It is not a general network CA and must not expose certificate enrollment endpoints to the LAN or to requester clients.

Recommended hierarchy:

```text
AccessGate Internal Root CA
|-- AccessGate Agent Issuing CA
|   `-- one client certificate per AG-Agent
`-- AccessGate Server Issuing CA
    `-- AG-Server internal API certificate
```

The Root CA signs only issuing CAs. The Agent Issuing CA signs only agent client certificates. The Server Issuing CA signs only AG-Server certificates. This separation prevents one compromised leaf certificate from requiring a full tree rebuild.

Each AG-Agent certificate is bound to a single `agentId` and tracked by serial, fingerprint, issuer generation, validity window, and revocation state. The AG-Server must validate both the certificate chain and the exact expected agent identity. A valid certificate for `server-b` must not authenticate as `server-a`.

Agent certificate compromise is handled by revoking that single agent certificate and denying renewal. Other agents remain valid. Rebootstrap creates new local key material and a new certificate for the affected agent only.

Deleting a target server from the Web UI must revoke the agent certificate and disable the agent identity even if the target host is offline. The deleted agent may still exist on disk, but it can no longer authenticate to AccessGate.

## Key Master Model

The preferred default is AccessGate-owned lease key generation:

- The client does not submit SSH public keys.
- The AG-Server generates a unique SSH key pair for every lease.
- The AG-Server stores the generated public key and key fingerprint with the lease.
- The AG-Server returns the generated private key exactly once to the requester.
- The AG-Server never persists generated private keys after delivery.
- The AG-Agent receives only public keys and structured restrictions.
- Lost private-key delivery requires revoking the lease and requesting a new one.

This makes AccessGate the trust point for SSH lease material. It avoids accepting arbitrary requester-supplied authorized-keys content and lets AccessGate control key type, key comments, fingerprints, TTLs, restrictions, and audit records.

Client-provided public keys are not part of the v1 baseline. They may be considered later only behind explicit policy, strict key parsing, and injection-safe rendering.

## Lease Model

A lease should contain at least:

- Lease ID
- Lease version
- Lease generation
- Case ID for approval-bound requests
- Requester identity
- Target server ID
- Target Linux user
- Requested access role
- AccessGate-generated public key
- Public key fingerprint
- Key delivery mode, default `generated_once`
- Justification
- Requested timeframe
- Created timestamp
- Approved timestamp
- Expiration timestamp
- Approval requirement
- Approver identity
- Optional source IP restrictions
- Optional forced command
- Optional SSH restrictions
- Current state

`version` is incremented on every material lease change, such as TTL changes, role changes, restriction changes, approval state changes, revocation, or key updates.

`generation` is incremented when the lease enters a new lifecycle generation where stale events or commands must be distinguishable. Revocation should carry the current generation so AG-Server and AG-Agent can tell whether a revoke, expiry, or status event belongs to the current lease state.

Example state values:

- `pending`
- `pending_approval`
- `approved`
- `active`
- `expired`
- `revoked`
- `failed`

## Access Roles and Timeframes

AccessGate starts with two role classes:

- `normal`: temporary automation access with a maximum TTL of 1 hour.
- `serviceuser`: long-running or unlimited access for service integrations.

Normal access can be approved automatically when policy allows it. The maximum lease duration for normal access is 1 hour. Requests above this maximum must be rejected or reduced to the allowed maximum, depending on policy.

Unlimited serviceuser access is allowed by the model but must never be auto-activated. It requires explicit human approval in the Web UI. Until approval, the lease remains in `pending_approval` and is not installed on the target AG-Agent.

The AG-Server should still support bounded serviceuser leases. Whether bounded serviceuser leases require approval is a policy decision per client, target, and Linux user.

## Lease Versioning and Generation

Every lease is versioned. AG-Agents must persist the highest lease version they have applied.

Example:

```text
Lease active at version 6
Operator changes TTL
AG-Server increments lease to version 7
AG-Agent fetches desired state
AG-Agent sees local version 6 and desired version 7
AG-Agent applies version 7 and reports success
```

Versioning solves update ordering. If an AG-Agent receives or observes an older version after a newer one, it must ignore the stale version and report its current applied version.

Generation solves lifecycle ambiguity. A lease can expire locally while an operator also revokes it. Both events are valid, but the AG-Server can safely deduplicate and order them when each event carries:

- Lease ID
- Version
- Generation
- Event ID
- Event type

Revocation commands must include the lease version and generation they apply to. If an AG-Agent has already moved beyond that generation, it reports a no-op stale command result instead of applying old state.

## Rapid Lease Revocation

Lease revocation uses a hybrid fast path plus reconciliation fallback.

When a requester or operator revokes a lease:

1. AG-Server removes the lease from active state immediately.
2. AG-Server archives the lease as revoked.
3. AG-Server sends a signed rapid revoke notification to the target AG-Agent.
4. AG-Agent validates the AG-Server trust channel, timestamp, nonce, lease ID, version, and generation.
5. AG-Agent removes the matching AccessGate-managed key line immediately.
6. AG-Agent terminates active SSH sessions for the affected Linux user without killing unrelated processes owned by that user.
7. AG-Agent fetches desired state immediately after local removal.
8. Periodic desired-state polling remains the fallback if the rapid push is missed.

The rapid revoke endpoint is not a normal requester API. It is part of AG-Server-to-AG-Agent internal communication and must use the same agent trust model as retire/tombstone commands.

## Desired State Reconciliation

AccessGate should prefer desired state over imperative repair commands.

Instead of relying on `reconcile` as "do this action", the AG-Agent asks:

```text
What should my local AccessGate-managed SSH state look like?
```

The AG-Server answers with a desired state document containing the complete set of active leases for that AG-Agent, including versions and generations. Revoked, rejected, expired, and otherwise inactive leases are omitted. The AG-Agent compares desired state with its own AccessGate-managed local state and converges:

- Install missing desired leases.
- Update leases where desired version is newer.
- Remove local leases absent from desired state.
- Ignore stale desired versions older than local applied versions.
- Report the applied desired state version back to the AG-Server.

This makes recovery robust after missed pushes, AG-Agent restarts, AG-Server restarts, network splits, or manual local drift.

The AG-Agent must not modify user-defined SSH keys. Drift cleanup applies only to the AG-Agent's own managed lease list and managed authorized-keys files.

The AG-Server can still push notifications, but pushes should mean "desired state changed, fetch current desired state" rather than "blindly execute this one mutation".

## Agent Events

Every AG-Agent event must have a stable event ID.

Required event envelope fields:

- Event ID
- AG-Agent ID
- Lease ID if applicable
- Lease version if applicable
- Lease generation if applicable
- Event type
- Event timestamp
- Idempotency key

Example event types:

- `lease.installed`
- `lease.install.failed`
- `lease.updated`
- `lease.removed`
- `lease.expired`
- `lease.revoked`
- `desired_state.applied`
- `desired_state.failed`

The AG-Server must deduplicate events by event ID. Replaying the same event must be safe.

## Policy Engine

The policy model should evolve toward rule-based evaluation instead of a purely tabular allowlist.

A policy rule should be able to express:

- Requester identity, such as `portal`
- Target scope, such as one server, server group, or all servers
- Allowed Linux users
- Allowed roles
- Time windows
- Maximum TTL
- Required SSH restrictions
- Source network constraints
- Approval requirements
- Forced command requirements
- Concurrent lease limits

Example policy intent:

```text
Portal may access all servers as deploy
only between 09:00 and 17:00
for at most 30 minutes
without shell access
only from VLAN 30
```

Policy evaluation should return both a decision and the restrictions to enforce. The AG-Server should store the policy decision context with the lease for auditability.

## Rate Limiting and Quotas

AccessGate should enforce rate limits and lease quotas to prevent runaway automation and misconfiguration.

Examples:

- Max 20 active leases per requester.
- Max 100 API requests per requester per minute.
- Max 10 pending approval cases per requester.
- Max 5 generated private-key deliveries per requester per hour.
- Lower limits for public Informer endpoints per source IP.

Rate limit responses should be explicit and machine-readable. Limits should be part of policy so different clients can have different ceilings.

## Approval Cases

An approval case is created when a lease request cannot be activated immediately.

The first API response for an approval-bound request must contain:

- `state: pending_approval`
- `approvalRequired: true`
- `caseId`
- Human-readable status text
- Requested target, role, Linux user, and timeframe

The requester's automation flow must treat this as a paused workflow. It can poll or retry later with the case ID. Before approval, the AG-Server must not install the key on the target AG-Agent and must not hand out generated private key material.

After human approval, the requester calls the claim endpoint with the case ID. If the case is approved, the AG-Server activates the lease, coordinates installation through the target AG-Agent, and returns the final lease details. If the case is still pending, rejected, revoked, or expired, the AG-Server returns that state.

The claim response is the only moment where the generated private key may be returned for approval-bound leases. It must never be logged, persisted, or returned again.

## Target Server SSH Integration

The AG-Agent should avoid modifying user-managed SSH files directly.

Recommended `sshd_config` pattern:

```text
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys_accessgate
```

The AG-Agent only manages:

```text
/home/<user>/.ssh/authorized_keys_accessgate
```

This keeps AccessGate-managed keys separate from manually maintained access.

## High-Level Sequence

```text
Client Service -> AG-Server: request lease
AG-Server -> AG-Server: authenticate and authorize
AG-Server -> AG-Server: decide immediate activation or pending approval
AG-Server -> AG-Agent: notify desired state changed
AG-Agent -> AG-Server: fetch desired state
AG-Agent -> Local State: persist lease
AG-Agent -> SSH File: install public key
AG-Agent -> AG-Server: lease active through authenticated internal API
Client Service -> Target Server: SSH with private key
AG-Agent -> AG-Agent: expire lease at deadline
AG-Agent -> SSH File: remove public key
AG-Agent -> AG-Server: lease expired through authenticated internal API
```

## Unlimited Approval Sequence

```text
Client Service -> AG-Server: request unlimited serviceuser lease
AG-Server -> AG-Server: authenticate and policy-check request
AG-Server -> Lease Store: create pending_approval lease
AG-Server -> Client Service: return pending_approval with caseId
Human Approver -> Web UI: review justification and target
Human Approver -> AG-Server: approve lease
Client Service -> AG-Server: claim approved case with caseId
AG-Server -> AG-Agent: notify desired state changed
AG-Agent -> AG-Server: fetch desired state
AG-Agent -> Local State: persist lease
AG-Agent -> SSH File: install public key
AG-Agent -> AG-Server: lease active
AG-Server -> Client Service: return activated lease details or generated key material
```

## Failure Behavior

If the AG-Server is down:

- Existing active leases continue until local expiration.
- AG-Agents still remove expired keys.
- New leases cannot be issued unless a future offline mode is introduced.

If an AG-Agent is down:

- The AG-Server cannot activate new leases for that server.
- Existing keys remain as last written until the AG-Agent starts again.
- On startup, the AG-Agent must immediately remove expired leases before accepting new work.

If the target server reboots:

- The AG-Agent starts automatically.
- The AG-Agent loads local lease state.
- Expired leases are removed during startup reconciliation.

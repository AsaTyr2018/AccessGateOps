# Security Model

## Trust Boundaries

AccessGate has three major trust zones:

- AG-Server, the central authorization service.
- AG-Agents on managed target servers.
- Client services requesting access.

The AG-Server is highly sensitive because it can grant access. AG-Agents are also sensitive because they modify SSH authorization on target servers.

## Authentication

### Public Informer

The Public Informer endpoints are intentionally unauthenticated. They are meant to help automated clients and AI agents understand how to use AccessGate.

They must be strictly read-only and must not expose operational data.

Allowed content:

- API version and compatibility notes.
- Request schemas.
- Flow descriptions.
- Supported roles and TTL rules.
- Error code documentation.
- Generic examples.

Forbidden content:

- Private keys or generated key material.
- API keys or credential hints.
- Active leases.
- Approval case details.
- Target server inventory.
- Requester identities.
- AG-Agent internals.
- Policy contents that reveal infrastructure layout.

Public Informer endpoints should have rate limiting, structured caching, and generic responses. They should not provide a side channel for discovering managed infrastructure.

### Client to AG-Server

Initial options:

- API key per service.
- mTLS per service.
- OIDC client credentials.

Recommended path:

1. Start with API keys for simple internal deployment.
2. Add mTLS for stronger service identity.
3. Consider OIDC later if integration with an identity provider becomes useful.

API keys must be stored hashed in the AG-Server, never in plaintext.

#### API Key Issuance

API keys for users, services, and AI agents should be created only from an authenticated Ops Web UI session.

Rules:

- No default API keys.
- API keys are shown exactly once.
- API keys are stored hashed.
- Full API keys are never logged.
- API keys are bound to requester identity and policy groups.
- API keys can have expiration and rotation metadata.
- API keys can have rate limits and active lease quotas.
- Revocation is immediate.

The operator who created, rotated, or revoked a key must be recorded in audit logs.

#### Target Server Bootstrap

Target server onboarding may accept temporary SSH bootstrap credentials.

Supported methods:

- Username and password.
- Username and SSH private key.

Rules:

- Bootstrap credentials are write-only in the Web UI.
- Bootstrap credentials are never persisted.
- Bootstrap credentials are never logged.
- Bootstrap jobs are short-lived.
- Operator confirmation is required before a target is added and activated.
- AG-Agent is installed before the target server becomes active.
- AG-Agent credentials are exchanged during bootstrap.
- Target server remains disabled until AG-Agent health and authentication are verified.

Password onboarding is the simplest path for broad sysops use. SSH key onboarding is preferred where available. Both methods are privileged and operator-only.

For the initial bootstrap, the operator is the trust anchor for adding the target. AccessGate should display the target host key fingerprint and require explicit operator confirmation before bootstrap credentials are used and before the server can become active.

### Web UI Operator Access

The Web UI must not be publicly open and must not ship with a fixed default user or password.

Preferred initial model:

- Operator obtains a one-time Ops Login Link from the AG-Server console.
- Operator opens the link in a browser.
- AG-Server validates the embedded token and creates a short-lived operator session.

Example CLI:

```text
accessgate -opskey --operator operator --ttl 1h
```

Ops Login Link rules:

- Generated only from privileged local AG-Server context.
- One-time use.
- Default TTL: 1 hour.
- Maximum TTL enforced by AG-Server configuration.
- Embedded token stored hashed at rest.
- Full token never appears in logs.
- Token is carried in a path segment, for example `/ops/agops_...`, not in a query parameter.
- Successful login immediately redirects to `/ops` without the token in the URL.
- Token consumption must be atomic so only the first successful click can create a session.
- A consumed token must never create a second session.
- Unknown, expired, consumed, and inactive tokens should receive the same generic `503 Service Unavailable` response.
- Failed attempts are rate-limited.
- Successful and failed attempts are audited.
- Successful login creates an operator identity for approval/revoke actions.

This model intentionally avoids long-lived static Web UI credentials. It treats AG-Server console access as the root of operator trust.

#### Container and Kubernetes Operation

When AccessGate runs as a container or Kubernetes workload, the Ops Login Link should still be generated from a privileged runtime context instead of a permanent remote admin endpoint.

Examples:

```text
kubectl -n accessgate exec deploy/accessgate -- accessgate -opskey --operator operator
docker exec accessgate accessgate -opskey --operator operator
```

The AG-Server must use `ACCESSGATE_PUBLIC_URL` to produce the externally reachable link. The pod or container must not infer this from its internal IP.

Example:

```text
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

Runtime access through `kubectl exec` or `docker exec` is considered privileged. Kubernetes RBAC or Docker socket access controls become part of the operator trust boundary.

#### Local TLS Degraded Mode

Production mode should require HTTPS:

```text
ACCESSGATE_TLS_MODE=required
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

When local certificate infrastructure such as StepCA is unavailable during maintenance, AccessGate may allow an explicit degraded local mode:

```text
ACCESSGATE_TLS_MODE=disabled-local
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

or:

```text
ACCESSGATE_PUBLIC_URL=http://10.0.0.10:8080
```

Rules for degraded local mode:

- Must be explicitly configured.
- Must be limited to trusted local networks.
- Must not be exposed to the public internet.
- Must keep Ops Login Links one-time use.
- Must keep short TTLs.
- Must keep path-based tokens, never query tokens.
- Must redirect to `/ops` after token consumption.
- Should be visibly marked in logs and Web UI session context.
- Should be switched back to `ACCESSGATE_TLS_MODE=required` when certificates are restored.

Degraded local mode is a maintenance convenience, not the default security posture.

`ACCESSGATE_TLS_MODE=disabled-local` applies only to the externally exposed operator/client HTTP surface during maintenance. AG-Server-to-AG-Agent and AG-Agent-to-AG-Server communication must remain trusted and authenticated.

#### Web UI Activation Window

The Web UI should not be continuously exposed. It should only become available while at least one of these is true:

- An unexpired Ops Login Link exists.
- An operator session created from an Ops Login Link is active.

When neither condition is true, operator Web UI routes should be offline.

Acceptable offline behavior:

- Web UI listener is not bound.
- Web UI routes return `503 Service Unavailable`.
- Reverse proxy has no active route to the Web UI.

The Public Informer and authenticated service API can remain available according to their own exposure policies. The activation window applies specifically to operator Web UI routes.

Security requirements:

- Creating an Ops Login Link opens the Web UI activation window.
- Consuming an Ops Login Link keeps the Web UI available for the resulting session lifetime.
- Expiring the last Ops Login Link and last operator session closes the Web UI activation window.
- Inactive Web UI routes must not leak whether pending approvals or active leases exist.
- Activation and deactivation are audited.

### AG-Server to AG-Agent

AG-Server commands to AG-Agents must be authenticated cryptographically.

Recommended options:

- HTTPS with strict certificate validation and pinned AG-Agent identity.
- HMAC-signed requests using an AG-Agent-specific AG-Server-to-AG-Agent API key.
- Timestamp and nonce validation to prevent replay attacks.
- Optional later upgrade to mTLS.

The AG-Agent must reject unsigned or untrusted lease instructions.

The AG-Server is the internal trust anchor for managed AG-Agent certificates. During bootstrap, the AG-Server issues or provisions the AG-Agent certificate material and records the expected AG-Agent identity.

### AG-Agent to AG-Server

AG-Agents must also authenticate to the AG-Server. This is a separate trust direction and must use a separate credential.

Recommended options:

- HTTPS with strict certificate validation and pinned AG-Server identity.
- HMAC-signed requests using an AG-Server-issued AG-Agent-to-AG-Server API key.
- Timestamp and nonce validation to prevent replay attacks.
- Optional later upgrade to mTLS.

The AG-Agent-to-AG-Server key must not be accepted for AG-Server-to-AG-Agent commands. The AG-Server-to-AG-Agent key must not be accepted for AG-Agent-to-AG-Server event ingestion.

### Internal API Keys

For each AG-Agent, AccessGate should maintain two separate internal credentials:

- `ag_agent_to_ag_server_key`: used by the AG-Agent when calling the AG-Server.
- `ag_server_to_ag_agent_key`: used by the AG-Server when calling the AG-Agent.

Both keys should be random high-entropy secrets, stored hashed where possible, and rotatable independently.

Plain bearer API keys are simple but weaker. The preferred first implementation is HMAC request signing:

```text
X-AccessGate-Agent: server1
X-AccessGate-Timestamp: 2026-07-07T14:00:00Z
X-AccessGate-Nonce: random-value
X-AccessGate-Signature: hmac-sha256(...)
```

The signature should cover:

- HTTP method
- Request path
- Timestamp
- Nonce
- Request body hash

The receiver must reject stale timestamps, reused nonces, and invalid signatures.

### Internal Agent PKI

AccessGate should include a private, non-exposed PKI used only for AG-Agent communication. It must not provide a general-purpose CA API, ACME endpoint, or LAN-visible certificate enrollment surface.

Recommended hierarchy:

```text
AccessGate Internal Root CA
|-- AccessGate Agent Issuing CA
|   |-- AG-Agent server-a certificate
|   |-- AG-Agent server-b certificate
|   |-- AG-Agent server-c certificate
|   |-- AG-Agent server-d certificate
|   `-- AG-Agent gpu-worker-1 certificate
`-- AccessGate Server Issuing CA
    `-- AG-Server internal API certificate
```

The Root CA signs only issuing CAs. The Agent Issuing CA signs only AG-Agent client certificates. The Server Issuing CA signs only AG-Server certificates. Issuing CAs should use `patoperatorn=0` and purpose-limited key usages.

Agent certificates must be individually revocable. The AG-Server must not accept a client certificate only because it chains to the Agent Issuing CA. It must also verify:

- Agent ID in the certificate identity.
- Certificate serial number.
- Certificate fingerprint.
- Issuer ID and issuer generation.
- Not-before and not-after window.
- Local revocation state.

Suggested agent certificate identity:

```text
URI SAN: spiffe://accessgate.local/agent/<agent-id>
EKU: clientAuth
TTL: 7 to 30 days
```

Suggested AG-Server certificate identity:

```text
DNS SAN: accessgate-agent.internal
DNS SAN: accessgate.example.com
EKU: serverAuth
TTL: 30 to 90 days
```

The AG-State should track agent certificate records:

```text
agentId
certSerial
certFingerprint
issuerId
issuerGeneration
notBefore
notAfter
status: active | revoked | rotated | expired
revokedAt
revocationReason
lastSeenAt
```

Compromise of one AG-Agent must be handled by revoking only that agent certificate and refusing renewal for that serial/fingerprint. Other AG-Agent certificates must remain valid. This lets AccessGate cut off one compromised "finger" without replacing the whole certificate tree.

Certificate renewal should happen over an already authenticated AG-Agent channel before expiry. A revoked or expired certificate must not be renewable. Rebootstrap creates a new agent key pair, certificate serial, and fingerprint.

### Agent Removal and Certificate Revocation

Deleting a server from the Web UI must revoke the related AG-Agent identity before or during removal.

AccessGate distinguishes two removal modes:

- `clean_retire`: the AG-Agent is still trusted long enough to uninstall itself.
- `cut_off_finger`: AccessGate immediately revokes the AG-Agent identity and does not wait for remote cleanup.

Required behavior for `Servers -> Delete` clean retire:

1. Reject deletion if active leases still reference the target.
2. Mark the target as `retiring`.
3. Keep the AG-Agent identity valid only for retire traffic.
4. Send a signed `agent.retire` command with command ID, target agent ID, current generation, short TTL, and reason.
5. Require the AG-Agent to remove AccessGate-managed SSH keys.
6. Require the AG-Agent to remove local AccessGate certificates, private keys, CA bundles, shared secrets, config, and state.
7. Require the AG-Agent to schedule self-uninstall.
8. Accept `retire.completed` if it arrives.
9. Revoke the AG-Agent certificate serial/fingerprint.
10. Revoke or rotate the AG-Agent shared secret.
11. Remove or archive the target inventory entry.
12. Write audit events for target deletion and certificate revocation.

Required behavior for `cut_off_finger`:

1. While the current AG-Server trust is still valid, send one final signed `agent.tombstone` command with command ID, agent ID, certificate serial/fingerprint, issuer generation, agent generation, short TTL, and reason.
2. Give the AG-Agent only a very short grace period to accept and self-destroy.
3. Immediately revoke the AG-Agent certificate serial/fingerprint.
4. Immediately revoke or rotate the AG-Agent shared secret.
5. Stop accepting all mTLS/HMAC traffic from that agent identity.
6. Archive the target as `removed_tombstone_acknowledged` if an acknowledgement arrived, otherwise `removed_remote_unconfirmed`.
7. Do not wait for remote uninstall confirmation beyond the tombstone grace period.
8. Write audit events for emergency removal and certificate revocation.

If the target server is offline, certificate revocation must still complete locally on the AG-Server. The AG-Agent may remain installed on disk, but it is cryptographically dead to AccessGate.

`agent.tombstone` is the final trusted command before revocation. It is never sent after revocation and must not delay local revocation beyond its short grace period. A compliant AG-Agent must remove AccessGate-managed SSH keys, local AccessGate certificates, private keys, CA bundles, shared secrets, config, state, unit, and binary.

### MITM Protection

Mutual API keys help identify both sides, but they are not sufficient by themselves to prevent man-in-the-middle attacks if traffic can be intercepted or replayed.

Required protections:

- TLS for all internal API communication.
- No disabled certificate validation.
- Certificate pinning or a private AccessGate-internal CA anchored at the AG-Server.
- HMAC signatures over request bodies.
- Short timestamp validity windows.
- Nonce replay cache.

This gives defense in depth without requiring a full SSH CA model.

## Authorization

Policies should answer:

- Which client service may access which target server?
- Which target Linux user may be used?
- Which access profile may be used, such as `normal` or `elevated`?
- What maximum TTL is allowed?
- Which source IPs are allowed?
- Is a forced command required?
- Are port forwarding, SSH agent forwarding, PTY, or X11 forwarding allowed?
- Which time windows are allowed?
- Which source networks are allowed?
- Which concurrent lease quotas apply?
- Which request rate limits apply?

Default policy should be deny-all.

Policies should be rule-based rather than only tabular. A rule can match requester, target scope, Linux user or access profile, role, time window, source network, and requested duration, then return an allow/deny decision plus enforced restrictions.

Example:

```text
requester=portal
target=*
linuxUser=deploy
timeWindow=09:00-17:00
maxTtl=30m
sourceNetwork=VLAN30
pty=false
forcedCommand=/usr/local/bin/accessgate-command-wrapper
```

The policy decision context should be stored with the lease for auditing.

For AI agent access, the preferred v1 abstraction is an access profile instead of a free-form Linux username:

```text
accessProfile=normal   -> group=accessgate-normal
accessProfile=elevated -> group=accessgate-elevated
```

The target bootstrap process creates these groups and their local rights. The AG-Agent may only manage group membership for explicitly configured AccessGate-owned groups, normally those with the `accessgate-` prefix. This prevents a policy or desired-state bug from silently placing generated users into broad local privilege groups.

## Rate Limiting

Rate limiting protects AccessGate from loops, broken automation, and accidental broad access requests.

Recommended limits:

- Requests per requester per minute.
- Active leases per requester.
- Pending approval cases per requester.
- Generated-key claims per requester per hour.
- Public Informer requests per source IP.

Rate limit decisions should be explicit in API responses and audit logs.

## SSH Restrictions

AccessGate-managed keys should be written with restrictive options wherever possible.

Example:

```text
from="10.0.0.5",no-agent-forwarding,no-X11-forwarding,no-pty,no-port-forwarding ssh-ed25519 AAAA... accessgate:lease=<id>:requester=<name>:expires=<timestamp>
```

For command-specific automation:

```text
command="/usr/local/bin/accessgate-command-wrapper <lease-id>",no-agent-forwarding,no-X11-forwarding,no-pty,no-port-forwarding ssh-ed25519 AAAA...
```

## Secret Handling

Preferred model:

- The AG-Server is the SSH lease key master.
- Clients do not submit SSH public keys for v1 leases.
- The AG-Server generates a unique key pair per lease.
- The AG-Server stores only the public key, key fingerprint, and lease metadata.
- The AG-Server returns the private key exactly once to the requester.
- The AG-Server does not persist the private key after delivery.
- The response must never be logged.
- AG-Agents only receive public keys and structured restrictions.

This concentrates key generation in AccessGate and makes it the trust point for lease material. The extra risk is private-key handling during one-time delivery, so generated private keys require strict response redaction, audit coverage, rate limits, and immediate memory cleanup after delivery.

Client-provided public keys are not part of the v1 baseline. If added later, they require strict key parsing and must never allow raw authorized-keys line injection.

## AG-Agent Privileges

The AG-Agent needs enough privilege to manage SSH access for allowed users.

Possible models:

- Run as root and manage files directly.
- Run as a restricted service user with narrowly scoped sudo rules.

Root is operationally simpler. A sudo-based model is safer but more complex.

If running as root, hardening is important:

- Minimal filesystem access.
- Strict config permissions.
- systemd sandboxing where possible.
- No shell command construction from untrusted input.
- Atomic file writes.

## Audit Requirements

The AG-Server should log:

- Client authentication attempts.
- Lease requests.
- Policy decisions.
- Lease activation result.
- Lease revocation.
- Lease expiration events from AG-Agents.

The AG-Agent should log:

- Lease received.
- Lease installed.
- Lease removed.
- Startup reconciliation.
- Authentication failures.
- Local file write failures.

Audit logs should include lease IDs but must not contain private keys or full secrets.

AG-Agent events must include event IDs so duplicate delivery can be detected. Audit storage should keep event IDs, lease IDs, lease versions, and lease generations together.

## Main Risks

### AG-Server Compromise

Risk: attacker can issue access leases.

Mitigations:

- Strong auth for AG-Server admin access.
- Strict network exposure.
- mTLS or signed AG-Agent commands.
- Short TTL limits.
- Audit logs.
- Optional manual approval for privileged targets.
- Per-AG-Agent AG-Server-to-AG-Agent keys with independent rotation.

### AG-Agent Compromise

Risk: attacker can modify local SSH access on that target.

Mitigations:

- Limit AG-Agent network exposure.
- Verify AG-Server strictly.
- Keep AG-Agent small.
- Use systemd hardening.
- Monitor managed authorized-keys files.
- Keep AG-Agent-to-AG-Server and AG-Server-to-AG-Agent keys separate.

### Leaked Client Private Key

Risk: attacker can use an active lease until expiration.

Mitigations:

- Short TTL.
- Source IP restrictions.
- Requester-specific policies.
- Immediate revoke API.

### Cleanup Failure

Risk: expired keys remain.

Mitigations:

- Local lease state.
- AG-Agent startup reconciliation.
- Periodic expiration loop.
- Managed authorized-keys file can be regenerated from state.

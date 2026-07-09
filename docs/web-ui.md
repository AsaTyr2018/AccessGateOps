# Web UI

## Purpose

The AccessGate Web UI is a slim, dark, direct operator interface for lease visibility and human approval.

It is not a marketing page and not a general dashboard. The first screen should be the operational lease view.

## Core Views

### Leases

The main view lists leases with fast filtering.

Columns:

- State
- Case ID
- Requester
- Target server
- Linux user
- Role
- Timeframe
- Created time
- Expiration time
- Reason
- Actions

Primary states:

- `pending_approval`
- `approved`
- `active`
- `expired`
- `revoked`
- `failed`

Primary actions:

- Revoke active lease
- Approve pending unlimited serviceuser lease
- Inspect details

### Pending Approval

This view focuses on leases that require human action.

Each item should show:

- Case ID
- Requester identity
- Target server
- Linux user
- Requested role
- Public key fingerprint
- Source IP restriction
- Justification
- Requested timeframe
- Policy result

Approval must be explicit. Unlimited serviceuser leases must not be activated through bulk auto-approval.

After approval, the case remains visible as approved. The requesting client service or AI agent must claim the case through the API before key material or final activated lease details are returned.

### Lease Detail

The detail view shows the full audit context:

- Lease ID
- Case ID
- Request payload summary
- Requester authentication identity
- Target AG-Agent
- Current state
- State transitions
- Approval identity
- Revoke identity
- AG-Agent install status
- AG-Agent remove status

The UI must never display generated lease private keys. Public keys may be shown as fingerprints by default, with full public key reveal as an explicit secondary action.

### API Keys

The Web UI should provide an operator-only API key management view.

Supported actions:

- Create API key for user, service, or AI agent.
- Bind requester to policy groups.
- Set rate limits and active lease quotas.
- Set expiration or rotation interval.
- Revoke API key.
- Rotate API key.
- View key metadata and audit history.

API keys are shown exactly once after creation and are never shown again.

The full key must not appear in logs, tables, audit details, screenshots, or browser history.

### Servers and AG-Agents

The Web UI should provide an operator-only server onboarding view.

Supported actions:

- Add target server by hostname or IP.
- Select bootstrap authentication method: password or SSH key.
- Provide temporary bootstrap SSH credentials.
- Start AG-Agent install.
- Watch bootstrap status.
- Verify AG-Agent health.
- Mark target server active only after AG-Agent verification.
- Re-run bootstrap or repair failed installs.
- Delete target server and revoke the AG-Agent identity.

The Web UI must treat bootstrap credentials as write-only secrets. They should be used only by the bootstrap job and never displayed again.

The Web UI should present both bootstrap methods clearly:

- Password mode: host, port, username, password.
- SSH key mode: host, port, username, private key, optional passphrase.

Password mode is the simplest path for broad sysops use. SSH key mode should be recommended when available.

Delete behavior must be explicit and destructive:

- Reject delete while active leases still reference the target.
- Offer `Clean Retire` for normal cooperative removal.
- Offer `Cut Off Finger` for emergency or non-cooperative removal.
- Revoke the AG-Agent certificate serial/fingerprint.
- Revoke or rotate the AG-Agent shared secret.
- Stop accepting mTLS/HMAC traffic from that agent identity.
- Archive the target record and write audit events.

`Clean Retire` keeps the AG-Agent identity valid only for retire traffic, sends a signed `agent.retire` command, lets the AG-Agent remove AccessGate-managed SSH keys, delete local certificates/private keys/CA bundles/secrets/config/state, and uninstall itself before certificate revocation.

`Cut Off Finger` sends one final signed `agent.tombstone` command while trust is still valid, waits only a very short grace period, then revokes the certificate and shared secret immediately. A compliant AG-Agent uses `agent.tombstone` to delete AccessGate-managed SSH keys, certificates, private keys, CA bundles, secrets, config, state, unit, and binary. The Web UI must not wait for remote uninstall confirmation beyond the tombstone grace period.

If the host is offline, the Web UI should still complete local certificate revocation and show that the remote uninstall was not confirmed. From AccessGate's perspective, the agent is dead once its identity is revoked.

## Visual Direction

- Dark theme.
- Compact table-first layout.
- No decorative hero section.
- Minimal chrome.
- Clear state colors.
- Direct action buttons.
- Dense but readable spacing.

Suggested state colors:

- `pending_approval`: amber
- `approved`: blue
- `active`: green
- `expired`: muted gray
- `revoked`: red
- `failed`: red or magenta

## Approval Rules

Normal access:

- Maximum TTL: 1 hour.
- Can be auto-approved if policy allows.
- Does not require human approval by default.

Serviceuser access:

- Bounded serviceuser leases are policy-controlled.
- Unlimited serviceuser leases require human approval.
- Unlimited leases stay in `pending_approval` until approved.
- Rejected or revoked leases must not remain installed on AG-Agents.

## Operator Actions

### Approve Unlimited Lease

Approving an unlimited serviceuser lease:

1. Records the operator identity.
2. Records an approval timestamp.
3. Records an optional approval reason.
4. Changes approval state from `pending_approval` to `approved`.
5. Waits for the requesting client service or AI agent to claim the case.
6. Activates the lease and notifies the target AG-Agent that desired state changed during claim.

### Revoke Lease

Revoking a lease:

1. Records the operator identity.
2. Records a revoke timestamp.
3. Changes lease state to `revoked`.
4. Notifies the target AG-Agent that desired state changed.
5. Keeps the audit record permanently.

Revocation should be available from the list and detail views.

### Create API Key

Creating an API key:

1. Records the operator identity.
2. Creates requester metadata.
3. Binds policy groups and rate limits.
4. Generates a high-entropy API key.
5. Stores only the key hash.
6. Displays the full API key exactly once.

### Add Target Server

Adding a target server:

1. Records the operator identity.
2. Creates a pending target server record.
3. Starts a bootstrap job with temporary SSH credentials.
4. Installs AG-Agent on the target.
5. Exchanges AG-Agent credentials.
6. Verifies AG-Agent health.
7. Marks the server active.
8. Discards bootstrap credentials.

## Authentication

The Web UI must require operator authentication and must not be open by default.

AccessGate should not ship with a fixed default username and password. The preferred initial operator access model is a console-issued one-time Ops Login Link.

Unlimited approvals must require an operator identity. Anonymous or service-token approvals are not allowed.

## Ops Login Link

An operator with console access to the AG-Server can request a temporary Web UI login link:

```text
accessgate -opskey
```

The command returns a one-time login link with a default TTL of 1 hour. The secret token is embedded in the link and should not be displayed as a separate manual key by default.

Example:

```text
AccessGate Ops Login
Expires: 2026-07-07T15:00:00Z
Open once: https://accessgate.local/ops/agops_...
```

The operator opens the link. If valid, AccessGate consumes the token and creates a short-lived operator session.

The login token should be carried as a path segment rather than a query parameter. This avoids query-string scraping from browser history, proxy logs, analytics tooling, and accidental referrer leakage. After successful token consumption, AccessGate should immediately redirect to `/ops` without the token in the URL.

Required behavior:

- Ops Login Links are one-time use.
- Ops Login Links expire after 1 hour by default.
- Ops Login Links are generated only from the AG-Server console or an equivalent privileged local CLI context.
- Link tokens are stored hashed server-side.
- Full link tokens are never logged.
- Failed link-token attempts are rate-limited and audited.
- Successful use records operator label, source IP, user agent, creation time, and use time.
- Operator sessions created from Ops Login Links expire independently and should be short-lived.
- The link token is only a bootstrap credential. After first successful use, only the operator session remains valid.
- Clicking the same link a second time must not create a new session.

The CLI should allow an operator label for audit clarity:

```text
accessgate -opskey --operator operator --ttl 1h
```

TTL may be configurable but should default to 1 hour and should have a maximum configured by AG-Server policy.

The AG-Server should use `ACCESSGATE_PUBLIC_URL` to build the link:

```text
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

In Kubernetes:

```text
kubectl -n accessgate exec deploy/accessgate -- accessgate -opskey --operator operator
```

In Docker:

```text
docker exec accessgate accessgate -opskey --operator operator
```

If TLS is temporarily unavailable during maintenance, the AG-Server may run in explicit local degraded mode:

```text
ACCESSGATE_TLS_MODE=disabled-local
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
```

The generated link then uses `http://`. This is only acceptable on trusted local networks and should be returned to HTTPS when certificates are restored.

## One-Time Consumption

Ops Login Links must be consumed atomically.

On first successful request to:

```text
https://accessgate.local/ops/agops_...
```

AccessGate must:

1. Verify the token hash exists.
2. Verify the token is not expired.
3. Verify the token has not already been consumed.
4. Mark the token as consumed in the same atomic operation.
5. Create a short-lived operator session.
6. Set the session cookie.
7. Redirect to `/ops` without the token in the URL.

If the same link is clicked again, AccessGate must not create another session. It should return the same generic inactive response used for invalid, expired, consumed, or inactive Web UI routes.

Recommended response for second click, invalid token, expired token, or consumed token:

```text
503 Service Unavailable
```

The response must not reveal whether the token was valid, expired, consumed, or unknown.

The operator who consumed the token first can continue working through the issued session cookie until the session expires.

## Web UI Activation Window

The Web UI should be coupled to Ops Login Link activity. If there is no active Ops Login Link and no active operator session, the Web UI should be offline.

This means:

- By default, the Web UI is not reachable.
- Creating an Ops Login Link opens a temporary Web UI activation window.
- The activation window lasts until the link token expires or is consumed.
- If the link token is consumed, the Web UI remains available while the resulting operator session is active.
- When the last active Ops Login Link and last active operator session expire, the Web UI shuts down or stops serving operator routes.

Possible implementation modes:

- The AG-Server keeps the Web UI listener disabled until an Ops Login Link exists.
- The listener stays bound, but Web UI routes return `503 Service Unavailable` while inactive.
- A reverse proxy only routes to the Web UI while an activation flag exists.

Preferred first implementation:

- Keep the AG-Server process running.
- Keep API and Public Informer endpoints available as configured.
- Gate only Web UI operator routes behind an `ops_ui_active` state.
- Return a minimal `503` response for inactive Web UI routes.
- Do not reveal whether pending approvals exist while the Web UI is inactive.

The Ops Link command should print the activation status:

```text
AccessGate Ops Login
Expires: 2026-07-07T15:00:00Z
Web UI: active until 2026-07-07T15:00:00Z
Open once: https://accessgate.local/ops/agops_...
```

## Ops Login Link Threat Model

The Ops Login Link model assumes that console access to the AG-Server is already privileged. It avoids static Web UI passwords and reduces the value of leaked old credentials.

Important limits:

- An attacker with AG-Server console access can issue an Ops Login Link.
- Ops Login Links must therefore be treated as privileged break-glass credentials.
- The Web UI should still be network-restricted to trusted management networks where possible.
- HTTPS is required for Web UI login and sessions except during explicitly configured `ACCESSGATE_TLS_MODE=disabled-local` maintenance mode.
- Session cookies must be `HttpOnly`, `Secure`, and `SameSite=Strict` where practical.
- Offline Web UI mode reduces the exposed attack surface but does not replace HTTPS, route authorization, audit logging, or network restrictions.

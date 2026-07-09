# API Draft

This is an early planning draft, not a final contract.

## Public Informer

The Public Informer is a read-only API surface for humans, automation services, and AI agents. It explains how to talk to AccessGate without requiring authentication.

Public Informer endpoints must not return secrets, target inventory, active leases, approval case details, requester identities, or AG-Agent internals.

### Get Informer Overview

```http
GET /v1/informer
```

Response:

```json
{
  "service": "AccessGate",
  "apiVersion": "v1",
  "purpose": "Request and manage time-limited SSH access leases.",
  "authRequiredForAccessRequests": true,
  "publicEndpoints": [
    "GET /v1/informer",
    "GET /v1/informer/agent-contract",
    "GET /v1/informer/process",
    "GET /v1/informer/schema",
    "GET /v1/informer/errors"
  ],
  "authenticatedEndpoints": [
    "POST /v1/leases",
    "POST /v1/access-cases/{caseId}/claim",
    "GET /v1/targets",
    "GET /v1/leases/{leaseId}",
    "POST /v1/leases/{leaseId}/revoke"
  ],
  "roles": [
    {
      "name": "normal",
      "description": "Temporary automation access.",
      "maxTtlSeconds": 3600,
      "humanApprovalRequired": false
    },
    {
      "name": "serviceuser",
      "description": "Long-running service integration access.",
      "maxTtlSeconds": null,
      "humanApprovalRequiredForUnlimited": true
    }
  ],
  "accessProfiles": ["normal", "elevated"],
  "agentContract": "GET /v1/informer/agent-contract",
  "recommendedFlow": "Call POST /v1/leases with target, role, accessProfile, timeframe, and reason. AccessGate maps the profile to an AccessGate-owned local user, generates a unique lease key pair, and returns private key material exactly once. If pending_approval is returned, store caseId and later call POST /v1/access-cases/{caseId}/claim."
}
```

### Get Agent Contract

```http
GET /v1/informer/agent-contract
```

Single machine-readable contract for AI agents. It includes authentication rules, endpoint lists, access profiles, request and response schemas, full lease examples, SSH key handling, retry/propagation guidance, cleanup rules, and error recovery actions.

### Get Process Guide

```http
GET /v1/informer/process
```

Response:

```json
{
  "normalAccess": [
    "Submit role=normal and timeframe.type=duration.",
    "Keep timeframe.seconds at or below 3600.",
    "Receive the generated private key exactly once when state=active.",
    "Use the returned private key to connect.",
    "Stop using the lease before expiresAt."
  ],
  "normalProfile": [
    "Submit accessProfile=normal for a managed AccessGate user without sudo.",
    "The AG-Agent maps this profile to accessgate-normal and the accessgate-normal group."
  ],
  "elevatedProfile": [
    "Submit accessProfile=elevated for a managed AccessGate user with passwordless sudo.",
    "The AG-Agent maps this profile to accessgate-elevated and the accessgate-elevated group."
  ],
  "unlimitedServiceuserAccess": [
    "Submit role=serviceuser and timeframe.type=unlimited.",
    "Store the returned caseId when state=pending_approval.",
    "Wait for human approval in the Web UI.",
    "Call POST /v1/access-cases/{caseId}/claim.",
    "Receive generated private key material exactly once after claim succeeds."
  ],
  "requiredFields": [
    "target",
    "role",
    "accessProfile",
    "timeframe",
    "reason"
  ]
}
```

### Get Request Schema

```http
GET /v1/informer/schema
```

Response:

```json
{
  "createLease": {
    "method": "POST",
    "path": "/v1/leases",
    "authentication": "Bearer client API key",
    "requiredFields": {
      "target": "string",
      "role": "normal | serviceuser",
      "accessProfile": "normal | elevated",
      "timeframe": {
        "type": "duration | unlimited",
        "seconds": "number, required when type=duration"
      },
      "reason": "string"
    },
    "derivedFields": {
      "linuxUser": "AccessGate-owned user selected from accessProfile"
    },
    "keyDelivery": {
      "mode": "generated_once",
      "notes": "AccessGate generates the lease key pair. The private key is returned only once, immediately for active leases or after approval for approval-bound leases."
    }
  }
}
```

### Get Error Guide

```http
GET /v1/informer/errors
```

Response:

```json
{
  "errors": [
    {
      "code": "authentication_required",
      "meaning": "The endpoint requires a valid client or operator credential."
    },
    {
      "code": "policy_denied",
      "meaning": "The requester is not allowed to create this lease."
    },
    {
      "code": "approval_required",
      "meaning": "The request created an approval case and must be approved by a human."
    },
    {
      "code": "case_pending",
      "meaning": "The approval case has not been approved yet."
    },
    {
      "code": "case_not_claimable",
      "meaning": "The case is rejected, revoked, expired, already claimed, or belongs to another requester."
    },
    {
      "code": "ttl_too_long",
      "meaning": "The requested normal access duration is above the 1 hour maximum."
    },
    {
      "code": "rate_limited",
      "meaning": "The requester exceeded a configured request rate or concurrent lease quota."
    },
    {
      "code": "stale_version",
      "meaning": "The request references an older lease version or generation."
    }
  ]
}
```

## Web UI Operator Auth

The Web UI uses console-issued one-time Ops Login Links instead of a fixed username/password.

The key itself is created outside the HTTP API by a privileged local CLI command:

```text
accessgate -opskey --operator operator --ttl 1h
```

The CLI output contains a one-time login link with an embedded token. The AG-Server stores only a token hash and metadata.

The CLI builds the link from `ACCESSGATE_PUBLIC_URL`.

Examples:

```text
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
ACCESSGATE_PUBLIC_URL=https://accessgate.example.com
ACCESSGATE_PUBLIC_URL=http://10.0.0.10:8080
```

The CLI should support an explicit override:

```text
accessgate -opskey --operator operator --base-url http://10.0.0.10:8080
```

For Kubernetes:

```text
kubectl -n accessgate exec deploy/accessgate -- accessgate -opskey --operator operator
```

Creating an Ops Login Link also opens a temporary Web UI activation window. If no unexpired Ops Login Link and no active operator session exist, Web UI operator routes should be offline.

### Consume Ops Login Link

```http
GET /ops/{one-time-token}
```

Successful response:

```json
{
  "sessionId": "ops_sess_01J2...",
  "operator": "operator",
  "expiresAt": "2026-07-07T15:00:00Z"
}
```

Alternative JSON exchange endpoint for non-browser clients:

```http
POST /v1/ops/session
Content-Type: application/json
```

Request:

```json
{
  "token": "agops_..."
}
```

Required behavior:

- The link token is invalidated immediately after successful use.
- After successful token use, the browser is redirected to `/ops` without the token in the URL.
- The Web UI remains active for the created operator session lifetime.
- Expired or already-used link tokens are rejected.
- Failed attempts are rate-limited by source IP and key fingerprint prefix.
- Full link tokens are never logged.
- The response should set an `HttpOnly`, `Secure`, `SameSite=Strict` session cookie for browser use.
- Token consumption must be atomic. Exactly one request can turn a valid token into an operator session.
- A second click on the same link must not create another session.

The token must not be placed in a query parameter. The preferred link format is:

```text
https://accessgate.local/ops/agops_...
```

Atomic consume sketch:

```sql
UPDATE ops_login_links
SET consumed_at = now()
WHERE token_hash = ?
  AND consumed_at IS NULL
  AND expires_at > now();
```

Only if exactly one row is updated may the AG-Server create an operator session.

Second clicks, consumed tokens, expired tokens, unknown tokens, and inactive Web UI state should all use the same generic response.

### Web UI Inactive Response

When no Ops Login Link and no operator session are active, Web UI operator routes should not serve the panel.

```http
GET /ops
```

Response:

```json
{
  "error": {
    "code": "ops_ui_inactive",
    "message": "Operator Web UI is not active"
  }
}
```

Recommended status code:

```text
503 Service Unavailable
```

The response must not reveal pending approvals, active leases, target names, or operator metadata.

The same response shape should be used for:

- Unknown Ops Login Link token.
- Expired Ops Login Link token.
- Already consumed Ops Login Link token.
- Web UI inactive state.

### Get Current Operator Session

```http
GET /v1/ops/session
Cookie: ag_ops_session=<session>
```

Response:

```json
{
  "operator": "operator",
  "expiresAt": "2026-07-07T15:00:00Z",
  "permissions": [
    "lease.approve",
    "lease.revoke",
    "lease.read"
  ]
}
```

### End Operator Session

```http
DELETE /v1/ops/session
Cookie: ag_ops_session=<session>
```

Response:

```json
{
  "state": "ended"
}
```

## Client to AG-Server

### List Allowed Targets

AccessGate should expose an authenticated target address book for clients, users, services, and AI agents.

```http
GET /v1/targets
Authorization: Bearer <client-api-key>
```

Response:

```json
{
  "targets": [
    {
      "target": "server1",
      "displayName": "server1",
      "host": "10.0.0.20",
      "allowedRoles": ["normal"],
      "allowedAccessProfiles": ["normal", "elevated"],
      "maxTtlSeconds": 3600
    }
  ]
}
```

The response is policy-filtered for the authenticated requester. It must not expose targets that the requester cannot use.

### Create Lease

```http
POST /v1/leases
Authorization: Bearer <client-api-key>
Content-Type: application/json
```

Request:

```json
{
  "target": "server1",
  "role": "normal",
  "accessProfile": "normal",
  "timeframe": {
    "type": "duration",
    "seconds": 1800
  },
  "sourceIp": "10.0.0.5",
  "restrictions": {
    "pty": false,
    "agentForwarding": false,
    "x11Forwarding": false,
    "portForwarding": false
  },
  "reason": "portal job 123"
}
```

Response:

```json
{
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 1,
  "generation": 1,
  "state": "active",
  "approvalRequired": false,
  "target": "server1",
  "host": "10.0.0.20",
  "accessProfile": "normal",
  "linuxUser": "accessgate-normal",
  "expiresAt": "2026-07-07T14:30:00Z",
  "keyDelivery": "generated_once",
  "keyFingerprint": "SHA256:...",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----..."
}
```

Normal access is capped at 1 hour. For active leases, the generated private key is returned exactly once in the successful create response. If the response is lost, the requester must revoke the lease and request a new one.

A request for unlimited serviceuser access returns `pending_approval` and is not installed on the target AG-Agent until approved by a human operator.

Example unlimited request:

```json
{
  "target": "server1",
  "role": "serviceuser",
  "accessProfile": "elevated",
  "timeframe": {
    "type": "unlimited"
  },
  "sourceIp": "10.0.0.5",
  "reason": "permanent Portal integration for model sync"
}
```

Example response:

```json
{
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 1,
  "generation": 1,
  "caseId": "case_01J2ACCESSGATE",
  "state": "pending_approval",
  "status": "Pending approval",
  "approvalRequired": true,
  "target": "server1",
  "accessProfile": "elevated",
  "linuxUser": "accessgate-elevated",
  "expiresAt": null
}
```

The requester must store the `caseId`. Approval-bound requests require a second client-to-AG-Server call after human approval.

### Claim Approved Case

After an unlimited serviceuser request has been approved in the Web UI, the original requester calls the claim endpoint with the returned case ID.

```http
POST /v1/access-cases/{caseId}/claim
Authorization: Bearer <client-api-key>
Content-Type: application/json
```

Request:

```json
{
  "caseId": "case_01J2ACCESSGATE"
}
```

Approved response:

```json
{
  "caseId": "case_01J2ACCESSGATE",
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 2,
  "generation": 1,
  "state": "active",
  "target": "server1",
  "host": "10.0.0.20",
  "accessProfile": "elevated",
  "linuxUser": "accessgate-elevated",
  "expiresAt": null,
  "keyDelivery": "generated_once",
  "keyFingerprint": "SHA256:...",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----..."
}
```

Pending response:

```json
{
  "caseId": "case_01J2ACCESSGATE",
  "state": "pending_approval",
  "status": "Pending approval"
}
```

The generated private key must only be returned once, must not be logged, must not be persisted, and must not be retrievable again from the AG-Server.

### Revoke Lease

```http
POST /v1/leases/{leaseId}/revoke
Authorization: Bearer <client-api-key>
```

Response:

```json
{
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 3,
  "generation": 2,
  "state": "revoked"
}
```

### Get Lease

```http
GET /v1/leases/{leaseId}
Authorization: Bearer <client-api-key>
```

### List Leases

```http
GET /v1/leases?state=active,pending_approval
Authorization: Bearer <operator-or-service-token>
```

### Approve Lease

Only human/operator identities may approve unlimited serviceuser leases.

```http
POST /v1/leases/{leaseId}/approve
Cookie: ag_ops_session=<session>
Content-Type: application/json
```

Request:

```json
{
  "decisionReason": "Approved for Portal service integration"
}
```

Response:

```json
{
  "caseId": "case_01J2ACCESSGATE",
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 2,
  "generation": 1,
  "state": "approved",
  "approvedBy": "operator",
  "expiresAt": null
}
```

## Operator Admin API

These endpoints require an active operator session created through an Ops Login Link.

### Create API Key

```http
POST /v1/admin/api-keys
Cookie: ag_ops_session=<session>
Content-Type: application/json
```

Request:

```json
{
  "displayName": "codex-agent-main",
  "requesterType": "ai_agent",
  "owner": "operator",
  "policyGroups": ["ai-agent-standard"],
  "rateLimits": {
    "requestsPerMinute": 100,
    "activeLeases": 20
  },
  "expiresAt": "2027-07-07T00:00:00Z"
}
```

Response:

```json
{
  "apiKeyId": "agkey_01J2...",
  "requesterId": "req_ai_codex_main",
  "displayName": "codex-agent-main",
  "requesterType": "ai_agent",
  "apiKey": "agk_live_...",
  "shownOnce": true
}
```

The `apiKey` value is returned only once. The AG-Server stores only a hash.

### Revoke API Key

```http
POST /v1/admin/api-keys/{apiKeyId}/revoke
Cookie: ag_ops_session=<session>
Content-Type: application/json
```

Request:

```json
{
  "reason": "rotated"
}
```

### Start Target Server Bootstrap

```http
POST /v1/admin/servers/bootstrap
Cookie: ag_ops_session=<session>
Content-Type: application/json
```

Request:

```json
{
  "displayName": "server-x",
  "host": "10.0.0.20",
  "sshPort": 22,
  "bootstrapAuthMethod": "password",
  "bootstrapUser": "root",
  "bootstrapPassword": "write-only-secret",
  "labels": {
    "env": "local",
    "role": "worker"
  }
}
```

Response:

```json
{
  "bootstrapId": "boot_01J2...",
  "serverId": "srv_01J2...",
  "state": "pending"
}
```

Bootstrap credentials are write-only and must not be persisted or logged.

SSH key bootstrap request:

```json
{
  "displayName": "server-x",
  "host": "10.0.0.20",
  "sshPort": 22,
  "bootstrapAuthMethod": "ssh_key",
  "bootstrapUser": "root",
  "bootstrapPrivateKey": "write-only-private-key",
  "bootstrapPrivateKeyPassphrase": "optional-write-only-secret",
  "labels": {
    "env": "local",
    "role": "worker"
  }
}
```

Both `password` and `ssh_key` bootstrap methods are supported. Password mode is intended for broad operator usability. SSH key mode is preferred where operators can provide it.

### Get Bootstrap Status

```http
GET /v1/admin/servers/bootstrap/{bootstrapId}
Cookie: ag_ops_session=<session>
```

Response:

```json
{
  "bootstrapId": "boot_01J2...",
  "serverId": "srv_01J2...",
  "state": "verifying",
  "steps": [
    {
      "name": "connecting",
      "state": "complete"
    },
    {
      "name": "installing",
      "state": "complete"
    },
    {
      "name": "verifying",
      "state": "running"
    }
  ]
}
```

## AG-Server to AG-Agent

AG-Server-to-AG-Agent calls use the AG-Agent-specific AG-Server-to-AG-Agent credential. Requests should be sent over HTTPS and signed with HMAC. Plain bearer auth is not recommended for lease-changing operations.

Recommended headers:

```http
X-AccessGate-Agent: server1
X-AccessGate-Timestamp: 2026-07-07T14:00:00Z
X-AccessGate-Nonce: <random-nonce>
X-AccessGate-Signature: <hmac-sha256-signature>
```

The signature covers the method, path, timestamp, nonce, and request body hash.

### Notify Desired State Changed

```http
POST /v1/desired-state/changed
X-AccessGate-Agent: server1
X-AccessGate-Timestamp: 2026-07-07T14:00:00Z
X-AccessGate-Nonce: <random-nonce>
X-AccessGate-Signature: <hmac-sha256-signature>
Content-Type: application/json
```

Request:

```json
{
  "agentId": "server1",
  "desiredStateVersion": 42,
  "reason": "lease_changed"
}
```

Response:

```json
{
  "agentId": "server1",
  "accepted": true
}
```

The AG-Agent should treat this as a hint and fetch desired state from the AG-Server.

### Notify Revoke

```http
POST /v1/leases/{leaseId}/revoke-notify
X-AccessGate-Agent: server1
X-AccessGate-Timestamp: 2026-07-07T14:00:00Z
X-AccessGate-Nonce: <random-nonce>
X-AccessGate-Signature: <hmac-sha256-signature>
```

Request:

```json
{
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 3,
  "generation": 2,
  "desiredStateVersion": 43
}
```

Response:

```json
{
  "leaseId": "01J2ACCESSGATELEASE",
  "accepted": true
}
```

The AG-Agent still fetches desired state before changing local files. If the local lease generation is newer than the notification, the AG-Agent reports a stale notification event and does not apply old state.

## AG-Agent to AG-Server

### Get Desired State

```http
GET /v1/agents/{agentId}/desired-state
X-AccessGate-Agent: server1
X-AccessGate-Timestamp: 2026-07-07T14:00:00Z
X-AccessGate-Nonce: <random-nonce>
X-AccessGate-Signature: <hmac-sha256-signature>
```

Response:

```json
{
  "agentId": "server1",
  "desiredStateVersion": 43,
  "leases": [
    {
      "leaseId": "01J2ACCESSGATELEASE",
      "version": 3,
      "generation": 2,
      "state": "active",
      "accessProfile": "normal",
      "linuxUser": "accessgate-normal",
      "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
      "expiresAt": null,
      "restrictions": {
        "pty": false,
        "agentForwarding": false,
        "x11Forwarding": false,
        "portForwarding": false
      }
    }
  ]
}
```

Only leases that should be present locally appear in desired state. Revoked, rejected, expired, and otherwise inactive leases are omitted. The AG-Agent compares this active desired-state list with its own AccessGate-managed local lease list and removes every local managed lease that is absent from desired state.

The AG-Agent must not touch user-managed SSH keys outside AccessGate-managed files. The cleanup rule applies only to AccessGate-managed local state and `authorized_keys_accessgate`.

## Status Events

AG-Agent to AG-Server:

AG-Agent-to-AG-Server calls use the separate AG-Server-issued AG-Agent-to-AG-Server credential. They use the same signing pattern but are validated against the opposite key.

```http
POST /v1/agent-events
X-AccessGate-Agent: server1
X-AccessGate-Timestamp: 2026-07-07T14:30:01Z
X-AccessGate-Nonce: <random-nonce>
X-AccessGate-Signature: <hmac-sha256-signature>
Content-Type: application/json
```

Example:

```json
{
  "eventId": "evt_01J2ACCESSGATE",
  "agentId": "server1",
  "eventType": "lease.expired",
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 3,
  "generation": 2,
  "idempotencyKey": "server1:evt_01J2ACCESSGATE",
  "timestamp": "2026-07-07T14:30:01Z"
}
```

The AG-Server must deduplicate AG-Agent events by `eventId`. Duplicate delivery must be treated as success if the event was already processed.

Example install failure event:

```json
{
  "eventId": "evt_01J2INSTALLFAILED",
  "agentId": "server1",
  "eventType": "lease.install.failed",
  "leaseId": "01J2ACCESSGATELEASE",
  "version": 3,
  "generation": 2,
  "idempotencyKey": "server1:evt_01J2INSTALLFAILED",
  "timestamp": "2026-07-07T14:30:01Z",
  "error": {
    "code": "local_write_failed",
    "message": "Could not write managed authorized keys file"
  }
}
```

## Rate Limit Response

```json
{
  "error": {
    "code": "rate_limited",
    "message": "Requester exceeded concurrent active lease limit",
    "requestId": "req_01J2...",
    "limit": {
      "name": "active_leases_per_requester",
      "max": 20,
      "current": 20,
      "retryAfterSeconds": 60
    }
  }
}
```

## Error Shape

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Requester is not allowed to access target server as this user",
    "requestId": "req_01J2..."
  }
}
```

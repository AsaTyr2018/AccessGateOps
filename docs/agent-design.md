# AG-Agent Design

## Purpose

The AccessGate AG-Agent is the local enforcement component on each managed Linux server.

It receives desired-state change notifications from the AG-Server, fetches the current desired state, installs public SSH keys for the correct local user, and removes keys that are expired or no longer part of the AG-Server desired state.

## Local Files

Suggested paths:

```text
/etc/accessgate-agent/config.yaml
/var/lib/accessgate-agent/leases.json
/var/log/accessgate-agent/agent.log
```

Managed SSH key file per user:

```text
/home/<user>/.ssh/authorized_keys_accessgate
```

## Access Profiles and Groups

For AI-oriented leases, AccessGate can expose simple access profiles instead of requiring the requester to choose a Linux username.

Baseline profiles:

- `normal`: maps to a managed local user in the `accessgate-normal` group.
- `elevated`: maps to a managed local user in the `accessgate-elevated` group.

The profile-to-group mapping is created during bootstrap and stored in the AG-Agent config. The AG-Agent may only add managed AccessGate users to groups that are explicitly listed in that config. Group names should normally require the `accessgate-` prefix. The AG-Agent must never add users to broad system groups such as `sudo`, `wheel`, `root`, or `docker` unless a future target policy explicitly introduces and audits that behavior.

The first v1 elevated model may use passwordless sudo through a group sudoers rule:

```sudoers
%accessgate-elevated ALL=(ALL) NOPASSWD:ALL
```

In that model, AccessGate policy decides whether a requester may obtain an `elevated` lease. SSH only proves possession of the lease key; sudo must not ask for a separate password for the generated or managed user.

## Lease Persistence

The AG-Agent must persist leases before installing SSH keys.

Startup behavior:

1. Load local leases.
2. Remove expired leases from state.
3. Regenerate managed authorized-keys files.
4. Fetch desired state from the AG-Server.
5. Converge local state to desired state.
6. Start listening for AG-Server notifications.

This makes reboot behavior deterministic.

## File Write Strategy

The AG-Agent should never append blindly.

Recommended strategy:

1. Load local lease state.
2. Filter active leases per target user.
3. Render the complete managed authorized-keys file.
4. Write to a temporary file.
5. Set owner and permissions.
6. Atomically rename into place.

Expected permissions:

```text
/home/<user>/.ssh                     0700
/home/<user>/.ssh/authorized_keys_accessgate 0600
```

Ownership must match the target Linux user.

## Lease Entry Format

Example rendered key line:

```text
from="10.0.0.5",no-agent-forwarding,no-X11-forwarding,no-pty,no-port-forwarding ssh-ed25519 AAAAC3... accessgate:lease=01J...:requester=portal:expires=2026-07-07T14:30:00Z
```

## AG-Agent API

AccessGate uses hybrid AG-Agent communication:

- AG-Agent exposes a small HTTPS API for desired-state change notifications.
- AG-Agent periodically fetches desired state from the AG-Server.
- AG-Agent can fetch desired state immediately when notified.
- AG-Agent accepts signed rapid revoke notifications for immediate key removal.

This gives quick activation and repair after missed events.

## Minimal AG-Agent Endpoints

```text
GET  /health
POST /v1/desired-state/changed
POST /v1/leases/{leaseId}/revoke-notify
```

All endpoints except `/health` require AG-Server authentication.

The AG-Agent should not treat generic desired-state notifications as final authority. A desired-state notification means desired state may have changed, so the AG-Agent fetches current desired state and converges locally.

Rapid revoke notifications are intentionally stronger. A valid `revoke-notify` is a high-priority interrupt from the trusted AG-Server. The AG-Agent should:

1. Validate mTLS/HMAC, timestamp, nonce, lease ID, version, and generation.
2. Remove the matching `accessgate:lease=<leaseId>` line from `authorized_keys_accessgate`.
3. Terminate active SSH sessions for the affected Linux user without killing unrelated processes owned by that user.
4. Fetch desired state immediately after the local removal.
5. Continue periodic polling as fallback if the push is missed.

The rapid revoke endpoint must never accept normal requester API keys.

## Desired State Application

The AG-Agent stores:

- Last applied desired state version.
- Per-lease applied version.
- Per-lease applied generation.
- Local lease state.

Desired state application rules:

- Install desired leases missing locally.
- Update local leases when desired version is newer.
- Remove local managed leases missing from desired state.
- Ignore desired leases older than the local applied version.
- Report success or failure with an event ID.
- Ensure managed lease users are members of the local group for their assigned access profile.

The AG-Agent owns only its AccessGate-managed lease list and `authorized_keys_accessgate` files. It must not modify user-defined SSH keys outside its managed files. Within its managed lease list, anything not known from the latest AG-Server desired state is considered unauthorized drift and must be removed.

The AG-Agent should regenerate managed authorized-keys files from its local state after every desired state application.

## Agent Auto Update

The AG-Agent should be able to update itself from AG-Server-published agent artifacts.

Recommended flow:

1. AG-Agent signs the request with its per-agent shared secret.
2. AG-Agent calls `GET /v1/agent-binaries/{arch}/meta`.
3. AG-Agent compares the published SHA-256 with the hash of its local executable.
4. If the hash differs, AG-Agent downloads `GET /v1/agent-binaries/{arch}`.
5. AG-Agent writes the download to a temporary file.
6. AG-Agent verifies the downloaded SHA-256 before installing it.
7. AG-Agent atomically replaces its local binary.
8. AG-Agent asks systemd to restart `accessgate-agent`.

The version string is informational. The binary hash is the update authority.

The updater must never apply a binary whose checksum does not match the metadata response. If update fails, the current running binary must remain in place.

## Agent Channel Security

Each AG-Agent receives a per-agent shared secret during bootstrap. The secret is stored in a root-owned file:

```text
/etc/accessgate-agent/agent.secret
```

Expected permissions:

```text
owner: root
mode: 0600
```

AG-Agent-to-AG-Server requests must include:

- Agent ID
- Timestamp
- Nonce
- HMAC-SHA256 signature

The AG-Server validates the signature, the expected agent identity, and a short timestamp window. Desired-state responses, update metadata, and agent binary downloads are returned in an AES-GCM envelope derived from the agent secret. This prevents normal requester API keys from being used as the agent trust channel.

## Expiration Loop

The AG-Agent should run a periodic expiration loop.

Recommended interval:

```text
15s to 60s
```

On each tick:

1. Find expired leases.
2. Mark them expired locally.
3. Regenerate affected authorized-keys files.
4. Report expiration events to the AG-Server if reachable.

## Idempotency

All lease operations must be idempotent.

- Installing the same lease twice must be safe.
- Revoking an already expired lease must be safe.
- Reconciliation must be able to rebuild files from state.
- Applying the same desired state version twice must be safe.
- Replaying the same AG-Agent event must be safe.

Every outbound AG-Agent event must include an event ID. The AG-Server uses the event ID to deduplicate retries.

## Systemd Unit Draft

```ini
[Unit]
Description=AccessGate AG-Agent
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/accessgate-agent --config /etc/accessgate-agent/config.yaml
Restart=always
RestartSec=5
User=root
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/accessgate-agent /var/log/accessgate-agent /home
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The hardening settings may need adjustment depending on how SSH home directories are managed.

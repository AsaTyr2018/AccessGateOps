# Onboarding

This document describes two operator workflows:

- Issuing API keys for users, services, and AI agents.
- Adding a new target server and installing the AG-Agent.

## API Key Issuance

API keys should be created from the Ops Web UI by an authenticated operator.

There is no self-service API key issuance in the initial model. Human users, services, and AI agents receive API keys only through an operator action in the Ops Web UI.

Supported requester types:

- `user`
- `service`
- `ai_agent`

The operator should define:

- Display name
- Requester type
- Owner or contact
- Allowed policy groups
- Rate limits
- Active lease quotas
- Expiration date or rotation interval
- Optional source network restrictions

The API key is shown exactly once after creation.

Required behavior:

- Store only a hash of the API key.
- Never log the full API key.
- Show the full API key only once.
- Allow immediate revoke.
- Allow rotation without deleting audit history.
- Record creator identity, creation time, and policy bindings.
- Require an active operator session from an Ops Login Link.

Recommended API key format:

```text
agk_live_...
```

Example one-time display:

```text
AccessGate API Key
Name: codex-agent-main
Type: ai_agent
Key: agk_live_...
Shown once. Store it now.
```

## API Key Rotation

Rotation should create a new key version while preserving requester identity.

Suggested model:

- Requester ID remains stable.
- API key ID changes.
- Old key can overlap for a short configured grace period.
- Audit logs reference both requester ID and key ID.

## Target Server Onboarding

Adding a server should be possible from the Ops Web UI.

Operator input:

- Server display name
- Hostname or IP address
- SSH port
- Temporary bootstrap username, usually `root`
- Bootstrap authentication method
- Temporary bootstrap password or temporary bootstrap private key
- Optional server group
- Optional labels

Access profile setup:

- Bootstrap creates the local AccessGate groups required by the target policy.
- The baseline groups are `accessgate-normal` and `accessgate-elevated`.
- `accessgate-normal` has no sudo rights.
- `accessgate-elevated` may receive passwordless sudo for the first v1 implementation.
- AccessGate may only manage groups that are explicitly configured for the target and should normally require the `accessgate-` prefix.

The bootstrap credential is only used for installation and must not be stored.

Supported bootstrap authentication methods:

- `password`: username and password.
- `ssh_key`: username and private key.

Both methods should be available. Password bootstrap keeps onboarding simple for operators who are not comfortable managing SSH keys. SSH key bootstrap is preferred where available because it avoids password handling.

## Bootstrap Service

The AG-Server should start a short-lived bootstrap job/service to install the AG-Agent.

Responsibilities:

1. Connect to the target server over SSH.
2. Verify basic OS compatibility.
3. Detect target CPU architecture.
4. Install the matching AG-Agent binary or package.
5. Create the configured AccessGate local groups, such as `accessgate-normal` and `accessgate-elevated`.
6. Install the sudoers drop-in for elevated AccessGate groups if enabled by target policy.
7. Create AG-Agent config, including the allowed access profile to local group mapping.
8. Generate AG-Agent local key material or provision generated material.
9. Issue an AG-Agent certificate from the internal Agent Issuing CA.
10. Store the AG-Agent certificate record, serial, fingerprint, issuer generation, and revocation state.
11. Exchange AG-Agent-to-AG-Server and AG-Server-to-AG-Agent keys.
12. Configure systemd service.
13. Enable AG-Agent auto update.
14. Start AG-Agent.
15. Verify AG-Agent health and certificate identity.
16. Remove bootstrap artifacts.
17. Discard bootstrap SSH credentials from memory.

The bootstrap job should stream safe status events back to the Web UI.

Before the bootstrap job sends credentials to the target, AccessGate should display the SSH host key fingerprint and require explicit operator confirmation. This makes the operator the trust anchor for the initial add-server decision.

The bootstrap health check should tolerate normal systemd restart timing. A short retry loop is preferred over a single immediate `systemctl is-active` check.

It must never log:

- Root password
- Private bootstrap key
- AG-Agent API keys
- AG-Server-to-AG-Agent keys
- AG-Agent-to-AG-Server keys

## Agent Credential Exchange

Each AG-Agent receives two internal credentials:

- `ag_agent_to_ag_server_key`
- `ag_server_to_ag_agent_key`

The AG-Server stores only hashes where verification allows it. The AG-Agent stores its local secrets in a root-owned config file.

## Agent Certificate Provisioning

AccessGate should issue AG-Agent certificates only during an operator-approved bootstrap or repair flow. There is no public CA enrollment endpoint.

For every AG-Agent, bootstrap provisions:

- Agent private key.
- Agent client certificate.
- AccessGate Agent CA bundle.
- AG-Server internal API CA bundle or pin.
- Per-agent shared secret for signed/encrypted application messages.

The AG-Server records:

- Agent ID.
- Certificate serial number.
- Certificate fingerprint.
- Issuer ID and issuer generation.
- Validity window.
- Revocation state.

Agent certificates should be short-lived and renewed automatically over an already authenticated agent channel. If an agent certificate is revoked, renewal must be denied.

Suggested agent config:

```text
/etc/accessgate-agent/config.yaml
```

Expected permissions:

```text
owner: root
mode: 0600
```

## Bootstrap States

Suggested states:

- `pending`
- `connecting`
- `installing`
- `configuring`
- `starting_agent`
- `verifying`
- `complete`
- `failed`

Every bootstrap run should have a bootstrap ID and audit trail.

## Failure Handling

If bootstrap fails:

- Report the failed step.
- Do not keep bootstrap credentials.
- Do not mark the target server as active.
- If possible, remove partially installed AG-Agent files.
- Allow operator to retry with new credentials.

If AG-Agent starts but cannot authenticate:

- Mark server as `agent_unverified`.
- Do not allow leases for that target.
- Require repair or re-onboarding.

## Target Removal

Deleting a target server from the Ops Web UI must cryptographically disable the AG-Agent identity.

### Clean Retire

Clean retire is the normal removal path when the agent is still trusted and reachable.

1. Confirm no active leases reference the target.
2. Mark the target as `retiring`.
3. Send a signed `agent.retire` command with a short TTL.
4. AG-Agent removes AccessGate-managed SSH keys.
5. AG-Agent removes local AccessGate certificates, private keys, CA bundles, shared secrets, config, and state.
6. AG-Agent schedules a self-uninstall helper.
7. AG-Agent reports `retire.completed` if possible.
8. Revoke the AG-Agent certificate serial and fingerprint.
9. Revoke or rotate the AG-Agent shared secret.
10. Archive the target record and write audit events.

The self-uninstall helper should stop and disable `accessgate-agent`, remove the agent binary, remove the systemd unit, remove `/etc/accessgate-agent`, remove AccessGate local state, and reload systemd.

### Cut Off Finger

Cut off finger is the emergency or non-cooperative removal path.

1. Send one final signed `agent.tombstone` command while the current AG-Server trust is still valid.
2. AG-Agent accepts it only if trust, identity, generation, TTL, and replay checks pass.
3. AG-Agent removes AccessGate-managed SSH keys, local certificates, private keys, CA bundles, shared secrets, config, state, unit, and binary.
4. Wait only a very short grace period for acknowledgement.
5. Revoke the AG-Agent certificate serial and fingerprint immediately.
6. Revoke or rotate the AG-Agent shared secret immediately.
7. Stop accepting traffic from that agent identity.
8. Archive the target as `removed_tombstone_acknowledged` or `removed_remote_unconfirmed`.
9. Do not wait for remote uninstall confirmation beyond the tombstone grace period.

The tombstone command is the last trusted command before revocation. It is not sent after revocation.

If the target host is offline, local certificate revocation still succeeds. The agent is considered dead to AccessGate even if the service remains installed on the removed host.

## Security Notes

Password onboarding is convenient but higher risk. SSH key onboarding is preferred where operators can use it. Both are acceptable as operator-driven bootstrap flows if:

- Web UI access requires Ops Login Link authentication.
- Bootstrap credentials are never persisted.
- Logs redact all secrets.
- The bootstrap job is short-lived.
- The target server is marked active only after AG-Agent verification.
- Operators can later disable password SSH on the target server.

Future hardening options:

- Cloud-init or preseeded AG-Agent install.
- Pull-based agent registration token.
- Signed AG-Agent packages.
- Stronger host key pinning and inventory-based fingerprint preapproval.

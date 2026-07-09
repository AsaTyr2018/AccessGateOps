# AccessGate Internal Agent PKI

AccessGate should include an internal PKI used only for AG-Server and AG-Agent communication.

This PKI must not be exposed as a general-purpose CA. It has no public ACME endpoint, no LAN enrollment API, and no requester-facing certificate issuing surface.

## Certificate Hierarchy

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

## Roles

### Internal Root CA

- Signs only AccessGate issuing CAs.
- Does not sign AG-Agent or AG-Server leaf certificates directly.
- Is not exposed over the network.
- Should have a long lifetime.
- Should be stored encrypted at rest.

### Agent Issuing CA

- Signs only AG-Agent client certificates.
- Uses `patoperatorn=0`.
- Is purpose-limited to issuing agent identities.
- Can be rotated by issuer generation.

### Server Issuing CA

- Signs only AG-Server internal API server certificates.
- Uses `patoperatorn=0`.
- Is separate from the Agent Issuing CA.

## Agent Certificate Identity

Each AG-Agent receives a unique leaf certificate.

Suggested identity:

```text
URI SAN: spiffe://accessgate.local/agent/<agent-id>
EKU: clientAuth
TTL: 7 to 30 days
```

The AG-Server must verify more than the certificate chain. It must verify:

- Agent ID.
- Certificate serial number.
- Certificate fingerprint.
- Issuer ID.
- Issuer generation.
- Validity window.
- Local revocation state.

A valid certificate for `server-b` must never authenticate as `server-a`.

## Server Certificate Identity

Suggested identity:

```text
DNS SAN: accessgate-agent.internal
DNS SAN: accessgate.example.com
EKU: serverAuth
TTL: 30 to 90 days
```

The AG-Agent validates the AG-Server certificate against the AccessGate-internal CA bundle or a pinned AG-Server trust anchor.

## Agent Certificate Record

AccessGate should store one certificate record per active or historical AG-Agent identity:

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

## Revocation Model

Agent certificates are individually revocable.

If one AG-Agent is compromised:

1. Mark only that agent certificate as revoked.
2. Deny authentication for that serial/fingerprint immediately.
3. Deny renewal for that serial/fingerprint.
4. Keep every other agent certificate valid.
5. Rebootstrap the affected target to create new key material and a new certificate.

This is the "cut off one finger, keep the hand" model. A leaf compromise must not require replacing the Root CA, Agent Issuing CA, or all other agents.

## Renewal

Agent certificates should be short-lived and renewed automatically before expiry.

Renewal requirements:

- Renewal is allowed only over an existing authenticated AG-Agent channel.
- The current certificate must be valid and not revoked.
- The renewed certificate gets a new serial and fingerprint.
- The old certificate record becomes `rotated`.

## Target Removal

Deleting a server in the Ops Web UI must also revoke its AG-Agent identity.

AccessGate supports two removal modes:

- `clean_retire`: cooperative removal where the AG-Agent is still trusted long enough to remove itself.
- `cut_off_finger`: emergency removal where AccessGate immediately revokes the agent identity and forgets trust in that leaf.

## Clean Retire

Clean retire is the preferred path for normal server removal.

Required clean retire behavior:

1. Reject deletion while active leases reference the target.
2. Mark target as `retiring`.
3. Keep the AG-Agent identity valid only for retire traffic.
4. Send a signed `agent.retire` command with command ID, target agent ID, current generation, short TTL, and reason.
5. AG-Agent validates the command through mTLS/HMAC and generation checks.
6. AG-Agent removes all AccessGate-managed SSH key files.
7. AG-Agent removes local AccessGate certificate material, private keys, CA bundles, and shared secrets.
8. AG-Agent schedules a local uninstall helper.
9. AG-Agent reports `retire.completed` if possible.
10. AG-Server revokes the AG-Agent certificate serial/fingerprint and shared secret.
11. AG-Server archives the target and writes audit events.

The uninstall helper should stop and disable `accessgate-agent`, remove the agent binary, remove the systemd unit, remove `/etc/accessgate-agent`, remove AccessGate local state, and reload systemd. It must only remove AccessGate-owned files. `/etc/accessgate-agent` includes dead certificates, private keys, CA bundles, shared secrets, and agent config.

If the target host is offline during clean retire, AccessGate may wait for a short grace period. After timeout, the operator can continue with `cut_off_finger`.

## Cut Off Finger

Cut off finger is the emergency or non-cooperative removal path. It is used when an agent is compromised, unreachable, or no longer trusted.

Required cut off behavior:

1. Reject deletion while active leases reference the target unless the operator explicitly chooses an emergency force path.
2. Mark target as `tombstone_sent`.
3. Create a one-time `agent.tombstone` command while the current AG-Server trust is still valid.
4. Send `agent.tombstone` over the current trusted mTLS/HMAC channel with command ID, target agent ID, certificate serial/fingerprint, issuer generation, agent generation, short TTL, and reason.
5. AG-Agent accepts the command only if trust, identity, generation, TTL, and command replay checks pass.
6. AG-Agent removes AccessGate-managed SSH keys, local AccessGate certificate material, private keys, CA bundles, shared secrets, config, state, service unit, and binary.
7. AG-Agent may report `tombstone.accepted` or `tombstone.completed`.
8. AG-Server waits only a very short grace period for acknowledgement.
9. AG-Server immediately revokes the AG-Agent certificate serial/fingerprint.
10. AG-Server immediately revokes or rotates the AG-Agent shared secret.
11. AG-Server stops accepting all mTLS/HMAC traffic from that agent identity.
12. AG-Server removes the agent from active inventory and keeps an audit/archive record.
13. AG-Server records `removed_tombstone_acknowledged` if an acknowledgement arrived, otherwise `removed_remote_unconfirmed`.

After this point, AccessGate considers the agent cryptographically dead.

The tombstone command is the final trusted command before revocation. It is not sent after revocation. AccessGate must not keep trust open beyond the short tombstone grace period.

If the target host is offline, local revocation still succeeds. The AG-Agent may remain installed on disk, but it is cryptographically dead to AccessGate.

## Transport and Message Security

mTLS provides transport identity:

```text
who is connected to whom
```

HMAC, nonce, timestamp, lease version, and lease generation still provide message freshness and command integrity:

```text
what was authorized and whether it is current
```

The strongest model uses both:

- mTLS for AG-Server and AG-Agent connection identity.
- HMAC/AES-GCM for application-layer integrity, replay protection, and encrypted payloads.

# Workflow: AG-Agent Clean Retire vs Cut Off Finger

This workflow describes the two supported removal paths for a managed target server.

`clean_retire` is cooperative. The AG-Agent is still trusted long enough to remove AccessGate-managed keys and uninstall itself.

`cut_off_finger` is immediate revocation. AccessGate revokes the agent identity locally and does not wait for the remote host.

## Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Operator
    participant WebUI as Ops Web UI
    participant AGS as AG-Server
    participant PKI as Internal Agent PKI
    participant AGA as AG-Agent
    participant SSHD as sshd
    participant Systemd as systemd

    Operator->>WebUI: Delete target server
    WebUI->>AGS: Request target removal
    AGS->>AGS: Check active leases for target

    alt Active leases exist
        AGS-->>WebUI: Reject removal until leases are revoked/expired
    else No active leases
        WebUI-->>Operator: Choose removal mode

        alt Clean Retire
            Operator->>WebUI: Confirm Clean Retire
            WebUI->>AGS: POST target remove mode=clean_retire
            AGS->>AGS: Mark target retiring
            AGS->>AGA: Signed agent.retire command<br/>commandId, agentId, generation, TTL, reason
            AGA->>AGA: Validate mTLS/HMAC, TTL, generation, commandId
            AGA->>SSHD: Remove AccessGate-managed authorized_keys_accessgate files
            AGA->>AGA: Delete local certs, private keys,<br/>CA bundles, secrets, config, state
            AGA->>AGS: Report retire.accepted
            AGA->>Systemd: Schedule uninstall helper
            AGA->>AGS: Report retire.completed if possible
            Systemd->>Systemd: Stop and disable accessgate-agent
            Systemd->>Systemd: Remove agent binary, unit, and /etc/accessgate-agent
            AGS->>PKI: Revoke agent certificate serial/fingerprint
            AGS->>AGS: Revoke/rotate agent shared secret
            AGS->>AGS: Archive target
            AGS-->>WebUI: Removed cleanly
        else Cut Off Finger
            Operator->>WebUI: Confirm Cut Off Finger
            WebUI->>AGS: POST target remove mode=cut_off_finger
            AGS->>AGA: Final trusted agent.tombstone<br/>commandId, agentId, cert serial,<br/>fingerprint, generation, short TTL
            AGA->>AGA: Validate trust, identity, TTL,<br/>generation, replay protection
            AGA->>SSHD: Remove AccessGate-managed authorized_keys_accessgate files
            AGA->>AGA: Delete local certs, private keys,<br/>CA bundles, secrets, config, state
            AGA->>Systemd: Schedule uninstall helper
            AGA-->>AGS: Optional tombstone.accepted/completed
            AGS->>AGS: Wait only tombstone grace period
            AGS->>PKI: Immediately revoke agent certificate serial/fingerprint
            AGS->>AGS: Immediately revoke/rotate agent shared secret
            AGS->>AGS: Stop accepting all traffic from agent identity
            AGS->>AGS: Archive target as acknowledged or unconfirmed
            AGS-->>WebUI: Identity cut off
        end
    end
```

## Notes

- `clean_retire` is preferred when the agent is reachable and not suspected compromised.
- `cut_off_finger` is preferred when the agent is compromised, unreachable, or no longer trusted.
- In `clean_retire`, certificate revocation happens after retire completion or timeout.
- In `cut_off_finger`, `agent.tombstone` is the final trusted command before revocation.
- `agent.tombstone` must be short-lived, replay-protected, and bound to the current certificate serial/fingerprint and generation.
- AccessGate waits only a very short tombstone grace period, then revokes locally regardless of acknowledgement.
- The AG-Agent self-uninstall helper must remove only AccessGate-owned files, including dead certificates, private keys, CA bundles, secrets, config, and state.
- From AccessGate's perspective, a cut-off agent is dead even if the process still exists on the remote host.

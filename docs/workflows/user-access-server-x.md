# Workflow: User Requests Access to Server X

This workflow describes a human user requesting temporary normal access to `Server X`.

## Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant CLI as User CLI / Client
    participant AGS as AG-Server
    participant Policy as Policy Engine
    participant AGA as AG-Agent on Server X
    participant SSHD as sshd on Server X

    User->>CLI: Request access to Server X
    CLI->>AGS: POST /v1/leases<br/>role=normal, target=Server X,<br/>linuxUser, timeframe, reason
    AGS->>AGS: Authenticate requester
    AGS->>Policy: Evaluate requester, target, user, role, TTL, source
    Policy-->>AGS: Allow with restrictions
    AGS->>AGS: Generate unique lease key pair
    AGS->>AGS: Create lease<br/>version=1, generation=1, state=active
    AGS-->>CLI: Return active lease details<br/>and private key once
    AGS->>AGA: Notify desired state changed
    AGA->>AGS: GET desired state
    AGS-->>AGA: Desired state includes lease for Server X
    AGA->>AGA: Persist lease state
    AGA->>SSHD: Render authorized_keys_accessgate
    AGA->>AGS: POST agent event<br/>lease.installed, eventId, version, generation
    User->>SSHD: SSH using returned private key
    SSHD-->>User: Access granted
    AGA->>AGA: Expiration loop reaches expiresAt
    AGA->>SSHD: Remove key from managed authorized keys
    AGA->>AGS: POST agent event<br/>lease.expired, eventId, version, generation
    AGS->>AGS: Mark lease expired
```

## Notes

- Normal user access is capped at 1 hour.
- AccessGate generates the SSH key pair for the lease.
- The generated private key is returned exactly once.
- If private-key delivery is lost, the lease must be revoked and requested again.
- AG-Agent applies desired state and does not blindly trust mutation commands.
- Expiration is enforced locally by the AG-Agent even if AG-Server is unavailable.

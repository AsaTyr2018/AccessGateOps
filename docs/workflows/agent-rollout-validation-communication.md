# Workflow: AG-Agent Rollout, Validation, and Communication

This workflow describes how AccessGate adds a new managed server, installs the AG-Agent, validates the installation, and keeps the agent synchronized through desired-state communication.

## Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Operator
    participant WebUI as Ops Web UI
    participant AGS as AG-Server
    participant Bootstrap as Bootstrap Service
    participant Target as Target Server
    participant Systemd as systemd on Target
    participant AGA as AG-Agent on Target
    participant SSHD as sshd on Target

    Operator->>AGS: Console: accessgate -opskey --operator <name>
    AGS-->>Operator: One-time Ops Login Link
    Operator->>WebUI: Open /ops/agops_...
    WebUI->>AGS: Consume one-time Ops token
    AGS->>AGS: Create short-lived Ops session
    AGS-->>WebUI: Redirect to Ops UI

    Operator->>WebUI: Open Servers and click Add Server
    WebUI->>AGS: POST /v1/admin/targets<br/>host, sshPort, bootstrap user,<br/>password or SSH key, users, roles
    AGS->>AGS: Validate Ops session and target fields
    AGS->>AGS: Store target as pending_bootstrap
    AGS->>Bootstrap: Start bootstrap job

    Bootstrap->>Target: SSH connect with supplied bootstrap credential
    Bootstrap->>Target: Detect OS and CPU architecture
    Target-->>Bootstrap: uname -m / compatibility result
    Bootstrap->>AGS: Select matching AG-Agent binary
    Bootstrap->>Target: Upload AG-Agent binary, agent secret,<br/>and systemd unit
    Bootstrap->>Target: Configure /etc/hosts fallback if required
    Bootstrap->>SSHD: Configure AuthorizedKeysFile<br/>.ssh/authorized_keys_accessgate
    Bootstrap->>SSHD: Validate and reload sshd config
    Bootstrap->>Systemd: Enable and restart accessgate-agent
    Systemd->>AGA: Start AG-Agent as root
    Bootstrap->>Systemd: Wait until service is active
    Systemd-->>Bootstrap: accessgate-agent active

    AGA->>AGS: Signed GET /v1/agents/{agentId}/desired-state
    AGS-->>AGA: AES-GCM encrypted desired state<br/>active leases only
    AGA->>AGA: Persist desired-state version and leases
    AGA->>SSHD: Render managed authorized_keys_accessgate files
    AGA->>AGS: Report health/status event
    Bootstrap->>AGS: Mark target active and verified
    AGS-->>WebUI: Server shows active / verified

    loop Periodic agent reconciliation
        AGA->>AGS: Signed GET /v1/agents/{agentId}/desired-state
        AGS-->>AGA: Encrypted complete desired state for target
        AGA->>AGA: Compare local state with desired state
        AGA->>SSHD: Add, update, or remove managed keys
    end

    loop Agent auto update
        AGA->>AGS: Signed GET /v1/agent-binaries/{arch}/meta
        AGS-->>AGA: Encrypted version, size, sha256, download URL
        AGA->>AGA: Compare local binary SHA-256
        alt Hash differs
            AGA->>AGS: GET /v1/agent-binaries/{arch}
            AGS-->>AGA: AES-GCM encrypted matching AG-Agent binary
            AGA->>AGA: Verify downloaded SHA-256
            AGA->>Systemd: Replace binary and restart service
            Systemd->>AGA: Start updated AG-Agent
        else Hash matches
            AGA->>AGA: Keep current binary
        end
    end
```

## Notes

- The operator is the trust anchor for adding a new target server.
- Bootstrap credentials are used only for the install session and must not be persisted.
- Bootstrap should support both password and SSH-key authentication.
- The AG-Server selects the correct AG-Agent binary by detected target architecture.
- A target is marked active only after the AG-Agent service is installed, started, and verified.
- The AG-Agent owns only AccessGate-managed key files such as `authorized_keys_accessgate`.
- Desired state is the source of truth. The AG-Agent converges local state to the complete desired-state document instead of trusting one-off mutation commands.
- Expired and revoked leases are omitted from desired state, so the AG-Agent removes their managed keys.
- The agent auto-updater treats SHA-256 as the update authority. The version string is informational.
- AG-Agent communication uses per-agent shared secrets, HMAC-signed requests, timestamp validation, and AES-GCM encrypted envelopes for desired state, update metadata, and agent binaries.
- Requester API keys are not the AG-Agent trust channel.
- mTLS can still be added later as an additional transport identity layer.

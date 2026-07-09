# Workflow: AI Agent Requests Access to Server X

This workflow describes an AI agent, such as Codex or another automation service, requesting temporary normal access to `Server X`.

## Diagram

```mermaid
sequenceDiagram
    autonumber
    participant AI as AI Agent
    participant Informer as Public Informer
    participant AGS as AG-Server
    participant Policy as Policy Engine
    participant AGA as AG-Agent on Server X
    participant SSHD as sshd on Server X

    AI->>Informer: GET /v1/informer
    Informer-->>AI: API version, required fields, roles, flow
    AI->>AGS: POST /v1/leases<br/>role=normal, target=Server X,<br/>linuxUser, timeframe, reason
    AGS->>AGS: Authenticate AI service API key
    AGS->>AGS: Apply rate limits and requester quotas
    AGS->>Policy: Evaluate AI requester, target, user, role, TTL, source
    Policy-->>AGS: Allow with enforced restrictions
    AGS->>AGS: Generate unique lease key pair
    AGS->>AGS: Create lease<br/>version=1, generation=1, state=active
    AGS-->>AI: Return active lease details<br/>and private key once
    AGS->>AGA: Notify desired state changed
    AGA->>AGS: GET /v1/agents/{agentId}/desired-state
    AGS-->>AGA: Desired state with active lease
    AGA->>AGA: Compare local state and desired state
    AGA->>SSHD: Install public key in managed authorized keys
    AGA->>AGS: POST agent event<br/>lease.installed, eventId
    AI->>SSHD: SSH with returned private key
    SSHD-->>AI: Access granted
    AI->>SSHD: Perform requested automation
    AI->>AGS: Optional POST /v1/leases/{leaseId}/revoke
    AGS->>AGS: Increment version/generation, mark revoked
    AGS->>AGA: Notify desired state changed
    AGA->>AGS: Fetch desired state
    AGA->>SSHD: Remove key
    AGA->>AGS: POST agent event<br/>lease.revoked or lease.removed
```

## Notes

- The AI agent can discover the correct process through the Public Informer.
- Normal access remains short-lived and policy-controlled.
- AccessGate generates lease key pairs and returns private keys exactly once.
- Rate limits and active lease quotas protect against broken automation loops.
- The AI should revoke the lease early when work is complete.
- If the AI does not revoke, the AG-Agent removes the key when the TTL expires.

# Workflow: AI Agent Requests Serviceuser Access for Service X

This workflow describes an AI agent requesting long-running or unlimited `serviceuser` access for `Service X`. Unlimited serviceuser access requires human approval and a second claim call.

## Diagram

```mermaid
sequenceDiagram
    autonumber
    participant AI as AI Agent
    participant Informer as Public Informer
    participant AGS as AG-Server
    participant Policy as Policy Engine
    actor Operator
    participant WebUI as Web UI
    participant AGA as AG-Agent on Server X
    participant SSHD as sshd on Server X

    AI->>Informer: GET /v1/informer/process
    Informer-->>AI: serviceuser flow and required fields
    AI->>AGS: POST /v1/leases<br/>role=serviceuser, target=Server X,<br/>linuxUser=Service X user,<br/>timeframe=unlimited, reason
    AGS->>AGS: Authenticate AI service API key
    AGS->>AGS: Apply rate limits and pending-case quotas
    AGS->>Policy: Evaluate serviceuser request
    Policy-->>AGS: Approval required
    AGS->>AGS: Create approval case<br/>state=pending_approval,<br/>lease version=1, generation=1
    AGS-->>AI: Return pending_approval with caseId
    AI->>AI: Store caseId and pause workflow

    Operator->>AGS: Console: accessgate -opskey --operator <name> --ttl 1h
    AGS-->>Operator: One-time Ops Login Link<br/>https://accessgate.local/ops/agops_...
    Operator->>WebUI: Open Ops Login Link
    WebUI->>AGS: GET /ops/{one-time-token}
    AGS->>AGS: Atomically consume token and create session
    AGS-->>WebUI: Redirect to /ops with session cookie
    Operator->>WebUI: Review pending approval case
    WebUI->>AGS: POST /v1/leases/{leaseId}/approve
    AGS->>AGS: Mark case approved<br/>version=2, state=approved
    AGS-->>WebUI: Approval recorded

    AI->>AGS: POST /v1/access-cases/{caseId}/claim
    AGS->>AGS: Verify same requester, approved case, claimable state
    AGS->>AGS: Generate unique lease key pair
    AGS->>AGS: Activate lease<br/>version=3, state=active
    AGS-->>AI: Return active lease details<br/>and private key once
    AGS->>AGA: Notify desired state changed
    AGA->>AGS: GET desired state
    AGS-->>AGA: Desired state includes serviceuser lease
    AGA->>AGA: Persist lease version/generation
    AGA->>SSHD: Install managed public key
    AGA->>AGS: POST agent event<br/>lease.installed, eventId
    AI->>SSHD: Use serviceuser SSH access for Service X
```

## Notes

- Unlimited serviceuser access never auto-activates.
- The first AI request returns `pending_approval` and `caseId`.
- The human operator uses an Ops Login Link to access the Web UI.
- The Ops Login Link is one-time use and then replaced by an operator session.
- Approval only changes the case to approved. The AI must claim the case to activate the lease.
- AccessGate generates the serviceuser lease key pair only during successful claim.
- Private key material is returned only once during the claim response.

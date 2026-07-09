# Roadmap

## Phase 1: Design Baseline

- Define lease data model.
- Define AG-Server API.
- Define AG-Agent API.
- Define policy model.
- Decide implementation language.
- Decide storage backend.

## Phase 2: Minimal Prototype

- AG-Server can register one target server.
- AG-Agent can install and expire one lease.
- Client can request a lease and receive an AccessGate-generated private key exactly once.
- Public Informer exposes process and schema guidance.
- Authenticated target address book exposes only requester-allowed targets.
- Normal access requests are capped at 1 hour.
- Leases include version and generation counters.
- AG-Agent events include event IDs.
- AG-Agent manages `authorized_keys_accessgate`.
- AG-Agent uses hybrid notify plus pull desired-state communication.
- Basic audit logging exists.

## Phase 3: Security Hardening

- Hash API keys at rest.
- Add signed AG-Server-to-AG-Agent requests and trusted internal TLS.
- Add AG-Server anchored internal certificate issuance for AG-Agents.
- Add source IP restrictions.
- Add strict SSH key options.
- Add local startup reconciliation.
- Replace imperative reconciliation with desired state fetching.
- Add stale version and generation handling.
- Add requester rate limits and active lease quotas.
- Add systemd unit and hardening.

## Phase 4: Operational Features

- Admin CLI.
- Lease list and revoke commands.
- Slim dark Web UI for lease review.
- Ops Web UI API key issuance for users, services, and AI agents.
- Ops Web UI server onboarding with AG-Agent bootstrap.
- Console-issued Ops Login Link flow for Web UI access.
- Web UI activation window tied to active Ops Login Links and operator sessions.
- `ACCESSGATE_PUBLIC_URL` support for Docker and Kubernetes deployments.
- Explicit `ACCESSGATE_TLS_MODE=disabled-local` maintenance mode.
- Manual revoke from Web UI.
- Manual approval for unlimited serviceuser leases.
- AG-Agent health checks.
- Metrics endpoint.
- Structured logs.
- Backup and restore documentation.

## Phase 5: Policy Engine

- Per-client policies.
- Per-target policies.
- Max TTL per target/user/client.
- Rule-based policies with time windows, source networks, and enforced SSH restrictions.
- Concurrent lease quotas per requester.
- Approval workflows for unlimited serviceuser access.
- Optional approval workflows for sensitive bounded access.
- Forced command support.

## Phase 6: Kubernetes Integration

- Helm chart or manifests for AG-Server.
- Kubernetes Secret support for client API keys.
- Optional integration with existing Portal/MDSO workflows.
- AG-Agent install automation for Linux servers.
- Bootstrap job/service for target server onboarding.

## Open Decisions

- Implementation language: Go, Rust, Python, or Node.js.
- Storage: SQLite, Postgres, or embedded KV.
- Whether client-provided public keys should exist later as a restricted non-default mode.
- Admin UI: required early or CLI-first.

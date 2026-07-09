# AccessGate

AccessGate is a policy-driven SSH access broker for AI agents and automation systems, issuing temporary, auditable, and revocable access leases to managed Linux servers.

## What It Does

- Issues short-lived SSH leases instead of permanent shared access.
- Maps automation access to managed users such as `accessgate-normal` and `accessgate-elevated`.
- Supports normal and elevated AI/automation profiles.
- Generates per-lease SSH key material and returns the private key exactly once.
- Keeps an operator web panel for approvals, targets, audit history, and API keys.
- Provides a public Informer API so agents can discover the request contract.
- Pushes desired SSH access state to AG-Agents running on managed targets.

## Status

AccessGate is early software. The API, data model, deployment manifests, and security boundaries are still evolving.

## Repository Layout

```text
cmd/accessgate/        Server, agent, and CLI entrypoint
deploy/k8s/            Kubernetes deployment manifest
docs/                  Architecture, security model, API draft, onboarding
docs/workflows/        Sequence/workflow documentation
scripts/               Build helper scripts
```

## Quick Start

Build and test locally:

```bash
go test ./...
go build ./cmd/accessgate
```

Run the server:

```bash
ACCESSGATE_ADDR=:8080 \
ACCESSGATE_DATA_DIR=./data \
ACCESSGATE_PUBLIC_URL=http://localhost:8080 \
./accessgate
```

Read the public Informer:

```bash
curl http://localhost:8080/v1/informer
curl http://localhost:8080/v1/informer/agent-contract
```

## Web UI Access

The operator web UI is inactive by default. Create a short-lived Ops Login Link from a trusted runtime context:

Local server:

```bash
./accessgate -opskey --operator <name> --ttl 1h --base-url http://localhost:8080
```

Kubernetes:

```bash
kubectl -n accessgate exec deploy/accessgate -- \
  /accessgate -opskey --operator <name> --ttl 1h \
  --base-url https://accessgate.example.com
```

Open the returned link once. AccessGate consumes the token and redirects to `/ops` with an operator session cookie.

## Informer Contract

AI agents should start with:

```http
GET /v1/informer/agent-contract
```

The contract describes authentication, targets, lease schemas, SSH key handling, retry timing, cleanup rules, and error recovery.

## License

AccessGate is source-available under the PolyForm Noncommercial License 1.0.0.

You may use, study, modify, and share it for permitted non-commercial purposes. Commercial use requires prior written permission from the project owner.

See [LICENSE](LICENSE) for the full terms.

Important: this is not an OSI-approved open-source license because commercial use is restricted.

## Commercial Use

For commercial use, hosted offerings, resale, paid customer deployments, or production use in a commercial organization, request permission before using AccessGate.

## Security

AccessGate controls SSH access and should be treated as security-sensitive infrastructure. Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities.

## Documentation

- [Architecture](docs/architecture.md)
- [Security Model](docs/security-model.md)
- [AG-Agent Design](docs/agent-design.md)
- [Onboarding](docs/onboarding.md)
- [Kubernetes Deployment](docs/deployment-k8s.md)
- [API Draft](docs/api-draft.md)
- [Web UI](docs/web-ui.md)
- [Roadmap](docs/roadmap.md)

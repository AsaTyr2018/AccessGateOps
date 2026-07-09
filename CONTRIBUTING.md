# Contributing

Thanks for helping improve AccessGate.

## Development Setup

```bash
go test ./...
go build ./cmd/accessgate
```

## Expectations

- Keep security-sensitive behavior explicit and auditable.
- Do not commit secrets, API tokens, private keys, generated lease material, local data directories, or production state.
- Prefer small, reviewable changes.
- Update docs when changing API behavior, agent behavior, deployment, or security posture.
- Add or update tests for behavior that affects leases, authentication, authorization, key handling, target state, or cleanup.

## Pull Requests

Before opening a pull request:

- Run `go test ./...`.
- Confirm generated artifacts are not included.
- Document any migration or deployment impact.
- Mention any security-sensitive behavior changes.

## License

By contributing, you agree that your contributions are licensed under the repository license.

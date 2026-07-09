# Security Policy

AccessGate is security-sensitive software. It brokers SSH access, creates lease keys, manages target-side authorized keys, and exposes operator workflows.

## Reporting Vulnerabilities

Please do not open a public issue for vulnerabilities.

Report privately to the project owner or maintainer. Include:

- Affected version or commit.
- Impact and affected component.
- Reproduction steps.
- Logs or screenshots with secrets removed.
- Suggested mitigation if known.

## Sensitive Data

Never include:

- API tokens.
- Ops login links.
- Private SSH keys.
- Agent secrets.
- Production host details that are not already public.
- Lease private keys.

## Supported Versions

AccessGate is currently early-stage. Security fixes target the main development line unless otherwise stated.

## Disclosure

Please allow reasonable time for investigation and remediation before public disclosure.

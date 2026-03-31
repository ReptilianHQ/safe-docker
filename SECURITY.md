# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities by emailing [security@reptilian.dev](mailto:security@reptilian.dev).

Do not open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Model

See [THREAT_MODEL.md](./THREAT_MODEL.md) for the detailed threat model.

Key security properties:
- API key required for all operations except /health
- Dangerous actions (build, recreate) require human-in-the-loop approval via webhook
- Approval tokens are single-use, short-lived (default 2min), and never returned to the original requester
- All actions are audit-logged

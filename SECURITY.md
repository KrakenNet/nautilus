# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

Nautilus follows the version in [`pyproject.toml`](pyproject.toml); the
current release is named in the [README](README.md).

## Hardening

Configuration guidance — credentials, TLS termination, capability scoping,
keeping `/metrics` and `/admin` off a public listener — lives in
[docs/how-to/hardening.md](docs/how-to/hardening.md). A misconfiguration you
can fix from that guide is not a vulnerability report; a control that does not
hold when configured as documented is.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting: Security tab → Advisories → Report a vulnerability

### Response timeline

Acknowledge 48h, assess 7 days, fix critical within 30 days

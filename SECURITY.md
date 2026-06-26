# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use GitHub's private vulnerability reporting instead:
**[Report a vulnerability](https://github.com/John-Axe/iam-privesc-mapper/security/advisories/new)**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations

You should receive an acknowledgement within **72 hours** and a status update
within **7 days**. If you do not hear back, follow up on the same thread.

## Scope

This tool analyses IAM authorization data **locally** — it makes no outbound
connections in offline mode and only read-only IAM calls in live mode. Reports
about the tool being run against data the user controls are generally out of
scope; reports about the tool itself executing unintended code (e.g. via
malicious fixture input) are in scope.

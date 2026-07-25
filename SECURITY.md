# Security Policy

## Secrets

- Never commit domain credentials, service-account passwords, GitHub tokens, PST content, inventory databases, or production `appsettings.Production.json`.
- Use gMSA where possible. Pass a `PSCredential` interactively when a password-backed service account is unavoidable.
- Do not place PAT values in bootstrap URLs, PowerShell history, logs, or configuration files.

## Bootstrap Trust

- Prefer an internal HTTPS artifact endpoint.
- Supply `ExpectedSha256` through an independently trusted channel.
- Treat `ChecksumUri` from the same server as the bundle as an integrity check, not as a separate trust anchor.
- The installer accepts HTTP only with the explicit `AllowInsecureHttp` switch.
- PsExec is downloaded only from the Microsoft Sysinternals endpoint and must have a valid Microsoft Corporation Authenticode signature.

## Reporting

Report security issues privately to the repository owner. Do not include real credentials, mailbox content, PST files, or production inventory databases in an issue.

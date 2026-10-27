# Security policy (organization default)

This is the default policy for every repository of `ilorium-protocol`. The full policy is [SECURITY.md in the protocol repository](https://github.com/ilorium-protocol/protocol/blob/main/SECURITY.md).

## Reporting a vulnerability

Report in private. Do not open a public issue.

- Email: security@ilorium.com
- GitHub: [private vulnerability reporting](https://github.com/ilorium-protocol/protocol/security/advisories/new)

## What to expect

- Acknowledgment within 72 hours.
- Coordinated disclosure; public credit if you want it; no bounties for now.

## Scope

The protocol repository, the site (ilorium.com) and its repository, this repository, and the infrastructure of Organism Zero when it exists (planned). Organisms run by others are out of scope: their responsible party is named in their Spore. Misuse of the Ilorium name or a false Spore: open an issue with the "Misuse report" template.

## The security agent

`ilorium-security-agent[bot]` is an AI agent (Genome Law 5). It reviews pull requests, watches alerts and writes weekly reports under `governance/security/` in the protocol repository. It reviews and proposes; it never decides, never merges, and never answers with vulnerability details in public. Its code and permissions are in [security-agent/](security-agent/README.md). Its acknowledgment of mail to security@ is planned until the founder configures it; until then, a human reads the mailbox.

PGP key: planned.

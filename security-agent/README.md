# ilorium-security-agent

I am an AI agent. I review and propose; I never decide.

## Identity

- GitHub App: `ilorium-security-agent`, shown as `ilorium-security-agent[bot]`.
- Email: security-agent@ilorium.com.
- An AI (Genome Law 5). Every comment, issue and report it writes starts with the line above.
- It writes no commits and no branches (zero-write mode, decision 0002 in the protocol repository). It opens issues and comments. The commit path in `audit.py` (GraphQL `createCommitOnBranch`, GitHub signs, `Signed-off-by` from `AGENT_SIGNOFF`) exists in the code but is switched off: the workflow gives the App `Contents: read` and does not pass `AGENT_SIGNOFF`. Turning it on needs a new recorded decision.
- Its issues carry the labels `agent-authored` and `security`.
- Source: this directory. Workflows: [`../.github/workflows/`](../.github/workflows/).

Status: the agent code is written and tested offline. Everything it posts is planned until the founder creates the GitHub App and sets the variables and secrets listed below. Until then, the review workflow runs with the repository's workflow token and says so in its comment; the alert, audit and mailbox workflows print "planned" and exit.

## What it does

| Workflow | When | What |
| --- | --- | --- |
| `security-agent-review.yml` (reusable) | every pull request, from every repository | Deterministic checks over the diff: dependency changes, secret patterns and high-entropy strings, injection patterns in agent-readable files, protected paths without an IIP reference, vector changes without `needs-vectors`, workflow and policy paths, binaries. One sticky comment. Optional model review (advisory), planned until `SECURITY_AGENT_LLM_KEY` exists. |
| `security-agent-alerts.yml` | daily | Reads Dependabot, code scanning and secret scanning alerts in every repository and opens or updates one issue per alert with a proposed fix. Never includes a secret. |
| `security-agent-weekly-audit.yml` | Monday 09:00 UTC | Dependencies (pip-audit on the verifier when present), site headers, DNS (DNSSEC, CAA, MX, SPF, DMARC), organization and repository settings (read only), policy files. Opens one issue with the report (zero-write mode). A human may copy it to `governance/security/YYYY-MM-DD-report-NNNN.md` through a normal pull request. |
| `security-agent-mailbox.yml` | hourly, planned | Acknowledges mail to security@ with a template (AI disclosure, 72-hour commitment), labels it, opens a draft security advisory, notifies the founder. Runs only when `SECURITY_MAILBOX_SA_KEY` exists. |

The threat model these cover: rule changes outside governance; impersonation of the protocol (fake sites, "Ilorium certificates", Spores claiming membership: the audit checks the domain and DMARC, the misuse-report issue template exists); supply chain; prompt injection aimed at agents; account capture (the audit reads the organization settings). Fake evidence from organisms is out of scope: the verifier checks evidence, this agent does not.

## What it never does

- Never approves, requests changes on, or merges a pull request. The code has no method for it.
- Never pushes to any branch, `main` included. It holds no write permission on repository contents.
- Never publishes a release or creates a tag.
- Never changes an organization or repository setting, a ruleset, a secret or a variable.
- Never holds a production secret. The only secrets it sees are its own private key (through the token-minting action, never in the script), the optional model key, and the optional mailbox service-account key.
- Never dismisses an alert, closes an issue, or closes a mail thread.
- Never answers with vulnerability details in public.
- Never votes, never acts as Custodian, maintainer or Warden, never holds a key (governance-v1.md, section 7).

Its credentials are read plus "create issues and comments".

## GitHub App permissions

Create the App at `https://github.com/organizations/ilorium-protocol/settings/apps/new` with exactly these permissions. Each workflow then mints a token narrowed to the subset it needs (see the `permission-*` inputs in the workflows).

| Permission | Level | Used by |
| --- | --- | --- |
| Repository · Metadata | Read | all |
| Repository · Contents | Read | audit (reads policy files), review (reads the diff). Not write: zero-write mode, decision 0002. |
| Repository · Pull requests | Read and write | review (comments). Write is needed to comment on pull requests; no review-approve call exists in the code. |
| Repository · Issues | Read and write | review, alerts, audit |
| Repository · Code scanning alerts (security events) | Read | alerts, audit |
| Repository · Dependabot alerts | Read | alerts, audit |
| Repository · Secret scanning alerts | Read | alerts, audit |
| Repository · Administration | Read | audit (repository rulesets, security settings) |
| Repository · Workflows | None | — |
| Repository · Actions | None | — |
| Organization · Administration | Read | audit (2FA requirement, verified domain, default permission, security settings) |
| Organization · Members | Read | audit |

Planned, not granted today: Repository · Repository security advisories (write) for the mailbox step to open draft advisories. Grant it only when the mailbox is configured. Note: the token-minting action (`actions/create-github-app-token` v3.2.0) names the Dependabot permission `permission-vulnerability-alerts` and has no input for security advisories; the mailbox workflow therefore inherits the installation's permissions, narrowed to the protocol repository.

Subscribe to no events: the App does not receive webhooks; the workflows run on GitHub's schedule and on `pull_request`.

Install the App on the organization, "All repositories" (so the audit and the alert triage cover new repositories).

## Installation

1. Create the App as above. Name: `ilorium-security-agent`. Homepage: `https://github.com/ilorium-protocol/.github/tree/main/security-agent`. Webhook: inactive. "Where can this App be installed": only this account.
2. Generate a private key (PEM) and download it. Note the App ID.
3. Install the App on `ilorium-protocol`, all repositories.
4. In `ilorium-protocol/.github` → Settings → Secrets and variables → Actions:
   - Variable `SECURITY_AGENT_APP_ID`: the App ID.
   - Secret `SECURITY_AGENT_PRIVATE_KEY`: the PEM.
   - Do **not** define `AGENT_SIGNOFF` (zero-write mode, decision 0002). The workflow does not pass it anyway.
   - Optional secret `SECURITY_AGENT_LLM_KEY` and variable `SECURITY_AGENT_LLM_MODEL`: enable the model review step (planned).
   - Optional secret `SECURITY_MAILBOX_SA_KEY` (JSON of a Workspace service account with domain-wide delegation on security@ilorium.com, scopes gmail.readonly, gmail.modify, gmail.send) and variable `SECURITY_FOUNDER_EMAIL`: enable the mailbox step (planned).
5. The review workflow is called with `secrets: inherit` from each repository. For the App token to reach it from the protocol and site repositories, set the same `SECURITY_AGENT_APP_ID` variable and `SECURITY_AGENT_PRIVATE_KEY` secret at the **organization** level (Settings → Secrets and variables → Actions → organization), visible to all repositories. Organization-level secrets are the simplest way; repository-level copies work too.
6. Create the labels `agent-authored` and `security` in each repository (`org/labels.json` in the deployment kit). If a label is missing the agent says so in the job log and goes on.
7. Run `security-agent-weekly-audit` once by hand with `dry-run: true` and read the job summary.

## Logging

- Every action is a step in a public workflow run in this repository or in the calling repository. The run log shows every request the scripts make, with `--dry-run` output when nothing is posted.
- Every comment, issue and pull request it creates carries the AI disclosure line and a hidden marker (`<!-- ilorium-security-agent:... -->`) so it updates its own posts instead of duplicating them.
- Its commits are signed by GitHub and attributed to `ilorium-security-agent[bot]` with the human's `Signed-off-by:` trailer. `git log --author=ilorium-security-agent` lists all of them.
- When the Probe exists, the agent's actions will be recorded as beats of Organism Zero (planned, M1).

## Running locally

Standard library only; Python 3.11 or later.

```
python3 -I review.py --diff tests/fixtures/pr-clean.diff --title "x" --repo ilorium-protocol/protocol --pr 1 --dry-run
python3 -I audit.py --protocol-dir ../../protocol --skip headers,dns,org,repos --dry-run
python3 -I alerts.py --fixtures tests/fixtures/alerts.json --dry-run
python3 -I mailbox.py --print-ack
python3 -m pytest -q tests
```

Every script answers `--help`. `--dry-run` prints what would be posted instead of posting. The tests are offline: they fail on any socket connection.

## Files

| File | What |
| --- | --- |
| `review.py` | Pull request review (deterministic). |
| `llm_review.py` | Optional model review (advisory, planned). |
| `audit.py` | Weekly audit and report. |
| `alerts.py` | Alert triage into issues. |
| `mailbox.py` | Mailbox triage (planned, guarded). |
| `lib/github.py` | REST and GraphQL with urllib. No approve, merge, push, release or settings method. |
| `patterns/injection.txt` | Prompt-injection patterns (regex, one per line). |
| `patterns/secrets.txt` | Secret patterns (regex, one per line). |
| `PROMPT.md` | System prompt for the model review step. |
| `tests/` | pytest, offline, with fixture diffs and alert payloads. |

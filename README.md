# ilorium-protocol/.github

Organization-level files for `ilorium-protocol`:

- `profile/README.md`: the organization profile.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SUPPORT.md`: defaults inherited by every repository that has none.
- `.github/ISSUE_TEMPLATE/`: shared issue templates (copies of the protocol repository's).
- `.github/workflows/`: the security agent's workflows. `security-agent-review.yml` is reusable (`workflow_call`) and is called from every repository; the others run on a schedule here.
- `security-agent/`: the code and the identity of `ilorium-security-agent` (AI). See [security-agent/README.md](security-agent/README.md).

Licenses: code under Apache-2.0 (`LICENSE`); text under CC BY 4.0 where stated. Copyright The Ilorium Authors.

Status: release 1.0, draft. Interim governance.

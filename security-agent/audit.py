#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
"""Weekly security audit by the Ilorium security agent.

I am an AI agent. I review and propose; I never decide.

Sections of the audit, each reported as observed / not observed:

  dependencies   pip-audit over the verifier (if ``verifier/pyproject.toml`` exists
                 in the protocol checkout); otherwise "not observed: verifier absent".
  headers        HTTP response headers of https://ilorium.com (the list the site's
                 ``_headers`` file promises).
  dns            DNSSEC (DS, RRSIG), CAA, MX, SPF, DMARC, via ``dig`` on the runner.
  org            Organization and repository settings through the API: 2FA required,
                 verified domain, default repository permission, rulesets present,
                 secret scanning and push protection, Dependabot alerts, private
                 vulnerability reporting. Read-only.
  repo-files     SECURITY.md, CODEOWNERS, dependabot.yml, CodeQL workflow, the
                 security.txt in the site checkout.

Output: a Markdown report ``governance/security/YYYY-MM-DD-report-NNNN.md``. With
``--publish`` the agent commits it to a branch ``security-agent/report-YYYY-MM-DD``
of the protocol repository through GraphQL ``createCommitOnBranch`` (GitHub signs
the commit) with the trailer ``Signed-off-by:`` from the variable ``AGENT_SIGNOFF``,
and opens a pull request labeled ``agent-authored``, ``security``. Without
``AGENT_SIGNOFF`` it does not commit: it opens an issue with the report body.

Nothing in this script changes a setting, a secret, a branch other than its own
report branch, or a pull request's state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.github import AI_DISCLOSURE, GitHub, GitHubError  # noqa: E402

ORG = "ilorium-protocol"
PROTOCOL_REPO = "protocol"
SITE_ORIGIN = "https://ilorium.com"
DOMAIN = "ilorium.com"

# The headers the site's public/_headers promises for "/*". Values are checked
# for presence and, where a value is given, for containment of the expected text.
EXPECTED_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
}

AGENT_READABLE_PATHS = ("/llms.txt", "/.well-known/security.txt", "/.well-known/ilorium.json")


class Obs:
    """One observation line: observed / not observed, with a short detail."""

    def __init__(self, section: str, item: str, observed: bool | None, detail: str = ""):
        self.section = section
        self.item = item
        self.observed = observed  # True, False, or None = could not check
        self.detail = detail

    def word(self) -> str:
        if self.observed is True:
            return "observed"
        if self.observed is False:
            return "not observed"
        return "not checked"

    def to_dict(self):
        return {"section": self.section, "item": self.item, "status": self.word(), "detail": self.detail}


# ---------------------------------------------------------------------------
# dependencies

def audit_dependencies(protocol_dir: Path | None) -> list[Obs]:
    out: list[Obs] = []
    if not protocol_dir or not (protocol_dir / "verifier" / "pyproject.toml").exists():
        out.append(Obs("dependencies", "verifier/pyproject.toml present", False, "M0 code not published yet; pip-audit skipped."))
        return out
    out.append(Obs("dependencies", "verifier/pyproject.toml present", True))
    pip_audit = shutil.which("pip-audit")
    if not pip_audit:
        out.append(Obs("dependencies", "pip-audit available on the runner", False, "install step missing"))
        return out
    try:
        r = subprocess.run([pip_audit, "--format", "json", "--progress-spinner", "off", "."],
                           cwd=str(protocol_dir / "verifier"), capture_output=True, text=True, timeout=600)
        data = json.loads(r.stdout or "{}")
        deps = data.get("dependencies", data if isinstance(data, list) else [])
        vulns = [(d.get("name"), d.get("version"), v.get("id")) for d in deps for v in d.get("vulns", [])]
        if vulns:
            out.append(Obs("dependencies", "known vulnerabilities in verifier dependencies", True,
                           "; ".join(f"{n} {ver}: {vid}" for n, ver, vid in vulns[:20])))
        else:
            out.append(Obs("dependencies", "known vulnerabilities in verifier dependencies", False, f"{len(deps)} packages audited"))
    except Exception as e:  # noqa: BLE001
        out.append(Obs("dependencies", "pip-audit run", None, f"failed: {e}"))
    return out


# ---------------------------------------------------------------------------
# headers

def fetch_headers(url: str, timeout: int = 20) -> tuple[int | None, dict[str, str], str]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "ilorium-security-agent (AI)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, ""
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, ""
    except Exception as e:  # noqa: BLE001
        return None, {}, str(e)


def check_headers(headers: dict[str, str], expected: dict[str, str] = EXPECTED_HEADERS) -> list[Obs]:
    out = []
    for name, must_contain in expected.items():
        val = headers.get(name)
        if val is None:
            out.append(Obs("headers", f"{name}", False))
        elif must_contain and must_contain.lower() not in val.lower():
            out.append(Obs("headers", f"{name}", False, f"present but without `{must_contain}`: `{val[:120]}`"))
        else:
            out.append(Obs("headers", f"{name}", True, f"`{val[:120]}`"))
    return out


def audit_headers(origin: str) -> list[Obs]:
    status, headers, err = fetch_headers(origin + "/")
    if status is None:
        return [Obs("headers", f"{origin} reachable", None, err)]
    out = [Obs("headers", f"{origin} reachable", True, f"HTTP {status}")]
    out.extend(check_headers(headers))
    for path in AGENT_READABLE_PATHS:
        st, h, e = fetch_headers(origin + path)
        if st is None:
            out.append(Obs("headers", f"{path}", None, e))
            continue
        ok = st == 200
        detail = f"HTTP {st}; content-type `{h.get('content-type', '-')}`; access-control-allow-origin `{h.get('access-control-allow-origin', '-')}`"
        out.append(Obs("headers", f"{path} served", ok, detail))
    return out


# ---------------------------------------------------------------------------
# dns

def dig(qtype: str, name: str) -> list[str]:
    exe = shutil.which("dig")
    if not exe:
        raise FileNotFoundError("dig")
    r = subprocess.run([exe, "+short", "+time=5", "+tries=2", qtype, name], capture_output=True, text=True, timeout=30)
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def audit_dns(domain: str) -> list[Obs]:
    out: list[Obs] = []
    try:
        dig("A", domain)
    except FileNotFoundError:
        return [Obs("dns", "dig available on the runner", None, "dig not installed")]

    def q(qtype, name):
        try:
            return dig(qtype, name)
        except Exception as e:  # noqa: BLE001
            return [f"error: {e}"]

    ds = q("DS", domain)
    out.append(Obs("dns", "DNSSEC DS record at the parent", bool(ds), "; ".join(ds)[:200]))
    rrsig = q("RRSIG", domain)
    out.append(Obs("dns", "RRSIG on the apex", bool(rrsig), f"{len(rrsig)} signature(s)"))
    caa = q("CAA", domain)
    out.append(Obs("dns", "CAA records", bool(caa), "; ".join(caa)[:300]))
    if caa:
        out.append(Obs("dns", "CAA iodef to security@", any("iodef" in c and "security@" in c for c in caa)))
    mx = q("MX", domain)
    out.append(Obs("dns", "MX records", bool(mx), "; ".join(mx)[:200]))
    txt = q("TXT", domain)
    spf = [t for t in txt if "v=spf1" in t]
    out.append(Obs("dns", "SPF record", bool(spf), "; ".join(spf)[:200]))
    if spf:
        out.append(Obs("dns", "SPF ends with -all", any("-all" in s for s in spf)))
    dmarc = q("TXT", f"_dmarc.{domain}")
    dmarc = [t for t in dmarc if "v=DMARC1" in t]
    out.append(Obs("dns", "DMARC record", bool(dmarc), "; ".join(dmarc)[:200]))
    if dmarc:
        policy = re.search(r"p=(\w+)", dmarc[0])
        p = policy.group(1) if policy else "?"
        out.append(Obs("dns", "DMARC policy quarantine or reject", p in ("quarantine", "reject"), f"p={p}"))
    gh_challenge = q("TXT", f"_github-challenge-{ORG}.{domain}")
    out.append(Obs("dns", "GitHub domain verification TXT", bool(gh_challenge)))
    return out


# ---------------------------------------------------------------------------
# org and repositories

def audit_org(gh: GitHub, org: str) -> list[Obs]:
    out: list[Obs] = []
    try:
        o = gh.org_settings(org)
    except GitHubError as e:
        return [Obs("org", "organization settings readable", None, f"API {e.status}")]
    except Exception as e:  # noqa: BLE001
        return [Obs("org", "organization settings readable", None, str(e))]

    def flag(key, label, want=True):
        v = o.get(key)
        if v is None:
            out.append(Obs("org", label, None, f"field `{key}` not returned (permission?)"))
        else:
            out.append(Obs("org", label, (v == want), f"{key}={v}"))

    flag("two_factor_requirement_enabled", "two-factor authentication required")
    flag("is_verified", "domain verified")
    perm = o.get("default_repository_permission")
    out.append(Obs("org", "default repository permission is read or none", perm in ("read", "none", None) and perm is not None, f"{perm}"))
    flag("members_can_create_public_repositories", "members cannot create public repositories", want=False)
    flag("dependabot_alerts_enabled_for_new_repositories", "Dependabot alerts enabled for new repositories")
    flag("dependabot_security_updates_enabled_for_new_repositories", "Dependabot security updates for new repositories")
    flag("secret_scanning_enabled_for_new_repositories", "secret scanning for new repositories")
    flag("secret_scanning_push_protection_enabled_for_new_repositories", "push protection for new repositories")
    flag("advanced_security_enabled_for_new_repositories", "code security for new repositories")

    try:
        rs = gh.org_rulesets(org)
        names = [r.get("name") for r in rs]
        out.append(Obs("org", "organization rulesets present", bool(rs), ", ".join(map(str, names))[:200]))
    except Exception as e:  # noqa: BLE001
        out.append(Obs("org", "organization rulesets present", None, str(e)[:120]))
    return out


def audit_repos(gh: GitHub, org: str) -> list[Obs]:
    out: list[Obs] = []
    try:
        repos = gh.org_repos(org)
    except Exception as e:  # noqa: BLE001
        return [Obs("repos", "repository list readable", None, str(e)[:120])]
    for r in repos:
        name = r["name"]
        sa = r.get("security_and_analysis") or {}
        for key, label in (("secret_scanning", "secret scanning"),
                           ("secret_scanning_push_protection", "push protection"),
                           ("dependabot_security_updates", "Dependabot security updates")):
            v = (sa.get(key) or {}).get("status")
            out.append(Obs("repos", f"{name}: {label}", (v == "enabled") if v else None, v or "field absent"))
        try:
            pvr = gh.private_vulnerability_reporting(org, name)
            out.append(Obs("repos", f"{name}: private vulnerability reporting", bool(pvr.get("enabled"))))
        except Exception as e:  # noqa: BLE001
            out.append(Obs("repos", f"{name}: private vulnerability reporting", None, str(e)[:100]))
        try:
            rs = gh.repo_rulesets(org, name)
            out.append(Obs("repos", f"{name}: rulesets apply", bool(rs), ", ".join(str(x.get("name")) for x in rs)[:160]))
        except Exception as e:  # noqa: BLE001
            out.append(Obs("repos", f"{name}: rulesets apply", None, str(e)[:100]))
    return out


# ---------------------------------------------------------------------------
# files in checkouts

def audit_repo_files(protocol_dir: Path | None, site_dir: Path | None, github_dir: Path | None) -> list[Obs]:
    out: list[Obs] = []

    def present(section, base: Path | None, rel: str, label: str | None = None):
        label = label or rel
        if base is None:
            out.append(Obs(section, label, None, "checkout not provided"))
            return False
        ok = (base / rel).exists()
        out.append(Obs(section, label, ok))
        return ok

    if protocol_dir is not None:
        for rel in ("SECURITY.md", "CODEOWNERS", ".github/dependabot.yml", ".github/workflows/codeql.yml",
                    ".github/workflows/dco.yml", ".github/workflows/agent-readable-files.yml",
                    ".github/workflows/security-agent-review.yml", "governance/security/README.md",
                    "vectors/index.json", "verifier/pyproject.toml"):
            present("protocol-files", protocol_dir, rel)
    if site_dir is not None:
        for rel in ("public/_headers", "public/.well-known/security.txt", "public/.well-known/ilorium.json",
                    "public/llms.txt", ".github/workflows/security-agent-review.yml"):
            present("site-files", site_dir, rel)
    if github_dir is not None:
        for rel in ("SECURITY.md", "security-agent/README.md", ".github/workflows/security-agent-review.yml",
                    ".github/workflows/security-agent-alerts.yml", ".github/workflows/security-agent-weekly-audit.yml"):
            present("org-files", github_dir, rel)
    return out


# ---------------------------------------------------------------------------
# report

def next_report_number(protocol_dir: Path | None) -> int:
    if not protocol_dir:
        return 1
    d = protocol_dir / "governance" / "security"
    if not d.exists():
        return 1
    nums = [int(m.group(1)) for p in d.glob("*-report-*.md") for m in [re.search(r"report-(\d{4})", p.name)] if m]
    return (max(nums) + 1) if nums else 1


def render_report(date: str, number: int, observations: list[Obs], recommended: list[str],
                  limits: list[str]) -> str:
    title = f"Security report {number:04d} · {date}"
    lines = [f"# {title}", "", f"{AI_DISCLOSURE} This report was produced by `ilorium-security-agent` (AI, Genome Law 5) from a scheduled workflow run. Every line is an observation; nothing here is a verdict about any organism.", ""]
    observed = [o for o in observations if o.observed is True]
    not_observed = [o for o in observations if o.observed is False]
    not_checked = [o for o in observations if o.observed is None]

    def block(heading, items, prefix=""):
        lines.append(f"## {heading}")
        lines.append("")
        if not items:
            lines.append("- none")
        for o in items:
            detail = f" — {o.detail}" if o.detail else ""
            lines.append(f"- {prefix}{o.section}: {o.item}{detail}")
        lines.append("")

    block("Observed", observed)
    block("Not observed", not_observed, prefix="not observed: ")
    if not_checked:
        block("Not checked", not_checked, prefix="not checked: ")
    lines.append("## Recommended")
    lines.append("")
    if recommended:
        for i, r in enumerate(recommended, 1):
            lines.append(f"{i}. {r}")
    else:
        lines.append("- nothing new this week")
    lines.append("")
    lines.append("## Limits of this report")
    lines.append("")
    for l in limits:
        lines.append(f"- {l}")
    lines.append("")
    return "\n".join(lines)


def default_recommendations(observations: list[Obs]) -> list[str]:
    rec = []
    missing = {(o.section, o.item) for o in observations if o.observed is False}
    order = [
        (("org", "two-factor authentication required"), "Require two-factor authentication for every member of the organization."),
        (("org", "organization rulesets present"), "Import the rulesets in `org/rulesets/` so that `main` and `protocol/*` tags are protected."),
        (("org", "domain verified"), "Verify `ilorium.com` in the organization settings (DNS TXT challenge)."),
        (("org", "push protection for new repositories"), "Enable secret scanning and push protection for the organization."),
        (("dns", "DMARC record"), "Publish SPF, DKIM and DMARC for `ilorium.com`; start with `p=quarantine`."),
        (("dns", "DNSSEC DS record at the parent"), "Enable DNSSEC at the registrar and the DNS host."),
        (("dns", "CAA records"), "Publish CAA records limiting issuance to the CAs Cloudflare Pages uses, with `iodef` to security@."),
        (("headers", "strict-transport-security"), "Deploy the site's `_headers` file so the security headers reach the origin."),
    ]
    for key, text in order:
        if key in missing:
            rec.append(text)
    for o in observations:
        if o.section == "repos" and o.item.endswith("private vulnerability reporting") and o.observed is False:
            rec.append(f"Enable private vulnerability reporting on `{o.item.split(':')[0]}`.")
    return rec


DEFAULT_LIMITS = [
    "The agent reads; it does not change settings, DNS, secrets or branches other than its own report branch.",
    "An observation reflects one request at one time from one GitHub-hosted runner; it is not a continuous monitor.",
    "Evidence published by organisms is out of scope: the verifier checks evidence, this agent does not.",
    "Items marked not checked could not be read with the agent's permissions or tools; they are not failures.",
    "The model review step, if enabled, is advisory and never changes an observation.",
]


# ---------------------------------------------------------------------------
# publish

def publish(gh: GitHub, report: str, rel_path: str, date: str, number: int, signoff: str | None,
            base_branch: str = "main") -> None:
    owner, repo = ORG, PROTOCOL_REPO
    title = f"Security report {number:04d} · {date}"
    pr_body = (
        f"{AI_DISCLOSURE}\n\n"
        f"Weekly security report written by `ilorium-security-agent` (AI). Adds `{rel_path}`.\n\n"
        "The commit was created through GitHub's `createCommitOnBranch` mutation, so GitHub signed it. "
        "The `Signed-off-by:` trailer names the human responsible for this agent (DCO).\n\n"
        "A human Custodian reviews and merges. I never merge."
    )
    if not signoff:
        print("[audit] AGENT_SIGNOFF is not set: no commit is made. Opening an issue with the report instead.", file=sys.stderr)
        body = (f"{AI_DISCLOSURE}\n\n"
                "The repository variable `AGENT_SIGNOFF` is not set, so I did not commit this report. "
                "Set it to `Name <email>` of the responsible human and the next run will open a pull request.\n\n"
                f"Intended path: `{rel_path}`\n\n---\n\n{report}")
        gh.create_issue(owner, repo, title, body, labels=["security", "agent-authored"])
        return
    branch = f"security-agent/report-{date}"
    head = "0" * 40
    if not gh.dry_run:
        head = gh.branch_head_oid(owner, repo, base_branch)
        try:
            gh.create_branch(owner, repo, branch, head)
        except GitHubError as e:
            if e.status != 422:
                raise
            head = gh.branch_head_oid(owner, repo, branch)
    else:
        gh.create_branch(owner, repo, branch, head)
    message_body = f"Weekly report by ilorium-security-agent (AI).\n\nSigned-off-by: {signoff}"
    gh.create_commit_on_branch(owner, repo, branch, head, f"governance: {title.lower()}", message_body, {rel_path: report})
    pr = gh.create_pull_request(owner, repo, title, branch, base_branch, pr_body)
    number_ = pr.get("number") if isinstance(pr, dict) else None
    if number_:
        gh.add_labels(owner, repo, number_, ["agent-authored", "security"])
    elif gh.dry_run:
        gh.add_labels(owner, repo, 0, ["agent-authored", "security"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--protocol-dir", help="Checkout of ilorium-protocol/protocol (optional).")
    ap.add_argument("--site-dir", help="Checkout of ilorium-protocol/site (optional).")
    ap.add_argument("--github-dir", help="Checkout of ilorium-protocol/.github (optional).")
    ap.add_argument("--origin", default=SITE_ORIGIN)
    ap.add_argument("--domain", default=DOMAIN)
    ap.add_argument("--org", default=ORG)
    ap.add_argument("--skip", default="", help="Comma-separated sections to skip: dependencies,headers,dns,org,repos,files")
    ap.add_argument("--date", default=dt.date.today().isoformat())
    ap.add_argument("--number", type=int, help="Report number; default: next after the ones in governance/security/.")
    ap.add_argument("--out", help="Write the report to this path.")
    ap.add_argument("--json", help="Write observations as JSON to this path.")
    ap.add_argument("--publish", action="store_true", help="Commit the report to a branch and open a PR (or an issue if AGENT_SIGNOFF is absent).")
    ap.add_argument("--dry-run", action="store_true", help="Print what would be posted instead of posting.")
    args = ap.parse_args(argv)

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    protocol_dir = Path(args.protocol_dir) if args.protocol_dir else None
    site_dir = Path(args.site_dir) if args.site_dir else None
    github_dir = Path(args.github_dir) if args.github_dir else None

    obs: list[Obs] = []
    gh = GitHub(dry_run=args.dry_run)
    if "dependencies" not in skip:
        obs += audit_dependencies(protocol_dir)
    if "headers" not in skip:
        obs += audit_headers(args.origin)
    if "dns" not in skip:
        obs += audit_dns(args.domain)
    if "org" not in skip:
        obs += audit_org(gh, args.org) if gh.token else [Obs("org", "organization settings readable", None, "no token")]
    if "repos" not in skip:
        obs += audit_repos(gh, args.org) if gh.token else [Obs("repos", "repository list readable", None, "no token")]
    if "files" not in skip:
        obs += audit_repo_files(protocol_dir, site_dir, github_dir)

    number = args.number or next_report_number(protocol_dir)
    report = render_report(args.date, number, obs, default_recommendations(obs), DEFAULT_LIMITS)
    rel_path = f"governance/security/{args.date}-report-{number:04d}.md"

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps([o.to_dict() for o in obs], indent=2), encoding="utf-8")
    print(report)

    if args.publish or args.dry_run:
        publish(gh, report, rel_path, args.date, number, os.environ.get("AGENT_SIGNOFF"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

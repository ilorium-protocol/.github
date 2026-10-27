#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
"""Alert triage by the Ilorium security agent.

I am an AI agent. I review and propose; I never decide.

Reads, for every repository of the organization, the open Dependabot, code
scanning and secret scanning alerts, and opens or updates ONE issue per alert in
the affected repository, labeled ``security``, with a proposed fix. It never
dismisses an alert, never changes a dependency, never touches a setting.

Needs the App permissions: Dependabot alerts: read; Code scanning alerts
(security events): read; Secret scanning alerts: read; Issues: write; Metadata: read.
A repository where the alert API answers 403 or 404 (feature not enabled) is
reported as "not observed" and skipped.

Secret scanning alerts: the issue never includes the secret, its location in
full, or the alert's raw payload. It names the alert number and the secret
type only; the details stay in the Security tab.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.github import AI_DISCLOSURE, GitHub, GitHubError  # noqa: E402

ORG = "ilorium-protocol"
MARKER_PREFIX = "<!-- ilorium-security-agent:alert:"


def marker(kind: str, repo: str, number: int) -> str:
    return f"{MARKER_PREFIX}{kind}:{repo}:{number} -->"


# ---------------------------------------------------------------------------
# normalize alerts

def normalize_dependabot(repo: str, a: dict) -> dict:
    adv = a.get("security_advisory") or {}
    dep = a.get("dependency") or {}
    pkg = (dep.get("package") or {})
    vuln = a.get("security_vulnerability") or {}
    fixed = (vuln.get("first_patched_version") or {}).get("identifier")
    return {
        "kind": "dependabot",
        "repo": repo,
        "number": a.get("number"),
        "title": f"Dependabot alert #{a.get('number')}: {pkg.get('name')} ({pkg.get('ecosystem')}) {adv.get('severity', '')}".strip(),
        "severity": adv.get("severity", "unknown"),
        "summary": adv.get("summary", ""),
        "ids": [adv.get("ghsa_id"), adv.get("cve_id")],
        "manifest": dep.get("manifest_path"),
        "vulnerable_range": vuln.get("vulnerable_version_range"),
        "fix": f"Update `{pkg.get('name')}` to `{fixed}` or later in `{dep.get('manifest_path')}`." if fixed else f"No patched version is published yet for `{pkg.get('name')}`. Consider removing the dependency or isolating its use.",
        "url": a.get("html_url"),
    }


def normalize_code_scanning(repo: str, a: dict) -> dict:
    rule = a.get("rule") or {}
    inst = a.get("most_recent_instance") or {}
    loc = inst.get("location") or {}
    where = f"`{loc.get('path')}` line {loc.get('start_line')}" if loc.get("path") else "see alert"
    return {
        "kind": "code-scanning",
        "repo": repo,
        "number": a.get("number"),
        "title": f"Code scanning alert #{a.get('number')}: {rule.get('id') or rule.get('name')} ({rule.get('severity', '')})".strip(),
        "severity": rule.get("security_severity_level") or rule.get("severity", "unknown"),
        "summary": rule.get("description", ""),
        "ids": [rule.get("id")],
        "manifest": where,
        "vulnerable_range": None,
        "fix": f"Review {where}. Rule: {rule.get('name') or rule.get('id')}. Apply the fix the rule describes or document why the pattern is intended.",
        "url": a.get("html_url"),
    }


def normalize_secret_scanning(repo: str, a: dict) -> dict:
    # Never carry the secret or its exact location into the issue.
    return {
        "kind": "secret-scanning",
        "repo": repo,
        "number": a.get("number"),
        "title": f"Secret scanning alert #{a.get('number')}: {a.get('secret_type_display_name') or a.get('secret_type')}",
        "severity": "high",
        "summary": "A string that matches a known credential format was found in the repository history.",
        "ids": [],
        "manifest": "see the Security tab",
        "vulnerable_range": None,
        "fix": "Revoke the credential at its provider first; then remove it from history if the maintainers decide to, and close the alert with a reason. The value is not reproduced here.",
        "url": a.get("html_url"),
    }


def render_issue(n: dict) -> str:
    ids = ", ".join(i for i in n["ids"] if i)
    lines = [
        marker(n["kind"], n["repo"], n["number"]),
        f"**{AI_DISCLOSURE}**",
        "",
        f"Alert: {n['url'] or 'see the Security tab'}",
        f"Severity (as reported by GitHub): {n['severity']}",
    ]
    if ids:
        lines.append(f"Identifiers: {ids}")
    if n.get("manifest"):
        lines.append(f"Where: {n['manifest']}")
    if n.get("vulnerable_range"):
        lines.append(f"Vulnerable range: `{n['vulnerable_range']}`")
    lines += ["", "## Observed", "", n["summary"] or "GitHub reported this alert as open.", "",
              "## Proposed", "", n["fix"], "",
              "## Limits", "",
              "I opened this issue so the alert is on the record. I did not change any dependency, file or setting. A maintainer decides what to do and closes this issue; the alert itself is closed in the Security tab.",
              "", "— ilorium-security-agent (AI)"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main

def collect(gh: GitHub, org: str, repos: list[str] | None = None) -> tuple[list[dict], list[str]]:
    notes: list[str] = []
    alerts: list[dict] = []
    repo_names = repos or [r["name"] for r in gh.org_repos(org)]
    for name in repo_names:
        for label, fetch, norm in (
            ("dependabot", gh.dependabot_alerts, normalize_dependabot),
            ("code scanning", gh.code_scanning_alerts, normalize_code_scanning),
            ("secret scanning", gh.secret_scanning_alerts, normalize_secret_scanning),
        ):
            try:
                for a in fetch(org, name):
                    alerts.append(norm(name, a))
            except GitHubError as e:
                if e.status in (403, 404):
                    notes.append(f"not observed: {name}: {label} alerts (API {e.status}; feature not enabled or no permission)")
                else:
                    notes.append(f"not checked: {name}: {label} alerts (API {e.status})")
            except Exception as e:  # noqa: BLE001
                notes.append(f"not checked: {name}: {label} alerts ({e})")
    return alerts, notes


def upsert_issue(gh: GitHub, org: str, n: dict) -> None:
    body = render_issue(n)
    mk = marker(n["kind"], n["repo"], n["number"])
    existing = None
    if not gh.dry_run:
        q = f'repo:{org}/{n["repo"]} is:issue in:body "{mk}"'
        for it in gh.search_issues(q):
            if mk in (it.get("body") or ""):
                existing = it
                break
    if existing:
        if (existing.get("body") or "") != body:
            gh.update_issue(org, n["repo"], existing["number"], body=body)
        return
    gh.create_issue(org, n["repo"], n["title"], body, labels=["security", "agent-authored"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", default=ORG)
    ap.add_argument("--repos", default="", help="Comma-separated repository names (default: all in the org).")
    ap.add_argument("--fixtures", help="Offline: a JSON file {repo: {dependabot: [...], code_scanning: [...], secret_scanning: [...]}}")
    ap.add_argument("--dry-run", action="store_true", help="Print what would be posted instead of posting.")
    ap.add_argument("--json", help="Write normalized alerts to this path.")
    args = ap.parse_args(argv)

    gh = GitHub(dry_run=args.dry_run)
    print(AI_DISCLOSURE)

    if args.fixtures:
        data = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))
        alerts, notes = [], []
        for repo, groups in data.items():
            alerts += [normalize_dependabot(repo, a) for a in groups.get("dependabot", [])]
            alerts += [normalize_code_scanning(repo, a) for a in groups.get("code_scanning", [])]
            alerts += [normalize_secret_scanning(repo, a) for a in groups.get("secret_scanning", [])]
        gh.dry_run = True
    else:
        if not gh.token:
            print("[alerts] no GITHUB_TOKEN; nothing to read.", file=sys.stderr)
            return 2
        repos = [r.strip() for r in args.repos.split(",") if r.strip()] or None
        alerts, notes = collect(gh, args.org, repos)

    for note in notes:
        print(note)
    print(f"[alerts] {len(alerts)} open alert(s).", file=sys.stderr)
    if args.json:
        Path(args.json).write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    for n in alerts:
        upsert_issue(gh, args.org, n)
    return 0


if __name__ == "__main__":
    sys.exit(main())

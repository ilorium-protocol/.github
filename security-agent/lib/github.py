# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
"""Minimal GitHub REST and GraphQL client for the Ilorium security agent.

Standard library only (urllib, json). The token comes from the environment:
``GITHUB_TOKEN`` (an installation token of the ``ilorium-security-agent``
GitHub App, or the workflow token as a fallback).

Design limits, on purpose:

- There is no method that approves a pull request, merges one, pushes to a
  branch, creates a release, or changes a repository or organization setting.
  The agent reviews and proposes; it never decides.
- Every write method takes ``dry_run``; when true it prints the request and
  returns a placeholder instead of calling the API.
- Commits are made only through the GraphQL ``createCommitOnBranch`` mutation,
  so GitHub signs them with its own key. The agent holds no signing key.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
GRAPHQL = "https://api.github.com/graphql"
USER_AGENT = "ilorium-security-agent (AI; +https://github.com/ilorium-protocol/.github)"

AI_DISCLOSURE = "I am an AI agent. I review and propose; I never decide."


class GitHubError(RuntimeError):
    """An HTTP error from the GitHub API, with status and body."""

    def __init__(self, status: int, body: str, url: str):
        super().__init__(f"GitHub API {status} for {url}: {body[:500]}")
        self.status = status
        self.body = body
        self.url = url


def token_from_env() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


class GitHub:
    """REST + GraphQL helper. Read methods are plain; write methods honor dry_run."""

    def __init__(self, token: str | None = None, api: str = API, graphql: str = GRAPHQL,
                 dry_run: bool = False, out=None):
        self.token = token if token is not None else token_from_env()
        self.api = api.rstrip("/")
        self.graphql_url = graphql
        self.dry_run = dry_run
        self.out = out or sys.stdout

    # ---- transport -------------------------------------------------------

    def _headers(self, extra: dict | None = None) -> dict:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if extra:
            h.update(extra)
        return h

    def request(self, method: str, path: str, body: dict | list | None = None,
                params: dict | None = None, retries: int = 2):
        """Perform a REST call. ``path`` is absolute (``/repos/...``) or a full URL."""
        url = path if path.startswith("http") else self.api + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        last_err: Exception | None = None
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    raw = resp.read()
                    if not raw:
                        return None
                    ctype = resp.headers.get("Content-Type", "")
                    if "json" in ctype:
                        return json.loads(raw.decode("utf-8"))
                    return raw.decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code in (502, 503, 504) and attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    last_err = e
                    continue
                raise GitHubError(e.code, text, url) from None
            except urllib.error.URLError as e:
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    last_err = e
                    continue
                raise
        raise RuntimeError(f"request failed after retries: {last_err}")

    def get(self, path: str, params: dict | None = None):
        return self.request("GET", path, params=params)

    def paginate(self, path: str, params: dict | None = None, key: str | None = None,
                 max_pages: int = 20):
        """Iterate over a paginated list endpoint (per_page=100)."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 1
        while page <= max_pages:
            params["page"] = page
            data = self.get(path, params=params)
            items = data.get(key, []) if (key and isinstance(data, dict)) else data
            if not items:
                return
            for item in items:
                yield item
            if len(items) < params["per_page"]:
                return
            page += 1

    def graphql(self, query: str, variables: dict | None = None):
        body = {"query": query, "variables": variables or {}}
        data = json.dumps(body).encode("utf-8")
        headers = self._headers({"Content-Type": "application/json"})
        req = urllib.request.Request(self.graphql_url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise GitHubError(e.code, e.read().decode("utf-8", "replace"), self.graphql_url) from None
        if payload.get("errors"):
            raise RuntimeError("GraphQL errors: " + json.dumps(payload["errors"])[:1000])
        return payload.get("data")

    # ---- dry-run helper --------------------------------------------------

    def _would(self, what: str, payload) -> dict:
        print(f"[dry-run] would {what}:", file=self.out)
        print(json.dumps(payload, indent=2, ensure_ascii=False)[:4000], file=self.out)
        return {"dry_run": True, "action": what}

    # ---- read: repositories, pull requests, alerts -----------------------

    def org_repos(self, org: str):
        return list(self.paginate(f"/orgs/{org}/repos", params={"type": "all"}))

    def pull_files(self, owner: str, repo: str, number: int):
        return list(self.paginate(f"/repos/{owner}/{repo}/pulls/{number}/files"))

    def pull(self, owner: str, repo: str, number: int):
        return self.get(f"/repos/{owner}/{repo}/pulls/{number}")

    def issue_comments(self, owner: str, repo: str, number: int):
        return list(self.paginate(f"/repos/{owner}/{repo}/issues/{number}/comments"))

    def search_issues(self, query: str):
        return list(self.paginate("/search/issues", params={"q": query}, key="items", max_pages=5))

    def dependabot_alerts(self, owner: str, repo: str, state: str = "open"):
        return list(self.paginate(f"/repos/{owner}/{repo}/dependabot/alerts", params={"state": state}))

    def code_scanning_alerts(self, owner: str, repo: str, state: str = "open"):
        return list(self.paginate(f"/repos/{owner}/{repo}/code-scanning/alerts", params={"state": state}))

    def secret_scanning_alerts(self, owner: str, repo: str, state: str = "open"):
        return list(self.paginate(f"/repos/{owner}/{repo}/secret-scanning/alerts", params={"state": state}))

    def org_settings(self, org: str):
        return self.get(f"/orgs/{org}")

    def org_rulesets(self, org: str):
        return list(self.paginate(f"/orgs/{org}/rulesets"))

    def repo_rulesets(self, owner: str, repo: str):
        return list(self.paginate(f"/repos/{owner}/{repo}/rulesets"))

    def repo(self, owner: str, repo: str):
        return self.get(f"/repos/{owner}/{repo}")

    def private_vulnerability_reporting(self, owner: str, repo: str):
        return self.get(f"/repos/{owner}/{repo}/private-vulnerability-reporting")

    def branch_head_oid(self, owner: str, repo: str, branch: str) -> str:
        data = self.get(f"/repos/{owner}/{repo}/git/ref/heads/{branch}")
        return data["object"]["sha"]

    # ---- write: comments, issues, pull requests, branches, commits -------
    # No approve. No merge. No push. No release. No settings.

    def create_comment(self, owner: str, repo: str, number: int, body: str):
        payload = {"body": body}
        if self.dry_run:
            return self._would(f"create comment on {owner}/{repo}#{number}", payload)
        return self.request("POST", f"/repos/{owner}/{repo}/issues/{number}/comments", body=payload)

    def update_comment(self, owner: str, repo: str, comment_id: int, body: str):
        payload = {"body": body}
        if self.dry_run:
            return self._would(f"update comment {comment_id} on {owner}/{repo}", payload)
        return self.request("PATCH", f"/repos/{owner}/{repo}/issues/comments/{comment_id}", body=payload)

    def upsert_sticky_comment(self, owner: str, repo: str, number: int, marker: str, body: str):
        """Create or update the one comment that carries ``marker`` (an HTML comment)."""
        if marker not in body:
            body = f"{marker}\n{body}"
        existing = None
        if not self.dry_run:
            for c in self.issue_comments(owner, repo, number):
                if marker in (c.get("body") or ""):
                    existing = c
                    break
        if existing:
            return self.update_comment(owner, repo, existing["id"], body)
        return self.create_comment(owner, repo, number, body)

    def create_issue(self, owner: str, repo: str, title: str, body: str, labels: list[str] | None = None):
        payload = {"title": title, "body": body, "labels": labels or []}
        if self.dry_run:
            return self._would(f"create issue in {owner}/{repo}", payload)
        return self.request("POST", f"/repos/{owner}/{repo}/issues", body=payload)

    def update_issue(self, owner: str, repo: str, number: int, title: str | None = None,
                     body: str | None = None, labels: list[str] | None = None):
        payload = {}
        if title is not None:
            payload["title"] = title
        if body is not None:
            payload["body"] = body
        if labels is not None:
            payload["labels"] = labels
        if self.dry_run:
            return self._would(f"update issue {owner}/{repo}#{number}", payload)
        return self.request("PATCH", f"/repos/{owner}/{repo}/issues/{number}", body=payload)

    def create_branch(self, owner: str, repo: str, branch: str, from_sha: str):
        payload = {"ref": f"refs/heads/{branch}", "sha": from_sha}
        if self.dry_run:
            return self._would(f"create branch {branch} in {owner}/{repo}", payload)
        return self.request("POST", f"/repos/{owner}/{repo}/git/refs", body=payload)

    def create_commit_on_branch(self, owner: str, repo: str, branch: str, expected_head_oid: str,
                                headline: str, body: str, files: dict[str, str]):
        """Commit through GraphQL ``createCommitOnBranch``.

        GitHub creates and signs the commit server-side; the agent holds no key.
        ``files`` maps repository path -> file content (text). ``body`` must end
        with the ``Signed-off-by:`` trailer of the responsible human (DCO).
        """
        additions = [
            {"path": path, "contents": base64.b64encode(content.encode("utf-8")).decode("ascii")}
            for path, content in files.items()
        ]
        variables = {
            "input": {
                "branch": {"repositoryNameWithOwner": f"{owner}/{repo}", "branchName": branch},
                "message": {"headline": headline, "body": body},
                "fileChanges": {"additions": additions},
                "expectedHeadOid": expected_head_oid,
            }
        }
        if self.dry_run:
            shown = dict(variables["input"])
            shown["fileChanges"] = {"additions": [{"path": a["path"], "bytes": len(a["contents"])} for a in additions]}
            return self._would(f"createCommitOnBranch {owner}/{repo}@{branch}", shown)
        query = """
        mutation($input: CreateCommitOnBranchInput!) {
          createCommitOnBranch(input: $input) { commit { oid url } }
        }"""
        return self.graphql(query, variables)

    def create_pull_request(self, owner: str, repo: str, title: str, head: str, base: str, body: str):
        payload = {"title": title, "head": head, "base": base, "body": body, "draft": False}
        if self.dry_run:
            return self._would(f"create pull request in {owner}/{repo}", payload)
        return self.request("POST", f"/repos/{owner}/{repo}/pulls", body=payload)

    def add_labels(self, owner: str, repo: str, number: int, labels: list[str]):
        payload = {"labels": labels}
        if self.dry_run:
            return self._would(f"add labels to {owner}/{repo}#{number}", payload)
        try:
            return self.request("POST", f"/repos/{owner}/{repo}/issues/{number}/labels", body=payload)
        except GitHubError as e:
            # A missing label is not a reason to fail the run. Say so and go on.
            print(f"note: could not add labels {labels}: {e}", file=self.out)
            return None

    def create_security_advisory_draft(self, owner: str, repo: str, summary: str, description: str,
                                       severity: str = "medium"):
        """Open a draft repository security advisory (private until published by a human)."""
        payload = {"summary": summary[:1024], "description": description[:65535], "severity": severity}
        if self.dry_run:
            return self._would(f"create draft security advisory in {owner}/{repo}", payload)
        return self.request("POST", f"/repos/{owner}/{repo}/security-advisories", body=payload)

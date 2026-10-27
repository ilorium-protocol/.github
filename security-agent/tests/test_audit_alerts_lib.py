# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
import io
import json

import alerts
import audit
import mailbox
from lib.github import AI_DISCLOSURE, GitHub


# ---- lib.github -----------------------------------------------------------

def test_github_has_no_approve_merge_or_settings_methods():
    names = {n for n in dir(GitHub) if not n.startswith("_")}
    forbidden = {"approve", "merge", "merge_pull", "create_review", "push", "create_release",
                 "update_org", "update_repo", "delete_branch", "set_secret"}
    assert not (names & forbidden)


def test_github_dry_run_prints_and_does_not_call(monkeypatch):
    out = io.StringIO()
    gh = GitHub(token="x", dry_run=True, out=out)
    r = gh.create_issue("o", "r", "title", "body", ["security"])
    assert r["dry_run"] is True
    assert "would create issue in o/r" in out.getvalue()
    r = gh.create_commit_on_branch("o", "r", "b", "0" * 40, "head", "Signed-off-by: A <a@b>", {"p.md": "x"})
    text = out.getvalue()
    assert "createCommitOnBranch" in text
    assert "Signed-off-by" in text


def test_sticky_comment_dry_run_creates(monkeypatch):
    out = io.StringIO()
    gh = GitHub(token="x", dry_run=True, out=out)
    gh.upsert_sticky_comment("o", "r", 5, "<!-- m -->", "hello")
    assert "would create comment on o/r#5" in out.getvalue()
    assert "<!-- m -->" in out.getvalue()


def test_token_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "abc")
    assert GitHub().token == "abc"
    monkeypatch.delenv("GITHUB_TOKEN")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert GitHub().token is None


# ---- audit ----------------------------------------------------------------

def test_check_headers_observed_and_not():
    got = {"strict-transport-security": "max-age=63072000; includeSubDomains; preload",
           "x-frame-options": "SAMEORIGIN"}
    obs = audit.check_headers(got)
    by = {o.item: o for o in obs}
    assert by["strict-transport-security"].observed is True
    assert by["x-frame-options"].observed is False
    assert by["content-security-policy"].observed is False


def test_report_has_required_sections_and_disclosure():
    obs = [audit.Obs("org", "two-factor authentication required", False),
           audit.Obs("protocol-files", "SECURITY.md", True),
           audit.Obs("dns", "DMARC record", None, "dig not installed")]
    rec = audit.default_recommendations(obs)
    report = audit.render_report("2026-10-21", 1, obs, rec, audit.DEFAULT_LIMITS)
    assert report.startswith("# Security report 0001 · 2026-10-21")
    assert AI_DISCLOSURE in report
    for h in ("## Observed", "## Not observed", "## Recommended", "## Limits of this report"):
        assert h in report
    assert "- not observed: org: two-factor authentication required" in report
    assert "Require two-factor authentication" in rec[0]


def test_audit_offline_dry_run_without_signoff_opens_issue(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("AGENT_SIGNOFF", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    proto = tmp_path / "protocol"
    (proto / "governance" / "security").mkdir(parents=True)
    (proto / "SECURITY.md").write_text("x")
    rc = audit.main(["--protocol-dir", str(proto), "--skip", "headers,dns,org,repos", "--date", "2026-10-21", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr()
    assert "would create issue in ilorium-protocol/protocol" in out.out
    assert "not observed: dependencies: verifier/pyproject.toml present" in out.out
    assert "protocol-files: SECURITY.md" in out.out


def test_audit_offline_dry_run_with_signoff_commits_and_opens_pr(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("AGENT_SIGNOFF", "Example Human <human@example.org>")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    proto = tmp_path / "protocol"
    (proto / "governance" / "security").mkdir(parents=True)
    (proto / "governance" / "security" / "2026-10-21-report-0001.md").write_text("x")
    rc = audit.main(["--protocol-dir", str(proto), "--skip", "headers,dns,org,repos", "--date", "2026-10-28", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Security report 0002" in out
    assert "createCommitOnBranch ilorium-protocol/protocol@security-agent/report-2026-10-28" in out
    assert "Signed-off-by: Example Human <human@example.org>" in out
    assert "would create pull request" in out
    assert '"agent-authored"' in out and '"security"' in out


def test_next_report_number(tmp_path):
    assert audit.next_report_number(None) == 1
    d = tmp_path / "governance" / "security"
    d.mkdir(parents=True)
    assert audit.next_report_number(tmp_path) == 1
    (d / "2026-10-21-report-0003.md").write_text("")
    assert audit.next_report_number(tmp_path) == 4


# ---- alerts ---------------------------------------------------------------

def test_alerts_fixtures_dry_run_never_leaks_secret(fixtures, capsys):
    rc = alerts.main(["--fixtures", str(fixtures / "alerts.json"), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("would create issue in ilorium-protocol/protocol") == 3
    assert "ghp_THIS_MUST_NEVER_APPEAR" not in out
    assert "Update `jsonschema` to `4.23.1`" in out
    assert "py/clear-text-logging-sensitive-data" in out
    assert AI_DISCLOSURE in out


def test_alert_issue_body_has_marker_and_sections(fixtures):
    data = json.loads((fixtures / "alerts.json").read_text())
    n = alerts.normalize_dependabot("protocol", data["protocol"]["dependabot"][0])
    body = alerts.render_issue(n)
    assert body.startswith("<!-- ilorium-security-agent:alert:dependabot:protocol:7 -->")
    for h in ("## Observed", "## Proposed", "## Limits"):
        assert h in body
    assert "I did not change any dependency" in body


# ---- mailbox --------------------------------------------------------------

def test_mailbox_without_secret_is_planned(capsys, monkeypatch):
    monkeypatch.delenv("SECURITY_MAILBOX_SA_KEY", raising=False)
    assert mailbox.main([]) == 0
    assert "planned: mailbox triage not configured" in capsys.readouterr().out


def test_mailbox_ack_template(capsys):
    assert mailbox.main(["--print-ack"]) == 0
    out = capsys.readouterr().out
    assert AI_DISCLOSURE in out
    assert "72 hours" in out
    assert "security/advisories/new" in out

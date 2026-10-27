# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
import io
import re

import review
from lib.github import AI_DISCLOSURE


def _run(fixtures, name, title="", body="", labels=()):
    diff = (fixtures / name).read_text(encoding="utf-8")
    files = review.parse_unified_diff(diff)
    secrets = review.load_patterns(review.HERE / "patterns" / "secrets.txt")
    inj = review.load_patterns(review.HERE / "patterns" / "injection.txt", re.IGNORECASE | re.MULTILINE)
    findings = review.run_checks(files, title, body, list(labels), secrets, inj)
    return files, findings


def kinds(findings):
    return {f.kind for f in findings}


def test_parse_diff_counts_files_and_lines(fixtures):
    files = review.parse_unified_diff((fixtures / "pr-clean.diff").read_text())
    assert [f.path for f in files] == ["glossary.md", "CHANGELOG.md"]
    assert len(files[0].added) == 1
    assert files[0].added[0][0] == 12  # line number in the new file
    assert len(files[1].added) == 2


def test_clean_editorial_pr_has_no_findings(fixtures):
    _, findings = _run(fixtures, "pr-clean.diff", title="glossary: add Lighthouse", body="Editorial.")
    assert findings == []


def test_protected_paths_without_iip_are_flagged(fixtures):
    _, findings = _run(fixtures, "pr-genome-no-iip.diff", title="Relax Law 5", body="Small change.")
    k = kinds(findings)
    assert "protected-path-without-iip" in k
    assert "vector-change-without-reference" in k
    paths = {f.path for f in findings if f.kind == "protected-path-without-iip"}
    assert "genome/genome-v1.md" in paths
    assert "vectors/pulse/beat-001.json" in paths


def test_iip_reference_clears_protected_path_findings(fixtures):
    _, findings = _run(fixtures, "pr-genome-no-iip.diff", title="IIP-0004: Law 5 wording", body="See IIP-0004.")
    k = kinds(findings)
    assert "protected-path-without-iip" not in k
    assert "vector-change-without-reference" not in k
    assert "format-without-vectors" not in k


def test_format_change_without_vectors_is_flagged(fixtures):
    diff = """diff --git a/specs/evidence-format-v1.md b/specs/evidence-format-v1.md
index 1..2 100644
--- a/specs/evidence-format-v1.md
+++ b/specs/evidence-format-v1.md
@@ -1,1 +1,1 @@
-old
+new field
"""
    files = review.parse_unified_diff(diff)
    secrets = review.load_patterns(review.HERE / "patterns" / "secrets.txt")
    inj = review.load_patterns(review.HERE / "patterns" / "injection.txt", re.IGNORECASE | re.MULTILINE)
    findings = review.run_checks(files, "spec change", "", [], secrets, inj)
    assert "format-without-vectors" in kinds(findings)
    # the label clears it
    findings = review.run_checks(files, "spec change", "", ["needs-vectors"], secrets, inj)
    assert "format-without-vectors" not in kinds(findings)


def test_injection_secrets_dependencies_workflows_binaries(fixtures):
    files, findings = _run(fixtures, "pr-injection-and-secrets.diff", title="Update llms.txt", body="")
    k = kinds(findings)
    assert "injection-pattern" in k
    assert "secret-pattern" in k
    assert "dependency-change" in k
    assert "sensitive-path" in k
    assert "binary" in k
    inj_ids = {f.detail.split("`")[1] for f in findings if f.kind == "injection-pattern"}
    assert "ignore-previous" in inj_ids
    assert "html-comment-imperative" in inj_ids
    assert "zero-width-chars" in inj_ids
    assert "ai-only-note" in inj_ids or "when-you-read-this" in inj_ids
    secret_ids = {f.detail.split("`")[1] for f in findings if f.kind == "secret-pattern"}
    assert "github-pat-classic" in secret_ids
    assert "anthropic-api-key" in secret_ids
    # the sha256 hash line in requirements must not be reported as entropy
    assert not any(f.kind == "high-entropy-string" and "requirements.txt" in f.path for f in findings)


def test_secrets_are_redacted_in_report(fixtures):
    files, findings = _run(fixtures, "pr-injection-and-secrets.diff")
    report = review.render_report(findings, files, "t", [], identity_configured=True)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" not in report
    assert "ghp_…" in report or "ghp_A" in report


def test_report_starts_with_marker_and_disclosure(fixtures):
    files, findings = _run(fixtures, "pr-clean.diff")
    report = review.render_report(findings, files, "t", [], identity_configured=False)
    lines = report.splitlines()
    assert lines[0] == review.STICKY_MARKER
    assert AI_DISCLOSURE in lines[1]
    assert "not configured yet" in report
    assert "no findings" in report
    assert "approve" not in report.lower().replace("approve this pull request", "")


def test_model_section_is_appended(fixtures):
    files, findings = _run(fixtures, "pr-clean.diff")
    report = review.render_report(findings, files, "t", [], True, model_section="Findings: 0")
    assert "## Model review (advisory)" in report
    assert report.rstrip().endswith("security-agent")


def test_cli_dry_run_posts_nothing(fixtures, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    rc = review.main(["--diff", str(fixtures / "pr-clean.diff"), "--repo", "ilorium-protocol/protocol",
                      "--pr", "1", "--dry-run", "--title", "t"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[dry-run] would create comment on ilorium-protocol/protocol#1" in out


def test_entropy_helper():
    assert review.shannon_entropy("aaaa") == 0
    assert review.shannon_entropy("abcdefghijklmnop") == 4.0
    assert review.high_entropy_tokens("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == []

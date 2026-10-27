#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
"""Deterministic pull request review by the Ilorium security agent.

I am an AI agent. I review and propose; I never decide.

What this script does:
  1. Reads a unified diff (``--diff FILE`` or ``git diff BASE...HEAD`` in ``--repo-dir``).
  2. Runs deterministic checks and collects findings:
       - dependency changes (lock files, requirements, pyproject, package.json, go.mod, ...)
       - secret patterns over added lines (patterns/secrets.txt) and high-entropy strings
       - prompt-injection patterns in agent-readable files (patterns/injection.txt)
       - changes under protected paths (the germline) without an IIP reference
         (``IIP-\\d{4}`` in the PR title or body)
       - changes to formats, schemas or vectors without ``needs-vectors`` or an IIP
       - changes to workflows, CODEOWNERS, rulesets or the agent's own code
       - binary files
  3. Writes a Markdown report and, with ``--post``, upserts ONE sticky comment
     on the pull request. It never approves, requests changes, or merges.

Exit code is always 0 unless the script itself fails: findings are advisory.
The pull request's required checks are the protocol repository's own CI.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.github import AI_DISCLOSURE, GitHub  # noqa: E402

STICKY_MARKER = "<!-- ilorium-security-agent:review -->"

IIP_RE = re.compile(r"\bIIP-\d{4}\b")

# Paths that are the germline applied to git (CODEOWNERS in the protocol repo).
# A change here without an IIP reference is a finding of the first kind in the
# threat model: a rule change outside governance.
PROTECTED_PREFIXES = (
    "genome/",
    "governance-v1.md",
    "governance-v1.es.md",
    "manifest.md",
    "manifest.es.md",
    "schemas/",
    "vectors/",
    "iips/",
    "CODEOWNERS",
    ".github/CODEOWNERS",
)

# Paths whose change means a format changed: vectors must follow.
FORMAT_PREFIXES = (
    "schemas/",
    "specs/evidence-format-v1.md",
    "specs/probe-v1.md",
    "specs/pulse-v1.md",
)
VECTOR_PREFIXES = ("vectors/",)

SENSITIVE_PREFIXES = (
    ".github/workflows/",
    ".github/dependabot.yml",
    "security-agent/",
    "org/rulesets/",
    "SECURITY.md",
    "_headers",
    "public/_headers",
)

DEPENDENCY_FILES = (
    "requirements.txt", "requirements-dev.txt", "requirements.in", "constraints.txt",
    "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock", "pdm.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock",
)

AGENT_READABLE_SUFFIXES = (".md", ".txt", ".json", ".yml", ".yaml", ".html", ".svg", ".toml")
AGENT_READABLE_NAMES = ("llms.txt", "ilorium.json", "agent.json", "agent-card.json", "security.txt")

BINARY_HINT_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".tgz", ".whl", ".jar", ".exe", ".dll", ".so", ".dylib", ".bin", ".woff", ".woff2",
    ".ttf", ".otf", ".pyc", ".class", ".wasm",
)

ENTROPY_MIN_LEN = 32
ENTROPY_THRESHOLD = 4.5  # bits per char; base64/hex random tokens sit above this

# Lines that look like entropy but are not secrets.
ENTROPY_EXCLUDE = re.compile(
    r"(sha256|sha512|sha1|md5|blake2|integrity|checksum|digest|sri-|"
    r"[0-9a-f]{40}\b|[0-9a-f]{64}\b|data:image/|\.svg|\.woff2|font-face|"
    r"https?://|@[0-9a-f]{40}|SPDX|tree_oid|expectedHeadOid)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Diff parsing

class FileDiff:
    def __init__(self, path: str, old_path: str | None = None):
        self.path = path
        self.old_path = old_path or path
        self.added: list[tuple[int, str]] = []   # (line number in new file, text)
        self.removed: list[str] = []
        self.is_binary = False
        self.status = "modified"


def parse_unified_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    new_line = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            m = re.match(r'diff --git a/(.*?) b/(.*)$', raw)
            path = m.group(2) if m else raw[11:].split(" b/")[-1]
            old = m.group(1) if m else None
            current = FileDiff(path, old)
            files.append(current)
            new_line = 0
            continue
        if current is None:
            continue
        if raw.startswith("Binary files") or raw.startswith("GIT binary patch"):
            current.is_binary = True
            continue
        if raw.startswith("new file mode"):
            current.status = "added"
            continue
        if raw.startswith("deleted file mode"):
            current.status = "deleted"
            continue
        if raw.startswith("rename to "):
            current.status = "renamed"
            continue
        if raw.startswith("+++ ") or raw.startswith("--- "):
            continue
        if raw.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            new_line = int(m.group(1)) if m else 0
            continue
        if raw.startswith("+"):
            current.added.append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            current.removed.append(raw[1:])
        elif raw.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            new_line += 1
    return files


# ---------------------------------------------------------------------------
# Patterns

def load_patterns(path: Path, flags: int = 0) -> list[tuple[str, re.Pattern]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" not in line:
            continue
        pid, regex = line.split("\t", 1)
        out.append((pid.strip(), re.compile(regex.strip(), flags)))
    return out


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % ENTROPY_MIN_LEN)


def high_entropy_tokens(line: str) -> list[str]:
    if ENTROPY_EXCLUDE.search(line):
        return []
    hits = []
    for tok in TOKEN_RE.findall(line):
        if shannon_entropy(tok) >= ENTROPY_THRESHOLD and not tok.isalpha():
            hits.append(tok)
    return hits


def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-2:] + f" ({len(value)} chars)"


# ---------------------------------------------------------------------------
# Checks

class Finding:
    def __init__(self, kind: str, path: str, detail: str, line: int | None = None):
        self.kind = kind
        self.path = path
        self.detail = detail
        self.line = line

    def to_dict(self):
        return {"kind": self.kind, "path": self.path, "line": self.line, "detail": self.detail}


def is_protected(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in PROTECTED_PREFIXES)


def is_format(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in FORMAT_PREFIXES)


def is_vector(path: str) -> bool:
    return any(path.startswith(p) for p in VECTOR_PREFIXES)


def is_sensitive(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in SENSITIVE_PREFIXES)


def is_dependency_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in DEPENDENCY_FILES


def is_agent_readable(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in AGENT_READABLE_NAMES:
        return True
    if "/.well-known/" in f"/{path}":
        return True
    return path.endswith(AGENT_READABLE_SUFFIXES)


def looks_binary(fd: FileDiff) -> bool:
    return fd.is_binary or fd.path.lower().endswith(BINARY_HINT_SUFFIXES)


def run_checks(files: list[FileDiff], title: str, body: str, labels: list[str],
               secret_patterns, injection_patterns) -> list[Finding]:
    findings: list[Finding] = []
    text_ctx = f"{title}\n{body}"
    iips = sorted(set(IIP_RE.findall(text_ctx)))
    has_iip = bool(iips)
    has_needs_vectors = "needs-vectors" in labels or "needs-vectors" in text_ctx

    touched_formats = [f.path for f in files if is_format(f.path)]
    touched_vectors = [f.path for f in files if is_vector(f.path)]

    for fd in files:
        p = fd.path

        if looks_binary(fd):
            findings.append(Finding("binary", p, "Binary file in the change. Binaries cannot be reviewed as text; state what it is and where it comes from."))

        if is_protected(p) and not has_iip:
            findings.append(Finding(
                "protected-path-without-iip", p,
                "Change under a protected path (the germline applied to git) with no IIP reference "
                "(IIP-NNNN) in the title or body. Method changes need an IIP; editorial changes should say so.",
            ))

        if is_vector(p) and not (has_iip or has_needs_vectors):
            findings.append(Finding(
                "vector-change-without-reference", p,
                "Conformity vector changed without an IIP reference or the `needs-vectors` label.",
            ))

        if is_dependency_file(p):
            added = [t for _, t in fd.added if t.strip() and not t.strip().startswith("#")]
            removed = [t for t in fd.removed if t.strip() and not t.strip().startswith("#")]
            findings.append(Finding(
                "dependency-change", p,
                f"Dependency manifest changed: +{len(added)} / -{len(removed)} lines. "
                "Check each new or bumped package against its upstream release and the pinned hash.",
            ))
            for t in added[:20]:
                findings.append(Finding("dependency-added-line", p, t.strip()[:200]))

        if is_sensitive(p):
            findings.append(Finding("sensitive-path", p, "Workflow, policy, ruleset or agent code changed. Read with care; these paths shape what runs."))

        if fd.is_binary:
            continue

        for lineno, text in fd.added:
            for pid, rx in secret_patterns:
                for m in rx.finditer(text):
                    findings.append(Finding("secret-pattern", p, f"`{pid}`: {redact(m.group(0))}", lineno))
            for tok in high_entropy_tokens(text):
                findings.append(Finding("high-entropy-string", p, f"entropy {shannon_entropy(tok):.2f}: {redact(tok)}", lineno))

        if is_agent_readable(p):
            for lineno, text in fd.added:
                for pid, rx in injection_patterns:
                    if rx.search(text):
                        findings.append(Finding("injection-pattern", p, f"`{pid}` matched on an added line of an agent-readable file.", lineno))

    if touched_formats and not touched_vectors and not (has_iip or has_needs_vectors):
        findings.append(Finding(
            "format-without-vectors", ", ".join(touched_formats),
            "A record format or schema changed but no conformity vector changed, and the PR carries "
            "neither an IIP reference nor `needs-vectors`.",
        ))

    # Collapse duplicates
    seen = set()
    unique = []
    for f in findings:
        key = (f.kind, f.path, f.line, f.detail)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Report

KIND_TITLES = {
    "secret-pattern": "Possible secrets",
    "high-entropy-string": "High-entropy strings",
    "injection-pattern": "Injection patterns in agent-readable files",
    "protected-path-without-iip": "Protected paths without an IIP reference",
    "vector-change-without-reference": "Vector changes without reference",
    "format-without-vectors": "Format changes without vectors",
    "dependency-change": "Dependency changes",
    "dependency-added-line": "Dependency lines added",
    "sensitive-path": "Workflows, policies, agent code",
    "binary": "Binary files",
}

KIND_ORDER = list(KIND_TITLES)


def render_report(findings: list[Finding], files: list[FileDiff], title: str, iips: list[str],
                  identity_configured: bool, model_section: str | None = None) -> str:
    lines = [STICKY_MARKER, f"**{AI_DISCLOSURE}**", ""]
    lines.append("Security agent review (deterministic checks). Findings are observations for the human reviewer; they are not a verdict and they do not block the pull request by themselves.")
    lines.append("")
    if not identity_configured:
        lines.append("Note: the agent identity (GitHub App `ilorium-security-agent`) is not configured yet. This comment was posted with the workflow token.")
        lines.append("")
    lines.append(f"Files changed: {len(files)}. IIP references: {', '.join(iips) if iips else 'none'}.")
    lines.append("")
    if not findings:
        lines.append("Observed: no findings from the deterministic checks.")
    else:
        by_kind: dict[str, list[Finding]] = {}
        for f in findings:
            by_kind.setdefault(f.kind, []).append(f)
        for kind in KIND_ORDER:
            if kind not in by_kind:
                continue
            lines.append(f"### {KIND_TITLES[kind]} ({len(by_kind[kind])})")
            for f in by_kind[kind][:40]:
                loc = f"`{f.path}`" + (f" line {f.line}" if f.line else "")
                lines.append(f"- {loc}: {f.detail}")
            if len(by_kind[kind]) > 40:
                lines.append(f"- … {len(by_kind[kind]) - 40} more")
            lines.append("")
    lines.append("")
    lines.append("What I checked: dependency manifests, secret patterns and high-entropy strings on added lines, injection patterns in agent-readable files, protected paths against an IIP reference, vectors against `needs-vectors`, workflow and policy paths, binary files.")
    lines.append("What I did not check: whether the change is correct, whether the evidence it describes is genuine, or anything outside the diff.")
    if model_section:
        lines.append("")
        lines.append("## Model review (advisory)")
        lines.append("")
        lines.append(model_section.strip())
    lines.append("")
    lines.append("— ilorium-security-agent (AI). Source: https://github.com/ilorium-protocol/.github/tree/main/security-agent")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry

def git_diff(repo_dir: str, base: str, head: str) -> str:
    cmd = ["git", "-C", repo_dir, "diff", "--no-color", "--no-ext-diff", f"{base}...{head}"]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--diff", help="Path to a unified diff file (offline mode).")
    ap.add_argument("--repo-dir", default=".", help="Git checkout to diff when --diff is absent.")
    ap.add_argument("--base", default=os.environ.get("PR_BASE_SHA", "origin/main"))
    ap.add_argument("--head", default=os.environ.get("PR_HEAD_SHA", "HEAD"))
    ap.add_argument("--title", default=os.environ.get("PR_TITLE", ""))
    ap.add_argument("--body", default=os.environ.get("PR_BODY", ""))
    ap.add_argument("--body-file", help="Read the PR body from this file (safer than passing it as an argument).")
    ap.add_argument("--labels", default=os.environ.get("PR_LABELS", ""), help="Comma-separated PR labels.")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/name")
    ap.add_argument("--pr", type=int, default=int(os.environ.get("PR_NUMBER", "0") or 0))
    ap.add_argument("--post", action="store_true", help="Upsert the sticky comment on the PR.")
    ap.add_argument("--dry-run", action="store_true", help="Print what would be posted instead of posting.")
    ap.add_argument("--identity-configured", action="store_true", help="Set when the App token is in use.")
    ap.add_argument("--model-section-file", help="Append this file's content under 'Model review (advisory)'.")
    ap.add_argument("--json", help="Also write findings as JSON to this path.")
    ap.add_argument("--out", help="Write the Markdown report to this path.")
    args = ap.parse_args(argv)

    body = args.body
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8", errors="replace")

    diff_text = Path(args.diff).read_text(encoding="utf-8", errors="replace") if args.diff else git_diff(args.repo_dir, args.base, args.head)
    files = parse_unified_diff(diff_text)
    labels = [l.strip() for l in args.labels.split(",") if l.strip()]

    secret_patterns = load_patterns(HERE / "patterns" / "secrets.txt")
    injection_patterns = load_patterns(HERE / "patterns" / "injection.txt", re.IGNORECASE | re.MULTILINE)

    findings = run_checks(files, args.title, body, labels, secret_patterns, injection_patterns)
    iips = sorted(set(IIP_RE.findall(f"{args.title}\n{body}")))
    model_section = Path(args.model_section_file).read_text(encoding="utf-8", errors="replace") if args.model_section_file and Path(args.model_section_file).exists() else None
    report = render_report(findings, files, args.title, iips, args.identity_configured, model_section)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")

    print(report)
    print(f"\n[review] {len(findings)} finding(s) across {len(files)} file(s).", file=sys.stderr)

    if args.post or args.dry_run:
        if not args.repo or not args.pr:
            print("[review] --post needs --repo owner/name and --pr N", file=sys.stderr)
            return 2 if args.post else 0
        owner, name = args.repo.split("/", 1)
        gh = GitHub(dry_run=args.dry_run)
        gh.upsert_sticky_comment(owner, name, args.pr, STICKY_MARKER, report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

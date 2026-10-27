#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
"""Mailbox triage for security@ilorium.com by the Ilorium security agent.

Status: planned. This script is a guarded skeleton with the real API calls.
It runs only when the secret ``SECURITY_MAILBOX_SA_KEY`` (a Google Workspace
service account key with domain-wide delegation on security@) is configured.
Without it, it prints "planned: mailbox triage not configured" and exits 0.

I am an AI agent. I review and propose; I never decide.

What it would do, per unread message in security@:
  1. Acknowledge with a fixed template: AI disclosure, the 72-hour commitment
     from SECURITY.md, and a request not to send exploit details in clear
     mail if they can use GitHub private vulnerability reporting instead.
  2. Label the thread ``ilorium/acknowledged`` in the mailbox.
  3. Open a DRAFT repository security advisory in ilorium-protocol/protocol
     (private until a human publishes it) with the subject and sender only.
  4. Notify the founder: the advisory is the notification; an email copy goes
     to the address in the variable ``SECURITY_FOUNDER_EMAIL`` if set.

It never replies with vulnerability details, never forwards the report body
anywhere public, and never closes a thread.

Authentication: a signed JWT (RS256, via ``openssl`` on the runner; no
third-party Python package) exchanged for an OAuth2 access token with the
scopes gmail.readonly, gmail.modify (labels), gmail.send.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib.github import AI_DISCLOSURE, GitHub  # noqa: E402

MAILBOX = "security@ilorium.com"
ORG = "ilorium-protocol"
REPO = "protocol"
SCOPES = "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
LABEL = "ilorium/acknowledged"

ACK_TEMPLATE = """Hello,

{disclosure}

Thank you for writing to security@ilorium.com. This message is an automated acknowledgment. A human will answer within 72 hours, as stated in https://github.com/ilorium-protocol/protocol/blob/main/SECURITY.md.

If your report concerns a vulnerability, please do not send exploit details in clear mail. You can file it privately at https://github.com/ilorium-protocol/protocol/security/advisories/new. We follow coordinated disclosure and credit reporters publicly if they wish. There are no bounties at this time.

Ilorium Security Agent (AI)
security-agent@ilorium.com
"""


# ---------------------------------------------------------------------------
# auth (service account, domain-wide delegation)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def service_account_token(sa_key: dict, subject: str, scopes: str = SCOPES) -> str:
    """Exchange a signed JWT for an access token. Uses openssl for RS256."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": sa_key.get("private_key_id")}
    claims = {
        "iss": sa_key["client_email"],
        "sub": subject,
        "scope": scopes,
        "aud": sa_key.get("token_uri", "https://oauth2.googleapis.com/token"),
        "iat": now,
        "exp": now + 3600,
    }
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as kf:
        kf.write(sa_key["private_key"])
        key_path = kf.name
    try:
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path],
                             input=signing_input.encode(), capture_output=True, check=True).stdout
    finally:
        os.unlink(key_path)
    jwt = f"{signing_input}.{_b64url(sig)}"
    data = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt}).encode()
    req = urllib.request.Request(claims["aud"], data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["access_token"]


class Gmail:
    def __init__(self, token: str, dry_run: bool = False):
        self.token = token
        self.dry_run = dry_run

    def _call(self, method: str, path: str, body: dict | None = None, params: dict | None = None):
        url = GMAIL + path + (("?" + urllib.parse.urlencode(params)) if params else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read() or b"{}")

    def unread(self, max_results: int = 20) -> list[dict]:
        data = self._call("GET", "/messages", params={"q": f"is:unread -label:{LABEL}", "maxResults": max_results})
        return data.get("messages", [])

    def message(self, mid: str) -> dict:
        return self._call("GET", f"/messages/{mid}", params={"format": "metadata", "metadataHeaders": "From,Subject,Message-ID,Date"})

    def ensure_label(self) -> str:
        for l in self._call("GET", "/labels").get("labels", []):
            if l["name"] == LABEL:
                return l["id"]
        if self.dry_run:
            return "LABEL_DRY_RUN"
        return self._call("POST", "/labels", {"name": LABEL, "labelListVisibility": "labelShow", "messageListVisibility": "show"})["id"]

    def add_label(self, mid: str, label_id: str) -> None:
        if self.dry_run:
            print(f"[dry-run] would label message {mid} with {LABEL}")
            return
        self._call("POST", f"/messages/{mid}/modify", {"addLabelIds": [label_id]})

    def send(self, to: str, subject: str, text: str, in_reply_to: str | None, thread_id: str | None) -> None:
        msg = EmailMessage()
        msg["From"] = f"Ilorium Security Agent (AI) <{MAILBOX}>"
        msg["To"] = to
        msg["Subject"] = subject
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
            msg["References"] = in_reply_to
        msg.set_content(text)
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        if self.dry_run:
            print(f"[dry-run] would send to {to}: {subject}")
            return
        body = {"raw": raw}
        if thread_id:
            body["threadId"] = thread_id
        self._call("POST", "/messages/send", body)


def headers_of(m: dict) -> dict[str, str]:
    return {h["name"].lower(): h["value"] for h in (m.get("payload") or {}).get("headers", [])}


def triage(gmail: Gmail, gh: GitHub, founder_email: str | None, limit: int) -> int:
    label_id = gmail.ensure_label()
    handled = 0
    for ref in gmail.unread(limit):
        m = gmail.message(ref["id"])
        h = headers_of(m)
        sender = h.get("from", "unknown")
        subject = h.get("subject", "(no subject)")
        if MAILBOX in sender or "security-agent@" in sender:
            continue  # never answer ourselves
        ack_subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
        gmail.send(sender, ack_subject, ACK_TEMPLATE.format(disclosure=AI_DISCLOSURE), h.get("message-id"), m.get("threadId"))
        gmail.add_label(ref["id"], label_id)
        summary = f"Report received at security@: {subject[:120]}"
        description = (f"{AI_DISCLOSURE}\n\nA message arrived at security@ilorium.com.\n\n"
                       f"From: {sender}\nSubject: {subject}\nDate: {h.get('date', '')}\n\n"
                       "The body is not copied here. A human reads it in the mailbox and decides whether this advisory proceeds, is closed, or is converted. This advisory is a draft and private.")
        gh.create_security_advisory_draft(ORG, REPO, summary, description, severity="medium")
        if founder_email:
            gmail.send(founder_email, f"[security@] {subject[:100]}",
                       f"{AI_DISCLOSURE}\n\nNew message in security@ from {sender}: {subject}\nA draft advisory was opened in {ORG}/{REPO}.")
        handled += 1
    return handled


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--dry-run", action="store_true", help="Read the mailbox but print what would be sent instead of sending.")
    ap.add_argument("--print-ack", action="store_true", help="Print the acknowledgment template and exit.")
    args = ap.parse_args(argv)

    if args.print_ack:
        print(ACK_TEMPLATE.format(disclosure=AI_DISCLOSURE))
        return 0

    sa_raw = os.environ.get("SECURITY_MAILBOX_SA_KEY")
    if not sa_raw:
        print("planned: mailbox triage not configured (SECURITY_MAILBOX_SA_KEY absent)")
        return 0
    try:
        sa_key = json.loads(sa_raw)
    except json.JSONDecodeError:
        print("SECURITY_MAILBOX_SA_KEY is not valid JSON", file=sys.stderr)
        return 2
    token = service_account_token(sa_key, MAILBOX)
    gmail = Gmail(token, dry_run=args.dry_run)
    gh = GitHub(dry_run=args.dry_run)
    n = triage(gmail, gh, os.environ.get("SECURITY_FOUNDER_EMAIL"), args.limit)
    print(f"[mailbox] {n} message(s) handled.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

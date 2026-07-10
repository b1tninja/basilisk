from __future__ import annotations

import re


def filter_armored_by_uids(armored: bytes, approved_emails: list[str]) -> bytes:
    """Best-effort filter: keep only user IDs matching approved email addresses."""
    if not approved_emails:
        return armored
    allowed = {e.lower() for e in approved_emails}
    text = armored.decode("utf-8", errors="replace")
    lines = text.splitlines()
    out: list[str] = []
    for line in lines:
        if "@" in line:
            keep = any(email in line.lower() for email in allowed)
            if not keep and not line.startswith("-----"):
                continue
        out.append(line)
    return "\n".join(out).encode("utf-8")


def emails_from_uids(uids: list[str]) -> list[str]:
    emails: list[str] = []
    for uid in uids:
        m = re.search(r"<([^>]+)>", uid)
        if m and "@" in m.group(1):
            emails.append(m.group(1).lower())
        elif "@" in uid:
            emails.append(uid.strip().lower())
    return emails

from __future__ import annotations

import re
from typing import Any


# Conventional OpenPGP User ID: Name (Comment) <email@host>
# See Sequoia "Conventional User IDs" / RFC 9580 §5.11 (convention only).
_ANGLE_EMAIL = re.compile(r"<([^>]+)>")
_PREFIX_WITH_COMMENT = re.compile(r"^(.*?)\s*\(([^)]*)\)\s*$")
# Bare addr-spec (whole UID is only the email).
_BARE_EMAIL = re.compile(r"^[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+$")


def parse_uid_parts(uid: str | Any) -> dict[str, str | None]:
    """Parse a User ID into conventional parts.

    OpenPGP User ID packets are opaque UTF-8; name/email are not separate
    fields on the wire. pysequoia only exposes ``str(UserId)``. This helper
    applies the de-facto conventional form once on the server so clients never
    need to split UID strings.

    Returns:
        ``{"raw", "name", "email", "comment"}`` — ``email`` is lowercased when
        present; ``name``/``comment`` preserve original casing; missing parts
        are ``None``.
    """
    raw = str(uid).strip() if uid is not None else ""
    if not raw:
        return {"raw": "", "name": None, "email": None, "comment": None}

    email: str | None = None
    name: str | None = None
    comment: str | None = None

    m = _ANGLE_EMAIL.search(raw)
    if m and "@" in m.group(1):
        email = m.group(1).strip().lower()
        prefix = raw[: m.start()].strip()
        cm = _PREFIX_WITH_COMMENT.fullmatch(prefix)
        if cm:
            name = cm.group(1).strip() or None
            comment = cm.group(2).strip() or None
        elif prefix:
            name = prefix
    elif _BARE_EMAIL.fullmatch(raw):
        email = raw.lower()

    return {"raw": raw, "name": name, "email": email, "comment": comment}


def structure_uids(uids: list[str] | None) -> list[dict[str, str | None]]:
    """Map stored UID strings to structured objects for API responses."""
    return [parse_uid_parts(u) for u in (uids or [])]


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
    """Extract emails from UID strings using conventional parsing only."""
    emails: list[str] = []
    for uid in uids:
        email = parse_uid_parts(uid)["email"]
        if email:
            emails.append(email)
    return emails

"""Tests for conventional OpenPGP User ID parsing (server-side only)."""

from basilisk.openpgp.canonical import emails_from_uids, parse_uid_parts, structure_uids


def test_parse_name_email():
    p = parse_uid_parts("Alice Example <alice@example.com>")
    assert p["raw"] == "Alice Example <alice@example.com>"
    assert p["name"] == "Alice Example"
    assert p["email"] == "alice@example.com"
    assert p["comment"] is None


def test_parse_name_comment_email():
    p = parse_uid_parts("Alice (work) <alice@example.com>")
    assert p["name"] == "Alice"
    assert p["comment"] == "work"
    assert p["email"] == "alice@example.com"


def test_parse_angle_email_only():
    p = parse_uid_parts("<alice@example.com>")
    assert p["name"] is None
    assert p["email"] == "alice@example.com"


def test_parse_bare_email():
    p = parse_uid_parts("alice@example.com")
    assert p["email"] == "alice@example.com"
    assert p["name"] is None


def test_parse_freeform_name_with_at_not_email():
    # Not conventional — do not treat whole string as email.
    p = parse_uid_parts("John Doe john@example.com")
    assert p["email"] is None
    assert p["raw"] == "John Doe john@example.com"


def test_parse_name_only():
    p = parse_uid_parts("No Email Name")
    assert p["email"] is None
    assert p["name"] is None
    assert p["raw"] == "No Email Name"


def test_emails_from_uids():
    assert emails_from_uids(
        [
            "Alice <alice@example.com>",
            "bob@example.com",
            "No Email",
            "John Doe john@example.com",
        ]
    ) == ["alice@example.com", "bob@example.com"]


def test_structure_uids():
    out = structure_uids(["Alice <a@b.co>", "x@y.z"])
    assert out[0]["email"] == "a@b.co"
    assert out[0]["name"] == "Alice"
    assert out[1]["email"] == "x@y.z"

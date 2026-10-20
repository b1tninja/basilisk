"""Optional FastMCP server. Importing this module does not import FastMCP.

Run it with ``python -m basilisk.mcp`` after ``pip install -r requirements-mcp.txt``.
The tool names and the confirm/overwrite rules are in ``docs/proposals/mcp.md``.
"""

from __future__ import annotations

from basilisk.mcp.tools import key_status, lookup_key, search

INSTRUCTIONS = """\
basilisk-mcp reads the local verifying keyserver store. It looks up a
certificate the way HKP get does, searches the way HKP index does, and
reports whether a fingerprint is pending, approved, rejected, or expired,
and whether the stored blob still matches its digest.

These tools do not upload, send, or fetch. A future upload tool must be
named basilisk_send_* and return a plan until confirm=true. A future tool
that writes a file must be named basilisk_write_* and must refuse to
replace a file that is already there.
"""


def build_server():
    """Construct the FastMCP server. Raises ImportError when the extra is absent."""
    from fastmcp import FastMCP

    mcp = FastMCP("basilisk", instructions=INSTRUCTIONS)
    mcp.tool(lookup_key, name="basilisk_lookup_key")
    mcp.tool(search, name="basilisk_search")
    mcp.tool(key_status, name="basilisk_key_status")
    return mcp


def main() -> None:
    try:
        server = build_server()
    except ImportError as exc:
        raise SystemExit(
            "FastMCP is not installed. pip install -r requirements-mcp.txt"
        ) from exc
    server.run()

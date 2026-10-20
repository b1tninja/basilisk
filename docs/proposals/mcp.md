# Read-only MCP

A small optional server that reads the certificate store the keyserver already
uses. It is not part of the Function App, it opens no socket of its own until
someone runs it, and the keyserver's requirements do not include it.

```
pip install -r requirements-mcp.txt
python -m basilisk.mcp
```

The store is whatever `BASILISK_DB_PATH` and `BASILISK_BLOB_PATH` point at.
Tests point those at a temporary directory and never leave the machine.

## Tools

| Tool | What it does |
| --- | --- |
| `basilisk_lookup_key` | HKP get. Pending certificates come back with user IDs stripped. A redirect is reported and not followed. |
| `basilisk_search` | HKP index, the machine-readable text an HKP client parses. |
| `basilisk_key_status` | Approval state, revocation, expiration, and whether the blob bytes still match the stored digest. Pending and rejected user IDs are omitted. |

## Names, when a later tool is not read-only

This follows the naming in [b1tninja/hardly](https://github.com/b1tninja/hardly).

- A tool that uploads a key, sends mail, or otherwise transmits bytes is named `basilisk_send_*`. With `confirm` omitted or false it returns a plan and sends nothing. It sends only when `confirm=true`.
- A tool that writes a file is named `basilisk_write_*`. If the path already exists it refuses. It does not take an overwrite flag that defaults to replacing the file.
- Every other tool only reads.

There is no `send_` tool and no `write_` tool in this version. Lookup, search, and status do not need one.

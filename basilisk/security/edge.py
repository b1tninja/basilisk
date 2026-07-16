"""Front Door / edge trust helpers."""

from __future__ import annotations

import os


def expected_afd_id() -> str:
    return os.environ.get("BASILISK_AFD_ID", "").strip()


def request_has_trusted_afd(headers: dict[str, str]) -> bool:
    """
    When BASILISK_AFD_ID is set, require X-Azure-FDID to match.
    This blocks direct origin hits that bypass Front Door / WAF.
    """
    expected = expected_afd_id()
    if not expected:
        return True
    for key, value in headers.items():
        if key.lower() == "x-azure-fdid" and value.strip() == expected:
            return True
    return False

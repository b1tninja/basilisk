"""The one implementation of "add a per-deployment source to a page's policy".

A browser enforces the **intersection** of the `<meta http-equiv>` policy a
document carries and the `Content-Security-Policy` header the response arrives
with. Most of Basilisk's policy is a build-time constant and lives in the HTML;
the signalling socket is not — its hostname comes out of a connection string
that differs per deployment — so it has to be merged into the meta somewhere
after the build and before a browser reads it.

**This module is flask-free on purpose.** It used to live inside
``basilisk.portal.static``, which imports Flask, so the only thing that could
call it was a running web server. That was the whole defect: in the deployment
that matters the portal HTML is *not* served by Flask at all — Front Door routes
``/*`` to the storage account's ``$web`` container and only ``/api/*``,
``/pks/*``, ``/claim/*``, ``/.auth/*`` and ``/health`` reach the Function App.
So the merge never ran on the documents that needed it, the header carried
``wss://…`` and the meta did not, the intersection was empty for that source,
and shared sessions could not open a socket on the deployed site.

Living here, it can be applied by the packaging step — to the artifact that is
actually uploaded — and by the Flask path, from one piece of code.
"""

from __future__ import annotations

import re

#: The value half of a `connect-src` directive, in either a meta tag or a header.
_CONNECT_SRC_RE = re.compile(r"(connect-src\s+)([^;\"]+)")


def connect_src_sources(policy: str) -> list[str]:
    """The sources a policy's ``connect-src`` lists, in order.

    Returns ``[]`` when the policy names no ``connect-src`` at all — which is
    *not* the same as allowing nothing, because the directive then falls back to
    ``default-src``. Callers comparing two policies must treat the empty list as
    "not stated here" rather than as an empty allowlist.
    """
    match = _CONNECT_SRC_RE.search(policy)
    return match.group(2).split() if match else []


def merge_connect_src(html: str, extra_sources: tuple[str, ...]) -> str:
    """Add per-deployment sources to a document's own ``connect-src``.

    Additive and idempotent: sources already present are left alone, which keeps
    a page's own extra entries intact and means applying this twice — once at
    packaging, once by Flask — cannot grow a duplicate.

    Only the first ``connect-src`` is rewritten; a page carries one policy.
    """
    if not extra_sources:
        return html

    def add(match: re.Match[str]) -> str:
        prefix, existing = match.group(1), match.group(2)
        parts = existing.split()
        for source in extra_sources:
            if source not in parts:
                parts.append(source)
        return f"{prefix}{' '.join(parts)}"

    return _CONNECT_SRC_RE.sub(add, html, count=1)


def missing_from_meta(meta_policy: str, header_policy: str) -> list[str]:
    """Sources the header allows that the document's own policy does not.

    Every one of these is a source the browser will refuse, because the two
    policies intersect — and it is the shape of bug that cannot be seen from
    either side alone. A deployment whose header is right and whose meta is
    stale looks correct in every configuration file and is broken in the
    browser.

    ``'self'`` and other keywords are compared as written; nothing here tries to
    resolve them, because a keyword that appears in one policy and not the other
    is exactly as much of a problem as a hostname that does.
    """
    meta = connect_src_sources(meta_policy)
    if not meta:
        return []
    return [source for source in connect_src_sources(header_policy) if source not in meta]

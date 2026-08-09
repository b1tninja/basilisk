"""The three places a `connect-src` has to agree, and the one source that is
not a constant.

A browser applies the `<meta>` policy and the response header as an
*intersection*, and Front Door overwrites the origin's header on the way out.
So a signalling socket is only reachable when all three allow it — and the
signalling host is per-deployment, which is exactly why it cannot be baked into
the policy string the way the keyserver hosts are.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from basilisk.config import get_settings
from basilisk.portal.static import merge_connect_src

ROOT = Path(__file__).resolve().parents[2]
CONNECTION = "Endpoint=https://basilisk.webpubsub.azure.com;AccessKey=k;Version=1.0;"


def _connect_src(policy: str) -> list[str]:
    match = re.search(r"connect-src ([^;\"]+)", policy)
    return match.group(1).split() if match else []


@pytest.fixture(autouse=True)
def _reset():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.unit
def test_the_meta_the_header_and_front_door_start_from_the_same_list():
    toolkit = (ROOT / "web" / "toolkit.html").read_text(encoding="utf-8")
    meta = _connect_src(toolkit)
    assert meta, "no CSP meta in web/toolkit.html"

    front_door = (ROOT / "terraform" / "modules" / "basilisk" / "frontdoor.tf").read_text(
        encoding="utf-8"
    )
    # Front Door overwrites the origin's header, so this string is the one the
    # browser actually sees on a cached page.
    values = re.findall(r'"(connect-src [^"]+)"', front_door)
    assert values, "no connect-src in frontdoor.tf"
    for value in values:
        # The interpolated signalling origin is the one per-deployment source.
        assert [s for s in _connect_src(value) if "${" not in s] == meta
        assert "${local.signaling_wss_origin}" in value

    from basilisk.config import Settings

    settings = Settings.from_env()
    # The server's own header is built from config rather than written out, so
    # its constant part is what has to line up with the two static copies.
    assert [s for s in settings.csp_connect_src().split() if not s.startswith("ws")] == meta


@pytest.mark.unit
def test_the_signalling_host_comes_from_config_and_never_from_a_literal(monkeypatch):
    monkeypatch.setenv("AZURE_WEBPUBSUB_CONNECTION_STRING", CONNECTION)
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.signaling_ws_origin() == "wss://basilisk.webpubsub.azure.com"
    assert "wss://basilisk.webpubsub.azure.com" in settings.csp_connect_src()

    # Not hardcoded anywhere: a second deployment has a different hostname, and
    # a literal would silently be the first deployment's.
    for path in (
        ROOT / "web" / "toolkit.html",
        ROOT / "web" / "quorum.html",
        ROOT / "terraform" / "modules" / "basilisk" / "frontdoor.tf",
        ROOT / "basilisk" / "serve.py",
    ):
        assert "webpubsub.azure.com" not in path.read_text(encoding="utf-8"), path


@pytest.mark.unit
def test_a_local_double_is_a_ws_source_not_a_wss_one(monkeypatch):
    monkeypatch.setenv(
        "AZURE_WEBPUBSUB_CONNECTION_STRING", "Endpoint=http://127.0.0.1:8081;AccessKey=k;"
    )
    get_settings.cache_clear()
    assert get_settings().signaling_ws_origin() == "ws://127.0.0.1:8081"


@pytest.mark.unit
def test_a_malformed_connection_string_turns_signalling_off_rather_than_crashing(monkeypatch):
    monkeypatch.setenv("AZURE_WEBPUBSUB_CONNECTION_STRING", "this is not a connection string")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.signaling_ws_origin() is None
    assert "ws" not in settings.csp_connect_src()


@pytest.mark.unit
def test_merging_adds_the_source_without_disturbing_the_page_it_found():
    # `quorum.html` carries `stun:` sources the other pages do not. Merging has
    # to be additive, or enabling signalling would silently remove them.
    page = (ROOT / "web" / "quorum.html").read_text(encoding="utf-8")
    merged = merge_connect_src(page, ("wss://x.webpubsub.azure.com",))
    before, after = _connect_src(page), _connect_src(merged)
    assert after == [*before, "wss://x.webpubsub.azure.com"]
    assert "stun:stun.cloudflare.com:3478" in after
    # Idempotent: a page served twice does not grow a duplicate source.
    assert merge_connect_src(merged, ("wss://x.webpubsub.azure.com",)) == merged
    assert merge_connect_src(page, ()) == page


@pytest.mark.unit
def test_the_served_page_and_the_served_header_allow_the_same_socket(monkeypatch):
    monkeypatch.setenv("AZURE_WEBPUBSUB_CONNECTION_STRING", CONNECTION)
    get_settings.cache_clear()
    from basilisk.serve import create_app

    response = create_app().test_client().get("/toolkit")
    assert response.status_code == 200
    header = _connect_src(response.headers["Content-Security-Policy"])
    served = _connect_src(response.get_data(as_text=True))
    assert "wss://basilisk.webpubsub.azure.com" in header
    # The intersection is what the browser enforces, so a source in one and not
    # the other is a source that does not exist.
    assert "wss://basilisk.webpubsub.azure.com" in served
    assert set(served) <= set(header)

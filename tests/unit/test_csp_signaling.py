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
from basilisk.security.csp import missing_from_meta

ROOT = Path(__file__).resolve().parents[2]
CONNECTION = "Endpoint=https://basilisk.webpubsub.azure.com;AccessKey=k;Version=1.0;"
#: A deployment-shaped signalling origin, standing in for the interpolation.
WSS = "wss://basilisk-dev-wps.webpubsub.azure.com"


def _front_door_policy() -> str:
    """The CSP Front Door overwrites onto every static response, as written."""
    text = (ROOT / "terraform" / "modules" / "basilisk" / "frontdoor.tf").read_text(
        encoding="utf-8"
    )
    values = re.findall(r'"(connect-src [^"]+)"', text)
    assert len(values) == 1, f"expected one connect-src in frontdoor.tf, found {len(values)}"
    return values[0]


FRONT_DOOR_POLICY = _front_door_policy()


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
def test_the_built_pages_alone_would_veto_the_header_front_door_sends():
    """The production failure, stated as a property of the artifact.

    `keys.b1tninja.com` served `/toolkit` from the storage account's `$web`
    container — Front Door routes `/*` there and only `/api/*`, `/pks/*`,
    `/claim/*`, `/.auth/*` and `/health` to the Function App. So the bytes in
    the blob were `web/dist/toolkit.html` exactly as built, the header was Front
    Door's (with `wss://…`), and the browser intersected the two: signalling had
    no reachable origin and shared sessions could not start.

    The Flask test below passes and always did, because it exercises a route
    these documents do not take in the deployment that matters. This is the
    assertion that fails on the artifact itself.
    """
    header = FRONT_DOOR_POLICY.replace("${local.signaling_wss_origin}", WSS)
    for page in sorted((ROOT / "web").glob("*.html")):
        meta = page.read_text(encoding="utf-8")
        if not _connect_src(meta):
            continue
        assert missing_from_meta(meta, header) == [WSS], (
            f"{page.name}: expected the built page to be missing exactly the "
            "per-deployment signalling origin — anything else means the meta "
            "and the Front Door header have drifted on a constant source"
        )


@pytest.mark.unit
def test_packaging_merges_the_origin_so_the_uploaded_page_allows_it():
    """…and the packaging step is what closes it, for every page.

    Asserted over `web/*.html` rather than a fixture because these are the
    documents that get uploaded, and a page added later must be covered the day
    it lands. `missing_from_meta` returning empty is the whole property: after
    the merge there is nothing the header allows that the document refuses.
    """
    header = FRONT_DOOR_POLICY.replace("${local.signaling_wss_origin}", WSS)
    pages = [p for p in sorted((ROOT / "web").glob("*.html")) if _connect_src(p.read_text("utf-8"))]
    assert pages, "no page carries a CSP meta — the sweep would be vacuous"
    for page in pages:
        merged = merge_connect_src(page.read_text(encoding="utf-8"), (WSS,))
        assert missing_from_meta(merged, header) == [], page.name


@pytest.mark.unit
def test_the_packaging_step_is_the_one_that_runs_on_the_deployed_artifact():
    """The merge has to happen where the bytes are uploaded, not per request.

    A grep, because the alternative is running a bash script that needs npm and
    Azure credentials. It pins the two facts that make the fix work: packaging
    reads the origin, and it does so *before* the clean-URL aliases are copied —
    `/toolkit` is served by the extensionless blob, so injecting after the copy
    would fix the page nobody fetches and leave the one they do.
    """
    script = (ROOT / "scripts" / "package-static.sh").read_text(encoding="utf-8")
    assert "BASILISK_SIGNALING_WSS_ORIGIN" in script
    assert "merge_connect_src" in script
    assert script.index("merge_connect_src") < script.index('cp "$html" "${OUT}/${base}"')

    deploy = (ROOT / "scripts" / "deploy-static.sh").read_text(encoding="utf-8")
    assert "signaling_wss_origin" in deploy, "deploy does not read the terraform output"
    assert "export BASILISK_SIGNALING_WSS_ORIGIN" in deploy


@pytest.mark.unit
def test_an_unresolved_signalling_origin_stops_the_deploy_rather_than_warning():
    """The silent path has to be the failing one.

    `terraform output` is wrapped so that an uninitialised workspace, a renamed
    output or any other error yields an empty string. When that was a warning it
    scrolled past in CI, the pages uploaded with signalling off, and Front Door
    cached them for a day — a deploy switching off a headline feature and saying
    so only on stderr. Both layers now refuse.

    `none` is the deliberate opt-out, spelled the way `rtc.ice stun=none` spells
    the same idea: this codebase already distinguishes "nobody said" from
    "somebody said none", and `NO_ICE_SERVERS` exists for exactly that. Reusing
    the word beats inventing a second flag.
    """
    deploy = (ROOT / "scripts" / "deploy-static.sh").read_text(encoding="utf-8")
    # The failure has to come before anything is uploaded.
    assert "exit 1" in deploy
    assert deploy.index("exit 1") < deploy.index("az storage blob upload-batch")
    assert "BASILISK_SIGNALING_WSS_ORIGIN=none" in deploy, "no documented opt-out"
    assert "WARNING: no signalling origin" not in deploy, "still warns instead of refusing"

    package = (ROOT / "scripts" / "package-static.sh").read_text(encoding="utf-8")
    assert 'origin == "none"' in package, "packaging has no explicit opt-out"
    assert "SystemExit(1)" in package, "packaging still proceeds on an unset origin"


@pytest.mark.unit
def test_the_deploy_checks_the_live_site_afterwards():
    """The one check that sees what a visitor gets.

    Everything else in this repo inspects an artifact or a harness. This runs
    against the deployed URL after the upload and the purge, and compares the
    two halves of the policy the browser will intersect — which is the check
    that would have caught this from the outside.
    """
    smoke = (ROOT / "scripts" / "smoke-test.sh").read_text(encoding="utf-8")
    assert "check_csp_meta_allows_header" in smoke
    # Against /toolkit: the page that opens the socket, so a header-only source
    # costs a feature there rather than nothing.
    assert "/toolkit?" in smoke
    # And it is wired into the deploy, not merely defined.
    deploy_ci = (ROOT / "scripts" / "deploy-github-actions.sh").read_text(encoding="utf-8")
    assert "smoke-test.sh" in deploy_ci


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

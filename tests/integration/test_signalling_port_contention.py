"""Two servers on one machine must not both want the same signalling socket.

``basilisk.serve`` starts the local Web PubSub double in-process whenever the
connection string points at loopback, and the dev connection string used to
name a constant port. Nothing was wrong with that until two servers ran at
once — a second e2e spec, a dev run beside a test run — at which point the
second process died inside ``bind`` before Flask was ever created and the
harness could report only that the server never answered ``/health``.

A guard that starts one server proves nothing about that, so this starts
several and holds them **all** up at the same time: the assertion is that N
concurrent servers listen on N different sockets and that each one advertises
the socket it actually bound. Nothing is torn down until every process has
reported, because a server that has already exited cannot collide with
anything.

The two failure modes are platform-split and the test catches both. On Linux
the loser of the old race raised ``OSError: [Errno 98] Address already in use``
and never printed a line. On Windows ``SO_REUSEADDR`` lets the second bind
succeed on a port the first still owns, so both processes came up and both
claimed ``ws://127.0.0.1:8081`` — no crash, and a page that dialled it reached
whichever of the two the OS felt like. Distinctness is the assertion that fails
in both worlds.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from basilisk.config import get_settings
from basilisk.serve import create_app, start_local_signalling

ROOT = Path(__file__).resolve().parents[2]

#: Four is enough to lose a one-port race and small enough to stay quick. The
#: old code fails this at two.
CONCURRENT = 4

#: Start signalling exactly the way ``basilisk.serve`` does, say where it
#: landed, and then hold the socket open until the parent lets go — the holding
#: is what makes the next process's start concurrent rather than sequential.
BOOT = """
import json, sys
from basilisk.config import get_settings
from basilisk.serve import start_local_signalling

double = start_local_signalling("127.0.0.1")
# Both, because they answer different questions: `bound` is the socket this
# process is listening on, `advertised` is what every page's CSP and every
# negotiate grant will name. The defect being guarded is the two disagreeing.
print(
    json.dumps(
        {
            "bound": None if double is None else double.port,
            "advertised": get_settings().signaling_ws_origin(),
        }
    ),
    flush=True,
)
sys.stdin.readline()
"""


def _first_line(proc: subprocess.Popen, timeout: float = 60.0) -> str:
    """One line of the child's stdout, or "" if it died or wedged.

    A dead child's pipe reaches EOF immediately, so the timeout is only ever
    spent on a child that is genuinely stuck.
    """
    out: list[str] = []
    reader = threading.Thread(target=lambda: out.append(proc.stdout.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    return out[0] if out else ""


@pytest.mark.integration
def test_concurrent_servers_never_contend_for_one_signalling_port():
    env = dict(os.environ)
    # Unset, so the dev fallback in `config.py` is what every child resolves —
    # which is the string the failing e2e servers were running on.
    env.pop("AZURE_WEBPUBSUB_CONNECTION_STRING", None)
    env["BASILISK_ALLOW_DEV_SECRET"] = "1"
    env["PYTHONUNBUFFERED"] = "1"

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", BOOT],
            cwd=str(ROOT),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(CONCURRENT)
    ]
    try:
        # Spawned first, read second: every child is already racing for a port
        # by the time the first line is collected.
        reports = []
        for i, proc in enumerate(procs):
            line = _first_line(proc)
            if not line.strip():
                proc.kill()
                # Whatever it said before it died, the way the e2e harness
                # reports a server that never answered.
                raise AssertionError(
                    f"server {i} of {CONCURRENT} never named a signalling port:\n"
                    f"{(proc.stderr.read() or '(no output)').strip()}"
                )
            reports.append(json.loads(line))

        for i, report in enumerate(reports):
            assert report["bound"], f"server {i} started no double at all"
            assert report["advertised"] == f"ws://127.0.0.1:{report['bound']}", (
                f"server {i} advertised {report['advertised']!r} but bound port {report['bound']} — "
                "the address handed to the page is not the one anything is listening on"
            )

        advertised = [r["advertised"] for r in reports]
        assert len(set(advertised)) == CONCURRENT, (
            f"{CONCURRENT} concurrent servers claimed {len(set(advertised))} distinct "
            f"signalling origins: {advertised}"
        )

        # Distinct strings are not proof of distinct owners; every one of them
        # has to be a socket that is up right now, with all the others up too.
        for report in reports:
            with socket.create_connection(("127.0.0.1", report["bound"]), timeout=5):
                pass
    finally:
        for proc in procs:
            proc.kill()
            proc.wait(timeout=10)


@pytest.mark.integration
def test_a_connection_string_that_names_a_port_is_still_obeyed(monkeypatch):
    """Choosing a port is what happens when nobody has chosen one.

    ``docker-compose.e2e.yml`` publishes 8081 out of the container and puts that
    number in the connection string; a double that wandered off it would leave
    the published port owned by nothing. So a named port is taken as named, and
    the endpoint — which is what the client is handed and what ``verify_token``
    checks every ``aud`` against — is left exactly as configured.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        wanted = probe.getsockname()[1]
    connection = f"Endpoint=http://127.0.0.1:{wanted};AccessKey=k;Version=1.0;"
    monkeypatch.setenv("AZURE_WEBPUBSUB_CONNECTION_STRING", connection)
    get_settings.cache_clear()

    double = start_local_signalling("127.0.0.1")
    assert double is not None
    try:
        assert double.port == wanted
        assert double.endpoint.endpoint == f"http://127.0.0.1:{wanted}"
        # Nothing was published back, because nothing needed correcting.
        assert os.environ["AZURE_WEBPUBSUB_CONNECTION_STRING"] == connection
    finally:
        double.stop()
        get_settings.cache_clear()


@pytest.mark.integration
def test_the_policy_the_app_serves_names_the_socket_the_double_bound(monkeypatch):
    """The port has to be known before ``create_app`` freezes the CSP header.

    ``portal/static.py`` merges the signalling origin into each page's ``<meta>``
    per request, but the response header is built once at app creation and the
    browser enforces the *intersection*. So a double that binds after the app is
    built produces two policies that name different sockets and a page that can
    reach neither — the same shape of defect that shipped once already.
    """
    monkeypatch.delenv("AZURE_WEBPUBSUB_CONNECTION_STRING", raising=False)
    get_settings.cache_clear()

    double = start_local_signalling("127.0.0.1")
    assert double is not None, "the dev connection string points at loopback and must start a double"
    try:
        origin = get_settings().signaling_ws_origin()
        assert origin == f"ws://127.0.0.1:{double.port}"
        assert re.fullmatch(r"ws://127\.0\.0\.1:\d+", origin), origin

        policy = create_app().test_client().get("/health").headers["Content-Security-Policy"]
        assert origin in policy, f"{origin} is not in the header policy: {policy}"
    finally:
        double.stop()
        get_settings.cache_clear()

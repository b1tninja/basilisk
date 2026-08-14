"""The integrity pin, checked against the bytes a visitor is actually served.

`/integrity/module-roots.json` is the document every visitor's power-on self
test compares its live module root against. Until these checks existed, nothing
in the repository ever compared it to the artifact the deploy built: the Vitest
suite reads `web/dist` before the upload, and `IntegrityPanel` reads the page it
is running inside — which is why `deployment-check.js` says in its own words
that a server serving tampered code can serve a tampered checker with it.

`scripts/smoke-test.sh` runs on the machine that made the artifact, after the
upload and after the Front Door purge, and exits non-zero. It is the one place
"built" and "served" are two separate things that can be held up against each
other, so these assert that it does, and that it refuses rather than skipping
when it has nothing to compare against.

Greps, for the reason `test_csp_signaling.py` uses them: running the script
needs Azure credentials and a deployment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = (ROOT / "scripts" / "smoke-test.sh").read_text(encoding="utf-8")


@pytest.mark.unit
def test_the_smoke_test_compares_the_served_pin_with_the_staged_one():
    assert "check_served_pin_matches_staged" in SMOKE
    # Defined *and* called. A helper nobody invokes is the shape of a check
    # that has been retired without anyone saying so.
    assert SMOKE.count("check_served_pin_matches_staged") >= 2
    assert "/integrity/module-roots.json" in SMOKE


@pytest.mark.unit
def test_the_smoke_test_compares_the_served_pages_with_the_staged_ones():
    """The pin alone would leave the larger hole open.

    An edge serving last deploy's HTML with this deploy's pin passes a
    pin-to-pin comparison and fails in every visitor's browser. The module
    hashes in the page are what the pin describes, so they are what has to
    match — and comparing the `integrity=` token set rather than re-folding it
    into a Merkle root keeps the fold in `web/src/lib/module-integrity.js` the
    only implementation of it.
    """
    assert "check_served_sri_matches_staged" in SMOKE
    assert SMOKE.count("check_served_sri_matches_staged") >= 2
    assert "integrity=" in SMOKE
    # No second Merkle implementation crept in alongside it. Comments stripped
    # first: the comment that explains why there isn't one names it repeatedly.
    code = "\n".join(l for l in SMOKE.splitlines() if not l.lstrip().startswith("#"))
    assert "merkle" not in code.lower()
    assert "sha256sum" not in code.lower()


@pytest.mark.unit
def test_a_missing_staged_artifact_fails_rather_than_skipping():
    """Silence is how a check retires itself.

    The deploy path always has the staged directory on disk — `deploy-static.sh`
    uploads from it minutes earlier — so an absent one means the build layout
    moved, and a run that quietly said nothing would keep reporting a green
    smoke test for a comparison that had stopped happening.

    `none` is the deliberate opt-out, spelled the way this repository already
    spells the same idea for signalling: `BASILISK_SIGNALING_WSS_ORIGIN=none`
    exists so "nobody said" and "somebody said none" cannot be confused.
    """
    assert "SMOKE_STAGE_DIR" in SMOKE
    assert 'STAGE_DIR" == "none"' in SMOKE
    assert "no staged pin at" in SMOKE

    missing = SMOKE.index("no staged pin at")
    # The refusal sets the failure flag; it does not merely print.
    tail = SMOKE[missing : missing + 600]
    assert "FAIL=1" in tail


@pytest.mark.unit
def test_the_refusals_name_a_remedy_the_reader_can_perform():
    for phrase in (
        # A pin that 404s and a pin that differs are different failures.
        "the site is serving no pin document",
        "the served pin is not the one this deploy built",
        "the served page pins different modules than the staged one",
    ):
        assert phrase in SMOKE, phrase
    assert "Re-run scripts/deploy-static.sh" in SMOKE


@pytest.mark.unit
def test_the_comparison_runs_on_every_deploy_and_can_stop_one():
    deploy_ci = (ROOT / "scripts" / "deploy-github-actions.sh").read_text(encoding="utf-8")
    assert "smoke-test.sh" in deploy_ci
    # After the upload, so there is something to compare against. Comments
    # stripped: the file's own header line names both scripts in the wrong
    # order, and ordering is a property of what runs.
    code = "\n".join(
        l for l in deploy_ci.splitlines() if not l.lstrip().startswith("#")
    )
    assert code.index("deploy-static.sh") < code.index("smoke-test.sh")
    assert "exit 1" in SMOKE


@pytest.mark.unit
def test_the_roots_it_prints_are_not_truncated():
    """A root a reader cannot copy is a root they cannot take anywhere.

    The whole point of printing both values on a mismatch is that someone can
    ask a second machine which one it sees. `head -c`, `cut -c` and `${x:0:n}`
    over a root would each turn that into a number that merely looks precise.
    """
    for maimed in ("head -c", "cut -c", "0:16", "slice(0, 16)"):
        assert maimed not in SMOKE, maimed

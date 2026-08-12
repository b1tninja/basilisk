import { IntegrityPanel } from "basilisk-portal";
import type { DeploymentVerdict } from "basilisk-portal";

/*
 * "Is the code in this tab the code it should be?", answered on the page it is
 * asking about.
 *
 * `docs/THREAT-MODEL.md` opens with this problem and then tells the reader to
 * compare `/integrity/module-roots.json` against the SRI hashes in the HTML by
 * hand. Almost nobody does. This is that comparison, run and explained.
 *
 * **Four of the six outcomes are "cannot verify", and none of them is green.**
 * That is the design, not a gap in it: no SRI on the page, no pin document
 * configured, pins unreachable, mirrors disagreeing. Those are the *common*
 * states, and a tick beside any of them would be a lie a reader would act on.
 * The tone token is doing real work here — `--warn` for the ones that mean "no
 * answer", `--error` for the two that mean "the answer is bad".
 *
 * Two rules the layout holds to, both visible below:
 *
 * - **The limitation is never behind a disclosure.** The sentence about a
 *   tampered server serving a tampered checker sits under *every* verdict,
 *   including the successful one — because a green tick is exactly the moment
 *   a reader stops reading. Collapsing it would make the panel more reassuring
 *   and less true.
 * - **The roots are shown in full.** A truncated hash is decorative; the whole
 *   point is that a person can compare it against another machine or another
 *   person, so it is complete and it is selectable.
 *
 * Every story is a fixed `verdict` with `live={false}`. The panel runs the real
 * check on mount otherwise, and a design surface must not depend on what the
 * machine rendering it happens to have been served.
 */

const CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
  "connect-src 'self' https://keys.openpgp.org https://keys.mailvelope.com; " +
  "img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';";

const LIVE_ROOT = "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021";
const OTHER_ROOT = "41bb90de77c2a8f5b0e1cc7d2299a4531ff08b6ea72d40c3195e6b8aa04d7712";

const base: DeploymentVerdict = {
  status: "verified",
  tone: "ok",
  headline: "",
  detail: "",
  root: LIVE_ROOT,
  expectedRoot: "",
  leafCount: 34,
  pageKey: "toolkit.html",
  pinUrls: ["/integrity/module-roots.json"],
  fetched: 1,
  raw: "",
};

const panel = (verdict: DeploymentVerdict) => (
  <IntegrityPanel verdict={verdict} policy={CSP} live={false} />
);

/**
 * The only green state, and the one carrying the most weight per pixel. Two
 * pin documents agreed with a root folded from 34 modules the browser had
 * already checked individually — and the limitation still sits underneath it.
 */
export const Verified = () =>
  panel({
    ...base,
    headline: "Matches the published pin for toolkit.html.",
    detail:
      "34 modules loaded, folding to root 9f2c1a44b8e07d31…, and 2 pin documents agree. " +
      "The browser separately enforced each module's own SRI hash on load, so nothing " +
      "outside this set executed.",
    expectedRoot: LIVE_ROOT,
    pinUrls: ["/integrity/module-roots.json", "https://mirror.example/module-roots.json"],
    fetched: 2,
    raw: "Integrity pin matched (2 sources).",
  });

/**
 * **The failure the whole mechanism exists to make visible**, and the only
 * screen in the product that tells someone to stop.
 *
 * Both roots are on screen because the reader's next move is comparing them
 * somewhere else. The copy names the boring explanations first — a stale cache,
 * a half-finished deploy — since those are the common ones, and then says the
 * thing that matters: from here they are indistinguishable from the other one.
 */
export const Mismatch = () =>
  panel({
    ...base,
    status: "mismatch",
    tone: "error",
    headline: "The code in this tab is not the code the pin describes.",
    detail:
      "Module Merkle root mismatch (live 9f2c1a44b8e07d31… ≠ pin 41bb90de77c2a8f5…). " +
      "This is the failure the whole mechanism exists to make visible. It can be a stale " +
      "cache or a half-finished deploy — those are the boring explanations and they are the " +
      "common ones — but it is indistinguishable from the interesting one. Close the tab, " +
      "clear the cache, and load it again; if the root still differs, do not enter key " +
      "material into this page.",
    expectedRoot: OTHER_ROOT,
  });

/**
 * Mirrors exist so that subverting one host is not enough. Two answers means a
 * deploy caught mid-flight or one of them lying, and from the page those look
 * the same — so this is `--error`, not `--warn`, even though nothing has been
 * proven wrong. The "Pinned root" row is deliberately absent: there is no one
 * expected value to print, and printing either would pick a side.
 */
export const MirrorsDisagree = () =>
  panel({
    ...base,
    status: "disagree",
    tone: "error",
    headline: "The pin mirrors do not agree with each other.",
    detail:
      "Integrity pin mirrors disagree (9f2c1a44b8e07d31 vs 41bb90de77c2a8f5). Mirrors exist " +
      "so that subverting one host is not enough; two answers means either a deploy caught " +
      "mid-flight or one of them is lying, and from here those look identical. Do not use " +
      "this tab for anything sensitive until the mirrors converge.",
    pinUrls: ["/integrity/module-roots.json", "https://mirror.example/module-roots.json"],
    fetched: 2,
  });

/**
 * A blocked fetch and a suppressed one look identical from inside the page.
 * Drawn as a failure rather than a shrug for that reason: the check that would
 * have caught tampering is the check that did not run.
 */
export const Unreachable = () =>
  panel({
    ...base,
    status: "unreachable",
    tone: "error",
    headline: "Cannot verify — the pin document could not be read.",
    detail:
      "Integrity pin fetch failed (HTTP 503). A blocked or offline fetch looks exactly like " +
      "a suppressed one. Treat this as unverified rather than as fine: the check that would " +
      "have caught tampering is the check that did not run.",
    fetched: 0,
  });

/**
 * **The state most deployments are actually in.** A root was computed and the
 * browser did enforce every module's own SRI hash — so this is not nothing —
 * but with no pin document there is nothing independent to compare it against.
 * "Pin sources: none configured" is the row that says so, and the copy hands
 * the reader the only thing that would help: write the number down and compare
 * it with somebody else.
 */
export const Unpinned = () =>
  panel({
    ...base,
    status: "unpinned",
    tone: "warn",
    headline: "Cannot verify — no pin document is configured.",
    detail:
      "The 34 modules this page loaded fold to root 9f2c1a44b8e07d31…, and the browser did " +
      "enforce their individual SRI hashes — a modified module would have failed to execute. " +
      "What is missing is anything independent to compare the root against, so this number " +
      "attests to nothing but itself. Write it down and compare it with another machine, or " +
      "another person, if that matters to you.",
    pinUrls: [],
    fetched: 0,
  });

/**
 * The dev server, said plainly — and the same words on a deployed origin mean
 * the build skipped the integrity step, so none of the threat model's first
 * section applies to the page you are reading. Every fact row empties out,
 * which is the point: there is nothing to show, and inventing a placeholder
 * root would be worse than a dash.
 */
export const NoIntegrityHashes = () =>
  panel({
    ...base,
    status: "no-sri",
    tone: "warn",
    headline: "Cannot verify — this page carries no integrity hashes.",
    detail:
      "Nothing on it declares an SRI digest, so there is no set of module hashes to check. " +
      "That is normal on the dev server, which serves unhashed modules and a looser " +
      "Content-Security-Policy than production. If you are seeing this on a deployed origin, " +
      "the build that produced it did not run the integrity step, and none of the guarantees " +
      "in the threat model's first section apply to it.",
    root: "",
    leafCount: 0,
    pageKey: "index.html",
    pinUrls: [],
    fetched: 0,
  });

/**
 * The first frame, before any answer exists. Reached by giving the panel no
 * verdict at all with `live={false}` — the same props the shell uses minus the
 * permission to run — so this is the component's own initial state rather than
 * a fixture imitating it.
 */
export const Checking = () => <IntegrityPanel policy={CSP} live={false} />;

/**
 * The placed-run arc, across two real browsers.
 *
 * Plan → gate → offer → *a person accepts* → run → signed result → register →
 * the stopped run completes. `handoff-offer.test.js` and `handoff-result.test.js`
 * prove that sequence in node, against real OpenPGP and a real engine, with both
 * peers in one process and every document handed from one variable to another.
 * What they cannot say is whether any of it survives being two machines: that
 * `runRecipe` gates the same way inside Chromium, that an offer built from one
 * browser's slot registry is accepted by another browser's own plan, that a
 * result signed in one realm verifies against the key the other realm fetched
 * from the directory, and that the session carries both between two contexts
 * that share no JavaScript at all.
 *
 * That is this file: two isolated browser contexts, the page the real server
 * serves, the real Flask directory and negotiate endpoint, the product's own
 * local Web PubSub double started by the product's own `serve.py`, real
 * host-candidate ICE, real key confirmation, and the same assertion set as the
 * node proofs — including the control, which is the half that makes the rest
 * mean anything: at every point where the machine could have carried on by
 * itself, it is asked to, and it does not.
 *
 * ## What is real, and what is not
 *
 * Real: both browsers, both `RTCPeerConnection`s, the toolkit page and its
 * chunks as Flask serves them (CSP merge included), `NotebookSession` resolved
 * out of the chunks the page loaded, `readHandoffOffer` and `readSignedResult`
 * inside it, the keyserver, `/api/v1/notebook/negotiate` with its proof and
 * rate-limit gates, the Web PubSub subprotocol over a real socket, OpenPGP
 * throughout, and the placed-run modules themselves — compiled from
 * `src/lib/toolkit/` for the browser, unminified and unaltered.
 *
 * Not real, and there are three:
 *
 * 1. **The signalling service is `webpubsub_local.py`**, not Azure. It is the
 *    repo's own stand-in, it speaks the documented wire, it verifies tokens
 *    with the same code that mints them, and `basilisk.serve` starts it in
 *    production-shaped conditions whenever the connection string is loopback.
 *    Azure cannot run on a laptop; this is the closest thing that can.
 * 2. **The peer labels are the test's.** `@mara` and `@okafor` are bound to
 *    fingerprints by a roster the suite supplies, and the label a signature
 *    resolves to is passed to `acceptCellResult` as `by`. Both are the caller's
 *    job by design — `attest.js` and `handoff.js` are explicit that the session
 *    never learns a label — so there is no layer here that could have supplied
 *    them and no stub standing in for one.
 * 3. **The clicks are `page.evaluate` calls.** There is no UI to click, which
 *    is not a limitation of the harness; see the next paragraph.
 *
 * ## What the bundle can do
 *
 * All five of `planRun`, `buildOfferFor`, `acceptHandoffOffer`,
 * `buildResultFor` and `acceptCellResult` now ship, and this file has watched
 * that number go from none to five.
 *
 * `useNotebook.runFrom` builds a plan when the room can bind the notebook's
 * labels and passes it as `engine.js`'s `placement`, so the gate reports the
 * cells this peer declined. `offerCell` hands one of those to the peer that
 * owns it. `sendCellResult` signs what a cell wrote with the key the session
 * was opened under, because `sendResult` refuses anything not cleartext-signed.
 * `acceptHandoff` checks an offer or a result that arrived and registers the
 * bindings it returns — from a function only a press reaches, which is the
 * consent rule `handoff.js` states, held one layer out.
 *
 * The assertion below is now "every one of the five", in one direction, and it
 * is the direction that can regress: a refactor that drops the last caller of
 * any of them puts the arc back in the bundle-less state this suite was
 * written to describe.
 *
 * Most of the arc is still compiled from `src/lib/toolkit/` and imported into
 * the page rather than resolved out of the chunks — a property of this harness
 * rather than of the product, and the reason the chunk assertions below exist
 * at all.
 *
 * None of the five takes that on trust any more. `__useArc("shipped")` pulls
 * all five back out of the `/assets/` chunks the page already fetched — each
 * found by a sentence only it ships, because export bindings are minified and
 * function names with them — and points the arc at them. `/assets/` excludes
 * the source-compiled bundle at `/e2e/`, so a hit can only be shipped bytes.
 *
 * Every step of the arc is then run a second time on those functions and has to
 * give the same answer: the plan, the offer, the verdict on it, the result, and
 * the verdict on that. Only steps that register nothing are repeated, so the
 * run above still decides everything exactly once.
 *
 * Two fields are excluded from the comparison rather than matched, and both are
 * excluded for the same reason: an offer carries `offeredAt` and a result
 * carries `ranAt`. That they *differ* is asserted too — a cached value from the
 * first pass would repeat, and these do not.
 *
 * What is left on trust is the plumbing around the five: the session, the
 * signing, and the transport are still the compiled ones.
 *
 * ## What may skip, and what may not
 *
 * Two environment facts stand this down and nothing else does: no Chromium
 * download, and no Python that can import the server. Both are classified by
 * the pure functions the sibling suites use — `classifyLaunchFailure` and
 * `classifyPythonFailure` — and both classifiers file "present but broken" as a
 * failure, per `turn-relay.e2e.js`'s rule. A suite that filed a broken engine or
 * a server that will not boot under "no browser" would skip itself green on the
 * day the arc broke.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  DIST_ROOT,
  chromiumAvailability,
  openPeers,
  until,
} from "../helpers/browser-peers.js";
import {
  basiliskAvailability,
  classifyPythonFailure,
  seedDirectory,
  startBasilisk,
} from "../helpers/basilisk-server.js";
import {
  ARC_PATH,
  buildArcBundle,
  freePorts,
  makeIdentities,
  proxyToBasilisk,
  signalingEnv,
} from "../helpers/placed-run-arc.js";


/**
 * Resolve `planRun` out of the chunks the page actually loaded, and plan the
 * same notebook with it.
 *
 * The suite drives modules compiled from `src/lib/toolkit/` because for most of
 * this file's life there were no shipped bytes to drive. There are now — all
 * five arc functions ship — and this is the first assertion that reaches them.
 *
 * A **string**, for two reasons. Vitest rewrites `import()` in anything it
 * transforms, so this cannot be a function literal in this file; and the page's
 * own CSP carries no `unsafe-eval`, so it cannot be `eval`ed in the page
 * either. Passed to `evaluate` as a string it is compiled by the runner, the
 * same way `LOAD` is — and because a string is evaluated as an *expression*
 * rather than called, it is an IIFE with its arguments baked in by
 * `JSON.stringify`, the same way this file already inlines `ARC_PATH`. Only chunks the page already fetched are considered, so
 * this re-reads an evaluated module rather than pulling a second copy of the
 * graph.
 *
 * Found by a sentence `planRun` ships and nothing else does — the same needle
 * `ONLY_IN` uses on disk — because export bindings are minified and function
 * names with them, while a string literal survives intact.
 */
const shippedPlanExpr = (args) => `(async () => {
  const { src, me, roster } = ${JSON.stringify(args)};
  const paths = [...new Set(
    performance.getEntriesByType("resource")
      .map((x) => new URL(x.name).pathname)
      .filter((n) => n.startsWith("/assets/") && n.endsWith(".js"))
  )];
  const found = [];
  for (const p of paths) {
    let mod;
    try { mod = await import(p); } catch (_) { continue; }
    for (const k of Object.keys(mod)) {
      const v = mod[k];
      if (typeof v !== "function") continue;
      if (!String(v).includes("keying-unplaced")) continue;
      found.push(v);
    }
  }
  if (found.length !== 1) {
    throw new Error("expected exactly one shipped planRun, found " + found.length);
  }
  const compiled = window.__arc.compileRecipe(window.__arc.migrateRecipe(src).recipe);
  const plan = found[0](compiled, { me, roster });
  return {
    ok: plan.ok,
    play: plan.play,
    cells: plan.cells.map((c) => ({ index: c.index, peer: c.peer, mine: c.mine })),
  };
})()`;

/* ─────────────────────────── what may stand down ─────────────────────────── */

const browser = await chromiumAvailability();
if (!browser.ok && browser.kind === "broken") {
  it("launches the browser the placed-run suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${browser.reason}`);
  });
}

const python = browser.ok
  ? await basiliskAvailability()
  : { ok: false, python: "", reason: browser.reason, kind: /** @type {const} */ ("absent") };
if (browser.ok && !python.ok && python.kind === "broken") {
  it("runs the server the placed-run suite signals through", () => {
    expect.unreachable(`python answered and the server would not import: ${python.reason}`);
  });
}

const ready = browser.ok && python.ok;
const standDown = !browser.ok ? browser : python;

// `turn-relay.e2e.js`'s line, for its reason: a module-scope `console.warn` is
// swallowed by Vitest's collector, so the reason a suite did nothing is carried
// by a test that always runs and whose name states the outcome.
it(
  ready
    ? "has a browser and a server to prove the arc against"
    : `stands down, and only for a reason that is not news: ${standDown.kind}`,
  () => {
    if (ready) {
      expect(python.python).toBeTruthy();
      return;
    }
    console.warn(`[placed-run-arc.e2e] skipping ${standDown.kind} — ${standDown.reason}`);
    expect(standDown.kind).not.toBe("broken");
  }
);

/* ───────────────────────────── the notebook ──────────────────────────────── */

/**
 * Three cells and two machines, and the third one is what makes this an arc
 * rather than a delivery.
 *
 * mara publishes a seed. okafor's cell turns it into `$b64`. **mara's last cell
 * reads `$b64`** — so mara's run does not merely skip a cell and walk on, it
 * stops, which is the state a returned result exists to end. Lifted verbatim
 * from `handoff-result.test.js`'s `ROUND_TRIP` so that a difference between node
 * and a browser is a difference in the runtime and not in the notebook.
 */
const NOTEBOOK = `@mara publish
bytes deadbeef | encode hex | out $seed

@okafor publish
in $seed | decode hex | encode base64 | out $b64

@mara
in $b64 | out $done
`;

/** What `deadbeef` comes back as, once it has been round-tripped. */
const EXPECTED_B64 = "3q2+7w==";

/* ───────────────────────── the page's own machinery ──────────────────────── */

/**
 * Resolve the shipped `NotebookSession` and the shipped OpenPGP, then load the
 * arc bundle.
 *
 * A **string**, for `quorum-key-confirmation.e2e.js`'s reason: Vitest rewrites
 * `import()` in anything it transforms into a module-runner binding that does
 * not exist in a browser. Only chunks the page already fetched are considered,
 * so this re-reads evaluated modules rather than pulling a second copy of the
 * graph in — which is what keeps the session found here the page's own.
 *
 * The constructor is identified by shape, not by name: export bindings are
 * mangled, method names are not, and it ships a string of its own.
 */
const LOAD = `(async () => {
  const paths = [...new Set(
    performance.getEntriesByType("resource")
      .map((x) => new URL(x.name).pathname)
      .filter((n) => /^\\/assets\\/.*\\.js$/.test(n))
  )];
  // Method names survive minification even where export bindings do not, so
  // the constructor is identifiable by shape. \`_onMailbox\` is deliberately not
  // in this list: it was the HTTP mailbox's entry point and the Web PubSub
  // migration deleted it, which is why the sibling suite's copy of this scan
  // now matches nothing. The four handoff methods are here because they are
  // what this suite actually needs off the prototype.
  const WANTED = [
    "start", "stop", "sendChat", "sendChatTo",
    "sendOffer", "sendResult", "publishManifest", "publishAttestation",
    "_onRelayEnvelope", "_handleSignal", "_maybeDeriveSession", "_maybeSendKeyConfirm",
  ];
  const found = [];
  for (const p of paths) {
    let mod;
    try { mod = await import(p); } catch (_) { continue; }
    for (const k of Object.keys(mod)) {
      const v = mod[k];
      if (typeof v !== "function" || !v.prototype) continue;
      const own = Object.getOwnPropertyNames(v.prototype);
      if (!WANTED.every((n) => own.includes(n))) continue;
      if (!String(v).includes("Key confirmation failed")) continue;
      found.push({ chunk: p, exportName: k, ctor: v });
    }
  }
  if (found.length !== 1) {
    throw new Error(
      "expected exactly one NotebookSession in the chunks the page loaded, found " +
        found.length + ": " + JSON.stringify(found.map((f) => f.chunk + "#" + f.exportName))
    );
  }
  const pgpPath = paths.find((n) => /\\/assets\\/openpgp[^/]*\\.js$/.test(n));
  if (!pgpPath) throw new Error("the toolkit page did not load an openpgp chunk");
  window.__Session = found[0].ctor;
  window.__pgp = await import(pgpPath);
  window.__arc = await import(${JSON.stringify(ARC_PATH)});
  if (typeof window.__arc.planRun !== "function") {
    throw new Error("the arc bundle does not export planRun");
  }
  return { chunk: found[0].chunk, exportName: found[0].exportName, pgp: pgpPath };
})()`;

/**
 * Everything the arc does inside a page, installed once.
 *
 * A **string** again, and this time for a second reason on top of the first:
 * these are the functions the suite calls in place of a person, and keeping
 * them in one readable block is what lets the reader check that no two of them
 * are secretly the same act. In particular `acceptOffer` and `acceptResult`
 * take `register` as an argument and default it to *false*, so every call site
 * below says out loud whether it is checking a document or consenting to it.
 *
 * Prose inside it quotes with `"` rather than a backtick, and there is no
 * template literal anywhere in it: a template literal is what carries it, and
 * either would end it early.
 */
/**
 * A sentence each of the five arc functions ships and nothing else does.
 *
 * Used twice: the chunk assertions at the bottom scan the built files with
 * these on disk, and `__useArc` resolves the same five inside the page. One
 * definition because two would drift, and a needle that stops matching is a
 * silent hole in the on-disk half.
 *
 * They are string literals rather than function names on purpose — the build
 * minifies export bindings and function names with them, and a literal comes
 * through intact.
 */
const ARC_NEEDLES = {
  planRun: "keying-unplaced",
  buildOfferFor: "so there is nothing to hand over",
  acceptHandoffOffer: "under cover of a cell that never asked",
  buildResultFor: "and should not have been handed over",
  acceptCellResult: "an answer to a question nobody asked",
};

const INSTALL = `(() => {
  /**
   * A mutable copy of the arc, so the five functions under test can be swapped
   * for the ones the browser shipped without touching anything else.
   *
   * A module namespace object has read-only properties, so this is a spread
   * rather than the namespace itself. Every helper below reads arc.fn at call
   * time, which is what lets one swap redirect all of them at once.
   */
  const arc = { ...window.__arc };

  const NEEDLE = ${JSON.stringify(ARC_NEEDLES)};

  let shipped = null;

  /**
   * Find the five in the chunks the page already fetched.
   *
   * Export bindings are minified and function names with them, so each is found
   * by a string literal only it contains — the same needles the on-disk
   * assertions use. Only /assets/ paths are considered, which excludes the
   * source-compiled arc bundle at /e2e/, so a hit can only be shipped bytes.
   */
  const resolveShipped = async () => {
    if (shipped) return shipped;
    const paths = [...new Set(
      performance.getEntriesByType("resource")
        .map((x) => new URL(x.name).pathname)
        .filter((n) => n.startsWith("/assets/") && n.endsWith(".js"))
    )];
    const hits = {};
    for (const path of paths) {
      let mod;
      try { mod = await import(path); } catch (_) { continue; }
      for (const k of Object.keys(mod)) {
        const v = mod[k];
        if (typeof v !== "function") continue;
        const src = String(v);
        for (const name of Object.keys(NEEDLE)) {
          if (!src.includes(NEEDLE[name])) continue;
          if (hits[name] && hits[name] !== v) {
            throw new Error("two shipped candidates for " + name);
          }
          hits[name] = v;
        }
      }
    }
    const missing = Object.keys(NEEDLE).filter((n) => !hits[n]);
    if (missing.length) throw new Error("not shipped: " + missing.join(","));
    shipped = hits;
    return shipped;
  };

  /**
   * Point the arc at the compiled modules or at the shipped ones.
   *
   * The suite runs its whole arc on "source", then repeats individual steps on
   * "shipped" and requires the same answer. Only steps that register nothing
   * are repeated, so the swap never changes what the run has decided.
   */
  window.__useArc = async (which) => {
    const from = which === "shipped" ? await resolveShipped() : window.__arc;
    for (const name of Object.keys(NEEDLE)) arc[name] = from[name];
    return { which, names: Object.keys(NEEDLE) };
  };

  /** Peer-local state. There is no shared realm; this is all one side knows. */
  const S = window.__S = {
    src: "",
    me: "",
    roster: {},
    compiled: null,
    plan: null,
    /** The manifest this peer holds for the run, however it came by it. */
    manifest: null,
    /** Bindings a person has accepted. A fresh run is seeded from these. */
    held: [],
    /** The registry the last run left behind, for reading slots out of. */
    last: null,
    /** What this peer offered, and to whom — the caller's record, not the session's. */
    offered: [],
  };

  const label = (b) => b.label;

  window.__setup = async ({ src, me, roster }) => {
    S.src = src;
    S.me = me;
    S.roster = roster;
    S.compiled = arc.compileRecipe(arc.migrateRecipe(src).recipe);
    S.plan = arc.planRun(S.compiled, { me, roster });
    return {
      ok: S.plan.ok,
      me: S.plan.me,
      summary: arc.summarizePlan(S.plan),
      cells: S.plan.cells.map((c) => ({
        index: c.index,
        mine: c.mine,
        runsOn: [...c.runsOn],
        peer: c.peer,
        produces: [...(c.produces || [])],
      })),
    };
  };

  /** Build the manifest for this notebook — deterministic, so both sides agree. */
  window.__manifest = async () => {
    const chains = arc.planChains(S.compiled);
    const manifest = await arc.buildRunManifest({
      title: "placed run",
      recipeSource: arc.migrateRecipe(S.src).recipe,
      peers: S.roster,
      cells: chains.map((chain, i) => ({
        index: i,
        peer: String(chain.peer || ""),
        publish: !!chain.publish,
        recipe: arc.serializeRecipe({ chains: [chain] }),
      })),
    });
    S.manifest = manifest;
    return { manifest, digest: await arc.manifestDigest(manifest) };
  };

  /** Adopt a manifest that arrived over the wire, verified by the session. */
  window.__adoptManifest = async (manifest) => {
    S.manifest = manifest;
    return arc.manifestDigest(manifest);
  };

  /**
   * Run the notebook as this peer, gated, in a registry seeded only with what a
   * person has accepted. Fresh each time, exactly as "handoff-result.test.js"
   * does it: a run is what the notebook plus the accepted values produce, and
   * carrying a previous run's slots forward would hide which of the two the
   * outcome came from.
   */
  window.__run = async () => {
    const registry = arc.createSlotRegistry();
    for (const b of S.held) registry.register("$" + b.label, b.value);
    const skipped = [];
    let stopped = null;
    const arts = await arc
      .runRecipe(S.compiled.ast, {}, {
        slotRegistry: registry,
        placement: { plan: S.plan, onSkip: (s) => skipped.push(s) },
      })
      .catch((err) => {
        stopped = err;
        return [];
      });
    S.last = registry;
    return {
      skipped: skipped.map((s) => ({
        cell: s.cell,
        waitingOn: s.waitingOn,
        runsOn: [...s.runsOn],
        produces: [...s.produces],
      })),
      stopped: stopped ? String(stopped.message) : null,
      withheld: stopped && stopped.basiliskWithheld ? { ...stopped.basiliskWithheld } : null,
      slots: ["seed", "b64", "done"].filter((l) => registry.has(l)),
      artifacts: arts.map((a) => String(a.content ?? "")),
    };
  };

  /** What the last run put in a slot — the offer's and the result's source. */
  const readSlot = (l) => (S.last && S.last.has(l) ? S.last.resolve(l) : null);

  window.__buildOffer = async (cell) => {
    const skipped = { cell, waitingOn: S.plan.cells[cell].runsOn[0] || "", runsOn: [], why: "", produces: [] };
    const built = await arc.buildOfferFor({
      plan: S.plan,
      compiled: S.compiled,
      manifest: S.manifest,
      skipped,
      readSlot,
    });
    return {
      ok: built.ok,
      summary: arc.summarizeHandoff(built),
      refusals: built.refusals.map((r) => r.reason),
      json: built.ok ? arc.offerToJson(built.offer) : "",
      offer: built.offer,
    };
  };

  /** Remember an offer went out — the record "acceptCellResult" answers from. */
  window.__recordOffer = (row) => {
    S.offered.push(row);
    return S.offered.length;
  };

  /**
   * Check an offer against this peer's own plan, notebook and manifest.
   *
   * "register" is the click. With it false this answers a question and changes
   * nothing; with it true a person has decided, and the bindings go in.
   */
  window.__acceptOffer = async (json, { register = false } = {}) => {
    const offer = arc.parseHandoffOffer(json);
    const held = new Set(S.held.map(label));
    const verdict = await arc.acceptHandoffOffer(offer, {
      plan: S.plan,
      compiled: S.compiled,
      manifest: S.manifest,
      hasSlot: (l) => held.has(l),
    });
    if (verdict.ok && register) S.held.push(...verdict.bindings);
    return {
      ok: verdict.ok,
      cell: verdict.cell,
      summary: arc.summarizeHandoff(verdict),
      refusals: verdict.refusals.map((r) => r.reason),
      bindings: verdict.bindings.map(label),
      registered: verdict.ok && register,
      heldNow: S.held.map(label),
    };
  };

  window.__buildResult = async (cell, armoredPrivate) => {
    const built = await arc.buildResultFor({
      plan: S.plan,
      compiled: S.compiled,
      manifest: S.manifest,
      cell,
      readSlot,
    });
    if (!built.ok) {
      return {
        ok: false,
        summary: arc.summarizeHandoff(built),
        refusals: built.refusals.map((r) => r.reason),
        signed: "",
      };
    }
    const key = await window.__pgp.readPrivateKey({ armoredKey: armoredPrivate });
    const { armored } = await arc.signOpenPgp(arc.resultToJson(built.result), [key], "cleartext");
    return {
      ok: true,
      summary: arc.summarizeHandoff(built),
      refusals: [],
      result: built.result,
      signed: armored,
    };
  };

  /**
   * Check a result the session already verified, against this peer's own plan
   * and its own record of what it handed out. "register" is the click again.
   */
  window.__acceptResult = async (result, fromFpr, { register = false } = {}) => {
    const by = arc.labelForFingerprint(S.roster, fromFpr);
    const held = new Set(S.held.map(label));
    const verdict = await arc.acceptCellResult(result, {
      plan: S.plan,
      compiled: S.compiled,
      manifest: S.manifest,
      by,
      offered: S.offered,
      hasSlot: (l) => held.has(l),
    });
    if (verdict.ok && register) S.held.push(...verdict.bindings);
    return {
      ok: verdict.ok,
      by,
      cell: verdict.cell,
      summary: arc.summarizeHandoff(verdict),
      refusals: verdict.refusals.map((r) => r.reason),
      bindings: verdict.bindings.map(label),
      registered: verdict.ok && register,
      heldNow: S.held.map(label),
    };
  };

  window.__held = () => S.held.map(label);

  /* ── the session, which is the only thing that crosses the machine ── */

  window.__startSession = async (cfg) => {
    const privateKey = await window.__pgp.readPrivateKey({ armoredKey: cfg.armoredPrivate });
    if (!privateKey.isDecrypted()) throw new Error("test key came back locked");
    window.__errors = [];
    window.__statuses = [];
    window.__offers = [];
    window.__results = [];
    window.__manifests = [];
    const session = new window.__Session({
      roomId: cfg.roomId,
      audienceFprs: cfg.audience,
      privateKey,
      myFingerprint: cfg.fpr,
      role: cfg.role,
      // No third party. Two contexts of one browser reach each other over host
      // candidates on the loopback interface, and an empty list is honoured.
      iceServers: [],
      onManifest: (m) => window.__manifests.push(m),
      onOffer: (o) => window.__offers.push(o),
      onResult: (r) => window.__results.push(r),
      onStatus: (s) => window.__statuses.push(s),
      onError: (e) => window.__errors.push(String((e && e.message) || e)),
    });
    window.__session = session;
    await session.start();
    return true;
  };

  window.__mesh = () => {
    const peers = [];
    for (const [fpr, p] of window.__session.peers) {
      peers.push({
        fpr,
        status: p.status,
        kcVerified: p.kcVerified,
        pgpVerified: p.pgpVerified,
        channelState: p.channel ? p.channel.readyState : null,
        connectionState: p.link && p.link.pc ? p.link.pc.connectionState : null,
        offered: [...p.offered],
        returned: [...p.returned],
      });
    }
    return {
      peers,
      errors: window.__errors.slice(),
      offers: window.__offers.map((o) => ({ from: o.from, cell: o.cell, manifest: o.manifest })),
      results: window.__results.map((r) => ({ from: r.from, cell: r.cell, manifest: r.manifest })),
      manifests: window.__manifests.map((m) => ({ from: m.from, digest: m.digest })),
      statuses: window.__statuses.slice(),
    };
  };

  window.__roomId = (audience) => window.__arc.deriveRoomId(audience);
  return true;
})()`;

/* ──────────────────────────────── the run ────────────────────────────────── */

describe.runIf(ready)("two browsers run a placed cell for each other", () => {
  /** @type {any} */ let fx;
  /** @type {any} */ let server;
  /** @type {any} */ let A;
  /** @type {any} */ let B;
  /** @type {any} */ let mara;
  /** @type {any} */ let okafor;
  /** @type {any} */ let loaded;
  /** @type {any} */ let out = {};
  /** @type {string} */ let roomId = "";
  /** @type {string[]} */ let audience = [];
  /** @type {Record<string, string>} */ let roster = {};

  beforeAll(async () => {
    // The identities first: the directory has to hold both public keys before
    // either session starts, because `start()` fetches the audience from it and
    // fails loudly rather than meshing with a stranger.
    [mara, okafor] = await makeIdentities(["mara@placed.test", "okafor@placed.test"]);

    // Both ports out of one allocation. Two sequential calls could hand back
    // the same number, and the same number for both means the signalling
    // double silently fails to bind inside a Flask that came up fine.
    const [wsPort, httpPort] = await freePorts(2);
    server = await startBasilisk({
      python: python.python,
      port: httpPort,
      env: signalingEnv(wsPort),
    });
    const seeded = await seedDirectory(server, [mara.corpus, okafor.corpus]);
    if (seeded.refused.length) {
      throw new Error(`the directory refused a test key: ${JSON.stringify(seeded.refused)}`);
    }

    const arc = await buildArcBundle(DIST_ROOT);
    out.arcBytes = arc.code.length;
    out.openpgpChunk = arc.openpgpChunk;

    // Everything the two browsers ask the server for, in order. `seedDirectory`
    // above went straight to Flask rather than through the proxy, so this list
    // is the pages' own traffic and nothing else.
    /** @type {string[]} */
    const calls = [];
    fx = await openPeers({
      path: "/toolkit",
      count: 2,
      routes: proxyToBasilisk(server, arc.code, {
        onRequest: (method, path) => calls.push(`${method} ${path}`),
      }),
    });
    [A, B] = fx.peers;

    loaded = {
      a: await A.page.evaluate(LOAD),
      b: await B.page.evaluate(LOAD),
    };
    for (const p of fx.peers) await p.page.evaluate(INSTALL);

    // The page's own CSP, as this deployment emits it. Read from the document
    // rather than from the file, because the file is not what a browser got.
    out.csp = await A.page.evaluate(() =>
      document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute("content") || ""
    );
    out.wsPort = wsPort;

    roster = { mara: mara.fpr, okafor: okafor.fpr };
    audience = [mara.fpr, okafor.fpr].sort();
    roomId = await A.page.evaluate((a) => window.__roomId(a), audience);

    // Both sides plan the same notebook, each for themselves.
    out.planA = await A.page.evaluate((c) => window.__setup(c), {
      src: NOTEBOOK,
      me: "mara",
      roster,
    });
    out.planB = await B.page.evaluate((c) => window.__setup(c), {
      src: NOTEBOOK,
      me: "okafor",
      roster,
    });

    // Plan it a second time with the `planRun` the browser actually shipped,
    // so the run below is checked against the bytes and not only the sources.
    out.shippedPlanA = await A.page.evaluate(
      shippedPlanExpr({ src: NOTEBOOK, me: "mara", roster })
    );

    // The joiner first, and then a pause. The joiner-first ordering is
    // `notebook-pair.js`'s: an invite is published once, the moment the
    // creator's room is joined, and a creator who is first publishes it to an
    // empty room. The pause is this harness's own — `/api/v1/notebook/negotiate`
    // rate-limits one call per half second per IP and one per quarter second
    // per room, and both peers are one IP asking about one room. A collision is
    // survivable (the signalling channel re-negotiates on its retry ladder) but
    // it would put a second of nothing at the start of every run.
    await B.page.evaluate((c) => window.__startSession(c), {
      roomId,
      audience,
      fpr: okafor.fpr,
      armoredPrivate: okafor.armoredPrivate,
      role: "joiner",
    });
    await new Promise((r) => setTimeout(r, 1500));
    await A.page.evaluate((c) => window.__startSession(c), {
      roomId,
      audience,
      fpr: mara.fpr,
      armoredPrivate: mara.armoredPrivate,
      role: "creator",
    });

    const mesh = () =>
      Promise.all([A.page.evaluate(() => window.__mesh()), B.page.evaluate(() => window.__mesh())]);
    await until(
      async () => {
        const [a, b] = await mesh();
        return { a, b };
      },
      (v) => v.a.peers[0]?.kcVerified === true && v.b.peers[0]?.kcVerified === true,
      { timeout: 90000, interval: 250, what: "key confirmation on both ends" }
    );

    /* ── 1. mara commits to the run and publishes what she committed to ── */

    const built = await A.page.evaluate(() => window.__manifest());
    out.manifestDigest = built.digest;
    const signedManifest = await A.page.evaluate(
      async ([manifest, armored]) => {
        const key = await window.__pgp.readPrivateKey({ armoredKey: armored });
        const json = JSON.stringify(manifest);
        const { armored: signed } = await window.__arc.signOpenPgp(json, [key], "cleartext");
        return signed;
      },
      [built.manifest, mara.armoredPrivate]
    );
    out.manifestSent = await A.page.evaluate((s) => window.__session.publishManifest(s), signedManifest);
    await until(
      () => B.page.evaluate(() => window.__mesh()),
      (v) => v.manifests.length > 0,
      { timeout: 20000, interval: 100, what: "the manifest reaching okafor" }
    );
    // okafor adopts the manifest the *session verified*, not one he rebuilt.
    // Everything he checks the offer against is then a document that arrived.
    out.adoptedByB = await B.page.evaluate(
      () => window.__adoptManifest(window.__manifests[0].manifest)
    );

    /* ── 2. mara runs, and the gate stops her ── */

    out.maraStopped = await A.page.evaluate(() => window.__run());

    /* ── 3. mara offers the cell she declined to perform ── */

    out.offer = await A.page.evaluate(() => window.__buildOffer(1));
    out.offerSent = await A.page.evaluate(
      ([to, json]) => window.__session.sendOffer(to, json),
      [okafor.fpr, out.offer.json]
    );
    await A.page.evaluate((row) => window.__recordOffer(row), {
      manifest: out.manifestDigest,
      cell: 1,
      to: "okafor",
    });
    await until(
      () => B.page.evaluate(() => window.__mesh()),
      (v) => v.offers.length > 0,
      { timeout: 20000, interval: 100, what: "the offer reaching okafor" }
    );

    // Mara builds the same offer again on the shipped `buildOfferFor`. Building
    // an offer registers nothing — it reads slots and returns JSON — so this is
    // safe to repeat, and the JSON has to come out byte for byte the same.
    out.offerShipped = await A.page.evaluate(async () => {
      await window.__useArc("shipped");
      try {
        return await window.__buildOffer(1);
      } finally {
        await window.__useArc("source");
      }
    });

    /* ── 4. okafor, before anybody has clicked ── */

    out.bBeforeClick = {
      held: await B.page.evaluate(() => window.__held()),
      run: await B.page.evaluate(() => window.__run()),
      // The check, run with `register` false: it says yes, and puts nothing in.
      checked: await B.page.evaluate(
        (json) => window.__acceptOffer(json, { register: false }),
        out.offer.json
      ),
    };
    // The same check again, on the bytes the browser shipped. `register` is
    // false on both passes, so this decides nothing twice — it asks the same
    // question of two implementations and requires one answer.
    out.bCheckedShipped = await B.page.evaluate(async (json) => {
      await window.__useArc("shipped");
      try {
        return await window.__acceptOffer(json, { register: false });
      } finally {
        await window.__useArc("source");
      }
    }, out.offer.json);

    out.bStillStopped = await B.page.evaluate(() => window.__run());

    /* ── 5. okafor accepts. This is the click. ── */

    out.accepted = await B.page.evaluate(
      (json) => window.__acceptOffer(json, { register: true }),
      out.offer.json
    );
    out.okaforRan = await B.page.evaluate(() => window.__run());

    /* ── 6. okafor signs what came out and hands it back ── */

    out.result = await B.page.evaluate((k) => window.__buildResult(1, k), okafor.armoredPrivate);
    // The fourth of the five, on the same slots. Building a result registers
    // nothing either, so okafor can do it twice. The signature is not compared
    // — an OpenPGP signature carries a timestamp and is not reproducible — but
    // the result it signs over is, and that is the part the arc produces.
    out.resultShipped = await B.page.evaluate(async (k) => {
      await window.__useArc("shipped");
      try {
        return await window.__buildResult(1, k);
      } finally {
        await window.__useArc("source");
      }
    }, okafor.armoredPrivate);

    out.resultSent = await B.page.evaluate(
      ([to, signed]) => window.__session.sendResult(to, signed),
      [mara.fpr, out.result.signed]
    );
    await until(
      () => A.page.evaluate(() => window.__mesh()),
      (v) => v.results.length > 0,
      { timeout: 20000, interval: 100, what: "the result reaching mara" }
    );

    /* ── 7. mara, before anybody has clicked ── */

    const arrived = await A.page.evaluate(() => ({
      from: window.__results[0].from,
      result: window.__results[0].result,
    }));
    out.arrivedResult = arrived.result;
    out.aBeforeClick = {
      held: await A.page.evaluate(() => window.__held()),
      checked: await A.page.evaluate(
        ([r, f]) => window.__acceptResult(r, f, { register: false }),
        [arrived.result, arrived.from]
      ),
      run: await A.page.evaluate(() => window.__run()),
    };

    // And the same for the returning half, on the shipped `acceptCellResult`.
    out.aCheckedShipped = await A.page.evaluate(async ([r, f]) => {
      await window.__useArc("shipped");
      try {
        return await window.__acceptResult(r, f, { register: false });
      } finally {
        await window.__useArc("source");
      }
    }, [arrived.result, arrived.from]);

    /* ── 8. mara accepts, and the run that stopped completes ── */

    out.registered = await A.page.evaluate(
      ([r, f]) => window.__acceptResult(r, f, { register: true }),
      [arrived.result, arrived.from]
    );
    out.maraFinished = await A.page.evaluate(() => window.__run());

    const [meshA, meshB] = await mesh();
    out.meshA = meshA;
    out.meshB = meshB;
    out.calls = calls.slice();
  }, 300_000);

  afterAll(async () => {
    if (fx) {
      for (const p of fx.peers) {
        await p.page.evaluate(() => {
          try {
            window.__session?.stop();
          } catch (_) {
            /* already down */
          }
        }).catch(() => {});
      }
      await fx.close();
    }
    await server?.close();
  });

  /* ────────────────────────── what was reached ─────────────────────────── */

  it("drives the page the server serves, with the signalling origin merged in", () => {
    // The CSP a deployment emits, not the one in the built file. `connect-src`
    // gained exactly one source — the double's ws origin — which is what
    // `static.py` exists to do and what a raw `dist/` would not have.
    expect(out.csp).toContain("connect-src 'self'");
    expect(out.csp).toContain(`ws://127.0.0.1:${out.wsPort}`);
    expect(out.csp).toContain("default-src 'none'");
  });

  it("reaches the shipped NotebookSession without a stable export existing", () => {
    expect(loaded.a.chunk).toMatch(/^\/assets\/.*\.js$/);
    expect(loaded.a.chunk).toBe(loaded.b.chunk);
    expect(loaded.a.exportName).toBe(loaded.b.exportName);
    expect(loaded.a.pgp).toMatch(/^\/assets\/openpgp[^/]*\.js$/);
    // The arc bundle borrows that same chunk, so there is one OpenPGP in the
    // realm: the key okafor signs with and the key mara's session verifies
    // against are objects of one implementation.
    expect(out.openpgpChunk).toBe(loaded.a.pgp);
  });

  it("bootstraps through the real negotiate endpoint and the real keyserver", () => {
    // Two sessions, two grants — from the shipped Flask route, past its proof
    // and rate-limit gates, minting tokens the local double then verified with
    // the same code that minted them. Nothing in this suite speaks the
    // subprotocol or signs a token.
    const negotiations = out.calls.filter((c) => c === "POST /api/v1/notebook/negotiate");
    expect(negotiations.length).toBeGreaterThanOrEqual(2);
    // Both peers fetched both audience keys from the directory, which is what
    // makes the signature check on the result a check against a *directory*
    // key rather than against a key the test handed over.
    expect(out.calls.filter((c) => c === "GET /pks/lookup").length).toBeGreaterThanOrEqual(4);
    // The page was served by Flask through the proxy, so the document under
    // test is the one a deployment emits rather than the file on disk.
    expect(out.calls).toContain("GET /toolkit");
    for (const side of [out.meshA, out.meshB]) {
      expect(side.statuses).toContain("Signalling connected");
    }
  });

  it("meshes two contexts over a real connection, key-confirmed both ways", () => {
    for (const side of [out.meshA, out.meshB]) {
      const p = side.peers[0];
      expect(p.kcVerified, `errors: ${JSON.stringify(side.errors)}`).toBe(true);
      expect(p.pgpVerified).toBe(true);
      expect(p.status).toBe("connected");
      expect(p.channelState).toBe("open");
      expect(p.connectionState).toBe("connected");
    }
  });

  /* ─────────────────────────── plan and gate ───────────────────────────── */

  it("plans the same way in the bytes the browser shipped", () => {
    // Everything else in this file drives modules compiled from
    // `src/lib/toolkit/`, which proves the arc works but not that the *build*
    // carries it. The sibling assertions below prove the five functions are
    // present in the chunks; this one runs one of them and checks the answer.
    //
    // Compared against `planA` — the compiled planner's own output for the same
    // notebook, roster and identity — so a build that shipped a stale or
    // differently-configured planner would disagree here rather than pass.
    //
    // `play` is compared only against a literal below: `__setup` does not
    // return it, and the comparison is limited to what both sides expose.
    expect(out.shippedPlanA.ok).toBe(out.planA.ok);
    expect(out.shippedPlanA.cells).toEqual(
      out.planA.cells.map((c) => ({ index: c.index, peer: c.peer, mine: c.mine }))
    );

    // And it is a placed run, not a trivially-equal pair of empties: the
    // notebook has three cells across two peers, two of which are not Mara's.
    expect(out.shippedPlanA.play).toBe("placed");
    expect(out.shippedPlanA.cells.map((c) => c.peer)).toEqual(["mara", "okafor", "mara"]);
    expect(out.shippedPlanA.cells.filter((c) => !c.mine)).toHaveLength(1);
  });

  it("hands a cell over the same way in the bytes the browser shipped", () => {
    // The other four, each repeated on the shipped implementation at the point
    // in the run where its inputs exist. Every repeat is a step that registers
    // nothing, so the arc above decided everything exactly once.
    //
    // `buildOfferFor`: the offer is JSON over a manifest and a slot — the bytes
    // the peer would actually receive — so it is compared whole, minus the one
    // field that cannot repeat. An offer is stamped with the moment it was
    // built, so `offeredAt` differs by the milliseconds between the two calls.
    // That it differs is itself the proof this was built again rather than
    // returned from something the first pass cached.
    const withoutStamp = (json) => {
      const { offeredAt, ...rest } = JSON.parse(json);
      expect(typeof offeredAt).toBe("string");
      return rest;
    };
    expect(out.offerShipped.ok).toBe(true);
    expect(withoutStamp(out.offerShipped.json)).toEqual(withoutStamp(out.offer.json));
    expect(JSON.parse(out.offerShipped.json).offeredAt).not.toBe(
      JSON.parse(out.offer.json).offeredAt
    );
    expect(out.offerShipped.summary).toBe(out.offer.summary);
    expect(out.offerShipped.refusals).toEqual([]);

    // The digest the offer commits to is the cell, and it is the same cell.
    expect(JSON.parse(out.offerShipped.json).cellDigest).toBe(
      JSON.parse(out.offer.json).cellDigest
    );

    // `acceptHandoffOffer`: the verdict, the cell it is for, and the labels it
    // would bind. Checked against okafor's own pre-click check of the same JSON.
    expect(out.bCheckedShipped.ok).toBe(true);
    expect(out.bCheckedShipped.cell).toBe(out.bBeforeClick.checked.cell);
    expect(out.bCheckedShipped.bindings).toEqual(out.bBeforeClick.checked.bindings);
    expect(out.bCheckedShipped.summary).toBe(out.bBeforeClick.checked.summary);
    // It stayed a question: the shipped pass registered nothing either.
    expect(out.bCheckedShipped.registered).toBe(false);

    // `buildResultFor`: the result, not the signature over it. An OpenPGP
    // signature carries a timestamp, so the armor differs on every call while
    // the document it commits to does not — and the document is stamped too,
    // with `ranAt`, for the same reason the offer carries `offeredAt`.
    expect(out.resultShipped.ok).toBe(true);
    const { ranAt: shippedRanAt, ...shippedResult } = out.resultShipped.result;
    const { ranAt: sourceRanAt, ...sourceResult } = out.result.result;
    expect(shippedResult).toEqual(sourceResult);
    expect(typeof shippedRanAt).toBe("string");
    expect(shippedRanAt).not.toBe(sourceRanAt);
    expect(out.resultShipped.summary).toBe(out.result.summary);

    // The value it carries is the round-trip this whole notebook exists to do,
    // so the shipped builder is moving the real answer and not an empty shell.
    expect(shippedResult.produced.map((x) => x.data)).toContain(EXPECTED_B64);

    // `acceptCellResult`: mara's verdict on the result that came back, checked
    // against her own pre-click check of the same bytes from the same peer.
    expect(out.aCheckedShipped.ok).toBe(true);
    expect(out.aCheckedShipped.by).toBe("okafor");
    expect(out.aCheckedShipped.cell).toBe(out.aBeforeClick.checked.cell);
    expect(out.aCheckedShipped.bindings).toEqual(out.aBeforeClick.checked.bindings);
    expect(out.aCheckedShipped.summary).toBe(out.aBeforeClick.checked.summary);
    expect(out.aCheckedShipped.registered).toBe(false);

    // Not vacuous: each of these carried something across. The offer names a
    // slot, and both accepts would have bound one.
    expect(out.offerShipped.json.length).toBeGreaterThan(0);
    expect(out.bCheckedShipped.bindings.length).toBeGreaterThan(0);
    expect(out.aCheckedShipped.bindings.length).toBeGreaterThan(0);
  });

  it("plans the same notebook two ways, one for each peer", () => {
    expect(out.planA.ok).toBe(true);
    expect(out.planB.ok).toBe(true);
    expect(out.planA.me).toBe("mara");
    expect(out.planB.me).toBe("okafor");
    // Cell 1 is okafor's on both sides. That agreement is the whole basis of
    // the exchange: the offer says nothing about who runs the cell, so the two
    // plans have to reach it independently or nothing can be accepted.
    expect(out.planA.cells.map((c) => c.mine)).toEqual([true, false, true]);
    expect(out.planB.cells.map((c) => c.mine)).toEqual([false, true, false]);
    expect(out.planA.cells[1].runsOn).toEqual(["okafor"]);
    expect(out.planB.cells[1].runsOn).toEqual(["okafor"]);
  });

  it("stops mara's run at the cell that needed what okafor holds", () => {
    // Cell 0 ran here; cell 1 is okafor's and was declined; cell 2 is mara's
    // own and reads what cell 1 writes, so the run stops rather than finishing
    // short. Identical to the node proof, in Chromium.
    expect(out.maraStopped.slots).toEqual(["seed"]);
    expect(out.maraStopped.skipped.map((s) => s.cell)).toEqual([1]);
    expect(out.maraStopped.skipped[0]).toMatchObject({
      waitingOn: "okafor",
      produces: ["b64"],
    });
    expect(out.maraStopped.withheld).toEqual({
      cell: 2,
      slot: "b64",
      from: 1,
      peer: "okafor",
    });
    expect(out.maraStopped.stopped).toContain("Cell 2 reads `$b64`");
  });

  it("stops okafor's run in the mirror position, for want of mara's seed", () => {
    // Before anything is accepted, okafor's own run is stopped too — at cell 1,
    // his own cell, because it reads a slot mara's cell writes. That is the
    // state an offer ends, and it is the reason an offer carries values at all.
    expect(out.bBeforeClick.run.withheld).toEqual({
      cell: 1,
      slot: "seed",
      from: 0,
      peer: "mara",
    });
    expect(out.bBeforeClick.run.slots).toEqual([]);
  });

  /* ──────────────────────────── the offer ──────────────────────────────── */

  it("builds an offer carrying the public value and nothing else", () => {
    expect(out.offer.ok, out.offer.summary).toBe(true);
    expect(out.offer.offer).toMatchObject({
      v: 2,
      kind: "basilisk.cell-handoff",
      manifest: out.manifestDigest,
      cell: 1,
    });
    expect(out.offer.offer.needs).toEqual([
      { label: "seed", type: "text", data: "deadbeef" },
    ]);
    expect(Object.keys(out.offer.offer).sort()).toEqual([
      "cell",
      "cellDigest",
      "kind",
      "manifest",
      "needs",
      "offeredAt",
      "v",
    ]);
    expect(out.offer.summary).toContain("nothing runs until somebody says so");
  });

  it("carries the manifest and the offer across two realms, and the session says so", () => {
    // The manifest okafor checked the offer against is the one the session
    // verified against mara's directory key, not one he rebuilt from a string
    // the test handed him.
    expect(out.manifestSent).toBe(1);
    expect(out.adoptedByB).toBe(out.manifestDigest);
    expect(out.meshB.manifests).toEqual([{ from: mara.fpr, digest: out.manifestDigest }]);

    expect(out.offerSent).toBe(1);
    expect(out.meshB.offers).toEqual([
      { from: mara.fpr, cell: 1, manifest: out.manifestDigest },
    ]);
    // The courier recorded that it delivered, which is all it is entitled to
    // know: `peer.offered` is a pairing, not a decision.
    expect(out.meshB.peers[0].offered).toEqual([`${out.manifestDigest}:1`]);
  });

  /* ─────────────────────── the click, and its absence ──────────────────── */

  it("delivers an offer that is pending, and stays pending while nobody clicks", () => {
    // The offer arrived and checks out. Nothing registered it.
    expect(out.bBeforeClick.checked.ok, out.bBeforeClick.checked.summary).toBe(true);
    expect(out.bBeforeClick.checked.bindings).toEqual(["seed"]);
    expect(out.bBeforeClick.checked.registered).toBe(false);
    expect(out.bBeforeClick.checked.heldNow).toEqual([]);
    expect(out.bBeforeClick.held).toEqual([]);

    // And the control: run it again and it stops in the same place. Checking an
    // offer changes nothing — the bindings are sitting in a verdict, and a run
    // is a `register` call away.
    expect(out.bStillStopped.withheld).toEqual({
      cell: 1,
      slot: "seed",
      from: 0,
      peer: "mara",
    });
    expect(out.bStillStopped.slots).toEqual([]);
  });

  it("runs the cell once a person has accepted, and only then", () => {
    expect(out.accepted.ok, out.accepted.summary).toBe(true);
    expect(out.accepted.registered).toBe(true);
    expect(out.accepted.heldNow).toEqual(["seed"]);

    expect(out.okaforRan.stopped).toBe(null);
    expect(out.okaforRan.withheld).toBe(null);
    expect(out.okaforRan.skipped.map((s) => s.cell)).toEqual([0, 2]);
    expect(out.okaforRan.slots).toEqual(["seed", "b64"]);
    expect(out.okaforRan.artifacts.some((a) => a.includes(EXPECTED_B64))).toBe(true);
  });

  /* ──────────────────────────── the result ─────────────────────────────── */

  it("hands back a signed claim about the cell it ran", () => {
    expect(out.result.ok, out.result.summary).toBe(true);
    expect(out.result.result).toMatchObject({
      v: 1,
      kind: "basilisk.cell-result",
      manifest: out.manifestDigest,
      cell: 1,
      produced: [{ label: "b64", type: "text", data: EXPECTED_B64 }],
    });
    expect(out.result.signed).toMatch(/^-----BEGIN PGP SIGNED MESSAGE-----/);
    expect(out.resultSent).toBe(1);
  });

  it("verifies that signature against the directory key, in the shipped session", () => {
    // `readSignedResult` ran inside the page's own `NotebookSession`, against
    // the key `fetchAudienceKeys` pulled from the real keyserver — so what mara
    // is holding is bytes okafor signed, parsed out of what the signature
    // covered, and not a JSON blob the harness carried across.
    expect(out.meshA.results).toEqual([
      { from: okafor.fpr, cell: 1, manifest: out.manifestDigest },
    ]);
    expect(out.meshA.peers[0].returned).toEqual([`${out.manifestDigest}:1`]);
    expect(out.arrivedResult).toEqual(out.result.result);
    expect(out.meshA.errors).toEqual([]);
  });

  it("holds the returned value pending at the far end too", () => {
    // The same rule at the end where the machine that would carry on is the
    // origin's own, on values nobody has looked at.
    expect(out.aBeforeClick.checked.ok, out.aBeforeClick.checked.summary).toBe(true);
    expect(out.aBeforeClick.checked.by).toBe("okafor");
    expect(out.aBeforeClick.checked.bindings).toEqual(["b64"]);
    expect(out.aBeforeClick.checked.registered).toBe(false);
    expect(out.aBeforeClick.held).toEqual([]);
    // Still stopped, in the same place, for the same reason.
    expect(out.aBeforeClick.run.withheld).toEqual({
      cell: 2,
      slot: "b64",
      from: 1,
      peer: "okafor",
    });
  });

  it("registers, and the previously stopped run completes — the seam, end to end", () => {
    expect(out.registered.ok, out.registered.summary).toBe(true);
    expect(out.registered.registered).toBe(true);
    expect(out.registered.heldNow).toEqual(["b64"]);

    expect(out.maraFinished.stopped).toBe(null);
    expect(out.maraFinished.withheld).toBe(null);
    // Cell 1 is still okafor's and still not run here — the value arrived, the
    // placement did not move.
    expect(out.maraFinished.skipped.map((s) => s.cell)).toEqual([1]);
    expect(out.maraFinished.slots).toEqual(["seed", "b64", "done"]);
    expect(out.maraFinished.artifacts.some((a) => a.includes(EXPECTED_B64))).toBe(true);
  });

  it("does all of it without tripping the policy the page was served under", async () => {
    // The keyserver and the negotiate endpoint are same-origin; the signalling
    // socket is not, and is allowed by exactly the source `static.py` merged in.
    // ICE is governed by no directive at all.
    expect(await A.cspViolations()).toEqual([]);
    expect(await B.cspViolations()).toEqual([]);
    for (const p of [A, B]) {
      expect(p.pageErrors().filter((e) => /Content Security Policy/i.test(e))).toEqual([]);
    }
  });
});

/* ───────────── the guard's own branches: nothing required, never skipped ──────────── */

describe("what a failed interpreter probe is taken to mean", () => {
  // `browser-peers-guard.test.js` pins `classifyLaunchFailure` both ways;
  // `classifyPythonFailure` had no such test, and it is now the second thing
  // that can stand this suite down. A given machine exercises exactly one
  // branch at runtime and it is never the interesting one — `turn-relay.e2e.js`
  // makes the same argument about Docker and answers it the same way. The
  // strings are Python's and node's own.
  it("stands down for an interpreter that is not there", () => {
    expect(classifyPythonFailure("spawn python3 ENOENT")).toBe("absent");
    expect(
      classifyPythonFailure("'python' is not recognized as an internal or external command")
    ).toBe("absent");
    expect(classifyPythonFailure("bash: python3: command not found")).toBe("absent");
  });

  it("stands down for an interpreter whose dependencies were never installed", () => {
    expect(classifyPythonFailure("ModuleNotFoundError: No module named 'flask'")).toBe("absent");
    expect(classifyPythonFailure("ImportError: cannot import name x")).toBe("absent");
  });

  it("does not stand down for anything else", () => {
    // The row that matters. Each of these is a Python that answered and
    // something being wrong, which is news — a guard that filed them under "no
    // Python" would skip this suite green on the day the server broke.
    expect(classifyPythonFailure("SyntaxError: invalid syntax")).toBe("broken");
    expect(classifyPythonFailure("OSError: [WinError 10048] address already in use")).toBe("broken");
    expect(classifyPythonFailure("pysequoia: DLL load failed")).toBe("broken");
    expect(classifyPythonFailure("")).toBe("broken");
  });
});

/* ─────────────────── what the product could not have done ────────────────── */

describe("the product cannot accept an offer at all", () => {
  // No browser and no server needed: this reads the build. It is the reason the
  // suite above compiles the arc from source, stated as an assertion so that
  // the reason cannot quietly stop being true — in either direction.
  const chunks = readdirSync(join(DIST_ROOT, "assets"))
    .filter((n) => n.endsWith(".js"))
    .map((n) => ({ name: n, text: readFileSync(join(DIST_ROOT, "assets", n), "utf8") }));

  /** The same needles the page resolves with — see `ARC_NEEDLES`. */
  const ONLY_IN = ARC_NEEDLES;

  it("ships the planner, because a shell now asks it where cells run", () => {
    // This assertion used to be `present).toEqual([])` for all five, and said
    // that if a shell were ever written it would fail. One was: `PlanPanel`
    // reads `planRun` and renders it in the Connections tab, so Rollup keeps
    // it. Stated as the narrower fact rather than deleted, because "the
    // planner ships" and "the handoff does not" are now two different truths
    // and collapsing them would lose the second.
    expect(chunks.some((c) => c.text.includes(ONLY_IN.planRun))).toBe(true);
  });

  it("ships every function the arc is made of", () => {
    // This assertion has now been through all three of its states: none of the
    // five shipped, then the planner and both accept halves, and now the build
    // halves too. `useNotebook` runs placed — it passes `engine.js`'s
    // `placement`, so the gate reports the cells this peer declined — offers
    // one to the peer that owns it, signs a result with the session's own key,
    // and registers what comes back. Rollup keeps all five because all five
    // are called.
    const missing = Object.entries(ONLY_IN)
      .filter(([, needle]) => !chunks.some((c) => c.text.includes(needle)))
      .map(([fn]) => fn);
    expect(missing).toEqual([]);
  });

  it("ships the gate, and now something that opens it", () => {
    // `placementGate` was always in the bundle — `engine.js` imports it — and
    // what was missing was a caller passing `placement`. `useNotebook.runFrom`
    // is that caller now, and only when the room can bind the notebook's
    // labels: an unbound plan places every cell on nobody, so no plan is built
    // and the gate is never made, which `placement.js` insists is a different
    // thing from a gate that admits everything.
    const gate = chunks.filter((c) => c.text.includes("does not know which peer you are"));
    expect(gate.length).toBeGreaterThan(0);
  });
});

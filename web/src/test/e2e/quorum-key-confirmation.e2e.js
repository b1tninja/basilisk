/**
 * Key confirmation between two real browsers, over two real
 * `RTCPeerConnection`s (§59b, and the gap `929a546` disclosed rather than hid).
 *
 * `src/test/notebook-dtls-binding.test.js` proves the property that matters —
 * a pairwise session key is bound to the transport that carries it, and a
 * signalling relay that rewrites one end's DTLS fingerprint leaves both ends
 * unconfirmed. It proves it in node, against real OpenPGP, real ECDH, real key
 * confirmation and a **fake** transport. The one thing it cannot say is that
 * any of it survives contact with a browser: that `extractDtlsFingerprint`
 * reads what Chromium actually wrote, that the local description exists at the
 * instant negotiation hands its fingerprint to the transcript, that two
 * certificates minted by two real engines differ, and that the mesh reaches
 * confirmation at all when the SDP is not a fixture.
 *
 * That is this file. Two isolated browser contexts, the shipped toolkit page,
 * the production CSP, real host-candidate ICE between them, and the same
 * assertion set as the node proof — including the tamper, which is the half
 * that makes the rest mean anything.
 *
 * ## How the session is reached, and why it is not a back door
 *
 * `929a546` reported that the shipped chunk's exports are minified, so a test
 * could not name `NotebookSession` from the page, and that standing this up would
 * mean "adding a stable export surface". It does not. Class *method* names
 * survive minification even when the module's export bindings do not, so the
 * constructor is identifiable by its shape — `start`/`stop`/`_onMailbox`/
 * `_maybeDeriveSession`/`_maybeSendKeyConfirm` on one prototype — plus a string
 * it ships (`"Key confirmation failed"`). `findNotebookSession` below scans the
 * chunks the page *already loaded* and requires exactly one match. Nothing is
 * added to production; if the shape ever stops matching, this fails loudly with
 * what it did find rather than skipping.
 *
 * Two consequences worth stating. It is the page's own module instance, so the
 * shipped `rtc.*` diagnostics see the mesh through the shared link inventory —
 * asserted below, which is also what proves the right copy was found. And it is
 * the minified chunk, not the source: this test drives the bytes that ship.
 *
 * ## What may skip, and what may not
 *
 * Nothing here needs the public internet. Two contexts of one browser reach
 * each other over host candidates on the loopback interface, and the mailbox
 * and keyserver are in this process. Only an absent Chromium download stands
 * this down; an installed browser that will not launch is a failure, per
 * `classifyLaunchFailure`.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers, until } from "../helpers/browser-peers.js";
import { createQuorumRoom } from "../helpers/quorum-room.js";
// Run in node against descriptions produced by two real engines — the parser
// the transcript depends on, fed the one input a fake can never supply.
import { extractDtlsFingerprint } from "../../lib/webrtc/sdp.js";
import { combineDtlsFingerprints } from "../../lib/notebook/crypto.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the key-confirmation suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(
    `[quorum-key-confirmation.e2e] skipping — chromium not installed (${availability.reason})`
  );
}

/** A fingerprint no transport would ever mint. */
const LIE = `sha-256 ${new Array(32).fill("00").join(":")}`;

/**
 * In-page: find the shipped `NotebookSession` and the shipped OpenPGP module.
 *
 * A **string**, not a function, because Vitest rewrites `import()` in anything
 * it transforms into `__vite_ssr_dynamic_import__`, a module-runner binding
 * that does not exist in a browser. Only chunks the page already fetched are
 * considered, so `import()` here re-reads an evaluated module rather than
 * pulling in a second copy of the graph — which is what keeps the link registry
 * shared with the page's own `rtc.*` ops.
 */
const LOAD_SESSION = `(async () => {
  const paths = [...new Set(
    performance.getEntriesByType("resource")
      .map((x) => new URL(x.name).pathname)
      .filter((n) => /^\\/assets\\/.*\\.js$/.test(n))
  )];
  const WANTED = [
    "start", "stop", "sendChat", "sendChatTo",
    "_onMailbox", "_handleSignal", "_maybeDeriveSession", "_maybeSendKeyConfirm",
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
  const pgp = await import(pgpPath);
  if (typeof pgp.readPrivateKey !== "function") {
    throw new Error("the shipped openpgp chunk does not export readPrivateKey");
  }
  const rtcPath = paths.find((n) => /\\/assets\\/rtc-ops-[^/]*\\.js$/.test(n));
  if (!rtcPath) throw new Error("the toolkit page did not load an rtc-ops chunk");
  window.__NotebookSession = found[0].ctor;
  window.__pgp = pgp;
  window.__ops = await import(rtcPath);
  return { chunk: found[0].chunk, exportName: found[0].exportName, pgp: pgpPath, rtc: rtcPath };
})()`;

/**
 * Start one side of the mesh in its browser.
 *
 * `iceServers: []` — no third party, and it is honoured now.
 *
 * This used to leave the list to the session's default, with a note that the
 * connection that matters is made of host candidates either way. That was
 * true, and the reason for it was that an empty list *could not be requested*:
 * the session read `?.length` and substituted Cloudflare and Google, so the
 * only way to run was the shipped configuration and two public STUN servers
 * were on the path of a key-confirmation test. Two browsers on one machine
 * have never needed either of them.
 *
 * So it is also a gate. If the substitution rule ever regresses to a truthiness
 * test, this suite starts sending binding requests to the public internet — and
 * the assertion that no `srflx` candidate appears in either side's SDP fails
 * loudly rather than the test quietly getting slower.
 *
 * @param {import("../helpers/browser-peers.js").Peer} peer
 * @param {{ roomId: string, audience: string[], fpr: string, armoredPrivate: string, role: string }} cfg
 */
const startSession = (peer, cfg) =>
  peer.page.evaluate(async (c) => {
    const Session = window.__NotebookSession;
    const privateKey = await window.__pgp.readPrivateKey({ armoredKey: c.armoredPrivate });
    if (!privateKey.isDecrypted()) throw new Error("test key came back locked");
    window.__errors = [];
    window.__statuses = [];
    window.__chats = [];

    // Every connection this page makes from here on records its own ICE and
    // connection-state transitions, from `new`.
    //
    // A subclass installed before the session exists, rather than listeners
    // attached to `link.pc` once one turns up: `iceConnectionState` reaches
    // `checking` within milliseconds of the answerer's first remote
    // description, and a poller cannot reliably be there first — Chromium
    // throttles timers in a backgrounded page to roughly 1 Hz, and at most one
    // of these two contexts is ever in the foreground. The first attempt missed
    // `ice:checking` on both ends for exactly that reason and would have
    // reported "connected" with no evidence it was ever checked. Behaviour is
    // untouched: `super(cfg)` is the real constructor and nothing else is
    // overridden. This is the same category of choice as `WEBRTC_FLAGS` —
    // observability in the harness, not a change to what is under test.
    if (!window.__pcWatch) {
      const Native = window.RTCPeerConnection;
      window.__pcWatch = new WeakMap();
      window.RTCPeerConnection = class extends Native {
        constructor(cfg) {
          super(cfg);
          /** @type {string[]} */
          const seen = [`@ice:${this.iceConnectionState}`, `@conn:${this.connectionState}`];
          window.__pcWatch.set(this, seen);
          this.addEventListener("iceconnectionstatechange", () =>
            seen.push(`ice:${this.iceConnectionState}`)
          );
          this.addEventListener("connectionstatechange", () =>
            seen.push(`conn:${this.connectionState}`)
          );
        }
      };
    }

    const session = new Session({
      roomId: c.roomId,
      audienceFprs: c.audience,
      privateKey,
      myFingerprint: c.fpr,
      role: c.role,
      iceServers: [],
      onChat: (m) => window.__chats.push(m),
      onStatus: (s) => window.__statuses.push(s),
      onError: (e) => window.__errors.push(String((e && e.message) || e)),
    });
    window.__session = session;
    await session.start();
    return true;
  }, cfg);

/**
 * Everything about one side, projected to something serialisable.
 *
 * `peer.link.pc` is read past the link deliberately, and for the same reason
 * `notebook-dtls-binding.test.js` reaches past it: the session cannot ask that
 * question — `lib/notebook/` may not name a connection — so comparing
 * `localDtls` to the fingerprint the *transport* minted has to happen from
 * outside. Asking the session for it would compare it to itself, and a driver
 * reporting one constant would sail through.
 *
 * @param {import("../helpers/browser-peers.js").Peer} peer
 */
const snapshot = (peer) =>
  peer.page.evaluate(() => {
    const session = window.__session;
    const peers = [];
    for (const [fpr, p] of session.peers) {
      const pc = p.link ? p.link.pc : null;
      peers.push({
        fpr,
        status: p.status,
        pgpVerified: p.pgpVerified,
        kcVerified: p.kcVerified,
        transcriptHash: p.transcriptHash,
        localDtls: p.localDtls,
        remoteDtls: p.remoteDtls,
        channelState: p.channel ? p.channel.readyState : null,
        live: !!(p.link && p.link.isLive()),
        connectionState: pc ? pc.connectionState : null,
        localSdp: pc && pc.localDescription ? pc.localDescription.sdp : "",
        remoteSdp: pc && pc.remoteDescription ? pc.remoteDescription.sdp : "",
        iceStates: pc ? (window.__pcWatch.get(pc) || []).slice() : [],
      });
    }
    return {
      peers,
      errors: window.__errors.slice(),
      statuses: window.__statuses.slice(),
      chats: window.__chats.slice(),
    };
  });

/** @param {import("../helpers/browser-peers.js").Peer} peer */
const stopSession = (peer) =>
  peer.page.evaluate(() => {
    try {
      window.__session.stop();
    } catch (_) {
      /* already down */
    }
  });

/* ─────────────────── the mesh, on an honest mailbox ─────────────────── */

describe.runIf(availability.ok)("two browsers confirm a pairwise key", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;
  /** @type {Awaited<ReturnType<typeof createQuorumRoom>>} */
  let room;
  /** @type {any} */
  let loaded;
  /** @type {any} */
  let lo;
  /** @type {any} */
  let hi;
  /** @type {any} */
  let result;

  beforeAll(async () => {
    room = await createQuorumRoom();
    fx = await openPeers({ path: "/toolkit", count: 2, routes: room.routes });
    const [A, B] = fx.peers;
    loaded = {
      a: await A.page.evaluate(LOAD_SESSION),
      b: await B.page.evaluate(LOAD_SESSION),
    };

    // `members` is in canonical (sorted) audience order, and the session's own
    // mesh policy makes the *lower* fingerprint the offerer — so naming the two
    // sides lo/hi rather than creator/joiner keeps the roles legible.
    const [loM, hiM] = room.members;
    lo = { peer: A, ...loM };
    hi = { peer: B, ...hiM };

    await startSession(A, {
      roomId: room.roomId,
      audience: room.audience,
      fpr: lo.fpr,
      armoredPrivate: lo.armoredPrivate,
      role: "creator",
    });
    await startSession(B, {
      roomId: room.roomId,
      audience: room.audience,
      fpr: hi.fpr,
      armoredPrivate: hi.armoredPrivate,
      role: "joiner",
    });

    // `until` throws with the last observed state on timeout, so reaching past
    // it is the fact; the boolean is recomputed from the final snapshots below
    // rather than taken from a return value that is a state object.
    await until(
      async () => ({ a: await snapshot(A), b: await snapshot(B) }),
      (v) => v.a.peers[0]?.kcVerified === true && v.b.peers[0]?.kcVerified === true,
      { timeout: 90000, interval: 250, what: "key confirmation on both ends" }
    );

    // The channel carries application data under the derived key, both ways.
    const sent = {
      lo: await A.page.evaluate((to) => window.__session.sendChatTo(to, "from lo"), hi.fpr),
      hi: await B.page.evaluate((to) => window.__session.sendChatTo(to, "from hi"), lo.fpr),
    };
    await until(
      async () => ({ a: await snapshot(A), b: await snapshot(B) }),
      (v) => v.a.chats.length > 0 && v.b.chats.length > 0,
      { timeout: 20000, interval: 100, what: "chat both ways" }
    );

    // What the shipped diagnostics make of it — same inventory, so this is also
    // the proof that the constructor found above is the page's own copy.
    const diag = (p) =>
      p.page.evaluate(() => window.__ops.execConnectionState().data);

    const a = await snapshot(A);
    const b = await snapshot(B);
    result = {
      confirmed: a.peers[0]?.kcVerified === true && b.peers[0]?.kcVerified === true,
      sent,
      a,
      b,
      diagA: await diag(A),
      diagB: await diag(B),
    };
  }, 180_000);

  afterAll(async () => {
    if (fx) {
      for (const p of fx.peers) await stopSession(p).catch(() => {});
      await fx.close();
    }
  });

  it("reaches the shipped NotebookSession without a stable export existing", () => {
    // The chunk is content-hashed and the export binding is a single mangled
    // letter, so both are resolved rather than written down. Pinning the shape
    // of what was found keeps this from silently matching something else.
    expect(loaded.a.chunk).toMatch(/^\/assets\/.*\.js$/);
    expect(loaded.a.chunk).toBe(loaded.b.chunk);
    expect(loaded.a.exportName).toBe(loaded.b.exportName);
    expect(loaded.a.pgp).toMatch(/^\/assets\/openpgp[^/]*\.js$/);
    expect(loaded.a.rtc).toMatch(/^\/assets\/rtc-ops-[\w-]+\.js$/);
  });

  it("bootstraps through the mailbox and the keyserver, and neither faulted", () => {
    // Both identities were fetched by both sides, and every posted envelope
    // opened. A harness that dropped signalling would read as a dead transport.
    expect(room.faults()).toEqual([]);
    expect(room.counts().lookups).toBeGreaterThanOrEqual(4);
    expect(room.counts().posts).toBeGreaterThan(0);
    expect(room.counts().polls).toBeGreaterThan(0);
    // The invite is the creator's, and only the creator's.
    const invites = room.signalled().filter((s) => s.type === "invite");
    expect(invites).toHaveLength(1);
    expect(invites[0].signer).toBe(lo.fpr);
  });

  it("confirms the key on both ends, over a live connection", () => {
    expect(
      result.confirmed,
      `errors: ${JSON.stringify([...result.a.errors, ...result.b.errors])}`
    ).toBe(true);

    for (const side of [result.a, result.b]) {
      const p = side.peers[0];
      expect(p.kcVerified).toBe(true);
      expect(p.pgpVerified).toBe(true);
      expect(p.status).toBe("connected");
      expect(p.channelState).toBe("open");
      expect(p.live).toBe(true);
      expect(p.connectionState).toBe("connected");
    }
  });

  it("gets there through checking, not straight to connected", () => {
    for (const side of [result.a, result.b]) {
      const states = side.peers[0].iceStates;
      // Watched from `new`, so an absent transition below is an absent
      // transition rather than a listener that arrived late.
      expect(states.slice(0, 2)).toEqual(["@ice:new", "@conn:new"]);
      expect(states).toContain("ice:checking");
      expect(states).toContain("ice:connected");
      expect(states).toContain("conn:connected");
      expect(states.indexOf("ice:checking")).toBeLessThan(
        states.indexOf("ice:connected")
      );
    }
  });

  it("connected without a packet to any third party", () => {
    // `iceServers: []` was a request; this is the check that it was kept all
    // the way down to the transport. A server-reflexive candidate in a
    // description means something answered a STUN binding request, which means
    // the empty list was replaced by the shipped defaults somewhere between
    // the constructor argument and `new RTCPeerConnection` — the exact defect
    // this suite used to run on top of, silently.
    for (const side of [result.a, result.b]) {
      const p = side.peers[0];
      expect(p.localSdp, "a reflexive candidate means STUN was contacted").not.toMatch(
        /\btyp srflx\b/
      );
      expect(p.remoteSdp).not.toMatch(/\btyp srflx\b/);
      // And host candidates are there, so the absence above is a config that
      // was honoured rather than a gather that produced nothing.
      expect(p.localSdp).toMatch(/\btyp host\b/);
    }
  });

  it("binds the transcript to the fingerprints both transports actually minted", () => {
    const a = result.a.peers[0];
    const b = result.b.peers[0];

    // Each end's `localDtls` is what its *own* connection wrote into its own
    // local description — read here from the description rather than from the
    // session, because asking the session would compare a number to itself.
    expect(a.localDtls).toBe(extractDtlsFingerprint(a.localSdp));
    expect(b.localDtls).toBe(extractDtlsFingerprint(b.localSdp));
    expect(a.remoteDtls).toBe(extractDtlsFingerprint(a.remoteSdp));
    expect(b.remoteDtls).toBe(extractDtlsFingerprint(b.remoteSdp));

    expect(a.localDtls).toMatch(/^sha-256 (?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(b.localDtls).toMatch(/^sha-256 (?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/);

    // Two real engines, two certificates. Without this, "both ends agree" would
    // also be true of a driver minting one constant — the failure mode
    // `929a546` had to add a separate provenance assertion to catch.
    expect(a.localDtls).not.toBe(b.localDtls);

    // Each end's view of the other is the other's view of itself.
    expect(a.remoteDtls).toBe(b.localDtls);
    expect(b.remoteDtls).toBe(a.localDtls);

    // …and so both folded the same field into the transcript, and reached the
    // same transcript, which is the thing key confirmation compares.
    expect(combineDtlsFingerprints(a.localDtls, a.remoteDtls)).toBe(
      combineDtlsFingerprints(b.localDtls, b.remoteDtls)
    );
    expect(a.transcriptHash).toBe(b.transcriptHash);
    expect(a.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("signals only the fingerprint the description beside it carries", () => {
    // The mailbox saw every offer and answer: the SDP a real engine produced
    // and the fingerprint its session claimed for that SDP, together. This is
    // the provenance check from the outside — a session that signalled a
    // fabricated but plausible fingerprint would pass every assertion above.
    const carrying = room
      .signalled()
      .filter((s) => s.type === "offer" || s.type === "answer");
    expect(carrying.length).toBeGreaterThanOrEqual(2);
    for (const s of carrying) {
      expect(s.sdp, `${s.type} from ${s.signer.slice(0, 8)} carried no SDP`).toBeTruthy();
      expect(s.dtlsFingerprint).toBe(extractDtlsFingerprint(s.sdp));
    }
    // Both sides spoke, and they did not claim the same certificate.
    const bySigner = new Map(carrying.map((s) => [s.signer, s.dtlsFingerprint]));
    expect([...bySigner.keys()].sort()).toEqual([...room.audience].sort());
    expect(bySigner.get(lo.fpr)).not.toBe(bySigner.get(hi.fpr));
    expect(bySigner.get(lo.fpr)).toBe(result.a.peers[0].localDtls);
    expect(bySigner.get(hi.fpr)).toBe(result.b.peers[0].localDtls);
    // And the mesh policy held: the lower fingerprint offered.
    expect(carrying.find((s) => s.type === "offer")?.signer).toBe(lo.fpr);
  });

  it("carries chat under the confirmed key, both ways", () => {
    expect(result.sent.lo).toBe(1);
    expect(result.sent.hi).toBe(1);
    expect(result.b.chats.map((c) => c.text)).toEqual(["from lo"]);
    expect(result.a.chats.map((c) => c.text)).toEqual(["from hi"]);
    expect(result.b.chats[0].from).toBe(lo.fpr);
    expect(result.a.chats[0].from).toBe(hi.fpr);
  });

  it("shows up in the shipped rtc.* inventory as an authenticated quorum link", () => {
    // The mesh registers its links in `webrtc/link-registry.js`, and
    // `rtc.state` reads that inventory. It answering at all is what proves the
    // constructor found in the bundle is the page's own module instance rather
    // than a second copy of the graph.
    for (const [diag, side] of [
      [result.diagA, hi.fpr],
      [result.diagB, lo.fpr],
    ]) {
      const row = diag.peers.find((p) => p.peer === side);
      expect(row, `rtc.state did not list ${side.slice(0, 8)}`).toBeTruthy();
      expect(row.origin).toBe("quorum");
      expect(row.connectionState).toBe("connected");
      expect(row.channelState).toBe("open");
      expect(row.authenticated).toBe(true);
    }
  });

  it("drives the whole exchange without tripping the production CSP", async () => {
    // The mailbox and the keyserver are same-origin, so `connect-src 'self'`
    // covers them; ICE is governed by no directive at all.
    expect(await fx.peers[0].cspViolations()).toEqual([]);
    expect(await fx.peers[1].cspViolations()).toEqual([]);
  });
});

/* ───────────── the same mesh, one substituted fingerprint ───────────── */

describe.runIf(availability.ok)("key confirmation refuses a substituted DTLS fingerprint", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;
  /** @type {Awaited<ReturnType<typeof createQuorumRoom>>} */
  let room;
  /** @type {any} */
  let lo;
  /** @type {any} */
  let hi;
  /** @type {any} */
  let result;

  beforeAll(async () => {
    /** @type {string} */
    let liar = "";
    // The strongest tamper the protocol permits, and the reason the mailbox
    // opens envelopes at all: the payload is rewritten and re-sealed under the
    // liar's *own* private key, so the signature, the room, the audience and
    // `from` are all correct. The SDP is left exactly as Chromium wrote it, so
    // DTLS still completes and the channel still opens — only the transcript
    // field disagrees. Nothing but the binding can see this.
    room = await createQuorumRoom({
      tamper: (payload, signerFpr) => {
        if (payload.dtlsFingerprint && signerFpr === liar) {
          payload.dtlsFingerprint = LIE;
        }
        return payload;
      },
    });
    liar = room.audience[0];

    fx = await openPeers({ path: "/toolkit", count: 2, routes: room.routes });
    const [A, B] = fx.peers;
    await A.page.evaluate(LOAD_SESSION);
    await B.page.evaluate(LOAD_SESSION);

    const [loM, hiM] = room.members;
    lo = { peer: A, ...loM };
    hi = { peer: B, ...hiM };

    await startSession(A, {
      roomId: room.roomId,
      audience: room.audience,
      fpr: lo.fpr,
      armoredPrivate: lo.armoredPrivate,
      role: "creator",
    });
    await startSession(B, {
      roomId: room.roomId,
      audience: room.audience,
      fpr: hi.fpr,
      armoredPrivate: hi.armoredPrivate,
      role: "joiner",
    });

    // The connection must come up, or the refusal below would prove nothing —
    // a mesh that never connected also never confirms.
    await until(
      async () => ({ a: await snapshot(A), b: await snapshot(B) }),
      (v) =>
        v.a.peers[0]?.live === true &&
        v.b.peers[0]?.live === true &&
        v.a.peers[0]?.channelState === "open" &&
        v.b.peers[0]?.channelState === "open",
      { timeout: 90000, interval: 250, what: "transport up on both ends" }
    );

    // Then give confirmation every chance to happen anyway. A negative test
    // that passes because it gave up early proves nothing.
    /** @type {boolean} */
    let confirmed = false;
    try {
      await until(
        async () => ({ a: await snapshot(A), b: await snapshot(B) }),
        (v) => v.a.peers[0]?.kcVerified === true && v.b.peers[0]?.kcVerified === true,
        { timeout: 15000, interval: 250, what: "confirmation that must not come" }
      );
      confirmed = true;
    } catch (_) {
      confirmed = false;
    }

    const refusal = (p, to) =>
      p.page.evaluate(
        (t) =>
          window.__session.sendChatTo(t, "nope").then(
            () => ({ threw: false, message: "" }),
            (e) => ({ threw: true, message: String(e.message || e) })
          ),
        to
      );

    result = {
      confirmed,
      a: await snapshot(A),
      b: await snapshot(B),
      refusedLo: await refusal(A, hi.fpr),
      refusedHi: await refusal(B, lo.fpr),
      broadcast: await A.page.evaluate(() => window.__session.sendChat("broadcast")),
    };
  }, 180_000);

  afterAll(async () => {
    if (fx) {
      for (const p of fx.peers) await stopSession(p).catch(() => {});
      await fx.close();
    }
  });

  it("delivered a lie the PGP layer could not see", () => {
    // The fixture did what it claimed: exactly the offerer's fingerprint
    // rewritten, every envelope re-sealed, nothing dropped.
    expect(room.faults()).toEqual([]);
    const tampered = room.signalled().filter((s) => s.tampered);
    expect(tampered.length).toBeGreaterThan(0);
    for (const s of tampered) expect(s.signer).toBe(lo.fpr);
    // The SDP beside it is untouched — which is why the transport still came up
    // and why only the transcript can catch this.
    for (const s of tampered) {
      expect(s.dtlsFingerprint).toBe(extractDtlsFingerprint(s.sdp));
      expect(s.dtlsFingerprint).not.toBe(LIE);
    }
  });

  it("comes up on both ends and still refuses to confirm", () => {
    expect(result.confirmed).toBe(false);
    for (const side of [result.a, result.b]) {
      const p = side.peers[0];
      // Not a connectivity failure. The handshake is failing because the
      // transcripts disagree.
      expect(p.live).toBe(true);
      expect(p.connectionState).toBe("connected");
      expect(p.channelState).toBe("open");
      expect(p.kcVerified).toBe(false);
    }
  });

  it("derives two different keys, and says so", () => {
    const a = result.a.peers[0];
    const b = result.b.peers[0];
    expect(a.transcriptHash).toBeTruthy();
    expect(b.transcriptHash).toBeTruthy();
    expect(a.transcriptHash).not.toBe(b.transcriptHash);
    // One side built its transcript over the lie; the other over the truth.
    expect([a.remoteDtls, b.remoteDtls]).toContain(LIE);
    // Somebody complained: the confirmation frame does not open under the
    // other side's key.
    expect([...result.a.errors, ...result.b.errors].length).toBeGreaterThan(0);
  });

  it("delivers nothing over the unconfirmed link", () => {
    expect(result.refusedLo.threw).toBe(true);
    expect(result.refusedLo.message).toMatch(/no verified peer/);
    expect(result.refusedHi.threw).toBe(true);
    expect(result.refusedHi.message).toMatch(/no verified peer/);
    expect(result.broadcast).toBe(0);
  });
});

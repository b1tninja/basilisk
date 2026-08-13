/**
 * STUN discovery and ICE configuration — the `quorum-ops` half, in a real
 * browser (§21a/22b/23a).
 *
 * `rtc-transport.e2e.js` drives the transport's own ops out of the `rtc-ops`
 * chunk. `stun.check`, `rtc.ice` and `parseIceConfig` live in `quorum-ops`, the
 * session-manager side of the seam, and nothing had ever run them anywhere:
 * they are gated on `RTCPeerConnection`, which `environment: "node"` does not
 * have. `quorum-lifecycle.test.js` pins the parameter handling that can be
 * decided without an engine; everything below needs one.
 *
 * The harness — server, contexts, CSP recorder, launch classifier — is
 * `helpers/browser-peers.js`, unchanged. Only one context is opened: every
 * question here is about this peer and a server, not about two peers.
 *
 * **What always runs, and what may skip.** Refusals, timeouts and the
 * `rtc.ice` → `RTCPeerConnection` round trip need nothing but this machine and
 * must never skip. Only the reflexive-address assertion needs the public
 * internet, and it classifies its outcome rather than guarding on
 * availability: srflx is a pass, no srflx is a skip with a reason, and a throw
 * or a malformed row is a failure — that would be a defect in the op rather
 * than a fact about the network.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the STUN suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[stun-discovery.e2e] skipping — chromium not installed (${availability.reason})`);
}

/**
 * In-page: import the app's own `quorum-ops` chunk.
 *
 * Unlike `rtc-ops`, this one is not modulepreloaded — the engine reaches it
 * only when a `quorum.*`/`stun.*` step runs, which is the point of it being a
 * lazy chunk (WebRTC and the mesh stay out of the base bundle). So the hashed
 * name is recovered from the chunks the page *did* load, which each carry it
 * as the specifier of that dynamic import. Same-origin `fetch`, so `'self'`
 * covers it; hardcoding the hash would rot on the next build.
 *
 * A string rather than a function because Vitest rewrites `import()` in
 * anything it transforms — see the note in `rtc-transport.e2e.js`.
 */
const LOAD_OPS = `(async () => {
  const loaded = performance
    .getEntriesByType("resource")
    .map((x) => new URL(x.name).pathname)
    .filter((n) => /\\/assets\\/[^/]*\\.js$/.test(n));
  let name = "";
  for (const path of loaded) {
    const text = await (await fetch(path)).text();
    const m = text.match(/quorum-ops-[\\w-]+\\.js/);
    if (m) { name = m[0]; break; }
  }
  if (!name) throw new Error("no loaded chunk names the quorum-ops chunk");
  const mod = await import("/assets/" + name);
  // The chunk holds more than this module, so Rollup re-exports quorum-ops as
  // a frozen namespace object under a single-letter key rather than spreading
  // its names at the top level. Found by looking for the ops instead of by
  // guessing the letter, which changes with the minifier.
  const isOps = (o) =>
    o && typeof o.execStunCheck === "function" && typeof o.execRtcIce === "function";
  window.__q = isOps(mod) ? mod : Object.values(mod).find(isOps);
  if (!window.__q) {
    throw new Error("quorum-ops chunk exposes no ops namespace: " + Object.keys(mod).join(","));
  }
  return "/assets/" + name;
})()`;

/** Run an op in the page and bring back either its value or its message. */
const call = (page, fn, ...args) =>
  page.evaluate(
    ([f, a]) =>
      Promise.resolve()
        .then(() => window.__q[f](...a))
        .then(
          (v) => ({ ok: true, value: v }),
          (e) => ({ ok: false, message: String(e && e.message ? e.message : e) })
        ),
    [fn, args]
  );

describe.runIf(availability.ok)("STUN discovery in a real browser", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let A;
  /** @type {string} */
  let opsUrl;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 1 });
    [A] = fx.peers;
    opsUrl = await A.page.evaluate(LOAD_OPS);
  });

  afterAll(async () => {
    await fx?.close();
  });

  it("runs the shipped quorum-ops chunk, not a source module", async () => {
    expect(opsUrl).toMatch(/^\/assets\/quorum-ops-[\w-]+\.js$/);
    expect(await A.cspViolations()).toEqual([]);
  });

  /* ── what the two CSPs actually do to ICE ── */

  describe("the policy a browser really computes, over both halves of it", () => {
    it("serves the response-header CSP the deployment sends", async () => {
      // The half this suite could not see. Flask sets a policy header on every
      // response and the browser *intersects* it with the page's own `<meta>`
      // tag, so a source named in only one of them is blocked. Serving files
      // alone tested the meta tag and called it the production CSP.
      const res = await A.page.request.get(`${fx.origin}/toolkit`);
      const header = res.headers()["content-security-policy"] || "";
      expect(header, "no policy header — the intersection is untested again").toMatch(
        /connect-src/
      );
      // The finding that made this matter: `quorum.html` named two `stun:`
      // sources in its meta tag and `Settings.csp_connect_src` named none, so
      // the intersection permitted none. That page is retired and no page
      // ships a `stun:` source now, which makes this the assertion that the
      // header did not quietly acquire the belief the meta gave up.
      expect(header).not.toMatch(/stun:/);
    });

    it("does not refuse a stun: server the policy never allowed", async () => {
      // **The empirical answer.** `quorum.html` carried `stun:` sources in its
      // meta CSP and `static.py` spoke of keeping them intact, which only
      // means something if `connect-src` governs ICE. The header names none, so
      // under that belief STUN was refused on every page — including the one
      // page that listed them — and `/toolkit`, which has never listed them,
      // would have been broken in production all along.
      //
      // It is not. Chromium gathers against a `stun:` URL no directive permits
      // and files no violation: `connect-src` does not reach ICE servers here.
      // So the meta entries buy nothing, and the toolkit's missing ones cost
      // nothing — the retirement moves no sources, it deletes a belief.
      //
      // Loopback with nothing listening: deterministic, no internet, and the
      // gather still has to *start* for a policy to have anything to refuse.
      const before = (await A.cspViolations()).length;
      const r = await call(A.page, "execStunCheck", {
        server: "stun:127.0.0.1:3478",
        timeout: 1500,
      });
      expect(r.ok, `stun.check threw: ${r.message}`).toBe(true);
      const fresh = (await A.cspViolations()).slice(before);
      expect(
        fresh.filter((v) => /connect-src/.test(v.directive) || /^stun:/.test(v.blocked)),
        "connect-src now reaches ICE — csp_connect_src() must list the STUN servers"
      ).toEqual([]);
    });
  });

  /* ── refusals: no network, no engine state, must never skip ── */

  describe("stun.check refuses a server it could never query", () => {
    it("names the step rather than surfacing the constructor's error", async () => {
      // Unguarded, `new RTCPeerConnection` answers `http://…` with
      // `SyntaxError: Failed to construct 'RTCPeerConnection': … is not a
      // valid stun or turn URL` and a `turn:` URL with `InvalidAccessError:
      // … Both username and credential are required`. Neither says `stun.check`
      // or `server=`, and this is the only place that difference can be
      // observed — node never reaches the constructor at all.
      for (const server of ["http://example.com", "turn:relay.example:3478"]) {
        const r = await call(A.page, "execStunCheck", { server });
        expect(r.ok, `${server} was accepted`).toBe(false);
        expect(r.message, server).toMatch(/^stun\.check: not a stun:\/stuns: URL/);
      }
    });
  });

  describe("stun.check against a server that will not answer", () => {
    /** @type {any} */
    let out;
    /** @type {number} */
    let elapsed;

    beforeAll(async () => {
      // Loopback with nothing listening: no internet, no DNS, deterministic.
      const t0 = Date.now();
      const r = await call(A.page, "execStunCheck", {
        server: "stun:127.0.0.1:3478",
        timeout: 1500,
      });
      elapsed = Date.now() - t0;
      expect(r.ok, `stun.check threw: ${r.message}`).toBe(true);
      out = r.value.data;
    });

    it("reports a verdict instead of throwing or hanging", () => {
      // Measured: Chromium never completes gathering against a dead STUN
      // server — `iceGatheringState` sits at "gathering" indefinitely — so the
      // timeout is the only thing that ends this, and a wrong one would hang
      // the run rather than fail it.
      expect(out.ok).toBe(false);
      expect(out.publicAddress).toBe(null);
      expect(out.ms).toBeGreaterThanOrEqual(1500);
      expect(elapsed).toBeLessThan(8000);
    });

    it("still gathered a host candidate, and says so", () => {
      // The distinction a "blocked" verdict is useless without: host-only
      // means the STUN round trip never completed, and the panel now draws
      // this map rather than dropping it.
      expect(out.candidates.host).toBeGreaterThan(0);
      expect(out.candidates.srflx).toBeUndefined();
      expect(out.candidates.relay).toBeUndefined();
    });

    it("advises the fallback that would actually help", () => {
      expect(out.note).toMatch(/no srflx/);
      expect(out.note).toMatch(/TURN relay \(rtc\.ice turn=\)/);
    });

    it("keeps the diagnostic out of the sensitive path", () => {
      expect(out.server).toBe("stun:127.0.0.1:3478");
      expect(out.v).toBe(1);
    });
  });

  /* ── the one assertion that needs the public internet ── */

  it("discovers a reflexive address, or classifies why it could not", async () => {
    const r = await call(A.page, "execStunCheck", { timeout: 8000 });
    expect(r.ok, `stun.check threw: ${r.message}`).toBe(true);
    const d = r.value.data;
    // Whatever the network did, the shape is owed. A malformed row is a defect
    // in the op and fails on both branches.
    expect(d.server).toBe("stun:stun.cloudflare.com:3478");
    expect(d.candidates.host).toBeGreaterThan(0);
    expect(d.ms).toBeGreaterThan(0);

    if (!d.candidates.srflx) {
      expect(d.ok).toBe(false);
      expect(d.publicAddress).toBe(null);
      expect(d.note).toMatch(/no srflx/);
      console.warn("[stun-discovery.e2e] skipped reflexive discovery — no srflx candidate");
      return;
    }
    expect(d.ok).toBe(true);
    // An address and a port, not a redacted `.local` name: mDNS obfuscation
    // applies to host candidates, and a reflexive address is by definition the
    // one the server saw.
    expect(d.publicAddress).toMatch(/^[\d.]+:\d+$|^\[?[\da-f:]+\]?:\d+$/i);
    expect(d.publicAddress).not.toMatch(/\.local/);
    expect(d.note).toMatch(/STUN reachable/);
  });

  /* ── rtc.ice: a config the engine will actually take ── */

  describe("rtc.ice emits a config RTCPeerConnection accepts", () => {
    /**
     * The round trip the engine performs: `rtc.ice` writes the artifact,
     * `parseIceConfig` reads it back out of the slot, and the result is handed
     * to a peer connection. Only a browser can answer the last step, and it is
     * where a config that *looks* valid gets refused.
     */
    const roundTrip = (page, params) =>
      page.evaluate((p) => {
        try {
          const emitted = window.__q.execRtcIce(p);
          const servers = window.__q.parseIceConfig(emitted.data);
          const pc = new RTCPeerConnection({ iceServers: servers });
          const taken = pc.getConfiguration().iceServers.length;
          pc.close();
          return { ok: true, servers, taken };
        } catch (e) {
          return { ok: false, message: String(e && e.message ? e.message : e) };
        }
      }, params);

    it("takes the built-in defaults", async () => {
      const r = await roundTrip(A.page, {});
      expect(r.ok, r.message).toBe(true);
      expect(r.taken).toBe(2);
    });

    it("takes several STUN servers", async () => {
      const r = await roundTrip(A.page, {
        stun: "stun:stun.cloudflare.com:3478, stun:stun.l.google.com:19302",
      });
      expect(r.ok, r.message).toBe(true);
      expect(r.taken).toBe(2);
    });

    it("takes a stun: URL with no port", async () => {
      // Chromium defaults to :3478 — measured, it reported a reflexive address
      // against `stun:stun.l.google.com` in 133 ms — so refusing a portless
      // URL in `rtc.ice` would refuse something that works.
      const r = await roundTrip(A.page, { stun: "stun:stun.l.google.com" });
      expect(r.ok, r.message).toBe(true);
    });

    it("takes several TURN relays, which it used to make unparseable", async () => {
      // `turn=` was consumed whole while `stun=` was split, so
      // `turn=turn:a,turn:b` emitted one server whose `urls` held two URLs.
      // The artifact rendered, `parseIceConfig` accepted it, and the failure
      // arrived here as Chromium's `ICE server parsing failed: Invalid port` —
      // a cell and a page away from the step that wrote it. This is the only
      // level at which that could be caught.
      const r = await roundTrip(A.page, {
        turn: "turn:relay.example.net:3478,turns:relay.example.net:5349",
        username: "u",
        credential: "c",
      });
      expect(r.ok, r.message).toBe(true);
      // Two defaults plus the two relays, each its own server.
      expect(r.taken).toBe(4);
      for (const s of r.servers) {
        const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
        for (const u of urls) expect(u).not.toContain(",");
      }
    });
  });

  describe("the ice-turn-relay template, with no relay behind it", () => {
    /** @type {any} */
    let out;

    beforeAll(async () => {
      // The template's own shape: a TURN URL and a credential from a slot,
      // pointed at a host that does not answer. What a user gets the first
      // time they run it before standing up a relay.
      out = await A.page.evaluate(async () => {
        const emitted = window.__q.execRtcIce({
          turn: "turns:turn.example.net:5349",
          username: "USER",
          credential: "not-a-real-credential",
        });
        const servers = window.__q.parseIceConfig(emitted.data);
        const pc = new RTCPeerConnection({ iceServers: servers });
        const byType = {};
        const errors = [];
        pc.addEventListener("icecandidateerror", (e) =>
          errors.push({ code: e.errorCode, url: e.url })
        );
        pc.createDataChannel("probe");
        const t0 = performance.now();
        const gathered = new Promise((resolve) => {
          const timer = setTimeout(resolve, 6000);
          pc.onicecandidate = (ev) => {
            if (!ev.candidate) {
              clearTimeout(timer);
              resolve(undefined);
              return;
            }
            const t = ev.candidate.type || "unknown";
            byType[t] = (byType[t] || 0) + 1;
          };
        });
        // Gathering starts at setLocalDescription, not at createDataChannel.
        await pc.setLocalDescription(await pc.createOffer());
        await gathered;
        const ms = Math.round(performance.now() - t0);
        const state = pc.iceGatheringState;
        pc.close();
        return { byType, errors, ms, state, sensitive: emitted.meta.sensitive };
      });
    });

    it("still gathers the candidates it can, rather than failing outright", () => {
      // A dead TURN server degrades; it does not break the gather. Which is
      // why 23b's fallback CTA is "Configure TURN" and not "retry".
      expect(out.byType.host).toBeGreaterThan(0);
    });

    it("produces no relay candidate, and does not pretend otherwise", () => {
      expect(out.byType.relay).toBeUndefined();
    });

    it("marks a credential-bearing config sensitive", () => {
      // The credential is in the artifact body; `sensitive` is what keeps it
      // behind the reveal gate rather than on screen next to the URL.
      expect(out.sensitive).toBe(true);
    });
  });

  /* ── the policy question, measured ── */

  it("drives STUN from quorum-ops without tripping the production CSP", async () => {
    // `connect-src` on the toolkit page is `'self'` plus two keyservers, and
    // every STUN packet above went to neither. Asserted rather than assumed:
    // no CSP directive governs ICE traffic in Chromium — `webrtc` is the only
    // directive that could, it is absent, and its default is to allow — so a
    // third-party STUN server is reached with no violation and no exemption.
    // If this ever goes red, `stun.check` and `quorum.*` are broken in
    // production and green in dev, which is the failure this file exists for.
    const violations = await A.cspViolations();
    expect(violations).toEqual([]);
    expect(A.pageErrors().filter((e) => /Content Security Policy/i.test(e))).toEqual([]);
  });
});

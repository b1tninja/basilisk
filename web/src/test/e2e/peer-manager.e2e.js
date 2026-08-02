/**
 * The peer connection manager, against two real browsers (§55).
 *
 * `peer-links.test.js` asserts every rule the manager has under
 * `environment: "node"` — the projection, the origin bounding, the refusals.
 * None of that can tell you whether two browsers actually connect, which is the
 * only claim that matters here and the exact claim `rtc.offer` failed for its
 * entire shipped life while passing `tsc`, the full suite, and a test file
 * named after it.
 *
 * So this file carries an offer between two isolated browser contexts through
 * the shipped ops, in the shipped bundle, under the shipped CSP, and measures:
 * the ICE state transitions in order, the nominated candidate pair, and bytes
 * on the channel in both directions.
 *
 * **The connection needs nothing but this machine.** Two contexts of one
 * browser reach each other over host candidates on the loopback interface — no
 * STUN, no TURN, no public internet. This test is a floor and must never be
 * skipped: if it fails, the manager is broken.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers, until } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the manager suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  console.warn(`[peer-manager.e2e] skipping — chromium not installed (${availability.reason})`);
}

/**
 * Import the app's own `peer-ops` chunk, resolved from what the page actually
 * loaded so no content hash is hardcoded. A **string**, not a function, because
 * Vitest rewrites `import()` in anything it transforms.
 */
const LOAD_OPS = `(async () => {
  const byName = (re) => performance
    .getEntriesByType("resource")
    .map((x) => new URL(x.name).pathname)
    .find((n) => re.test(n));
  const peerUrl = byName(/\\/assets\\/peer-ops-[^/]*\\.js$/);
  const rtcUrl = byName(/\\/assets\\/rtc-ops-[^/]*\\.js$/);
  if (!peerUrl) throw new Error("the toolkit page did not load a peer-ops chunk");
  if (!rtcUrl) throw new Error("the toolkit page did not load an rtc-ops chunk");
  window.__peer = await import(peerUrl);
  window.__ops = await import(rtcUrl);
  return peerUrl;
})()`;

describe.runIf(availability.ok)("the peer manager, two real browsers", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let A;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let B;
  let opsUrl = "";
  /** Hoisted: the refusal tests below reuse the real answer minted here. */
  /** @type {any} */
  let result;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 2 });
    [A, B] = fx.peers;
  });

  afterAll(async () => {
    await fx?.close();
  });

  /* ── the floor: a connection made entirely through the shipped ops ── */

  describe("an offer carried between two browsers", () => {
    beforeAll(async () => {
      // Direct op calls, resolved out of the chunks the shipped page loaded.
      // The engine dispatch and type resolution are covered at compile level by
      // the verb smoke; what this file exists for is the transport, and calling
      // the ops directly keeps a failure attributable to them rather than to
      // twelve layers of notebook.
      opsUrl = await A.page.evaluate(LOAD_OPS);
      await B.page.evaluate(LOAD_OPS);

      const offer = await A.page.evaluate(() =>
        window.__peer.execPeerOffer({ name: "a", timeout: 4000 }, {}).then((v) => v.data)
      );
      const answer = await B.page.evaluate(
        (sdp) =>
          window.__peer
            .execPeerAnswer({ type: "sdp", data: sdp, meta: { which: "offer" } }, { name: "b", timeout: 4000 }, {})
            .then((v) => v.data),
        offer
      );
      await A.page.evaluate(
        (sdp) =>
          window.__peer.execPeerAccept(
            { type: "sdp", data: sdp, meta: { which: "answer" } },
            { name: "a" }
          ),
        answer
      );

      // `peer.wait` is the assertion, not a helper around it: if ICE fails, this
      // is what refuses, and it refuses in `connStateReadout`'s words.
      const waited = await Promise.all([
        A.page.evaluate(() =>
          window.__peer.execPeerWait({ name: "a", wait: 30000 }).then(
            (v) => ({ ok: true, data: v.data, type: v.type }),
            (e) => ({ ok: false, message: e.message })
          )
        ),
        B.page.evaluate(() =>
          window.__peer.execPeerWait({ name: "b", wait: 30000 }).then(
            (v) => ({ ok: true, data: v.data, type: v.type }),
            (e) => ({ ok: false, message: e.message })
          )
        ),
      ]);

      await A.page.evaluate(() =>
        window.__peer.execPeerSend({ type: "text", data: "ping-from-A" }, { name: "a" })
      );
      await B.page.evaluate(() =>
        window.__peer.execPeerSend({ type: "text", data: "pong-from-B" }, { name: "b" })
      );

      const heard = await Promise.all([
        A.page.evaluate(() =>
          window.__peer.execPeerRecv({ name: "a", wait: 10000 }).then(
            (v) => v.data,
            (e) => `ERR ${e.message}`
          )
        ),
        B.page.evaluate(() =>
          window.__peer.execPeerRecv({ name: "b", wait: 10000 }).then(
            (v) => v.data,
            (e) => `ERR ${e.message}`
          )
        ),
      ]);

      // Read the transport through the app's own diagnostics — the ops that
      // used to refuse outright for anything not made by `quorum.*`.
      const diag = (p) =>
        p.page.evaluate(async () => {
          const [state, check, stats, quality] = await Promise.all([
            window.__ops.execConnectionState(),
            window.__ops.execCheckConnectivity(),
            window.__ops.execDataChannelStats(),
            window.__ops.execStatsReport(),
          ]);
          return {
            state: state.data,
            check: check.data,
            stats: stats.data,
            quality: quality.data,
          };
        });

      // Two settling waits, and both are about *sampling*, not about hoping.
      //
      // SCTP message accounting trails the send, and — measured here, on the
      // run that first caught it — Chromium marks a candidate pair `nominated`
      // while it is still `in-progress`, reaching `succeeded` a beat later. A
      // snapshot taken between the two reads as a nominated pair that never
      // succeeded, which is a scheduling artifact rather than a fact about the
      // transport. This test passed on its first run and failed on its second
      // for exactly that reason.
      await until(
        () => diag(A).then((d) => d.stats.peers[0]?.messagesReceived ?? 0),
        (n) => n >= 1,
        { timeout: 10000, what: "channel counters" }
      );
      await until(
        () =>
          diag(A).then(
            (d) => (d.check.peers[0]?.pairs || []).find((p) => p.nominated)?.state || "none"
          ),
        (s) => s === "succeeded",
        { timeout: 15000, what: "nominated pair reaching succeeded" }
      );

      result = {
        offer,
        answer,
        waited,
        heard,
        a: await diag(A),
        b: await diag(B),
      };
      if (process.env.PEER_EVIDENCE) {
        // The numbers behind the assertions below, dumped for a human. Off by
        // default: this is evidence for a reviewer, not a thing the suite needs.
        const { writeFileSync } = await import("node:fs");
        const pair = result.a.check.peers[0].pairs.find((p) => p.nominated);
        writeFileSync(
          "peer-evidence.txt",
          [
            `offer candidates : ${(offer.match(/^a=candidate:/gm) || []).length} | ufrag ${(offer.match(/^a=ice-ufrag:(\S+)/m) || [])[1]}`,
            `offer dtls fpr   : ${(offer.match(/^a=fingerprint:sha-256 (\S+)/m) || [])[1]}`,
            `answer setup     : ${(answer.match(/^a=setup:(\S+)/m) || [])[1]}`,
            `rtc.state        : ${JSON.stringify(result.a.state.peers)}`,
            `nominated pair   : ${JSON.stringify(pair)}`,
            `rtc.stats        : ${JSON.stringify(result.a.stats.peers[0])}`,
            `rtc.quality      : ${JSON.stringify(result.a.quality.peers[0])}`,
            `A heard / B heard: ${JSON.stringify(heard)}`,
            `peer.wait handles: ${JSON.stringify(result.waited.map((w) => w.data))}`,
          ].join("\n")
        );
      }
    }, 120_000);

    it("loads the shipped peer-ops chunk with no CSP violation", async () => {
      expect(opsUrl).toMatch(/^\/assets\/peer-ops-[\w-]+\.js$/);
      expect(await A.cspViolations()).toEqual([]);
      expect(await B.cspViolations()).toEqual([]);
    });

    it("emits an offer that carries candidates and a DTLS fingerprint", () => {
      expect(result.offer).toMatch(/^v=0/);
      expect(result.offer).toMatch(/^a=setup:actpass/m);
      expect(result.offer.match(/^a=candidate:/gm)?.length || 0).toBeGreaterThan(0);
      expect(result.offer).toMatch(/^a=candidate:.* typ host/m);
      expect(result.offer).toMatch(/^a=fingerprint:sha-256 (?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/m);
      expect(result.answer).toMatch(/^a=setup:active/m);
    });

    it("connects — which is the whole point, and is what rtc.offer could not do", () => {
      // `peer.wait` resolving *is* the assertion. It polls the real
      // `connectionState` and the real `readyState`, and refuses on `failed`.
      for (const [i, w] of result.waited.entries()) {
        expect(w.ok, `peer.wait on ${i ? "B" : "A"} refused: ${w.message}`).toBe(true);
        expect(w.type).toBe("channel");
        expect(w.data.state).toBe("open");
        expect(w.data.origin).toBe("peer");
      }
      expect(result.waited[0].data.link).toBe("a");
      expect(result.waited[1].data.link).toBe("b");
    });

    it("reports the connection through the diagnostics that used to refuse it", () => {
      // Before §57a these five opened with "no live exchange — run quorum.offer
      // or quorum.join first", so every one of them was blind to a connection
      // made any other way. This is that fix, measured.
      const rowA = result.a.state.peers.find((p) => p.peer === "a");
      expect(rowA).toBeTruthy();
      expect(rowA.connectionState).toBe("connected");
      expect(rowA.channelState).toBe("open");
      expect(rowA.origin).toBe("peer");
      // And it reports the link as unauthenticated, because it is.
      expect(rowA.authenticated).toBe(false);
    });

    it("nominates a host candidate pair, and carries real bytes over it", () => {
      const pairs = result.a.check.peers.find((p) => p.peer === "a")?.pairs || [];
      const nominated = pairs.find((p) => p.nominated);
      expect(nominated, "no candidate pair was nominated").toBeTruthy();
      expect(nominated.state).toBe("succeeded");
      expect(nominated.local.type).toBe("host");
      expect(nominated.remote.type).toBe("host");
      // DTLS and SCTP setup alone is well over a kilobyte each way; a pair that
      // was nominated and never used would sit near zero.
      expect(nominated.bytesSent).toBeGreaterThan(500);
      expect(nominated.bytesReceived).toBeGreaterThan(500);
    });

    it("passes a message each way through peer.send and peer.recv", () => {
      expect(result.heard[0]).toBe("pong-from-B");
      expect(result.heard[1]).toBe("ping-from-A");
      const dcA = result.a.stats.peers.find((p) => p.peer === "a");
      expect(dcA.readyState).toBe("open");
      expect(dcA.messagesSent).toBeGreaterThanOrEqual(1);
      expect(dcA.messagesReceived).toBeGreaterThanOrEqual(1);
      expect(dcA.bytesSent).toBe("ping-from-A".length);
      expect(dcA.bytesReceived).toBe("pong-from-B".length);
    });

    it("measures round-trip time on the link, and still reports no loss", () => {
      const q = result.a.quality.peers.find((p) => p.peer === "a");
      expect(q.rttMs).toBeTypeOf("number");
      expect(q.bytesSent).toBeGreaterThan(500);
      // Unchanged and deliberately so: an SCTP data channel carries no RTP, so
      // there is nothing to compute a loss rate from, whoever opened it.
      expect(q.packetLossPct).toBeNull();
    });
  });

  /* ── the refusals, against a real transport ── */

  it("refuses to answer an SDP that is already an answer", async () => {
    // Chromium accepts an answer's SDP as `{ type: "offer" }` without
    // complaint — same grammar — so without this guard `peer.answer` would open
    // a second live connection that no peer had asked for and that can never
    // connect. Measured against a real answer minted by a real browser, and it
    // must leave no link behind.
    const outcome = await B.page.evaluate(async (sdp) => {
      try {
        await window.__peer.execPeerAnswer({ type: "sdp", data: sdp }, { name: "z1" }, {});
        return { refused: false };
      } catch (e) {
        return { refused: true, message: e.message };
      }
    }, result.answer);
    expect(outcome.refused).toBe(true);
    expect(outcome.message).toMatch(/already an answer/);
    expect(outcome.message).toMatch(/peer\.accept/);

    const leaked = await B.page.evaluate(() => {
      try {
        window.__peer.execPeerClose({ name: "z1" });
        return true;
      } catch {
        return false;
      }
    });
    expect(leaked, "a refused peer.answer registered a link anyway").toBe(false);
  });

  it("refuses a second connection under a name that is already open", async () => {
    const outcome = await A.page.evaluate(async () => {
      try {
        await window.__peer.execPeerOffer({ name: "a", timeout: 2000 }, {});
        return { refused: false };
      } catch (e) {
        return { refused: true, message: e.message };
      }
    });
    expect(outcome.refused).toBe(true);
    expect(outcome.message).toMatch(/already open/);
    expect(outcome.message).toMatch(/peer\.close a/);
  });

  it("closes only the direct links, and forgets them", async () => {
    const after = await A.page.evaluate(() => {
      const out = window.__peer.execPeerClose({});
      return { closed: out.meta.closedIds, remaining: out.data.peers.map((p) => p.peer) };
    });
    expect(after.closed).toContain("a");
    expect(after.remaining).not.toContain("a");

    // And the diagnostics go back to refusing, by name, with both routes in.
    const refusal = await A.page.evaluate(() =>
      Promise.resolve()
        .then(() => window.__ops.execConnectionState())
        .then(() => ({ threw: false }), (e) => ({ threw: true, message: e.message }))
    );
    expect(refusal.threw).toBe(true);
    expect(refusal.message).toMatch(/no live connection/);
    expect(refusal.message).toMatch(/peer\.offer/);
    expect(refusal.message).toMatch(/quorum\.offer/);
  });

  it("drives the whole exchange without tripping the production CSP", async () => {
    expect(await A.cspViolations()).toEqual([]);
    expect(await B.cspViolations()).toEqual([]);
  });
});

/**
 * The WebRTC transport, against two real browsers (§23a/23b/26a/26b/29a/30d).
 *
 * Every other spec in `src/test/` runs under `environment: "node"`, where
 * `RTCPeerConnection` does not exist — so `rtc-channel-ops`, `quorum-room` and
 * `quorum-negotiation` assert roster and negotiation *logic* and have never
 * touched a peer connection. This file is the other half: the ops run in the
 * shipped bundle, in a real Chromium, under the real production CSP, and an
 * offer made in one browser is carried to another.
 *
 * **What always runs, and what may skip.** A connection between two contexts of
 * one browser needs only host candidates on the loopback/LAN interface — no
 * STUN, no TURN, no public internet. That test is the floor and must never be
 * skipped; if it fails, the transport is broken. Only the assertions that
 * genuinely require a public STUN server are allowed to stand down, and they
 * classify *why* rather than guarding on bare availability — the trap
 * `ssh-format.test.js` documents, where a guard on "did anything go wrong"
 * turned a real defect into a silent skip.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers, until } from "../helpers/browser-peers.js";

const availability = await chromiumAvailability();

// An absent browser download is a reason to stand down. A browser that is
// installed and will not run is a broken environment, and is reported as a
// failure — the distinction `ssh-format.test.js` had to learn, where guarding
// on availability alone let an unrelated refusal read as "not applicable".
if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the transport suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${availability.reason}`);
  });
} else if (!availability.ok) {
  // Loud, because a silently-skipped transport suite is how a defect ships.
  console.warn(`[rtc-transport.e2e] skipping — chromium not installed (${availability.reason})`);
}

/**
 * In-page: import the app's own rtc-ops chunk, resolved from what the page
 * actually loaded, so the content hash never has to be hardcoded.
 *
 * A **string**, not a function, because Vitest rewrites `import()` in anything
 * it transforms into `__vite_ssr_dynamic_import__` — which is a module-runner
 * binding that does not exist in a browser, so the source has to reach Chromium
 * untouched. Serializing the module namespace is impossible, hence the global.
 */
const LOAD_OPS = `(async () => {
  const url = performance
    .getEntriesByType("resource")
    .map((x) => new URL(x.name).pathname)
    .find((n) => /\\/assets\\/rtc-ops-[^/]*\\.js$/.test(n));
  if (!url) throw new Error("the toolkit page did not load an rtc-ops chunk");
  window.__ops = await import(url);
  return url;
})()`;

describe.runIf(availability.ok)("WebRTC transport, two real browsers", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let A;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let B;
  /** @type {string} */
  let opsUrl;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 2 });
    [A, B] = fx.peers;
    opsUrl = await A.page.evaluate(LOAD_OPS);
    await B.page.evaluate(LOAD_OPS);
  });

  afterAll(async () => {
    await fx?.close();
  });

  it("loads the shipped toolkit page in both peers with no CSP violation", async () => {
    // The page is the real one, so this also proves the harness is not quietly
    // testing a blank document — the ops came out of a content-hashed bundle.
    expect(opsUrl).toMatch(/^\/assets\/rtc-ops-[\w-]+\.js$/);
    expect(await A.cspViolations()).toEqual([]);
    expect(await B.cspViolations()).toEqual([]);
  });

  /* ── the floor: a connection needing nothing but this machine ── */

  describe("a data channel between two browser contexts", () => {
    /** @type {any} */
    let result;

    beforeAll(async () => {
      const arm = (p, role) =>
        p.page.evaluate((r) => {
          // `iceServers: []` is the whole point: host candidates only, so this
          // never depends on a server anyone else operates.
          const pc = new RTCPeerConnection({ iceServers: [] });
          window.__pc = pc;
          window.__states = [];
          window.__recv = [];
          pc.addEventListener("iceconnectionstatechange", () =>
            window.__states.push(`ice:${pc.iceConnectionState}`)
          );
          pc.addEventListener("connectionstatechange", () =>
            window.__states.push(`conn:${pc.connectionState}`)
          );
          const wire = (ch) => {
            window.__ch = ch;
            ch.addEventListener("message", (e) => window.__recv.push(e.data));
          };
          if (r === "offerer") wire(pc.createDataChannel("probe"));
          else pc.addEventListener("datachannel", (e) => wire(e.channel));
        }, role);

      const settled = (p) =>
        p.page.evaluate(async () => {
          const pc = window.__pc;
          await new Promise((res) => {
            if (pc.iceGatheringState === "complete") return res();
            pc.addEventListener("icegatheringstatechange", () => {
              if (pc.iceGatheringState === "complete") res();
            });
            setTimeout(res, 5000);
          });
          return pc.localDescription.sdp;
        });

      await arm(A, "offerer");
      await arm(B, "answerer");

      await A.page.evaluate(async () =>
        window.__pc.setLocalDescription(await window.__pc.createOffer())
      );
      const offer = await settled(A);
      await B.page.evaluate(async (sdp) => {
        await window.__pc.setRemoteDescription({ type: "offer", sdp });
        await window.__pc.setLocalDescription(await window.__pc.createAnswer());
      }, offer);
      const answer = await settled(B);
      await A.page.evaluate(
        (sdp) => window.__pc.setRemoteDescription({ type: "answer", sdp }),
        answer
      );

      const both = async () => ({
        a: await A.page.evaluate(() => window.__pc.connectionState),
        b: await B.page.evaluate(() => window.__pc.connectionState),
      });
      await until(both, (v) => v.a === "connected" && v.b === "connected", {
        timeout: 30000,
        what: "host-candidate connection",
      });

      await A.page.evaluate(() => window.__ch.send("ping-from-A"));
      await B.page.evaluate(() => window.__ch.send("pong-from-B"));

      const selected = (p) =>
        p.page.evaluate(async () => {
          const rep = await window.__pc.getStats();
          const byId = new Map();
          rep.forEach((s) => byId.set(s.id, s));
          let pair = null;
          let dc = null;
          rep.forEach((s) => {
            if (s.type === "candidate-pair" && s.nominated) {
              pair = {
                state: s.state,
                nominated: s.nominated,
                localType: byId.get(s.localCandidateId)?.candidateType,
                remoteType: byId.get(s.remoteCandidateId)?.candidateType,
                protocol: byId.get(s.localCandidateId)?.protocol,
                bytesSent: s.bytesSent,
                bytesReceived: s.bytesReceived,
              };
            }
            if (s.type === "data-channel") dc = { ...s };
          });
          const types = new Set();
          rep.forEach((s) => types.add(s.type));
          return {
            pair,
            dc,
            types: [...types].sort(),
            states: window.__states,
            recv: window.__recv,
          };
        });

      // Counters are sampled after a beat: SCTP accounting trails the send.
      await until(
        () => selected(A),
        (v) => v.dc?.messagesReceived >= 1,
        { timeout: 10000, what: "channel counters" }
      );
      result = { a: await selected(A), b: await selected(B) };
    });

    it("reaches connected through checking, over a host candidate pair", () => {
      // The transition order is the assertion — "connected" alone would also be
      // true of a connection that was never actually checked.
      expect(result.a.states).toContain("ice:checking");
      expect(result.a.states).toContain("ice:connected");
      expect(result.a.states).toContain("conn:connected");
      expect(result.a.states.indexOf("ice:checking")).toBeLessThan(
        result.a.states.indexOf("ice:connected")
      );
      expect(result.a.pair).toBeTruthy();
      expect(result.a.pair.state).toBe("succeeded");
      expect(result.a.pair.localType).toBe("host");
      expect(result.a.pair.remoteType).toBe("host");
      expect(result.a.pair.protocol).toBe("udp");
    });

    it("carries real bytes over the nominated pair, both ways", () => {
      // DTLS and SCTP setup alone is well over a kilobyte each way; a pair that
      // was nominated but never used would sit near zero.
      expect(result.a.pair.bytesSent).toBeGreaterThan(500);
      expect(result.a.pair.bytesReceived).toBeGreaterThan(500);
      expect(result.b.pair.bytesSent).toBeGreaterThan(500);
    });

    it("passes a message each way on the data channel", () => {
      expect(result.a.recv).toEqual(["pong-from-B"]);
      expect(result.b.recv).toEqual(["ping-from-A"]);
      expect(result.a.dc.state).toBe("open");
      expect(result.a.dc.messagesSent).toBe(1);
      expect(result.a.dc.messagesReceived).toBe(1);
      expect(result.a.dc.bytesSent).toBe("ping-from-A".length);
      expect(result.a.dc.bytesReceived).toBe("pong-from-B".length);
    });

    it("exposes every getStats field the rtc.* diagnostic ops read", () => {
      // `rtc.check`, `rtc.stats` and `rtc.quality` cannot be run here — they
      // require a live `quorum.*` session — so what is asserted instead is that
      // the fields they index into exist and are populated on a real report.
      // A rename in Chromium would otherwise surface as a tile full of zeroes.
      for (const k of ["state", "nominated", "bytesSent", "bytesReceived"]) {
        expect(result.a.pair).toHaveProperty(k);
      }
      for (const k of ["messagesSent", "messagesReceived", "bytesSent", "bytesReceived"]) {
        expect(result.a.dc[k]).toBeTypeOf("number");
      }
    });

    it("carries no RTP statistics at all, which is why loss is not reported", () => {
      // The whole stat vocabulary of a live connection here, pinned. `rtc.quality`
      // used to read `packetsLost` off a `remote-inbound-rtp` report and divide it
      // by the ICE path's packet counters — two different populations, and the
      // numerator's stat type does not exist on this connection or any this app
      // makes. `packetsLost` was therefore always its initial 0, and the tile
      // rendered that as a confident "0% loss".
      //
      // Listed exactly rather than as an absence, so the day a Chromium change
      // adds a type this fails and gets read, instead of an added RTP report
      // silently making the old arithmetic look defensible again.
      expect(result.a.types).toEqual([
        "candidate-pair",
        "certificate",
        "data-channel",
        "local-candidate",
        "peer-connection",
        "remote-candidate",
        "transport",
      ]);
      expect(result.a.types.filter((t) => /rtp|media|track|codec/.test(t))).toEqual([]);
    });

    it("reads loss off nothing, and says so rather than showing a zero", async () => {
      // `rtc.quality` needs a live `quorum.*` exchange, so it cannot be called
      // here — what is checked is the field it would have read. `packetsLost`
      // exists on no report, so any expression over it is a constant.
      const lossFields = await A.page.evaluate(async () => {
        const rep = await window.__pc.getStats();
        const found = [];
        rep.forEach((s) => {
          if ("packetsLost" in s) found.push(`${s.type}.packetsLost`);
          if ("fractionLost" in s) found.push(`${s.type}.fractionLost`);
        });
        return found;
      });
      expect(lossFields).toEqual([]);
    });
  });

  /* ── ICE restart: renegotiation in place, the way rtc.js drives it ── */

  it("rotates ICE credentials on restartIce and keeps the channel open", async () => {
    // `quorum/rtc.js` drives restart through `onnegotiationneeded` +
    // *no-arg* `setLocalDescription`, and its comment records that an earlier
    // build had no handler, so "Restart connection" only cleared flags. This
    // reproduces that exact wiring against a live peer so the claim is checked
    // rather than trusted.
    const fx2 = await openPeers({ path: "/toolkit", count: 2 });
    try {
      const [X, Y] = fx2.peers;
      const arm = (p, role) =>
        p.page.evaluate((r) => {
          const pc = new RTCPeerConnection({ iceServers: [] });
          window.__pc = pc;
          window.__out = [];
          window.__recv = [];
          window.__negotiations = 0;
          pc.addEventListener("icecandidate", (e) => {
            if (e.candidate) window.__out.push({ t: "ice", c: e.candidate.toJSON() });
          });
          pc.onnegotiationneeded = async () => {
            window.__negotiations += 1;
            await pc.setLocalDescription();
            window.__out.push({ t: "offer", sdp: pc.localDescription.sdp });
          };
          const wire = (ch) => {
            window.__ch = ch;
            ch.addEventListener("message", (e) => window.__recv.push(e.data));
          };
          if (r === "offerer") wire(pc.createDataChannel("quorum", { ordered: true }));
          else pc.addEventListener("datachannel", (e) => wire(e.channel));
        }, role);
      await arm(X, "offerer");
      await arm(Y, "answerer");

      // The signalling channel this test stands in for is the encrypted relay;
      // here it is just a loop moving one side's outbox into the other.
      const drain = async (from, to) => {
        const msgs = await from.page.evaluate(() => window.__out.splice(0));
        for (const m of msgs) {
          await to.page.evaluate(async (msg) => {
            const pc = window.__pc;
            if (msg.t === "ice") {
              try {
                await pc.addIceCandidate(msg.c);
              } catch {
                /* candidate for a superseded generation */
              }
            } else if (msg.t === "offer") {
              await pc.setRemoteDescription({ type: "offer", sdp: msg.sdp });
              await pc.setLocalDescription();
              window.__out.push({ t: "answer", sdp: pc.localDescription.sdp });
            } else if (msg.t === "answer" && pc.signalingState === "have-local-offer") {
              await pc.setRemoteDescription({ type: "answer", sdp: msg.sdp });
            }
          }, m);
        }
        return msgs.length;
      };
      let pumping = true;
      const pump = (async () => {
        while (pumping) {
          if (!(await drain(X, Y)) && !(await drain(Y, X))) {
            await new Promise((r) => setTimeout(r, 50));
          }
        }
      })();

      const both = async () => ({
        a: await X.page.evaluate(() => window.__pc.connectionState),
        b: await Y.page.evaluate(() => window.__pc.connectionState),
      });
      await until(both, (v) => v.a === "connected" && v.b === "connected", {
        timeout: 30000,
        what: "pre-restart connection",
      });

      const ufrag = () =>
        X.page.evaluate(() => window.__pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1]);
      const before = await ufrag();
      await X.page.evaluate(() => window.__pc.restartIce());

      // A restart that took is visible as a *new* negotiation and fresh ICE
      // credentials — not merely as a connection that stayed up, which is also
      // what doing nothing at all looks like.
      await until(
        () => X.page.evaluate(() => window.__negotiations),
        (n) => n >= 2,
        { timeout: 20000, what: "renegotiation after restartIce" }
      );
      const after = await until(ufrag, (u) => u !== before, {
        timeout: 20000,
        what: "ICE ufrag rotation",
      });
      expect(after).not.toBe(before);

      await until(both, (v) => v.a === "connected" && v.b === "connected", {
        timeout: 30000,
        what: "post-restart connection",
      });
      await X.page.evaluate(() => window.__ch.send("after-restart"));
      const recv = await until(
        () => Y.page.evaluate(() => window.__recv),
        (r) => r.includes("after-restart"),
        { timeout: 10000, what: "message after restart" }
      );
      expect(recv).toContain("after-restart");
      pumping = false;
      await pump;
    } finally {
      await fx2.close();
    }
  });

  /* ── the shipped ops, run in the page that ships them ── */

  describe("rtc.offer and rtc.answer", () => {
    /** @type {string} */
    let offer;
    /** @type {string} */
    let answer;

    beforeAll(async () => {
      const v = await A.page.evaluate(() => window.__ops.execCreateOffer({}, {}));
      offer = v.data;
      const w = await B.page.evaluate(
        (sdp) => window.__ops.execCreateAnswer({ type: "sdp", data: sdp }, {}, {}),
        offer
      );
      answer = w.data;
    });

    it("emits an offer carrying gathered candidates and a DTLS fingerprint", () => {
      expect(offer).toMatch(/^v=0/);
      // `waitForGathering` exists so the blob is hand-carriable; an offer with
      // no candidate lines is useless to whoever receives it.
      expect(offer.match(/^a=candidate:/gm)?.length || 0).toBeGreaterThan(0);
      expect(offer).toMatch(/^a=candidate:.* typ host/m);
      expect(offer).toMatch(/^a=ice-ufrag:\S+/m);
      expect(offer).toMatch(/^a=fingerprint:sha-256 (?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/m);
      expect(offer).toMatch(/^a=setup:actpass/m);
    });

    it("answers an offer made in a different browser", () => {
      // Cross-context is the only interesting version of this: an answer made
      // in the same realm as its offer proves nothing about interoperation.
      expect(answer).toMatch(/^v=0/);
      expect(answer).toMatch(/^a=setup:active/m);
      expect(answer.match(/^a=candidate:/gm)?.length || 0).toBeGreaterThan(0);
    });

    it("refuses to answer an SDP that is already an answer", async () => {
      // Regression: Chromium accepts an answer's SDP as `{ type: "offer" }`
      // without complaint — same grammar — so `rtc.offer | rtc.answer |
      // rtc.answer` used to emit a second plausible `answer.sdp` that no peer
      // had asked for. Measured against a real peer connection, not stubbed.
      const outcome = await B.page.evaluate(async (sdp) => {
        try {
          await window.__ops.execCreateAnswer({ type: "sdp", data: sdp }, {}, {});
          return { refused: false };
        } catch (e) {
          return { refused: true, message: e.message };
        }
      }, answer);
      expect(outcome.refused).toBe(true);
      expect(outcome.message).toMatch(/already an answer/);
    });

    it("still refuses text that is not SDP at all", async () => {
      const outcome = await B.page.evaluate(async () => {
        try {
          await window.__ops.execCreateAnswer({ type: "text", data: "not sdp" }, {}, {});
          return { refused: false };
        } catch (e) {
          return { refused: true, message: e.message };
        }
      });
      expect(outcome.refused).toBe(true);
      expect(outcome.message).toMatch(/expects an SDP offer/);
    });

    it("emits an offer whose peer connection is already gone", async () => {
      // **This is the shipped behaviour, and it is why `sdp-hand-carried`
      // cannot produce a connection.** `execCreateOffer` closes its
      // `RTCPeerConnection` in a `finally` before returning, so the ufrag and
      // certificate in the blob above belong to a transport that no longer
      // exists, and no op can apply an answer to it.
      //
      // Asserted rather than merely noted, so that making the hand-carried
      // flow connectable has to come here and delete this test on purpose.
      const live = await B.page.evaluate(async (sdp) => {
        const pc = new RTCPeerConnection({ iceServers: [] });
        window.__dead = pc;
        await pc.setRemoteDescription({ type: "offer", sdp });
        await pc.setLocalDescription(await pc.createAnswer());
        return pc.signalingState;
      }, offer);
      expect(live).toBe("stable");

      // Give it far longer than the ~4ms a live host-candidate pair takes.
      await new Promise((r) => setTimeout(r, 6000));
      const state = await B.page.evaluate(() => window.__dead.connectionState);
      expect(state).not.toBe("connected");
      expect(["new", "connecting", "failed"]).toContain(state);
      await B.page.evaluate(() => window.__dead.close());
    });

    it("names no op capable of applying an answer", async () => {
      // The other half of the finding above, stated where it can rot loudly:
      // the module has no `rtc.accept`, so the answer produced two tests up has
      // nowhere to go.
      const exports = await A.page.evaluate(() => Object.keys(window.__ops).sort());
      expect(exports).toContain("execCreateOffer");
      expect(exports).toContain("execCreateAnswer");
      expect(exports.filter((k) => /accept|applyAnswer/i.test(k))).toEqual([]);
    });
  });

  /* ── certificates and gathering ── */

  it("mints DTLS certificates of both algorithms with real fingerprints", async () => {
    for (const alg of ["ecdsa", "rsa"]) {
      const v = await A.page.evaluate((a) => window.__ops.execCertificate({ alg: a }), alg);
      expect(v.data.fingerprints).toHaveLength(1);
      expect(v.data.fingerprints[0].algorithm).toBe("sha-256");
      expect(v.data.fingerprints[0].value).toMatch(/^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/);
      expect(new Date(v.data.expires).getTime()).toBeGreaterThan(Date.now());
    }
  });

  it("gathers a host candidate whether or not any STUN server answers", async () => {
    // `rtc.gather` has no parameter for "no ICE servers" — an empty `ice=`
    // means the built-in STUN defaults — so this cannot ask for a host-only
    // gather. It does not need to: a host candidate comes off the local
    // interface and is owed unconditionally, however the STUN half fares.
    const g = await A.page.evaluate(() =>
      window.__ops.execGatherCandidates({ timeout: 4000 }, {})
    );
    expect(g.data.byType.host).toBeGreaterThan(0);
    expect(g.data.total).toBeGreaterThan(0);
    for (const c of g.data.candidates) {
      expect(["host", "srflx", "prflx", "relay"]).toContain(c.type);
      expect(["udp", "tcp"]).toContain(c.protocol);
    }
    // A missing TURN relay is documented as informational, not a failure.
    expect(g.data.notes.join(" ")).toMatch(/no relay/);
  });

  it("reaches the default STUN servers, or says why it could not", async () => {
    // The one assertion that needs the public internet. It classifies the
    // outcome instead of guarding on availability: a reflexive candidate is a
    // pass, *no* reflexive candidate is a skip with a reason, and anything else
    // — a throw, a malformed row — is a failure, because that would be a defect
    // in the op rather than a fact about the network.
    const g = await A.page.evaluate(() =>
      window.__ops.execGatherCandidates({ timeout: 8000 }, {}).then(
        (v) => ({ ok: true, data: v.data }),
        (e) => ({ ok: false, message: e.message })
      )
    );
    expect(g.ok, `rtc.gather threw: ${g.message}`).toBe(true);
    if (!g.data.byType.srflx) {
      expect(g.data.notes.join(" ")).toMatch(/no srflx/);
      console.warn("[rtc-transport.e2e] skipped STUN reachability — no srflx candidate");
      return;
    }
    const srflx = g.data.candidates.find((c) => c.type === "srflx");
    expect(srflx.relatedAddress).toBeTruthy();
    expect(srflx.port).toBeGreaterThan(0);
  });

  it("drives ICE and STUN without tripping the production CSP", async () => {
    // `connect-src` on the toolkit page is `'self'` plus two keyservers, and
    // every STUN packet above went somewhere else entirely. Measured, because
    // assuming either way would be guessing: no CSP directive governs ICE
    // traffic in Chromium, so a reflexive candidate off a third-party STUN
    // server is reached without a violation and without a policy exemption.
    expect(await A.cspViolations()).toEqual([]);
    expect(await B.cspViolations()).toEqual([]);
  });

  it("refuses every live-session op when nothing is connected", async () => {
    // `rtc.check`/`state`/`stats`/`restart`/`quality` read the live
    // `quorum.*` exchange. Standing one up needs the relay and two OpenPGP
    // identities, which is the session layer's fixture, not the transport's —
    // so what the transport owes is that each refuses by name rather than
    // returning an empty report that a tile would render as "all clear".
    const ops = {
      execConnectionState: "rtc.state",
      execCheckConnectivity: "rtc.check",
      execDataChannelStats: "rtc.stats",
      execRtcRestart: "rtc.restart",
      execStatsReport: "rtc.quality",
    };
    for (const [fn, name] of Object.entries(ops)) {
      const r = await A.page.evaluate(
        (f) =>
          Promise.resolve()
            .then(() => window.__ops[f]())
            .then(() => ({ threw: false }), (e) => ({ threw: true, message: e.message })),
        fn
      );
      expect(r.threw, `${name} did not refuse without a live exchange`).toBe(true);
      expect(r.message).toContain(name);
      expect(r.message).toMatch(/no live exchange/);
    }
  });
});

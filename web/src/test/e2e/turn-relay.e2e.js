/**
 * The TURN relay path, against a real relay (§21a/23a/26a).
 *
 * **What was dark.** `relay` is the one ICE candidate type this repo had never
 * obtained anywhere. `rtc-transport.e2e.js` proves a host-candidate connection
 * and `stun-discovery.e2e.js` proves a real reflexive address off a public STUN
 * server — but every TURN assertion in both was made against
 * `turn.example.net`, a host that does not answer. "No relay candidate" was the
 * expected result of each, which means a *broken* relay path would have read
 * exactly the same. `ice-turn-relay` has shipped as a template that whole time.
 *
 * That this is unexercised ground is not a guess: `rtc.ice` consumed `turn=`
 * whole while splitting `stun=`, so `turn=turn:a,turn:b` emitted one server
 * whose `urls` held two comma-joined URLs — an artifact that renders as valid
 * and dies a page later inside Chromium. It was fixed hours before this file
 * was written. `stun-discovery.e2e.js` pins the parse; this pins it against a
 * server that actually answers.
 *
 * **How the relay path is reached without simulating NAT.** Basilisk does not
 * implement ICE — Chromium does; Basilisk *configures* it. Containers on
 * separate networks would therefore mostly test Chromium's ICE stack.
 * `iceTransportPolicy: "relay"` gets to the same place from the other side: the
 * agent discards host and srflx and only a relay candidate can win, which is
 * the path a peer behind symmetric NAT depends on, with no NAT in the picture.
 * The standard acceptance check is the candidate type, and it is the assertion
 * throughout: STUN works if `srflx` appears, TURN works if `relay` appears.
 *
 * **What always runs, and what may skip.** The classifier's branches are pure
 * and always run. Everything else needs Docker, and stands down only for
 * reasons that are not news — no `docker`, no engine, no image and no network
 * to fetch one. A Docker that answers and then misbehaves fails the run: a
 * relay suite that filed every complaint under "no Docker" would skip itself
 * green on the day the relay path broke. See `helpers/coturn.js`.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromiumAvailability, openPeers, until } from "../helpers/browser-peers.js";
import { classifyDockerFailure, startCoturn } from "../helpers/coturn.js";

const browserAvail = await chromiumAvailability();
if (!browserAvail.ok && browserAvail.kind === "broken") {
  it("launches the browser the relay suite needs", () => {
    expect.unreachable(`chromium is installed but would not launch: ${browserAvail.reason}`);
  });
}

/* ── the guard's own branches: no Docker required, never skipped ── */

describe("what a failed docker invocation is taken to mean", () => {
  // A given machine exercises exactly one of these at runtime, and the branch
  // that must never swallow a real fault is the one no CI run reaches. The
  // strings are Docker's own.
  it("stands down for an absent binary", () => {
    expect(classifyDockerFailure("spawnSync docker ENOENT")).toBe("absent");
    expect(classifyDockerFailure("'docker' is not recognized as an internal or external command"))
      .toBe("absent");
    expect(classifyDockerFailure("docker: command not found")).toBe("absent");
  });

  it("stands down for an engine that is not running", () => {
    expect(
      classifyDockerFailure(
        "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine; " +
          "check if the path is correct and if the daemon is running: " +
          "open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified."
      )
    ).toBe("daemon");
    expect(
      classifyDockerFailure(
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. " +
          "Is the docker daemon running?"
      )
    ).toBe("daemon");
  });

  it("stands down for an image it can neither find nor fetch", () => {
    expect(
      classifyDockerFailure("dial tcp: lookup registry-1.docker.io: no such host")
    ).toBe("image");
    expect(classifyDockerFailure("net/http: TLS handshake timeout")).toBe("image");
  });

  it("does not stand down for anything else", () => {
    // The important row. Each of these is Docker answering and something being
    // wrong, which is news — a guard that swallowed them would be worse than no
    // guard, which is the trap `ssh-format.test.js` fell into and documents.
    expect(classifyDockerFailure("manifest for coturn/coturn:4.6.2 not found")).toBe("broken");
    expect(classifyDockerFailure("port is already allocated")).toBe("broken");
    expect(classifyDockerFailure("error while creating mount source path")).toBe("broken");
    expect(classifyDockerFailure("no space left on device")).toBe("broken");
    // "pull" alone must not read as a network fault: a bad pin is news.
    expect(classifyDockerFailure("failed to pull image: unauthorized")).toBe("broken");
  });
});

/* ── the relay itself ── */

const status = browserAvail.ok
  ? await startCoturn()
  : { ok: false, reason: browserAvail.reason, kind: "absent", relay: null };

if (!status.ok && status.kind === "broken") {
  it("stands up the TURN relay the suite needs", () => {
    expect.unreachable(`docker answered and coturn would not serve: ${status.reason}`);
  });
}

// A skip nobody can see is how a dark path stays dark, and the sibling suites'
// module-scope `console.warn` is swallowed by Vitest's collector — measured: it
// prints nothing at all. So the reason is carried by a test that always runs,
// whose *name* states the outcome and whose body writes it where a run cannot
// hide it. Without Docker this is the one line that explains the other 18.
it(
  status.ok
    ? "has a TURN relay to test against"
    : `stands down, and only for a reason that is not news: ${status.kind}`,
  () => {
    if (!status.ok) {
      console.warn(`[turn-relay.e2e] skipping ${status.kind} — ${status.reason}`);
      // Whatever else is true, the suite must not have stood down for the one
      // classification that means something is genuinely wrong.
      expect(status.kind).not.toBe("broken");
      return;
    }
    expect(RELAY.url).toMatch(/^turn:127\.0\.0\.1:\d+$/);
  }
);

const RELAY = status.relay;

/** The `ice=@slot` shape `rtc.gather` resolves through at runtime. */
const SLOT_BINDING = (data) => ({
  resolveSlot: (ref) => (ref === "@ice" ? { type: "endpoint", data } : null),
});

describe.runIf(status.ok)("the TURN relay path, against a real relay", () => {
  /** @type {import("../helpers/browser-peers.js").PeerFixture} */
  let fx;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let A;
  /** @type {import("../helpers/browser-peers.js").Peer} */
  let B;

  beforeAll(async () => {
    fx = await openPeers({ path: "/toolkit", count: 2 });
    [A, B] = fx.peers;
    // Both chunks, resolved from what the page actually loaded — see the notes
    // in `rtc-transport.e2e.js` and `stun-discovery.e2e.js` on why these are
    // strings and why the hashes are never hardcoded.
    for (const p of fx.peers) {
      await p.page.evaluate(LOAD_RTC_OPS);
      await p.page.evaluate(LOAD_QUORUM_OPS);
    }
  });

  afterAll(async () => {
    await fx?.close();
    RELAY?.stop();
  });

  /* ── the floor for this file: a relay candidate exists at all ── */

  describe("a relay candidate, with host and srflx forbidden", () => {
    /** @type {any} */
    let out;

    beforeAll(async () => {
      out = await A.page.evaluate(async (relay) => {
        const pc = new RTCPeerConnection({
          iceServers: [
            { urls: relay.url, username: relay.username, credential: relay.credential },
          ],
          // The mechanism: only relay candidates are considered.
          iceTransportPolicy: "relay",
        });
        const cands = [];
        const errors = [];
        pc.addEventListener("icecandidateerror", (e) =>
          errors.push({ code: e.errorCode, text: e.errorText, url: e.url })
        );
        pc.createDataChannel("probe");
        const done = new Promise((res) => {
          const t = setTimeout(res, 10000);
          pc.onicecandidate = (ev) => {
            if (!ev.candidate) {
              clearTimeout(t);
              res(undefined);
              return;
            }
            const c = ev.candidate;
            cands.push({
              type: c.type,
              address: c.address,
              port: c.port,
              protocol: c.protocol,
              related: c.relatedAddress,
            });
          };
        });
        await pc.setLocalDescription(await pc.createOffer());
        await done;
        const state = pc.iceGatheringState;
        pc.close();
        return { cands, errors, state };
      }, publicRelay());
    });

    it("gathers a relay candidate and nothing else", () => {
      // The acceptance check, stated plainly. Measured:
      // `relay 172.17.0.2:49170 udp` in ~75 ms.
      expect(out.errors, `coturn refused: ${JSON.stringify(out.errors)}`).toEqual([]);
      expect(out.cands.length).toBeGreaterThan(0);
      expect(out.cands.map((c) => c.type)).toEqual(out.cands.map(() => "relay"));
      expect(out.state).toBe("complete");
    });

    it("carries the relayed transport address the server allocated", () => {
      const r = out.cands[0];
      // The container's own address, and correct: a TURN client never sends to
      // a relayed address directly, it sends *through* the allocation. This is
      // why no relay port needs publishing — see `helpers/coturn.js`.
      expect(r.address).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
      expect(r.port).toBeGreaterThan(0);
      expect(r.protocol).toBe("udp");
      // A relay candidate's related address is the mapped address the
      // allocation was made from, never a `.local` mDNS name.
      expect(r.address).not.toMatch(/\.local/);
    });
  });

  /* ── the shipped template, end to end ── */

  describe("the ice-turn-relay template, with a relay actually behind it", () => {
    /** @type {any} */
    let out;

    beforeAll(async () => {
      // `rtc.ice turn=… username=… credential=@turncred | rtc.gather ice=@ice`
      // — the template's exact pipeline, through the shipped ops, with the
      // literal credential standing in for the input slot.
      out = await A.page.evaluate(async (relay) => {
        const emitted = window.__q.execRtcIce({
          turn: relay.url,
          username: relay.username,
          credential: relay.credential,
        });
        const servers = window.__q.parseIceConfig(emitted.data);
        const g = await window.__ops.execGatherCandidates(
          { ice: "@ice", timeout: 10000 },
          { resolveSlot: (ref) => (ref === "@ice" ? { type: "endpoint", data: emitted.data } : null) }
        );
        return { servers, sensitive: emitted.meta.sensitive, data: g.data };
      }, publicRelay());
    });

    it("gathers a relay candidate through rtc.ice and rtc.gather", () => {
      // The template is shipped and had never been verified end to end. It
      // works. Measured: `host ×1, srflx ×2, relay ×1`.
      expect(out.data.byType.relay).toBeGreaterThan(0);
      const relay = out.data.candidates.find((c) => c.type === "relay");
      expect(relay.protocol).toBe("udp");
      expect(relay.port).toBeGreaterThan(0);
      // `rtc.gather` does not force a transport policy, so the direct routes
      // are still gathered alongside — which is what the template's panel draws.
      expect(out.data.byType.host).toBeGreaterThan(0);
    });

    it("records the relay it reached, so nothing can report it as absent", () => {
      // This used to read `out.data.notes`, a prose row `rtc.gather` emitted.
      // e48f607 deleted that field -- nothing rendered it, and it was a second
      // spelling of what the candidate list already drew -- and replaced it
      // with `candidateAbsence`, which the panel consults *only* for a type
      // that gathered nothing. The test outlived the field by a commit and
      // could not say so: it needs Docker, and while Docker was down it was
      // skipped rather than failing. A skipped test reports nothing, including
      // its own staleness.
      expect(out.data.notes).toBeUndefined();

      // What carries the meaning now. The census is what lets a reader tell
      // "no TURN was configured" from "TURN was configured and stayed silent" --
      // the distinction the old note existed to make. Here a relay was asked
      // for and answered, so both halves must agree.
      expect(out.data.ice.turn).toBeGreaterThan(0);
      expect(out.data.byType.relay).toBeGreaterThan(0);
    });

    it("still marks the credential-bearing config sensitive", () => {
      expect(out.sensitive).toBe(true);
    });
  });

  /* ── parseIceConfig, against a server that answers ── */

  describe("parseIceConfig with real TURN input", () => {
    it("keeps several relays separable, and each one usable", async () => {
      // The comma-split regression, at the only level that could have caught
      // it: `stun-discovery.e2e.js` proves Chromium *accepts* the parse; this
      // proves the surviving server still allocates. A config whose `urls` held
      // `turn:a,turn:b` reached exactly here and died as "Invalid port".
      const r = await A.page.evaluate(async (relay) => {
        const emitted = window.__q.execRtcIce({
          turn: `${relay.url},turns:turn.example.net:5349`,
          username: relay.username,
          credential: relay.credential,
        });
        const servers = window.__q.parseIceConfig(emitted.data);
        const g = await window.__ops.execGatherCandidates(
          { ice: "@ice", timeout: 10000 },
          { resolveSlot: (ref) => (ref === "@ice" ? { type: "endpoint", data: emitted.data } : null) }
        );
        return { servers, byType: g.data.byType };
      }, publicRelay());

      // Two defaults plus two relays, each its own server, no commas anywhere.
      expect(r.servers).toHaveLength(4);
      for (const s of r.servers) {
        const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
        for (const u of urls) expect(u).not.toContain(",");
      }
      // And the live one still relayed, undisturbed by the dead one beside it.
      expect(r.byType.relay).toBeGreaterThan(0);
    });

    it("refuses a TURN URL with no credential, where the relay would 401", async () => {
      const r = await A.page.evaluate((relay) => {
        try {
          window.__q.execRtcIce({ turn: relay.url });
          return { threw: false, message: "" };
        } catch (e) {
          return { threw: true, message: String(e.message) };
        }
      }, publicRelay());
      // Refused in the step that wrote it, rather than as a silent absence of
      // relay candidates a page later — which is what the next test shows the
      // browser does with a credential the relay rejects.
      expect(r.threw).toBe(true);
      expect(r.message).toMatch(/rtc\.ice: TURN needs username= and credential=/);
    });
  });

  describe("a credential the relay refuses", () => {
    /** @type {any} */
    let out;

    beforeAll(async () => {
      out = await A.page.evaluate(async (relay) => {
        const pc = new RTCPeerConnection({
          iceServers: [
            { urls: relay.url, username: relay.username, credential: "not-the-password" },
          ],
          iceTransportPolicy: "relay",
        });
        const cands = [];
        const errors = [];
        pc.addEventListener("icecandidateerror", (e) =>
          errors.push({ code: e.errorCode, text: e.errorText, url: e.url })
        );
        pc.createDataChannel("probe");
        const done = new Promise((res) => {
          const t = setTimeout(res, 10000);
          pc.onicecandidate = (ev) => {
            if (!ev.candidate) {
              clearTimeout(t);
              res(undefined);
              return;
            }
            cands.push(ev.candidate.type);
          };
        });
        await pc.setLocalDescription(await pc.createOffer());
        await done;
        pc.close();
        return { cands, errors };
      }, publicRelay());
    });

    it("yields no relay candidate at all", () => {
      // This is the failure mode worth naming: a wrong password and a dead
      // relay are the same empty candidate list. The two are told apart only by
      // `icecandidateerror`, which nothing in the app currently reads.
      expect(out.cands).toEqual([]);
    });

    it("is a 401 on the wire, and only the error event says so", () => {
      expect(out.errors.length).toBeGreaterThan(0);
      expect(out.errors[0].code).toBe(401);
      expect(out.errors[0].url).toContain("turn:127.0.0.1:");
    });
  });

  describe("turns: and turn: are not the same request", () => {
    it("sends turns: over TLS, which a plaintext relay cannot answer", async () => {
      // The live half of the `turns:` vs `turn:` question. A self-signed cert
      // would be refused by Chromium regardless, so what is asserted is that
      // the scheme changes the request rather than being cosmetic: `turn:`
      // leaves as `?transport=udp` and allocates, `turns:` leaves as
      // `?transport=tcp` and gets nowhere against a relay with no TLS.
      const out = await A.page.evaluate(async (relay) => {
        const pc = new RTCPeerConnection({
          iceServers: [
            {
              urls: relay.url.replace(/^turn:/, "turns:"),
              username: relay.username,
              credential: relay.credential,
            },
          ],
          iceTransportPolicy: "relay",
        });
        const cands = [];
        const errors = [];
        pc.addEventListener("icecandidateerror", (e) =>
          errors.push({ code: e.errorCode, text: e.errorText, url: e.url })
        );
        pc.createDataChannel("probe");
        const done = new Promise((res) => {
          const t = setTimeout(res, 12000);
          pc.onicecandidate = (ev) => {
            if (!ev.candidate) {
              clearTimeout(t);
              res(undefined);
              return;
            }
            cands.push(ev.candidate.type);
          };
        });
        await pc.setLocalDescription(await pc.createOffer());
        await done;
        pc.close();
        return { cands, errors };
      }, publicRelay());

      expect(out.cands).toEqual([]);
      expect(out.errors.length).toBeGreaterThan(0);
      expect(out.errors[0].url).toMatch(/^turns:/);
      // Measured: code 701, "Failed to establish connection".
      expect(out.errors[0].url).toContain("transport=tcp");
    });
  });

  /* ── the whole point: a connection that can only be a relay ── */

  describe("a relay-only connection between two browser contexts", () => {
    /** @type {any} */
    let result;

    beforeAll(async () => {
      const arm = (p, role) =>
        p.page.evaluate(
          ([relay, r]) => {
            const pc = new RTCPeerConnection({
              iceServers: [
                { urls: relay.url, username: relay.username, credential: relay.credential },
              ],
              // Without this the two contexts would find each other over host
              // candidates on the loopback interface in milliseconds and the
              // relay would never be touched — which is precisely how a broken
              // relay path stays invisible.
              iceTransportPolicy: "relay",
            });
            window.__pc = pc;
            window.__out = [];
            window.__recv = [];
            window.__types = [];
            window.__errs = [];
            pc.addEventListener("icecandidateerror", (e) =>
              window.__errs.push({ code: e.errorCode, url: e.url })
            );
            pc.addEventListener("icecandidate", (e) => {
              if (!e.candidate) return;
              window.__types.push(e.candidate.type);
              window.__out.push({ t: "ice", c: e.candidate.toJSON() });
            });
            pc.onnegotiationneeded = async () => {
              await pc.setLocalDescription();
              window.__out.push({ t: "offer", sdp: pc.localDescription.sdp });
            };
            const wire = (ch) => {
              window.__ch = ch;
              ch.addEventListener("message", (e) => window.__recv.push(e.data));
            };
            if (r === "offerer") wire(pc.createDataChannel("probe"));
            else pc.addEventListener("datachannel", (e) => wire(e.channel));
          },
          [publicRelay(), role]
        );

      await arm(A, "offerer");
      await arm(B, "answerer");

      // The signalling channel stood in for, exactly as in `rtc-transport.e2e.js`.
      const drain = async (from, to) => {
        const msgs = await from.page.evaluate(() => window.__out.splice(0));
        for (const m of msgs) {
          await to.page.evaluate(async (msg) => {
            const pc = window.__pc;
            if (msg.t === "ice") {
              try {
                await pc.addIceCandidate(msg.c);
              } catch {
                /* superseded generation */
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
          if (!(await drain(A, B)) && !(await drain(B, A))) {
            await new Promise((r) => setTimeout(r, 50));
          }
        }
      })();

      const both = async () => ({
        a: await A.page.evaluate(() => window.__pc.connectionState),
        b: await B.page.evaluate(() => window.__pc.connectionState),
      });
      await until(both, (v) => v.a === "connected" && v.b === "connected", {
        timeout: 45000,
        what: "relay-only connection",
      });

      await A.page.evaluate(() => window.__ch.send("ping-through-the-relay"));

      const selected = (p) =>
        p.page.evaluate(async () => {
          const rep = await window.__pc.getStats();
          const byId = new Map();
          rep.forEach((s) => byId.set(s.id, s));
          let pair = null;
          rep.forEach((s) => {
            if (s.type !== "candidate-pair" || !s.nominated) return;
            const local = byId.get(s.localCandidateId);
            const remote = byId.get(s.remoteCandidateId);
            pair = {
              state: s.state,
              localType: local?.candidateType,
              remoteType: remote?.candidateType,
              protocol: local?.protocol,
              relayProtocol: local?.relayProtocol,
              bytesSent: s.bytesSent,
              bytesReceived: s.bytesReceived,
            };
          });
          return { pair, types: window.__types, errs: window.__errs, recv: window.__recv };
        });

      await until(
        () => selected(B),
        (v) => v.recv.length >= 1,
        { timeout: 15000, what: "message through the relay" }
      );
      result = { a: await selected(A), b: await selected(B) };
      pumping = false;
      await pump;
    });

    it("nominates a relay/relay pair, which is the whole assertion", () => {
      // Both ends, because a pair that is relay on one side and something else
      // on the other would mean the policy leaked.
      for (const side of [result.a, result.b]) {
        expect(side.pair).toBeTruthy();
        expect(side.pair.state).toBe("succeeded");
        expect(side.pair.localType).toBe("relay");
        expect(side.pair.remoteType).toBe("relay");
        expect(side.pair.protocol).toBe("udp");
        // How the *client* reached the relay, as opposed to how the relay
        // reached the peer. `turn:` with no `?transport=` is UDP.
        expect(side.pair.relayProtocol).toBe("udp");
      }
    });

    it("gathered only relay candidates on both sides", () => {
      expect(result.a.types).toEqual(result.a.types.map(() => "relay"));
      expect(result.b.types).toEqual(result.b.types.map(() => "relay"));
      expect(result.a.types.length).toBeGreaterThan(0);
      expect(result.a.errs).toEqual([]);
      expect(result.b.errs).toEqual([]);
    });

    it("carries real bytes through the relay, both ways", () => {
      // DTLS and SCTP setup alone is well over a kilobyte each way; a pair that
      // was nominated but never used would sit near zero. Measured ~2.2-2.4 kB.
      expect(result.a.pair.bytesSent).toBeGreaterThan(500);
      expect(result.a.pair.bytesReceived).toBeGreaterThan(500);
      expect(result.b.pair.bytesSent).toBeGreaterThan(500);
      expect(result.b.pair.bytesReceived).toBeGreaterThan(500);
    });

    it("delivers a data channel message across it", () => {
      expect(result.b.recv).toEqual(["ping-through-the-relay"]);
    });

    it("shows the relay doing the relaying, in coturn's own log", () => {
      // The far end of the same fact, from outside the browser: two
      // allocations, permissions, and a channel bound to a peer. If Chromium
      // ever reported a relay pair without one, this is what would catch it.
      const log = RELAY.logs();
      expect(log).toMatch(/ALLOCATE processed, success/);
      expect(log).toMatch(/CREATE_PERMISSION processed, success/);
      expect(log).toMatch(/CHANNEL_BIND processed, success/);
      expect(log).toContain(`realm <${RELAY.realm}>`);
      expect(log).toContain(`user <${RELAY.username}>`);
    });
  });

  /* ── the two-phase fallback, in a real engine ── */

  describe("escalating a live connection onto a relay, without rebuilding it", () => {
    /**
     * The claim `relay-fallback.js` is built on, measured rather than trusted.
     *
     * The unit suite proves the *code* calls `setConfiguration` and then
     * `restartIce`. What it cannot prove is that a browser honours the pair —
     * that a connection which gathered with no TURN in its list will gather a
     * relay candidate afterwards, on the same object, without being torn down
     * and rebuilt. Rebuilding is not a neutral alternative: a fresh
     * `RTCPeerConnection` mints a fresh DTLS certificate, and a quorum session
     * key is derived over a transcript that commits to the old fingerprint.
     *
     * The specs say it works. W3C webrtc-pc, "set the configuration" step 9:
     * a replaced ICE servers list takes effect at *the next gathering phase*,
     * and "if a script wants this to happen immediately, it should do an ICE
     * restart". RFC 8829 §4.1.18: changing the servers sets `needs-ice-restart`
     * so the next offer carries fresh credentials and starts that phase. This
     * is that sequence, run once, with the fingerprint compared across it.
     */
    /** @type {any} */
    let out;

    beforeAll(async () => {
      out = await A.page.evaluate(async (relay) => {
        const fingerprint = (sdp) => (sdp.match(/^a=fingerprint:(.+)$/m) || [])[1] || "";
        const gather = (pc, ms) =>
          new Promise((res) => {
            const seen = [];
            const t = setTimeout(() => res(seen), ms);
            pc.onicecandidate = (ev) => {
              if (!ev.candidate) {
                clearTimeout(t);
                res(seen);
                return;
              }
              seen.push(ev.candidate.type);
            };
          });

        // Phase one: exactly what this app ships — STUN only, no relay, no
        // credential, nothing a relay operator could hear about.
        const pc = new RTCPeerConnection({
          iceServers: [{ urls: `stun:127.0.0.1:${relay.port}` }],
        });
        pc.createDataChannel("probe");
        let candidates = gather(pc, 8000);
        await pc.setLocalDescription(await pc.createOffer());
        const first = await candidates;
        const firstPrint = fingerprint(pc.localDescription.sdp);
        const firstUfrag = (pc.localDescription.sdp.match(/^a=ice-ufrag:(.+)$/m) || [])[1];

        // Phase two: the two calls, in order, on the connection that already
        // exists. No close, no replacement.
        candidates = gather(pc, 8000);
        const before = pc.getConfiguration();
        pc.setConfiguration({
          ...before,
          iceServers: [
            { urls: `stun:127.0.0.1:${relay.port}` },
            { urls: relay.url, username: relay.username, credential: relay.credential },
          ],
        });
        pc.restartIce();
        await pc.setLocalDescription(await pc.createOffer({ iceRestart: true }));
        const second = await candidates;
        const secondPrint = fingerprint(pc.localDescription.sdp);
        const secondUfrag = (pc.localDescription.sdp.match(/^a=ice-ufrag:(.+)$/m) || [])[1];

        pc.close();
        return { first, second, firstPrint, secondPrint, firstUfrag, secondUfrag };
      }, publicRelay());
    });

    it("gathers no relay candidate in the first phase", () => {
      // The property the whole arrangement exists for. Not "a relay was low
      // priority" — no allocation happened, so coturn was never asked.
      expect(out.first.length).toBeGreaterThan(0);
      expect(out.first).not.toContain("relay");
    });

    it("gathers one in the second, after setConfiguration and restartIce", () => {
      expect(out.second).toContain("relay");
    });

    it("kept the connection, and with it the DTLS certificate", () => {
      // The reason this is an escalation rather than a reconnection. A rebuilt
      // connection would show a different fingerprint here, and a quorum
      // transcript that committed to the old one would no longer describe the
      // transport — which is the exact substitution `quorum-dtls-binding`
      // proves is caught.
      expect(out.firstPrint).toBeTruthy();
      expect(out.secondPrint).toBe(out.firstPrint);
      // ICE credentials, by contrast, *must* differ: that is what makes it a
      // restart rather than a re-offer.
      expect(out.secondUfrag).not.toBe(out.firstUfrag);
    });
  });

  /* ── what the diagnostics say ── */

  describe("stun.check, pointed at a relay that does answer STUN", () => {
    /** @type {any} */
    let out;

    beforeAll(async () => {
      // coturn answers STUN Binding on the same port, so this is also the
      // first *deterministic, offline* reflexive address in the suite —
      // `stun-discovery.e2e.js` can only get one from the public internet and
      // has to classify a miss as a skip.
      const r = await A.page.evaluate(
        (port) => window.__q.execStunCheck({ server: `stun:127.0.0.1:${port}`, timeout: 6000 }),
        RELAY.port
      );
      out = r.data;
    });

    it("discovers a reflexive address with no public internet involved", () => {
      expect(out.ok).toBe(true);
      expect(out.publicAddress).toMatch(/^\d+\.\d+\.\d+\.\d+:\d+$/);
      expect(out.candidates.srflx).toBeGreaterThan(0);
      expect(out.note).toMatch(/STUN reachable/);
    });

    it("reports no relay even though this very server is relaying", () => {
      // **A defect in the read-out, pinned.** `stun.check` validates its
      // `server=` as `stun:`/`stuns:` and builds
      // `new RTCPeerConnection({ iceServers: [{ urls: server }] })` — with no
      // username and no credential, and no parameter that could supply one. It
      // is therefore structurally incapable of producing a relay candidate, and
      // its `relay` count is a constant, not a measurement.
      //
      // The same server allocates relays for the connection above, so this is
      // as favourable a case as the op will ever see, and it still reports
      // none. The panel used to draw that constant beside the two real counts
      // as `RELAY ×0`, which reads as "TURN was checked and is missing" on the
      // one screen a user lands on when a connection fails. `NetworkArtifact`
      // now says the row was not probed and names the op that does probe it.
      expect(out.candidates.relay).toBeUndefined();
      expect(out.candidates.host).toBeGreaterThan(0);
    });
  });

  it("relays without tripping the production CSP", async () => {
    // Pinned for STUN already; measured again here because relay traffic is a
    // different question — an allocation is a long-lived flow to a third-party
    // host under a `connect-src` of `'self'` plus two keyservers. No CSP
    // directive governs ICE in Chromium; `webrtc-src` was proposed and never
    // shipped. Zero violations, and no exemption of any kind was added for it.
    expect(await A.cspViolations()).toEqual([]);
    expect(await B.cspViolations()).toEqual([]);
    for (const p of [A, B]) {
      expect(p.pageErrors().filter((e) => /Content Security Policy/i.test(e))).toEqual([]);
    }
  });
});

/* ── in-page chunk loaders (see the sibling suites for why these are strings) ── */

const LOAD_RTC_OPS = `(async () => {
  const url = performance
    .getEntriesByType("resource")
    .map((x) => new URL(x.name).pathname)
    .find((n) => /\\/assets\\/rtc-ops-[^/]*\\.js$/.test(n));
  if (!url) throw new Error("the toolkit page did not load an rtc-ops chunk");
  window.__ops = await import(url);
  return url;
})()`;

const LOAD_QUORUM_OPS = `(async () => {
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
  const isOps = (o) =>
    o && typeof o.execStunCheck === "function" && typeof o.execRtcIce === "function";
  window.__q = isOps(mod) ? mod : Object.values(mod).find(isOps);
  if (!window.__q) {
    throw new Error("quorum-ops chunk exposes no ops namespace: " + Object.keys(mod).join(","));
  }
  return "/assets/" + name;
})()`;

/** The relay's coordinates, in a shape `page.evaluate` can serialize. */
function publicRelay() {
  return {
    url: RELAY.url,
    username: RELAY.username,
    credential: RELAY.credential,
    // coturn answers STUN Binding on the same port, so a phase-one list can be
    // built from it without reaching the public internet.
    port: RELAY.port,
  };
}

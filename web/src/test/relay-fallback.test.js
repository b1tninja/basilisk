/**
 * "Fallback" has to mean *contacted only when needed*, not *last in priority*.
 *
 * ICE's own fallback is the second thing. A TURN server in `iceServers` is
 * allocated on during **gathering** — before any connectivity check has
 * succeeded or failed — so a relay listed as a fallback learns this machine's
 * address, and that a connection is happening, on every call including the
 * large majority that never relay a byte. That is the defect this suite exists
 * to catch, and it is invisible from the outside: the connection still works,
 * the relay is still last in priority, and nothing on screen changes.
 *
 * Four claims are pinned, and they are different claims:
 *
 *  1. **Phase one contacts no relay.** The list the connection is built from
 *     carries no `turn:` entry, whatever was configured, and no credential is
 *     requested while it is working.
 *  2. **Escalation happens on `failed` and only on `failed`.** Every state a
 *     connection can be in is enumerated, `disconnected` included — the
 *     transient one, which recovers on its own and must not summon a relay.
 *  3. **`setConfiguration` + `restartIce`, and both.** Read from the specs
 *     rather than assumed: W3C webrtc-pc "set the configuration" step 9 says a
 *     replaced ICE servers list takes effect at *the next gathering phase* and
 *     that a script wanting it sooner "should do an ICE restart"; RFC 8829
 *     §4.1.18 says changing the servers sets the `needs-ice-restart` bit. So
 *     either call alone is a no-op in the direction that matters, and the
 *     connection object survives — which is what makes rebuilding unnecessary,
 *     and for a quorum link actively wrong, since a new connection mints a new
 *     DTLS certificate the key transcript no longer commits to.
 *  4. **Once, then honestly.** One escalation per link; a second failure is
 *     reported as the end of the road rather than retried.
 *
 * A fake connection, not a browser: the thing under test is *when* a relay is
 * reached for, which is a scheduling claim, and `turn-relay.e2e.js` already
 * drives a real relay against a real Chromium when Docker is there.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  RELAY_DISCLOSURE,
  RELAY_OFF,
  RelayFallback,
  __resetRelayFallback,
  applyRelayServers,
  armRelayFallback,
  configureRelayFallback,
  firstPhaseServers,
  relayCarriedTraffic,
  relayFallbackDecision,
  relayFallbackSettings,
  withRelayServers,
} from "../lib/webrtc/relay-fallback.js";
import { DEFAULT_ICE_SERVERS, iceServerCensus } from "../lib/webrtc/ice.js";
import {
  __resetLinks,
  closeLink,
  getLink,
  linkRow,
  registerLink,
} from "../lib/webrtc/link-registry.js";

const RELAY = [
  { urls: ["turn:turn.example:3478?transport=udp"], username: "u", credential: "c" },
];

/**
 * Enough `RTCPeerConnection` to be escalated: the two state machines, the two
 * methods the spec says are needed, and a record of what was called in which
 * order.
 */
class StubConnection {
  /** @param {RTCIceServer[]} iceServers */
  constructor(iceServers = []) {
    this.configuration = { iceServers, bundlePolicy: "max-bundle", iceCandidatePoolSize: 0 };
    this.connectionState = "new";
    this.iceConnectionState = "new";
    /** @type {string[]} */
    this.calls = [];
    /** @type {Record<string, Function[]>} */
    this._listeners = {};
  }

  addEventListener(type, fn) {
    (this._listeners[type] ||= []).push(fn);
  }

  removeEventListener(type, fn) {
    this._listeners[type] = (this._listeners[type] || []).filter((f) => f !== fn);
  }

  getConfiguration() {
    return { ...this.configuration };
  }

  setConfiguration(next) {
    this.calls.push("setConfiguration");
    this.configuration = { ...next };
  }

  restartIce() {
    this.calls.push("restartIce");
    this.restarts = (this.restarts || 0) + 1;
  }

  /** Drive both state machines and fire the events a browser would. */
  async reach(connectionState, iceConnectionState = connectionState) {
    this.connectionState = connectionState;
    this.iceConnectionState = iceConnectionState;
    for (const fn of this._listeners.connectionstatechange || []) fn({});
    for (const fn of this._listeners.iceconnectionstatechange || []) fn({});
    // The supervisor's handler is async; two turns is enough for a fetch that
    // resolves immediately plus the apply that follows it.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  }
}

beforeEach(() => {
  __resetRelayFallback();
  __resetLinks();
});

afterEach(() => {
  __resetRelayFallback();
  __resetLinks();
});

/* ─────────────────── 1. phase one gathers no relay ─────────────────── */

describe("phase one is relay-free by construction", () => {
  it("strips a relay out of the list a connection starts from", () => {
    const asked = [
      { urls: "stun:stun.example:3478" },
      { urls: "turn:relay.example:3478", username: "u", credential: "c" },
    ];
    const { servers, removed } = firstPhaseServers(asked);
    expect(removed).toBe(1);
    // The assertion that matters is on the census, because that is what the
    // panel and `rtc.gather` read: zero TURN means zero allocations, which
    // means the relay operator has heard nothing.
    expect(iceServerCensus(servers)).toEqual({ stun: 1, turn: 0, total: 1 });
  });

  it("keeps the other URLs of a server that also lists a relay", () => {
    const { servers } = firstPhaseServers([
      { urls: ["stun:a.example:3478", "turns:a.example:5349"], username: "u", credential: "c" },
    ]);
    expect(servers).toEqual([
      { urls: ["stun:a.example:3478"], username: "u", credential: "c" },
    ]);
  });

  it("leaves a relay-free list exactly as it was, defaults included", () => {
    expect(firstPhaseServers(DEFAULT_ICE_SERVERS).servers).toEqual([...DEFAULT_ICE_SERVERS]);
    expect(firstPhaseServers(DEFAULT_ICE_SERVERS).removed).toBe(0);
    // Declining every third party stays declined — the fallback adds nothing
    // to a list somebody deliberately emptied.
    expect(firstPhaseServers([]).servers).toEqual([]);
  });

  it("does not mutate the shared default list while stripping", () => {
    const frozen = Object.freeze([
      Object.freeze({ urls: Object.freeze(["stun:a:3478", "turn:a:3478"]) }),
    ]);
    expect(() => firstPhaseServers(frozen)).not.toThrow();
    expect(frozen[0].urls).toEqual(["stun:a:3478", "turn:a:3478"]);
  });

  it("asks for no credential while the connection is working", async () => {
    const source = vi.fn(async () => ({ iceServers: RELAY }));
    configureRelayFallback({ enabled: true, source });
    const pc = new StubConnection(DEFAULT_ICE_SERVERS);
    const fallback = new RelayFallback(pc);

    for (const state of ["connecting", "connected", "disconnected", "connected"]) {
      await pc.reach(state, state === "connected" ? "completed" : state);
    }
    // The whole promise of the two phases, in one assertion: a connection that
    // works never causes a request to anybody about a relay.
    expect(source).not.toHaveBeenCalled();
    expect(pc.calls).toEqual([]);
    expect(fallback.status().phase).toBe("armed");
  });
});

/* ──────────── 2. escalation on `failed`, and only on `failed` ──────────── */

describe("the escalation rule, over every state a connection can be in", () => {
  const CONNECTION_STATES = [
    "new",
    "connecting",
    "connected",
    "disconnected",
    "failed",
    "closed",
  ];
  const ICE_STATES = [
    "new",
    "checking",
    "connected",
    "completed",
    "disconnected",
    "failed",
    "closed",
  ];

  it("holds for everything that is not failure", () => {
    for (const connectionState of CONNECTION_STATES) {
      for (const iceConnectionState of ICE_STATES) {
        const failed = connectionState === "failed" || iceConnectionState === "failed";
        expect(
          relayFallbackDecision({ connectionState, iceConnectionState, escalated: false }),
          `${connectionState}/${iceConnectionState}`
        ).toBe(failed ? "escalate" : "hold");
      }
    }
  });

  it("treats disconnected as transient, which is what it is", () => {
    // Named separately because it is the one that would be wrong in the
    // expensive direction: ICE recovers from `disconnected` routinely, and
    // escalating there would summon a relay for connections about to work.
    expect(
      relayFallbackDecision({
        connectionState: "disconnected",
        iceConnectionState: "disconnected",
      })
    ).toBe("hold");
  });

  it("watches both state machines, because they can disagree", () => {
    // Chromium aggregates ICE and DTLS into `connectionState`; an engine can
    // sit in `connecting` while ICE has already given up. Watching only the
    // aggregate would wait out the whole timeout before noticing.
    expect(
      relayFallbackDecision({ connectionState: "connecting", iceConnectionState: "failed" })
    ).toBe("escalate");
  });

  it("never escalates twice", () => {
    expect(
      relayFallbackDecision({ connectionState: "failed", escalated: true })
    ).toBe("exhausted");
  });
});

describe("the supervisor acts on the rule", () => {
  it("escalates on failure, once, and reports the end of the road", async () => {
    const source = vi.fn(async () => ({ iceServers: RELAY }));
    configureRelayFallback({ enabled: true, source });
    const pc = new StubConnection([{ urls: "stun:stun.example:3478" }]);
    const fallback = new RelayFallback(pc);

    await pc.reach("disconnected");
    expect(source).not.toHaveBeenCalled();

    await pc.reach("failed");
    expect(source).toHaveBeenCalledTimes(1);
    expect(fallback.status().phase).toBe("escalated");
    expect(iceServerCensus(pc.getConfiguration().iceServers).turn).toBe(1);

    // A second failure — and every failure after it — costs the relay operator
    // nothing, because there is nothing left to try.
    await pc.reach("failed");
    await pc.reach("failed");
    expect(source).toHaveBeenCalledTimes(1);
    expect(pc.restarts).toBe(1);
    expect(fallback.status().phase).toBe("exhausted");
  });

  it("does nothing at all when the user has not turned it on", async () => {
    const source = vi.fn(async () => ({ iceServers: RELAY }));
    // A deployment that has a relay to offer, and a user who has not asked for
    // one. The credential source exists and is never called.
    configureRelayFallback({ enabled: false, source });
    expect(armRelayFallback(new StubConnection())).toBeNull();

    const pc = new StubConnection();
    const fallback = new RelayFallback(pc);
    await pc.reach("failed");
    expect(source).not.toHaveBeenCalled();
    expect(fallback.status()).toEqual(RELAY_OFF);
  });

  it("is off with no source, so consent alone cannot summon a relay", () => {
    configureRelayFallback({ enabled: true, source: null });
    expect(relayFallbackSettings().source).toBeNull();
    expect(armRelayFallback(new StubConnection())).toBeNull();
  });

  it("reports a refused credential as no relay, not as a failure", async () => {
    configureRelayFallback({
      enabled: true,
      // What a deployment with no relay configured answers: 503.
      source: async () => {
        throw Object.assign(new Error("TURN relay is not configured"), { status: 503 });
      },
    });
    const pc = new StubConnection();
    const fallback = new RelayFallback(pc);
    await pc.reach("failed");
    expect(fallback.status().phase).toBe("unavailable");
    expect(fallback.status().reason).toMatch(/not configured/);
    expect(pc.calls).toEqual([]);
  });

  it("refuses a grant with no relay in it", async () => {
    // STUN-only would arm the fallback with servers that cannot carry a byte,
    // and the next failure would read as "the relay did not help".
    configureRelayFallback({
      enabled: true,
      source: async () => ({ iceServers: [{ urls: "stun:stun.example:3478" }] }),
    });
    const pc = new StubConnection();
    const fallback = new RelayFallback(pc);
    await pc.reach("failed");
    expect(fallback.status().phase).toBe("unavailable");
    expect(pc.calls).toEqual([]);
  });

  it("stops watching when told to", async () => {
    const source = vi.fn(async () => ({ iceServers: RELAY }));
    configureRelayFallback({ enabled: true, source });
    const pc = new StubConnection();
    const fallback = new RelayFallback(pc);
    fallback.stop();
    await pc.reach("failed");
    expect(source).not.toHaveBeenCalled();
  });
});

/* ───────────── 3. setConfiguration + restartIce, per the specs ───────────── */

describe("how the relay is put in front of a live connection", () => {
  it("changes the servers and then restarts ICE, in that order", () => {
    const pc = new StubConnection([{ urls: "stun:stun.example:3478" }]);
    expect(applyRelayServers(pc, pc.getConfiguration().iceServers, RELAY)).toBe(true);
    // The order is the spec's: a restart before the new list is set would
    // re-gather from the list that already failed.
    expect(pc.calls).toEqual(["setConfiguration", "restartIce"]);
    expect(iceServerCensus(pc.getConfiguration().iceServers)).toEqual({
      stun: 1,
      turn: 1,
      total: 2,
    });
  });

  it("hands back the fields that may not change on a live connection", () => {
    // `bundlePolicy`, `rtcpMuxPolicy` and — once a local description exists —
    // `iceCandidatePoolSize` throw InvalidModificationError if they differ.
    // A bare `{ iceServers }` asks the browser to reset them to their defaults.
    const pc = new StubConnection([]);
    pc.configuration.bundlePolicy = "max-compat";
    applyRelayServers(pc, [], RELAY);
    expect(pc.getConfiguration().bundlePolicy).toBe("max-compat");
    expect(pc.getConfiguration().iceCandidatePoolSize).toBe(0);
  });

  it("keeps the connection object, which is why rebuilding is not needed", () => {
    const pc = new StubConnection([]);
    applyRelayServers(pc, [], RELAY);
    // No close, no replacement: the DTLS certificate, the data channel and —
    // for a quorum link — the session key derived over both fingerprints all
    // survive. A fresh RTCPeerConnection would mint a new certificate and the
    // transcript would no longer describe the transport.
    expect(pc.calls).not.toContain("close");
    expect(pc.restarts).toBe(1);
  });

  it("declines rather than throws on an engine missing either half", () => {
    const noRestart = new StubConnection([]);
    // @ts-expect-error - deliberately removing the method
    noRestart.restartIce = undefined;
    expect(applyRelayServers(noRestart, [], RELAY)).toBe(false);

    const noConfig = new StubConnection([]);
    // @ts-expect-error - deliberately removing the method
    noConfig.setConfiguration = undefined;
    expect(applyRelayServers(noConfig, [], RELAY)).toBe(false);

    expect(applyRelayServers(null, [], RELAY)).toBe(false);
    // Nothing to add is not an escalation.
    expect(applyRelayServers(new StubConnection([]), [], [])).toBe(false);
  });

  it("puts the relay last and never lists a server twice", () => {
    const merged = withRelayServers(
      [{ urls: "stun:stun.example:3478" }],
      [{ urls: ["stun:stun.example:3478", "turn:relay.example:3478"] }]
    );
    expect(merged).toEqual([
      { urls: "stun:stun.example:3478" },
      { urls: ["turn:relay.example:3478"] },
    ]);
  });
});

/* ─────────────── 4. what the inventory and the copy report ─────────────── */

describe("the inventory reports the relay honestly", () => {
  const holder = (pc) => ({ pc, channel: null });

  it("says off when no relay will ever be contacted", () => {
    const pc = new StubConnection(DEFAULT_ICE_SERVERS);
    registerLink({ id: "a", origin: "peer", role: "offerer", holder: holder(pc) });
    expect(getLink("a").relay).toBeNull();
    const row = linkRow(getLink("a"));
    expect(row.relay).toEqual(RELAY_OFF);
    expect(row.relayed).toBe(false);
  });

  it("separates configured, escalated and actually carried the traffic", async () => {
    configureRelayFallback({ enabled: true, source: async () => ({ iceServers: RELAY }) });
    const pc = new StubConnection([{ urls: "stun:stun.example:3478" }]);
    const rec = registerLink({
      id: "b",
      origin: "peer",
      role: "offerer",
      holder: holder(pc),
      iceServers: [{ urls: "stun:stun.example:3478" }],
    });
    expect(linkRow(rec).relay.phase).toBe("armed");
    expect(linkRow(rec).relay.configured).toBe(false);

    await pc.reach("failed");
    const escalated = linkRow(rec);
    expect(escalated.relay.phase).toBe("escalated");
    expect(escalated.relay.configured).toBe(true);
    // Escalated is not relayed. ICE may still nominate a reflexive pair on the
    // restart, in which case the relay allocated and forwarded nothing —
    // drawing that as "relayed" would overstate what a third party saw.
    expect(escalated.relayed).toBe(false);

    rec.via = "relay";
    expect(linkRow(rec).relayed).toBe(true);
    expect(relayCarriedTraffic({ via: "srflx" })).toBe(false);
  });

  it("stops supervising a link that is closed", async () => {
    const source = vi.fn(async () => ({ iceServers: RELAY }));
    configureRelayFallback({ enabled: true, source });
    const pc = new StubConnection([]);
    pc.close = () => {};
    registerLink({ id: "c", origin: "peer", role: "offerer", holder: holder(pc) });
    closeLink("c");
    await pc.reach("failed");
    expect(source).not.toHaveBeenCalled();
  });
});

describe("what the disclosure claims", () => {
  it("gets the one distinction that matters exactly right", () => {
    // Overstating it in either direction is a defect. Understated, a user waves
    // through a third party that sees who they talk to and when. Overstated
    // ("the relay can read your messages"), a user refuses a relay that
    // genuinely cannot, and loses the connection for nothing.
    expect(RELAY_DISCLOSURE.readsTraffic).toBe(false);
    expect(RELAY_DISCLOSURE.seesAddresses).toBe(true);
    const summary = RELAY_DISCLOSURE.summary.toLowerCase();
    expect(summary).toContain("cannot read");
    expect(summary).toContain("dtls");
    expect(summary).toContain("end-to-end");
    expect(summary).toContain("ip address");
    expect(RELAY_DISCLOSURE.canSee.join(" ")).toMatch(/ip address/i);
    expect(RELAY_DISCLOSURE.cannotSee.join(" ")).toMatch(/contents/i);
  });

  it("cannot be edited by a consumer", () => {
    expect(Object.isFrozen(RELAY_DISCLOSURE)).toBe(true);
    expect(Object.isFrozen(RELAY_OFF)).toBe(true);
  });
});

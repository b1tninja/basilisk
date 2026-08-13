/**
 * The quorum **session manager** — the half of the seam `redesign/HANDOFF.md`
 * puts opposite the transport ("`quorum.*` is the session manager; `rtc.*` is
 * the transport"). Nothing here had ever been exercised: the four existing
 * `quorum-*.test.js` files cover `room`, `roster`, `relay` and the negotiation
 * rules, all of which are pure, and none of them touch `quorum-ops.js`.
 *
 * The transport is stubbed rather than mocked *around* — `NotebookSession` is
 * replaced with a fake whose roster and chat callbacks the test drives by hand,
 * so `execQuorumOpen`, `execQuorumRecv`, `closeQuorumExchange`, `restartLiveIce`
 * and the state projection all run their real bodies. What is asserted is the
 * manager's behaviour at the seam, which is exactly where the defects were.
 *
 * The network-facing half of this surface (`stun.check` against a real STUN
 * server) cannot run here — `environment: "node"` has no `RTCPeerConnection` —
 * so what is pinned in node is the *parameter* handling that decides whether a
 * request is well-formed before it reaches an engine at all. That split is
 * deliberate: a test that needed the public internet to say anything would be
 * a flake, and one that stubbed `RTCPeerConnection` would only ever prove the
 * stub agrees with itself.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const FPR_A = "A1".repeat(20); // sorts first — the local key throughout
const FPR_B = "B2".repeat(20);
const FPR_C = "C3".repeat(20);

/**
 * A `NotebookSession` with the shape `quorum-ops` actually consumes: a `peers`
 * **Map**, the callbacks (chat, offer, result and the rest), and
 * `start`/`stop`/`sendChat*`. The Map is the
 * load-bearing detail — `restartLiveIce` read it as an array of peers.
 */
const { FakeSession } = vi.hoisted(() => {
  class FakeSession {
    /** @type {FakeSession[]} */
    static instances = [];
    /** Runs inside `start()`, after `current` is set. */
    static onStart = null;

    constructor(opts) {
      this.opts = opts;
      this.roomId = opts.roomId;
      this.audienceFprs = opts.audienceFprs;
      this.myFpr = opts.myFingerprint;
      this.role = opts.role;
      this.iceServers = opts.iceServers;
      this.peers = new Map();
      this.started = 0;
      this.stopped = 0;
      this.sent = [];
      FakeSession.instances.push(this);
    }

    async start() {
      this.started += 1;
      await FakeSession.onStart?.(this);
    }
    stop() {
      this.stopped += 1;
    }
    async sendChat(text) {
      this.sent.push({ to: "", text });
    }
    async sendChatTo(to, text) {
      this.sent.push({ to, text });
    }

    /* ── drivers ── */

    /** Bring a peer up (optionally with a `link` that can restart ICE). */
    connect(fpr, extra = {}) {
      this.peers.set(fpr, {
        fingerprint: fpr,
        status: "connected",
        pgpVerified: true,
        kcVerified: true,
        link: null,
        channel: null,
        ...extra,
      });
      this.opts.onRoster?.(this.peers);
    }
    /**
     * Follow the room somewhere else, the way `_applyRotation` finishes.
     *
     * A driver rather than a call into `rotateQuorumRoom`, and that is the
     * point: this is the rotation a member is *told* about, which is every
     * member except the one that pressed Remove. The real session reaches this
     * same callback down both paths.
     */
    rotate(removeFpr, { epoch = 1, roomId = "ROTATEDROOMID" } = {}) {
      this.audienceFprs = this.audienceFprs.filter((f) => f !== removeFpr);
      this.peers.delete(removeFpr);
      this.roomId = roomId;
      this.opts.onRotate?.({
        epoch,
        roomId,
        audience: [...this.audienceFprs],
        removed: [removeFpr],
      });
    }
    /** Drop a peer the way a mid-session close looks to the roster. */
    drop(fpr, status = "failed") {
      const p = this.peers.get(fpr);
      if (p) Object.assign(p, { status, kcVerified: false });
      this.opts.onRoster?.(this.peers);
    }
    chat(from, text) {
      this.opts.onChat?.({ from, text, ts: 1700000000000 });
    }
    status(s) {
      this.opts.onStatus?.(s);
    }
    /** What the real session reports when an invite arrives signed by our key. */
    ownKeyElsewhere() {
      this.opts.onOwnKeyElsewhere?.();
    }
  }
  return { FakeSession };
});

vi.mock("../lib/notebook/session.js", async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, NotebookSession: FakeSession };
});

/**
 * `quorum-ops` talks to the shell over `window` events and nothing else, and
 * it decides once at module load whether there is a `window` to talk to. A
 * bare `EventTarget` is the whole contract — enough that `basilisk:quorum-state`
 * and `basilisk:quorum-cancel` are real, without pulling in a DOM.
 */
globalThis.window = /** @type {any} */ (new EventTarget());

const q = await import("../lib/toolkit/quorum-ops.js");
// The real list, from the WebRTC layer the mesh consumes — `rtc.ice`'s
// default is asserted against what ships rather than a copy, and the mock
// above cannot reach it.
const { DEFAULT_ICE_SERVERS } = await import("../lib/webrtc/ice.js");
const { deriveRoomId } = await import("../lib/notebook/room.js");

/** Enough of an OpenPGP private key for `execQuorumOpen`. */
const KEY_A = { getFingerprint: () => FPR_A.toLowerCase() };

/** `execQuorumOpen` gates on the constructor existing; it never calls it. */
class NoopPeerConnection {}

/** Every `basilisk:quorum-state` detail seen, in order. */
let events = [];
const onState = (ev) => events.push(ev.detail);

beforeEach(() => {
  globalThis.RTCPeerConnection = NoopPeerConnection;
  FakeSession.instances = [];
  FakeSession.onStart = (s) => s.connect(FPR_B);
  events = [];
  window.addEventListener("basilisk:quorum-state", onState);
});

afterEach(() => {
  window.removeEventListener("basilisk:quorum-state", onState);
  q.closeQuorumExchange("closed");
  FakeSession.onStart = null;
});

/** Open an exchange and hand back its fake session. */
async function open(params = {}, role = "creator") {
  const value = await q.execQuorumOpen(
    { to: `${FPR_A} ${FPR_B}`, ...params },
    KEY_A,
    null,
    role
  );
  return { value, session: FakeSession.instances.at(-1) };
}

/* ───────────────────────────── rtc.ice config ───────────────────────────── */

describe("rtc.ice emits a config a peer connection can actually take", () => {
  it("falls back to the shipped default list when stun= is empty", () => {
    const out = q.execRtcIce({});
    expect(out.type).toBe("endpoint");
    expect(out.data.iceServers.map((s) => s.urls)).toEqual(
      DEFAULT_ICE_SERVERS.flatMap((s) => (Array.isArray(s.urls) ? s.urls : [s.urls]))
    );
    expect(out.meta.sensitive).toBe(false);
  });

  it("splits several stun URLs into several servers", () => {
    const out = q.execRtcIce({ stun: "stun:a.example:3478, stun:b.example:3478" });
    expect(out.data.iceServers).toEqual([
      { urls: "stun:a.example:3478" },
      { urls: "stun:b.example:3478" },
    ]);
  });

  it("splits several turn URLs too, rather than shipping one unparseable server", () => {
    // Verified against Chromium 1234: a single `urls` holding two
    // comma-joined URLs throws `SyntaxError: … ICE server parsing failed:
    // Invalid port` at `new RTCPeerConnection`. Taken whole, this step emitted
    // exactly that config and the failure landed in `quorum.offer` instead.
    const out = q.execRtcIce({
      stun: "stun:a.example:3478",
      turn: "turn:r1.example:3478,turns:r2.example:5349",
      username: "u",
      credential: "c",
    });
    expect(out.data.iceServers).toEqual([
      { urls: "stun:a.example:3478" },
      { urls: "turn:r1.example:3478", username: "u", credential: "c" },
      { urls: "turns:r2.example:5349", username: "u", credential: "c" },
    ]);
  });

  it("never emits a urls string holding more than one URL", () => {
    // The general shape of the bug above, so a future `turns=` or `--relay`
    // cannot reintroduce it in a third place.
    for (const params of [
      { stun: "stun:a:3478 stun:b:3478" },
      { turn: "turn:a:3478 turn:b:3478", username: "u", credential: "c" },
      {},
    ]) {
      for (const s of q.execRtcIce(params).data.iceServers) {
        const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
        for (const u of urls) expect(u, JSON.stringify(params)).not.toContain(",");
      }
    }
  });

  it("refuses a URL that is not stun:/turns:", () => {
    expect(() => q.execRtcIce({ stun: "http://x" })).toThrow(/not a stun/);
    expect(() => q.execRtcIce({ stun: "", turn: "http://x", username: "u", credential: "c" }))
      .toThrow(/not a turn/);
    expect(() =>
      q.execRtcIce({ turn: "turn:a:3478,http://x", username: "u", credential: "c" })
    ).toThrow(/not a turn:\/turns: URL — http:\/\/x/);
  });

  it("refuses a TURN server with no credentials, before it reaches the engine", () => {
    expect(() => q.execRtcIce({ turn: "turn:relay.example:3478" })).toThrow(
      /needs username= and credential=/
    );
    expect(() =>
      q.execRtcIce({ turn: "turn:relay.example:3478", username: "u", credential: "" })
    ).toThrow(/needs username= and credential=/);
  });

  it("refuses an empty server list that was an accident", () => {
    // `stun=","` split to nothing and emitted `{ iceServers: [] }` — an
    // artifact that renders as an empty panel, constructs fine, gathers only
    // host candidates, and is then refused by `parseIceConfig` at the far end
    // of the pipeline. The complaint belongs at the step that wrote it, and it
    // now names the word to write if the empty list was the point.
    expect(() => q.execRtcIce({ stun: "," })).toThrow(/no ICE servers/);
    expect(() => q.execRtcIce({ stun: "," })).toThrow(/stun=none/);
  });

  it("emits an empty server list when the user asks for one", () => {
    // The whole point. `stun=` empty means *nobody said*, which the defaults
    // fill; `stun=none` means somebody said no. Before this word the second
    // was inexpressible — the only way to reach an empty list was to write
    // something that did not parse, and it was refused.
    const out = q.execRtcIce({ stun: "none" });
    expect(out.type).toBe("endpoint");
    expect(out.data.iceServers).toEqual([]);
    expect(out.meta.sensitive).toBe(false);
    // Case is not a second spelling to remember.
    expect(q.execRtcIce({ stun: "NONE" }).data.iceServers).toEqual([]);
    expect(q.execRtcIce({ stun: " none " }).data.iceServers).toEqual([]);
  });

  it("lets a chosen relay stand with no STUN beside it", () => {
    // `stun=none turn=…` is coherent: a relay you picked, and no reflexive
    // probe to anyone else. Refusing it would make "no third party" mean
    // "no third party except the one you cannot decline".
    const out = q.execRtcIce({
      stun: "none",
      turn: "turn:relay.example:3478",
      username: "u",
      credential: "c",
    });
    expect(out.data.iceServers).toEqual([
      { urls: "turn:relay.example:3478", username: "u", credential: "c" },
    ]);
  });

  it("still refuses a URL that is not a STUN URL, none or not", () => {
    // `none` is a word in the value, not a prefix that turns off validation.
    expect(() => q.execRtcIce({ stun: "none,stun:a.example:3478" })).toThrow(
      /not a stun/
    );
  });

  it("marks the config sensitive exactly when it carries a credential", () => {
    expect(q.execRtcIce({}).meta.sensitive).toBe(false);
    expect(
      q.execRtcIce({ turn: "turn:r:3478", username: "u", credential: "c" }).meta.sensitive
    ).toBe(true);
  });
});

describe("parseIceConfig blames the binding, not the parser", () => {
  const cfg = { v: 1, iceServers: [{ urls: "stun:a.example:3478" }] };

  it("accepts both the structured value and the legacy JSON text", () => {
    expect(q.parseIceConfig(cfg)).toHaveLength(1);
    expect(q.parseIceConfig(JSON.stringify(cfg))).toHaveLength(1);
  });

  it("round-trips what rtc.ice emits", () => {
    const out = q.execRtcIce({ stun: "stun:a.example:3478" });
    expect(q.parseIceConfig(out.data)).toEqual(out.data.iceServers);
  });

  it("says which parameter is wrong when the slot holds something else", () => {
    // Binding `ice=$passphrase` is how anyone gets here, and the raw
    // `SyntaxError: Unexpected token 'h', "hunter2" is not valid JSON` that
    // used to escape named neither `ice=` nor the step.
    for (const bad of ["hunter2", "", "-----BEGIN PGP MESSAGE-----"]) {
      expect(() => q.parseIceConfig(bad), JSON.stringify(bad)).toThrow(
        "ice=$slot does not hold rtc.ice output"
      );
    }
  });

  it("refuses well-formed JSON that is not an ICE config", () => {
    for (const bad of ['{"hello":1}', "[]", '{"iceServers":[]}']) {
      expect(() => q.parseIceConfig(bad), bad).toThrow(/does not hold rtc.ice output/);
    }
  });

  it("carries a deliberately empty list through instead of blaming it", () => {
    // An empty list used to be refused here as malformed, which is what made
    // `stun=none` unreachable from the other end of the pipeline: a user could
    // write the choice and the binding would reject it. It is accepted now —
    // but only from a value that declares itself an rtc.ice config, so
    // `ice=$somethingelse` still names the parameter rather than quietly
    // becoming "no third party".
    const none = q.execRtcIce({ stun: "none" });
    expect(q.parseIceConfig(none.data)).toEqual([]);
    expect(q.parseIceConfig(JSON.stringify(none.data))).toEqual([]);
  });
});

/* ───────────────────────── stun.check parameters ───────────────────────── */

describe("stun.check refuses a server it could never query", () => {
  it("names the step and the value, not the constructor", async () => {
    // Measured in Chromium 1234 before this guard: `http://example.com` came
    // back as `SyntaxError: Failed to construct 'RTCPeerConnection': …` and
    // `turn:relay:3478` as `InvalidAccessError: … Both username and credential
    // are required`, neither of which mentions `stun.check` or `server=`.
    for (const server of ["http://example.com", "turn:relay.example:3478", "example.com:3478"]) {
      await expect(q.execStunCheck({ server }), server).rejects.toThrow(
        /^stun\.check: not a stun:\/stuns: URL/
      );
    }
  });

  it("takes the default when server= is absent, empty, or blank", async () => {
    // Reaching the capability error is the proof the URL passed validation —
    // node has no RTCPeerConnection, which is the next gate.
    delete globalThis.RTCPeerConnection;
    for (const params of [{}, { server: "" }, { server: "   " }]) {
      await expect(q.execStunCheck(params)).rejects.toThrow(/WebRTC unavailable/);
    }
  });

  it("accepts stuns: and a stun: URL with no port", async () => {
    // Verified live: Chromium takes `stun:stun.l.google.com` and defaults to
    // :3478 — it reported a reflexive address in 133 ms — so rejecting a
    // portless URL here would refuse something that works.
    delete globalThis.RTCPeerConnection;
    for (const server of ["stun:stun.l.google.com", "stuns:stun.example:5349"]) {
      await expect(q.execStunCheck({ server }), server).rejects.toThrow(
        /WebRTC unavailable/
      );
    }
  });
});

/* ─────────────────────────── session lifecycle ─────────────────────────── */

describe("opening an exchange", () => {
  it("derives the room from the audience, whatever order it is written in", async () => {
    const { value } = await open({ to: `${FPR_B} ${FPR_A}` });
    expect(value.type).toBe("session");
    expect(value.data.room).toBe(await deriveRoomId([FPR_A, FPR_B]));
    expect(value.data.audience).toEqual([FPR_A, FPR_B]);
  });

  it("refuses an audience of fewer than two", async () => {
    await expect(q.execQuorumOpen({ to: FPR_A }, KEY_A, null, "creator")).rejects.toThrow(
      /at least two fingerprints/
    );
    // …and no exchange is left behind by the refusal.
    expect(q.getQuorumState().phase).toBe("idle");
  });

  it("refuses a second exchange and leaves the first one running", async () => {
    const { session } = await open();
    await expect(open()).rejects.toThrow(/already live/);
    expect(session.stopped).toBe(0);
    expect(q.getQuorumState().phase).toBe("connected");
    // The refused call must not have constructed a second transport either.
    expect(FakeSession.instances).toHaveLength(1);
  });

  it("reports connected and expected separately", async () => {
    // `expected` is the audience minus self; `peers=` is how many must arrive
    // before the step returns. A 3-key room that only needs one peer is a
    // legitimate state, and the panel has to be able to say so.
    FakeSession.onStart = (s) => s.connect(FPR_B);
    const { value } = await open({ to: `${FPR_A} ${FPR_B} ${FPR_C}` });
    const state = q.getQuorumState();
    expect(state.expected).toBe(2);
    expect(state.connected).toBe(1);
    expect(value.data.connected).toBe(1);
    expect(state.phase).toBe("connected");
  });

  it("closes and rethrows when the transport fails to start", async () => {
    FakeSession.onStart = () => {
      throw new Error("Missing public keys for: B2B2B2B2");
    };
    await expect(open()).rejects.toThrow(/Missing public keys/);
    expect(FakeSession.instances.at(-1).stopped).toBe(1);
    expect(q.getQuorumState().phase).toBe("idle");
    // A failed open still tells the panel it failed, before clearing.
    expect(events.at(-1).phase).toBe("failed");
  });

  it("gives up with an actionable message when no peer arrives", async () => {
    FakeSession.onStart = () => {};
    const failing = expect(open({ wait: 1000 })).rejects;
    await failing.toThrow(/no peer within 1s.*quorum\.join/s);
    // The second half of that sentence is new, and pinned rather than left to
    // the `.*`: a creator whose counterpart tab picked the *same* key waits
    // out the whole timeout with no proof available at this end — only the
    // side an invite reaches can prove it (see `_noteOwnKeyElsewhere`). So the
    // cause has to be named here as a question, or that reader is told to
    // check the one thing they already did.
    await failing.toThrow(/signing as a different key from this one/);
    expect(q.getQuorumState().phase).toBe("idle");
  });

  it("stops waiting the moment another session is found signing as this key", async () => {
    // The reported defect: two tabs, one vault, one key chosen twice. The wait
    // is bounded either way — this is not a hang — but two minutes of "waiting
    // for peer" for a peer that is structurally excluded is a refusal the
    // product declines to make until it is too late to act on.
    FakeSession.onStart = (s) => s.ownKeyElsewhere();
    const started = Date.now();
    await expect(open({ wait: 120000 })).rejects.toThrow(
      /another session in this room is signing as the key this one is using/
    );
    // Refused on its own account, not by outliving `wait=`.
    expect(Date.now() - started).toBeLessThan(5000);
    expect(q.getQuorumState().phase).toBe("idle");
  });

  it("names the way out, because two tabs is a fair thing to want", async () => {
    // A refusal that only says no leaves a tester with a working plan and no
    // way to run it: the two tabs mesh perfectly well under two keys.
    FakeSession.onStart = (s) => s.ownKeyElsewhere();
    await expect(open({ wait: 120000 })).rejects.toThrow(
      /open the session in each tab under a different key that this audience names/
    );
  });

  it("lets a meshed room stand even so", async () => {
    // A duplicate of this key somewhere else is not a reason to refuse a peer
    // who is really there — the check sits behind the connected one.
    FakeSession.onStart = (s) => {
      s.ownKeyElsewhere();
      s.connect(FPR_B);
    };
    const { value } = await open({ wait: 120000 });
    expect(value.data.connected).toBe(1);
    expect(q.getQuorumState().phase).toBe("connected");
  });
});

describe("the roster and the state agree", () => {
  it("counts a peer as connected only once it is key-confirmed", async () => {
    FakeSession.onStart = (s) => s.connect(FPR_B, { kcVerified: false });
    const opening = q.execQuorumOpen(
      { to: `${FPR_A} ${FPR_B}`, wait: 1000 },
      KEY_A,
      null,
      "creator"
    );
    await expect(opening).rejects.toThrow(/no peer within/);
    // The row still existed and still said "connected" — the *transport* was
    // up. What was missing is the proof, and the two are carried separately.
    const last = events.findLast((e) => e.peers.length);
    expect(last.peers[0].state).toBe("connected");
    expect(last.peers[0].authenticated).toBe(false);
    expect(last.connected).toBe(0);
  });

  it("falls back to waiting when a peer closes mid-session", async () => {
    const { session } = await open();
    expect(q.getQuorumState().phase).toBe("connected");
    session.drop(FPR_B, "failed");
    const state = q.getQuorumState();
    expect(state.phase).toBe("waiting");
    expect(state.connected).toBe(0);
    // `id` was `B2B2B2B2…B2B2` and is now the peer's label: `id` is written
    // into notebook source as `@<id>` and keys `planRun`'s roster, and an
    // elided fingerprint is not a legal peer label — it stopped notebooks
    // compiling and made `normalizeRoster` throw. `peer2` rather than `peer1`
    // because labels are ordered by the canonical audience, and `FPR_B` sorts
    // second in it.
    //
    // `display` was where the abbreviation went, and it is gone from the row
    // entirely. A projection has no business printing `B2B2B2B2…B2B2` at all:
    // twelve of forty characters is a value a reader compares and cannot check,
    // which is what `pages/index.tsx` warns about at eight. The panels render
    // `<Fingerprint variant="compact" label={id}>` from `fingerprint` now, so
    // the whole value is one press away and no part of it is on the row.
    expect(state.peers).toEqual([
      {
        id: "peer2",
        fingerprint: FPR_B,
        state: "failed",
        authenticated: false,
      },
    ]);
  });

  it("survives a peer that joins twice without duplicating its row", async () => {
    const { session } = await open();
    session.connect(FPR_B);
    session.connect(FPR_B);
    const state = q.getQuorumState();
    expect(state.peers).toHaveLength(1);
    expect(state.connected).toBe(1);
  });

  it("hands the panel the same snapshot the getter returns", async () => {
    const { session } = await open();
    session.connect(FPR_C);
    expect(events.at(-1)).toEqual(q.getQuorumState());
  });
});

describe("a room that moved without this machine ordering it", () => {
  /** Three in the room, so there is somebody to remove and somebody left. */
  const openThree = async () => {
    FakeSession.onStart = (s) => {
      s.connect(FPR_B);
      s.connect(FPR_C);
    };
    return open({ to: `${FPR_A} ${FPR_B} ${FPR_C}` });
  };

  it("updates the audience, which nothing used to do", async () => {
    // The defect underneath the label drift. `rotateQuorumRoom` patched the
    // snapshot, and only the initiator calls it; every other member followed
    // the rotation at the transport and kept a snapshot naming the room it had
    // left and the person who had just been removed from it.
    const { session } = await openThree();
    expect(q.getQuorumState().audience).toEqual([FPR_A, FPR_B, FPR_C]);

    session.rotate(FPR_B);

    const state = q.getQuorumState();
    expect(state.audience).toEqual([FPR_A, FPR_C]);
    expect(state.epoch).toBe(1);
    expect(state.room).toBe("ROTATEDROOMID");
    // All of it together or none of it: an invite naming three keys beside an
    // audience of two describes two different rooms.
    expect(state.expected).toBe(1);
    expect(state.invite).toContain("ROTATEDROOMID");
    expect(state.invite).toContain("2 keys");
    // The roster is the audience minus self, so this is everybody left that is
    // not this browser — the removed member is off it as well.
    expect(state.peers.map((p) => p.fingerprint)).toEqual([FPR_C]);
  });

  it("renumbers the labels the notebook addresses, which is the hazard", async () => {
    // `peerLabels` is positional over the canonical audience, so the row that
    // said `peer3` says `peer2` once the member above it is gone — and the key
    // behind it is a different key. This is the fact `useNotebook` watches for;
    // `live-relabel-drift.test.js` pins what it does about it.
    //
    // Read off the rows the panel draws, which is the audience minus this
    // browser: `peer1` is FPR_A and has no row because a session is never its
    // own peer.
    const { session } = await openThree();
    const was = Object.fromEntries(
      q.getQuorumState().peers.map((p) => [p.id, p.fingerprint])
    );
    expect(was).toEqual({ peer2: FPR_B, peer3: FPR_C });

    session.rotate(FPR_B);

    const now = Object.fromEntries(
      q.getQuorumState().peers.map((p) => [p.id, p.fingerprint])
    );
    expect(now).toEqual({ peer2: FPR_C });
    expect(now.peer2).not.toBe(was.peer2);
  });

  it("emits it, so a shell following the event and one polling agree", async () => {
    const { session } = await openThree();
    session.rotate(FPR_B);
    expect(events.at(-1)).toEqual(q.getQuorumState());
  });

  it("says nothing once the exchange is gone", async () => {
    // The rotation completes inside an envelope handler, and a session torn
    // down underneath it must not resurrect a snapshot for a room nobody is in.
    const { session } = await openThree();
    q.closeQuorumExchange("closed");
    const after = events.length;
    session.rotate(FPR_B);
    expect(events).toHaveLength(after);
    expect(q.getQuorumState().phase).toBe("idle");
  });
});

describe("closing an exchange", () => {
  it("stops the transport once and clears the roster", async () => {
    const { session } = await open();
    q.closeQuorumExchange("closed");
    expect(session.stopped).toBe(1);
    expect(events.at(-1)).toMatchObject({ phase: "closed", peers: [] });
    expect(q.getQuorumState().phase).toBe("idle");
  });

  it("is idempotent — a second close neither throws nor stops twice", async () => {
    const { session } = await open();
    q.closeQuorumExchange("closed");
    expect(() => q.closeQuorumExchange("closed")).not.toThrow();
    expect(() => q.execQuorumClose(null)).not.toThrow();
    expect(session.stopped).toBe(1);
  });

  it("closes on Cancel from the run bar", async () => {
    const { session } = await open();
    window.dispatchEvent(new CustomEvent("basilisk:quorum-cancel"));
    expect(session.stopped).toBe(1);
    expect(q.getQuorumState().phase).toBe("idle");
  });

  it("passes the pipeline value through, and mints one when there is none", async () => {
    await open();
    const carried = { type: "text", data: "keep me", meta: {} };
    expect(q.execQuorumClose(carried)).toBe(carried);
    const minted = q.execQuorumClose(null);
    expect(JSON.parse(minted.data)).toEqual({ v: 1, closed: true });
  });

  it("refuses every op that needs a live exchange, afterwards", async () => {
    await open();
    q.closeQuorumExchange("closed");
    await expect(q.execQuorumSend({ type: "text", data: "hi" }, {})).rejects.toThrow(
      /quorum.send: no live exchange/
    );
    await expect(q.execQuorumRecv({})).rejects.toThrow(/quorum.recv: no live exchange/);
    expect(() => q.createExchangeTransport("dkg.run")).toThrow(/no live exchange/);
    expect(q.getLiveSession()).toBe(null);
    expect(q.restartLiveIce()).toBe(0);
  });

  it("keeps the dead links on a failed close, and only then", async () => {
    // A clean close ended the session — there is nothing live to show. A failed
    // one is the moment the roster matters most: *which* link died.
    const { session } = await open();
    session.drop(FPR_B, "failed");
    q.closeQuorumExchange("failed");
    expect(events.at(-1).phase).toBe("failed");
    expect(events.at(-1).peers).toHaveLength(1);
  });
});

/* ──────────────────────────── send and receive ──────────────────────────── */

describe("quorum.send", () => {
  it("broadcasts without to=, and addresses one peer with it", async () => {
    const { session } = await open();
    await q.execQuorumSend({ type: "text", data: "hello" }, {});
    await q.execQuorumSend({ type: "text", data: "just you" }, { to: FPR_B });
    expect(session.sent).toEqual([
      { to: "", text: "hello" },
      { to: FPR_B, text: "just you" },
    ]);
  });

  it("returns the value unchanged so the pipeline continues", async () => {
    await open();
    const value = { type: "text", data: "x", meta: { sensitive: true } };
    expect(await q.execQuorumSend(value, {})).toBe(value);
  });

  it("sends bytes as text", async () => {
    const { session } = await open();
    await q.execQuorumSend({ type: "bytes", data: new TextEncoder().encode("raw") }, {});
    expect(session.sent[0].text).toBe("raw");
  });
});

describe("quorum.recv", () => {
  it("takes a message already queued", async () => {
    const { session } = await open();
    session.chat(FPR_B, "queued");
    const out = await q.execQuorumRecv({ wait: 1000 });
    expect(out).toMatchObject({ type: "text", data: "queued", meta: { from: FPR_B } });
  });

  it("waits for one that has not arrived yet", async () => {
    const { session } = await open();
    const pending = q.execQuorumRecv({ wait: 2000 });
    setTimeout(() => session.chat(FPR_B, "late"), 10);
    expect((await pending).data).toBe("late");
  });

  it("does not swallow the next message after a timeout", async () => {
    // The waiter queue is drained by identity, and the timeout used to search
    // for the promise's `resolve` while the queue held a *wrapper* around it.
    // Nothing ever matched, so a timed-out recv left a settled waiter behind
    // and `onChat` handed the next message to it — resolving an already
    // resolved promise and dropping the message, permanently and silently.
    const { session } = await open();
    await expect(q.execQuorumRecv({ wait: 1000 })).rejects.toThrow(/no message within 1s/);
    session.chat(FPR_B, "sent after the timeout");
    const out = await q.execQuorumRecv({ wait: 1000 });
    expect(out.data).toBe("sent after the timeout");
  });

  it("loses nothing across several timed-out reads", async () => {
    const { session } = await open();
    for (let i = 0; i < 2; i++) {
      await expect(q.execQuorumRecv({ wait: 1000 })).rejects.toThrow(/no message/);
    }
    session.chat(FPR_B, "one");
    session.chat(FPR_C, "two");
    const out = await q.execQuorumRecv({ wait: 1000, count: "all" });
    expect(out.type).toBe("bundle");
    expect(out.data.parts.map((p) => p.data)).toEqual(["one", "two"]);
  });

  it("requeues a message the from= filter rejects", async () => {
    const { session } = await open();
    session.chat(FPR_C, "from C");
    session.chat(FPR_B, "from B");
    const mine = await q.execQuorumRecv({ from: FPR_B, wait: 1000 });
    expect(mine.data).toBe("from B");
    // C's message is still there for a reader that wants it.
    const theirs = await q.execQuorumRecv({ from: FPR_C, wait: 1000 });
    expect(theirs.data).toBe("from C");
  });

  it("bundles when count is more than one, and stamps each sender", async () => {
    const { session } = await open();
    session.chat(FPR_B, "one");
    session.chat(FPR_C, "two");
    const out = await q.execQuorumRecv({ count: 2, wait: 1000 });
    expect(out.type).toBe("bundle");
    expect(out.data.count).toBe(2);
    expect(out.data.parts.map((p) => p.meta.from)).toEqual([FPR_B, FPR_C]);
  });

  it("aborts the moment the exchange closes underneath it", async () => {
    const { session } = await open();
    const pending = q.execQuorumRecv({ wait: 30000 });
    setTimeout(() => q.closeQuorumExchange("closed"), 10);
    await expect(pending).rejects.toThrow(/exchange closed while waiting/);
    expect(session.stopped).toBe(1);
  });

  it("keeps protocol chatter out of a user's inbox", async () => {
    // The DKG tap consumes what it recognizes; everything else must still
    // reach `quorum.recv`, or running a key generation fills the pipeline with
    // JSON nobody asked for.
    const { session } = await open();
    const t = q.createExchangeTransport("dkg.run");
    const seen = [];
    t.transport.subscribe((m) => seen.push(m));
    session.chat(FPR_B, JSON.stringify({ t: "dkg-commit", c: ["x"] }));
    session.chat(FPR_B, "ordinary chat");
    session.chat(FPR_B, JSON.stringify({ hello: "world" }));
    expect(seen).toHaveLength(1);
    const out = await q.execQuorumRecv({ count: "all", wait: 1000 });
    expect(out.data.parts.map((p) => p.data)).toEqual([
      "ordinary chat",
      '{"hello":"world"}',
    ]);
    t.release();
  });
});

/* ───────────────────────────── ICE restart ───────────────────────────── */

describe("restartLiveIce", () => {
  /**
   * A stand-in `PeerLink`: it reports whether it issued a restart, the way the
   * real one does for an engine without `restartIce`, and answers the `via`
   * lookup the roster projection makes on every connected peer.
   */
  const withRestart = () => {
    const calls = [];
    return {
      calls,
      link: {
        restartIce: () => {
          calls.push(1);
          return true;
        },
        selectedCandidateType: async () => "",
      },
    };
  };

  it("restarts every peer connection of the live exchange", async () => {
    // `session.peers` is a Map. Iterating it directly yields `[fpr, peer]`
    // entries, so the link was `undefined` on every pass, every peer failed the
    // restart check, and this returned 0 for every exchange there has ever been
    // — the Connections panel's Restart ICE button and its Session-strip twin
    // were both no-ops.
    const b = withRestart();
    const c = withRestart();
    FakeSession.onStart = (s) => {
      s.connect(FPR_B, { link: b.link });
      s.connect(FPR_C, { link: c.link });
    };
    await open({ to: `${FPR_A} ${FPR_B} ${FPR_C}` });
    expect(q.restartLiveIce()).toBe(2);
    expect(b.calls).toHaveLength(1);
    expect(c.calls).toHaveLength(1);
  });

  it("restarts the peers it can when one cannot", async () => {
    const b = withRestart();
    FakeSession.onStart = (s) => {
      s.connect(FPR_B, { link: b.link });
      s.connect(FPR_C, { link: null }); // torn down already
    };
    await open({ to: `${FPR_A} ${FPR_B} ${FPR_C}` });
    expect(q.restartLiveIce()).toBe(1);
  });

  it("counts a peer whose restartIce throws as not restarted", async () => {
    FakeSession.onStart = (s) =>
      s.connect(FPR_B, {
        link: {
          restartIce() {
            throw new Error("InvalidStateError");
          },
          selectedCandidateType: async () => "",
        },
      });
    await open();
    expect(q.restartLiveIce()).toBe(0);
  });

  it("is a no-op with no exchange, rather than throwing", () => {
    expect(q.restartLiveIce()).toBe(0);
  });
});

/* ──────────────────────── cross-run interference ──────────────────────── */

describe("an abandoned open cannot reach into the exchange that replaced it", () => {
  it("leaves a later exchange alone when a cancelled one gives up", async () => {
    // `waitForPeers` polls every 250 ms and used to read the module-global
    // `current` rather than the exchange it was started for. Cancel clears
    // `current`, so a second `quorum.offer` inside that window became the one
    // the abandoned loop was waiting on — and closed it on failure.
    FakeSession.onStart = () => {};
    const abandoned = q.execQuorumOpen(
      { to: `${FPR_A} ${FPR_B}`, wait: 30000 },
      KEY_A,
      null,
      "creator"
    );
    // Room derivation is async, so the transport does not exist yet.
    await new Promise((r) => setTimeout(r, 30));
    const first = FakeSession.instances.at(-1);
    expect(first).toBeTruthy();
    q.closeQuorumExchange("closed");

    // The replacement meshes immediately and must survive.
    FakeSession.onStart = (s) => s.connect(FPR_B);
    const { session: second } = await open();

    await expect(abandoned).rejects.toThrow(/cancelled/);
    expect(first.stopped).toBe(1);
    expect(second.stopped).toBe(0);
    expect(q.getLiveSession()).toBe(second);
    expect(q.getQuorumState().phase).toBe("connected");
  });
});

describe("a handed-over cell waits for a person", () => {
  /** What the session hands `onOffer` when a peer offers a cell. */
  const OFFER_DOC = {
    from: FPR_B,
    cell: 2,
    manifest: "4C1D9E07B8A2",
    ts: 1_700_000_000_000,
    offer: { v: 1, cell: 2, needs: [] },
  };

  /** And `onResult`, coming back the other way. */
  const RESULT_DOC = {
    from: FPR_B,
    cell: 2,
    manifest: "4C1D9E07B8A2",
    ts: 1_700_000_001_000,
    signed: "-----BEGIN PGP SIGNED MESSAGE-----",
    result: { v: 1, cell: 2, values: [] },
  };

  it("holds an offer pending instead of dropping it", async () => {
    // Before this, `quorum-ops` passed no `onOffer`, so the session's optional
    // call made a missing handler look exactly like a refusal — an offer the
    // sender was told had landed went on the floor.
    const { session } = await open();
    expect(q.getPendingHandoffs()).toEqual([]);
    session.opts.onOffer(OFFER_DOC);
    const pending = q.getPendingHandoffs();
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ kind: "offer", from: FPR_B, cell: 2 });
  });

  it("holds a result pending too, which is the end that matters more", async () => {
    // A result that resumed the run on a peer's say-so would continue *this*
    // machine on values nobody looked at.
    const { session } = await open();
    session.opts.onResult(RESULT_DOC);
    const pending = q.getPendingHandoffs();
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({ kind: "result", from: FPR_B, cell: 2 });
    expect(pending[0].signed).toBe(RESULT_DOC.signed);
  });

  it("hands each document out once, so a click cannot act on it twice", async () => {
    const { session } = await open();
    session.opts.onOffer(OFFER_DOC);
    const [only] = q.getPendingHandoffs();
    expect(q.takeHandoff(only.id)).toMatchObject({ cell: 2 });
    expect(q.takeHandoff(only.id)).toBeNull();
    expect(q.getPendingHandoffs()).toEqual([]);
  });

  it("hands back a copy, so a caller cannot mutate the queue in place", async () => {
    const { session } = await open();
    session.opts.onOffer(OFFER_DOC);
    q.getPendingHandoffs()[0].cell = 99;
    expect(q.getPendingHandoffs()[0].cell).toBe(2);
  });

  it("keeps nothing across a closed session", async () => {
    const { session } = await open();
    session.opts.onOffer(OFFER_DOC);
    q.closeQuorumExchange("closed");
    expect(q.getPendingHandoffs()).toEqual([]);
  });
});

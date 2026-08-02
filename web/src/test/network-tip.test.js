/**
 * Network-typed values that fall off the end of a pipeline (§25a).
 *
 * `valueToArtifacts` — the path a pipeline tip takes when no `out` claimed it —
 * had **no branch at all** for the network types, so it returned `[]` and a
 * dangling `rtc.gather` / `peer.offer` / `stun.check` / `rtc.certificate` /
 * `rtc.ice` / `rtc.state` / `rtc.check` rendered *nothing whatsoever*: not a
 * stub, not a fallback tile, no row. A user who ran the op to read the answer
 * saw a cell that looked like it had failed.
 *
 * Three separate things are pinned here.
 *
 *  1. **A tile exists, and it is worth reading** — it resolves to the shipped
 *     `network-value` kind and carries the structured body that kind's widget
 *     draws from. Zero artifacts is the regression; a tile that resolves to
 *     untyped `text` is the near-miss.
 *  2. **The dangling tip and `out @label` describe one value identically.**
 *     Asserted as field-by-field equality over everything that decides a kind
 *     or a rendering, with the label deliberately excluded — because naming it
 *     is the only thing `out` does here. Two spellings of one artifact is the
 *     failure mode 7d563cd cost a day to, and `ArtifactMatch.role` is exact,
 *     so a kind can only ever claim one of them.
 *  3. **The body is emitted in full**, unlike the keypair tip (§35g). That one
 *     withholds its body because materializing a private half is what `out` is
 *     for; none of that applies to a candidate list, so Copy and Download work
 *     rather than refusing with `ACTION_REASONS.neverAskedFor`.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

/**
 * A live connection, for the ops that read one.
 *
 * Registered into the **link registry** rather than mocked at `getLiveSession`,
 * because that is where the diagnostics now look (§57a). The ops still run
 * their real bodies over a real `getStats()` report — the values under test are
 * the ones the ops actually build, not fixtures written to match — and the
 * fixture now covers the path a hand-carried `peer.*` link takes as well as the
 * mesh's, which was the whole point of the move.
 */
const FAKE_STATS = [
  { id: "cp1", type: "candidate-pair", state: "succeeded", nominated: true,
    localCandidateId: "lc1", remoteCandidateId: "rc1", currentRoundTripTime: 0.031,
    bytesSent: 2048, bytesReceived: 4096, packetsSent: 12, packetsReceived: 14 },
  { id: "lc1", type: "local-candidate", candidateType: "srflx", port: 51820, protocol: "udp" },
  { id: "rc1", type: "remote-candidate", candidateType: "host", address: "10.0.0.2", port: 44100, protocol: "udp" },
  { id: "dc1", type: "data-channel", messagesSent: 3, messagesReceived: 5, bytesSent: 300, bytesReceived: 500 },
];

/** The holder a registered link reads `pc`/`channel` through. */
const fakeHolder = () => ({
  pc: {
    connectionState: "connected",
    iceConnectionState: "completed",
    iceGatheringState: "complete",
    signalingState: "stable",
    sctp: { transport: { iceTransport: { role: "controlling" } } },
    getStats: async () => ({ forEach: (fn) => FAKE_STATS.forEach(fn) }),
    restartIce: () => {},
    addEventListener: () => {},
  },
  channel: {
    readyState: "open",
    bufferedAmount: 0,
    bufferedAmountLowThreshold: 65535,
    ordered: true,
  },
});

const { closeLinksByOrigin, registerLink, __resetLinks } = await import(
  "../lib/quorum/link-registry.js"
);

const { compileRecipe } = await import("../lib/toolkit/recipe.js");
const { runRecipe } = await import("../lib/toolkit/engine.js");
const { NETWORK_TYPES, artifactMetaFromType, isObserveOnlyType, typeOf } = await import(
  "../lib/toolkit/types.js"
);
const { hasNetworkRenderer } = await import("../toolkit/widgets/NetworkArtifact.tsx");
const { ARTIFACT_KINDS, FALLBACK_KIND } = await import(
  "../toolkit/artifact-kinds/registry.tsx"
);
const { resolveArtifactKind } = await import("../toolkit/artifact-kinds/resolve.ts");
const { ARTIFACT_ACTIONS } = await import("../lib/toolkit/artifact-actions.js");
const { STEPS } = await import("../lib/toolkit/registry.js");

const SDP = [
  "v=0",
  "o=- 4611731400430051336 2 IN IP4 127.0.0.1",
  "s=-",
  "t=0 0",
  "a=fingerprint:sha-256 AB:CD:EF",
  "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
  "",
].join("\r\n");

/** Enough `RTCPeerConnection` for the ops that mint one. */
class StubPeerConnection {
  constructor() {
    this.iceGatheringState = "complete";
    this.localDescription = { sdp: SDP };
    this.onicecandidate = null;
  }
  createDataChannel(label) {
    // Returns a channel now, because `peer.offer` keeps one: the manager wires
    // `message` on it and holds it for `peer.send` / `peer.recv`. The old stub
    // returned `undefined`, which was fine for an op that closed its own
    // connection and never looked at the channel again.
    this.__channel = {
      label,
      readyState: "open",
      ordered: true,
      addEventListener() {},
      send() {},
      close() {},
    };
    return this.__channel;
  }
  async createOffer() {
    return { type: "offer", sdp: SDP };
  }
  async createAnswer() {
    return { type: "answer", sdp: SDP };
  }
  async setLocalDescription() {
    // One srflx candidate, then the null that ends gathering — so `rtc.gather`
    // and `stun.check` have a row to report rather than an empty list.
    setTimeout(() => {
      this.onicecandidate?.({
        candidate: {
          type: "srflx",
          address: "203.0.113.9",
          port: 51820,
          protocol: "udp",
          foundation: "1",
          priority: 1686052607,
          relatedAddress: "192.168.1.4",
        },
      });
      this.onicecandidate?.({ candidate: null });
    }, 0);
  }
  async setRemoteDescription() {}
  // A connection that has only just been created really does report nothing —
  // `rtc.check` reaches these now that a `peer.offer` link stays in the
  // inventory, and an empty report is the truthful answer rather than a stub
  // shaped to keep a test quiet.
  async getStats() {
    return { forEach: () => {} };
  }
  addEventListener() {}
  removeEventListener() {}
  close() {}
  static async generateCertificate() {
    return {
      expires: Date.now() + 30 * 86400_000,
      getFingerprints: () => [{ algorithm: "sha-256", value: "AB:CD:EF:01" }],
    };
  }
}

beforeAll(() => {
  globalThis.RTCPeerConnection = StubPeerConnection;
  __resetLinks();
  registerLink({
    id: "AAAABBBBCCCCDDDD",
    origin: "quorum",
    role: "offerer",
    holder: fakeHolder(),
    label: "quorum",
    authenticated: true,
  });
});
afterEach(() => {
  vi.clearAllMocks();
  // Only the direct links. The quorum fixture above is registered once in
  // `beforeAll` and has to survive, and `peer.offer tip` refuses a name that
  // is already open — which is the op behaving correctly, and would otherwise
  // make every tip assertion after the first one fail on its second run.
  closeLinksByOrigin("peer");
});

const artifactsOf = async (src) => {
  const { ast, validation } = compileRecipe(src);
  expect(validation.errors.map((e) => e.message), `fixture should compile: ${src}`).toEqual(
    []
  );
  return runRecipe(ast, {});
};

const kindOf = (a) => resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND);
const actionById = (id) => ARTIFACT_ACTIONS.find((a) => a.id === id);

/**
 * One recipe per network base that a step can actually produce, as a *tip* —
 * no `out`, which is the whole point.
 *
 * `session` has no row, and the omission is not an oversight: `quorum.offer`
 * needs a decrypted OpenPGP private key and a live signalling transport, so
 * there is no unit-testable route to one. It is covered structurally instead,
 * by the predicate test below — both emit sites gate on `NETWORK_TYPES`, which
 * contains it, and `artifactMetaFromType` gives it the same role.
 */
const TIPS = [
  ["endpoint", "rtc.ice", "network-value"],
  ["endpoint", "stun.check", "diagnostic"],
  ["candidate", "rtc.gather", "network-value"],
  ["sdp", "peer.offer tip", "network-value"],
  ["channel", "peer.wait AAAABBBBCCCCDDDD", "network-value"],
  ["certificate", "rtc.certificate", "network-value"],
  ["connstate", "rtc.state", "network-value"],
  ["connstate", "rtc.restart", "network-value"],
  ["stats", "rtc.check", "network-value"],
  ["stats", "rtc.stats", "network-value"],
  ["stats", "rtc.quality", "network-value"],
];

describe("a network value that falls off the end of a pipeline renders a tile", () => {
  for (const [base, src, kindId] of TIPS) {
    it(`${src} emits one ${base} tile`, async () => {
      const arts = await artifactsOf(src);
      // The regression is zero. Anything else is at least a tile.
      expect(arts, `${src} emitted no artifact at all`).toHaveLength(1);
      const [tip] = arts;
      expect(tip.netType).toBe(base);
      expect(tip.pipeType.base).toBe(base);
    });

    it(`${src} resolves to the ${kindId} kind`, async () => {
      const [tip] = await artifactsOf(src);
      // Not the fallback, and not untyped `text` — the near-miss that would
      // leave the shipped NetworkArtifact widget unreachable from a tip.
      expect(kindOf(tip).id).toBe(kindId);
      expect(tip.role).toBe(kindId === "diagnostic" ? "diagnostic" : "netvalue");
    });

    it(`${src} carries a body the widget can draw`, async () => {
      const [tip] = await artifactsOf(src);
      // `netData` is what every panel in NetworkArtifact reads; `content` is
      // what Copy and Download hand over. A tile needs both.
      expect(tip.netData, `${src} carries no structured data`).toBeTruthy();
      expect(String(tip.content).length).toBeGreaterThan(0);
      const el = kindOf(tip).view({ artifact: tip, masked: false });
      expect(el, `${src} draws no view`).toBeTruthy();
      expect(el.props.netType).toBe(base);
      expect(el.props.data).toBe(tip.netData);
    });
  }

  it("draws the real numbers the op measured, not an empty shell", async () => {
    // A tile that exists but says nothing is barely better than no tile. These
    // are the fields each panel puts on screen.
    const [gathered] = await artifactsOf("rtc.gather");
    expect(gathered.netData.candidates[0].address).toBe("203.0.113.9");
    expect(gathered.netData.byType.srflx).toBe(1);

    const [pairs] = await artifactsOf("rtc.check");
    expect(pairs.netKind).toBe("candidate-pairs");
    expect(pairs.netData.peers[0].pairs[0].nominated).toBe(true);
    expect(pairs.netData.peers[0].pairs[0].rttMs).toBe(31);

    const [state] = await artifactsOf("rtc.state");
    expect(state.netData.peers[0].connectionState).toBe("connected");

    const [cert] = await artifactsOf("rtc.certificate");
    expect(cert.netData.fingerprints[0].value).toBe("AB:CD:EF:01");

    const [quality] = await artifactsOf("rtc.quality");
    expect(quality.netData.peers[0].rttMs).toBe(31);
    expect(quality.netData.peers[0].bytesSent).toBe(2048);

    const [offer] = await artifactsOf("peer.offer tip");
    // SDP is text on the wire, so the panel prints `content`, not `netData`.
    expect(offer.content).toContain("a=fingerprint:sha-256");
    expect(kindOf(offer).view({ artifact: offer, masked: false }).props.content).toBe(
      offer.content
    );
  });
});

describe("rtc.quality reports no number it did not measure", () => {
  /**
   * `packetLossPct` used to be `packetsLost` from a `remote-inbound-rtp` report
   * over `packetsSent + packetsReceived` from the nominated candidate pair.
   * Neither half survives contact with this transport: loss statistics come
   * from RTP and the quorum mesh is SCTP data channels, so the numerator's
   * stat type is absent from every report — pinned exactly, against a live
   * connection, in `e2e/rtc-transport.e2e.js`. The numerator was a constant 0
   * and the denominator counted a different population of packets.
   *
   * A structural zero is worse than a gap here, because `0% loss` is where you
   * look when a call is going badly and it reads as an all-clear.
   */
  it("reports loss as null, not zero, on a report with no RTP", async () => {
    // FAKE_STATS is the shape a real connection has: a nominated candidate
    // pair with packet counters, a data channel, and no RTP anywhere.
    const [tip] = await artifactsOf("rtc.quality");
    const peer = tip.netData.peers[0];
    expect(peer.packetLossPct).toBe(null);
    // The counters it *did* read are still real and still reported.
    expect(peer.packetsSent).toBe(12);
    expect(peer.packetsReceived).toBe(14);
    expect(peer.rttMs).toBe(31);
  });

  it("explains the null in the value, so a downloaded report is self-describing", async () => {
    const [tip] = await artifactsOf("rtc.quality");
    expect(tip.netData.notes.join(" ")).toMatch(/packet loss is not measured/);
    expect(tip.netData.notes.join(" ")).toMatch(/SCTP/);
    // …and it survives serialization, which is what Download writes.
    expect(JSON.parse(tip.content).peers[0].packetLossPct).toBe(null);
  });

  it("promises no loss figure in the step's own documentation", () => {
    // The doc used to advertise "packet loss per connected peer", which is the
    // same claim in the place a user reads before running it.
    const doc = STEPS.find((s) => s.name === "rtc.quality").doc;
    expect(doc).toMatch(/[Pp]acket loss is not reported/);
  });
});

describe("the tip and `out @label` are one artifact, not two", () => {
  /**
   * Everything that decides which kind claims an artifact, how it renders, and
   * what Download writes. `label` is excluded on purpose — naming the value is
   * the only thing `out` is doing here, so a difference there is the feature.
   */
  const identity = (a) => ({
    role: a.role,
    tags: [...(a.tags || [])].sort(),
    netType: a.netType,
    netKind: a.netKind,
    mime: a.mime,
    encoding: a.encoding,
    sensitive: a.sensitive,
    filename: a.filename,
    pipeType: a.pipeType,
    content: a.content,
    kind: kindOf(a).id,
  });

  for (const [base, src] of [
    ["endpoint", "rtc.ice"],
    ["endpoint", "stun.check"],
    ["candidate", "rtc.gather"],
    ["certificate", "rtc.certificate"],
    ["connstate", "rtc.state"],
    ["stats", "rtc.check"],
  ]) {
    it(`${src} describes its ${base} the same way with and without out`, async () => {
      // `tee` so both artifacts come from **one** run of the op: several of
      // these carry a duration or a timestamp, so two invocations would differ
      // in the body for reasons that have nothing to do with the emit path.
      // The tee body writes the named tile; the stem falls off the end.
      const arts = await artifactsOf(`${src} | tee\n  - out @thing`);
      expect(arts, `${src} did not produce both an out tile and a tip`).toHaveLength(2);
      const named = arts.find((a) => a.label === "thing");
      const tip = arts.find((a) => a !== named);
      expect(identity(tip)).toEqual(identity(named));
      // …and the one difference that *should* exist does.
      expect(tip.label).not.toBe(named.label);
    });
  }

  it("keeps the op's own filename on both paths", async () => {
    // `out @thing` used to be able to rename a candidate dump to `thing.json`;
    // the op named it `candidates.json` and that name is the engine's, not a
    // second namer's (downloadNameFor's whole position).
    const arts = await artifactsOf("rtc.gather | tee\n  - out @thing");
    for (const a of arts) expect(a.filename, a.label).toBe("candidates.json");
  });
});

describe("nothing is withheld, so nothing refuses", () => {
  it("offers Copy and Download on a dangling network tip", async () => {
    // The contrast with the keypair tip (§35g) is the point: that one emits an
    // empty body and both actions refuse with ACTION_REASONS.neverAskedFor,
    // because materializing a private half is what `out` is for. A candidate
    // list is `sensitive: false` at its emit site — there is no held-back half
    // — so a tile that rendered the whole list while Copy said "this value was
    // not asked for" would be an incoherent pair.
    for (const src of ["rtc.gather", "peer.offer tip", "stun.check", "rtc.state"]) {
      // `peer.offer` refuses a name that is already open, and these loops run
      // several sources inside one `it` — so the per-test cleanup is not
      // enough on its own.
      closeLinksByOrigin("peer");
      const [tip] = await artifactsOf(src);
      expect(tip.sensitive, src).toBe(false);
      const ctx = { artifact: tip, masked: false };
      expect(actionById("copy").available(ctx), src).toBe(true);
      expect(actionById("download").available(ctx), src).toBe(true);
    }
  });

  it("emits no placeholder body on any network path", async () => {
    // `[keypair — use out or export before emitting]` and its siblings were
    // instructions rendered where a value goes. A body is a value or it is
    // absent; it is never a note to the reader about the recipe.
    for (const [, src] of TIPS) {
      closeLinksByOrigin("peer");
      for (const a of await artifactsOf(src)) {
        expect(a.content, `${src} → ${a.label}`).not.toMatch(/^\[.*\]$/);
      }
      closeLinksByOrigin("peer");
      for (const a of await artifactsOf(`${src} | out @x`)) {
        expect(a.content, `${src} | out → ${a.label}`).not.toMatch(/^\[.*\]$/);
      }
    }
  });
});

describe("the role comes from the type projection, not a second list", () => {
  it("gives every network base its role through artifactMetaFromType", () => {
    // These bases *are* the definition of `netvalue`; re-declaring them in
    // the engine would undo the consolidation the kind table's header records
    // (`hasNetworkRenderer` was deleted for exactly this reason).
    for (const base of [
      "candidate",
      "sdp",
      "stats",
      "connstate",
      "endpoint",
      "certificate",
      "session",
      "channel",
    ]) {
      expect(artifactMetaFromType(typeOf(base)).role, base).toBe("netvalue");
    }
  });

  it("declares no role of its own on the netvalue path", async () => {
    // Asserted through behaviour rather than by grepping: if the emit site
    // stamped a role, the projection's `if (!artifact.role)` guard would leave
    // it alone and these would not be `netvalue`.
    for (const src of ["rtc.ice", "rtc.gather", "peer.offer tip", "rtc.state", "rtc.check"]) {
      closeLinksByOrigin("peer");
      const [tip] = await artifactsOf(src);
      expect(tip.role, src).toBe("netvalue");
    }
  });

  it("keeps stun.check a diagnostic, which no projection could know", async () => {
    // `endpoint` projects to `netvalue`; that this *particular* endpoint is a
    // reachability verdict with a Configure TURN affordance is a fact about
    // why the artifact exists. Both `rtc.ice` and `stun.check` are `endpoint`
    // and they must not resolve to the same kind.
    const [check] = await artifactsOf("stun.check");
    const [ice] = await artifactsOf("rtc.ice");
    expect(check.pipeType.base).toBe(ice.pipeType.base);
    expect(kindOf(check).id).toBe("diagnostic");
    expect(kindOf(ice).id).toBe("network-value");
  });

  it("covers `session` by the same predicate, though no unit test can open one", () => {
    // quorum.offer needs a decrypted private key and a live transport, so the
    // tip cannot be driven here. What can be pinned is that it takes the same
    // route: one predicate gates both emit sites, and it contains session.
    expect(NETWORK_TYPES.has("session")).toBe(true);
    expect(artifactMetaFromType(typeOf("session")).role).toBe("netvalue");
    expect(
      ARTIFACT_KINDS.find((k) => k.id === "network-value").match.role
    ).toBe("netvalue");
  });
});

describe("the types with no tile have no producer either", () => {
  const producersOf = (base) =>
    STEPS.filter((s) => {
      if (s.output === base) return true;
      try {
        return s.effectiveIo?.({})?.output === base;
      } catch (_) {
        return false;
      }
    }).map((s) => s.name);

  it("has no step that outputs host or peer", () => {
    // Both are IoType vocabulary with nothing behind them, so there is no
    // dangling tip to render and a branch for them would be dead code guarding
    // dead code. If one ever gains a producer it lands as `text`, not
    // `netvalue` — they are deliberately absent from the base list that
    // defines the role.
    //
    // `channel` used to be on this list and is not any more: `peer.wait` gives
    // it a producer (§56). Being a HANDLE is about what may *consume* a value,
    // which `isObserveOnlyType` still refuses; it says nothing about whether
    // the value may be drawn, and `session` — also a handle — has been drawn
    // as a `netvalue` since §21a.
    for (const base of ["host", "peer"]) {
      expect(producersOf(base), base).toEqual([]);
      expect(artifactMetaFromType(typeOf(base)).role, base).toBe("text");
    }
  });

  it("gives the channel handle a producer, a role and a renderer, together", () => {
    // The three had to move in one commit: a producer without the role stamps
    // `text` on a live channel, and a role without a renderer resolves to
    // `network-value` and then draws nothing — the shape of the defect that
    // left `hasNetworkRenderer` undefined and the widgets catalog blank.
    expect(producersOf("channel")).toContain("peer.wait");
    expect(artifactMetaFromType(typeOf("channel")).role).toBe("netvalue");
    expect(hasNetworkRenderer("channel")).toBe(true);
    // And it is still refused as any computing op's input.
    expect(isObserveOnlyType("channel")).toBe(true);
  });

  it("has a producer for each of the six that can dangle", () => {
    // The counterpart, so the assertion above cannot rot into a tautology by
    // the whole registry losing its network ops.
    for (const base of [
      "endpoint",
      "candidate",
      "sdp",
      "certificate",
      "connstate",
      "stats",
      "channel",
    ]) {
      expect(producersOf(base).length, base).toBeGreaterThan(0);
    }
  });

  it("never lets an `item` reach a tile", async () => {
    // `item` is on the same reported list, but it exists only *inside* a
    // foreach body: the tip of a foreach is always a `bundle`, and a bundle is
    // excluded from the dangling-tip path outright. So there is nothing to
    // render and no branch to add — `:key` / `:value` are how an item becomes
    // something a tile can hold.
    const arts = await artifactsOf(
      "random 16 | sss.split threshold=2 shares=3 | blip39 | foreach :items\n  - peek"
    );
    expect(arts.length).toBeGreaterThan(0);
    for (const a of arts) {
      expect(a.pipeType?.base, a.label).not.toBe("item");
      expect(a.netType, a.label).toBeUndefined();
    }
  });
});

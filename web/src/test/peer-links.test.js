/**
 * The link registry and the manager's refusals (§55, §57a).
 *
 * `environment: "node"`, so there is no `RTCPeerConnection` here — which is
 * exactly the split the rest of this codebase already uses for WebRTC
 * (`offerCollisionAction`, `sdpRole`, `meshHealth`). What is asserted here is
 * everything that is a *rule*: the projection, the origin bounding, the
 * refusals and the sentences they carry. The half that needs a real transport —
 * two browsers, a carried offer, ICE reaching `connected`, bytes on the channel
 * — is `e2e/peer-manager.e2e.js`, and neither file can stand in for the other.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
  __resetLinks,
  closeLink,
  closeLinksByOrigin,
  getLink,
  linkRow,
  listLinkRows,
  listLinksByOrigin,
  normalizeLinkId,
  patchLink,
  registerLink,
  restartLink,
} from "../lib/quorum/link-registry.js";
import { linkOriginNote } from "../lib/toolkit/artifact-readouts.js";
import {
  ACCEPT_NOT_AN_ANSWER,
  ANSWER_NOT_AN_OFFER,
  execPeerAccept,
  execPeerClose,
  execPeerRecv,
  execPeerSend,
  execPeerWait,
} from "../lib/toolkit/peer-ops.js";

/** A holder shaped like the object a link reads `pc`/`channel` through. */
function holder(over = {}) {
  const { channel, ...pcOver } = over;
  return {
    pc: {
      connectionState: "connected",
      iceConnectionState: "completed",
      iceGatheringState: "complete",
      signalingState: "stable",
      addEventListener() {},
      restartIce() {
        this.__restarted = (this.__restarted || 0) + 1;
      },
      close() {},
      ...pcOver,
    },
    channel:
      channel === null
        ? null
        : { readyState: "open", ordered: true, send() {}, close() {}, ...(channel || {}) },
    // Only a link `peer.offer`/`peer.answer` opened carries these — they are
    // what `wireChannel` fills. A quorum link has neither, which is a case
    // `peer.recv` has to refuse rather than crash on; asserted below.
    inbox: [],
    waiters: [],
  };
}

const add = (id, over = {}, spec = {}) =>
  registerLink({
    id,
    origin: "peer",
    role: "offerer",
    holder: holder(over),
    label: "basilisk",
    ...spec,
  });

afterEach(() => {
  __resetLinks();
});

const OFFER = ["v=0", "m=application 9 UDP/DTLS/SCTP webrtc-datachannel", "a=setup:actpass"].join(
  "\r\n"
);
const ANSWER = OFFER.replace("a=setup:actpass", "a=setup:active");

describe("a connection name is a recipe token, not a slot", () => {
  it("accepts the shapes a recipe can serialize back", () => {
    for (const id of ["a", "default", "alice-laptop", "peer_2", "n1.b", "AABBCC"]) {
      expect(normalizeLinkId(id)).toBe(id);
    }
    // Empty means the default connection, which is what makes the two-party
    // case free of ceremony: `peer.offer | out @offer`.
    expect(normalizeLinkId("")).toBe("default");
    expect(normalizeLinkId(undefined)).toBe("default");
  });

  it("names the @ mistake specifically, because it is the likely one", () => {
    // Everything else in this language that threads a value between cells is a
    // slot, so `peer.offer @a` is the habit rather than a typo. A bare charset
    // complaint would read as "your name has a bad character" and send a reader
    // hunting for one.
    let msg = "";
    try {
      normalizeLinkId("@a", "peer.offer");
    } catch (err) {
      msg = err.message;
    }
    expect(msg).toMatch(/without the @/);
    expect(msg).toMatch(/peer\.offer a/);
    expect(msg).toMatch(/not a slot/);
    // And an ordinary bad name still gets the charset sentence.
    expect(() => normalizeLinkId("has space")).toThrow(/letters, digits/);
    expect(() => normalizeLinkId("-lead")).toThrow(/letters, digits/);
  });
});

describe("the inventory projects facts and no verdicts", () => {
  it("reads pc and channel through the holder rather than copying them", () => {
    // The reason the record holds a holder at all: a quorum peer's channel does
    // not exist when its RTCPeerConnection is created, and a copied field would
    // be stale from the first renegotiation on — in the direction that reads as
    // "connected, no channel".
    const h = holder({ connectionState: "connecting", channel: null });
    registerLink({ id: "late", origin: "peer", role: "offerer", holder: h });
    expect(linkRow(getLink("late")).channelState).toBe("closed");

    h.channel = { readyState: "open", ordered: true };
    h.pc.connectionState = "connected";
    expect(linkRow(getLink("late")).channelState).toBe("open");
    expect(linkRow(getLink("late")).connectionState).toBe("connected");
  });

  it("reports a torn-down link as closed, never as new", () => {
    // `new` and `closed` are the two states `.peer-dot` draws identically-ish,
    // and reporting a dead link as `new` is the bug bfec72a fixed one layer up:
    // a connection that failed drew the same as one that never started.
    const h = holder();
    registerLink({ id: "gone", origin: "peer", role: "offerer", holder: h });
    h.pc = null;
    expect(linkRow(getLink("gone")).connectionState).toBe("closed");
    expect(linkRow(getLink("gone")).signalingState).toBe("closed");
  });

  it("carries authentication as a fact the owner patches, not a guess", () => {
    add("q", {}, { origin: "quorum", authenticated: false });
    expect(listLinkRows()[0].authenticated).toBe(false);
    patchLink("q", { authenticated: true });
    expect(listLinkRows()[0].authenticated).toBe(true);
  });
});

describe("closing is bounded by origin", () => {
  it("never lets peer.close reach the mesh's links", async () => {
    // The mesh's links are in the same inventory on purpose, and they belong to
    // `quorum.close`, which also has session keys to zeroize and a signalling
    // poll to stop. Tearing one down from here would leave QuorumSession
    // believing it still had a transport.
    add("direct-1");
    add("direct-2");
    add("MESHPEER", {}, { origin: "quorum" });

    const out = execPeerClose({});
    expect(out.type).toBe("connstate");
    expect(out.meta.closedIds.sort()).toEqual(["direct-1", "direct-2"]);
    expect(listLinksByOrigin("peer")).toHaveLength(0);
    expect(listLinksByOrigin("quorum").map((l) => l.id)).toEqual(["MESHPEER"]);
  });

  it("closes one by name, and says which", () => {
    add("a");
    add("b");
    const out = execPeerClose({ name: "a" });
    expect(out.meta.closedIds).toEqual(["a"]);
    expect(listLinksByOrigin("peer").map((l) => l.id)).toEqual(["b"]);
  });

  it("names what is open when a name is wrong", () => {
    // A typo and a cell run out of order are the two causes, and both are
    // obvious the moment the real names are on screen.
    add("alice");
    expect(() => execPeerClose({ name: "alicce" })).toThrow(/open connections: alice/);
    __resetLinks();
    expect(() => execPeerClose({ name: "alice" })).toThrow(/nothing is open/);
  });

  it("forgets a closed link, so the row goes with it", () => {
    add("a");
    expect(closeLink("a")).toBe(true);
    expect(getLink("a")).toBeNull();
    expect(closeLink("a")).toBe(false);
  });
});

describe("the refusals name the other op", () => {
  it("refuses an answer where an offer belongs, and points at peer.accept", async () => {
    add("a");
    await expect(
      execPeerAccept({ type: "sdp", data: OFFER }, { name: "a" })
    ).rejects.toThrow(/peer\.answer/);
    expect(ACCEPT_NOT_AN_ANSWER).toMatch(/a=setup:actpass/);
    expect(ANSWER_NOT_AN_OFFER).toMatch(/peer\.accept/);
  });

  it("trusts the artifact's own `which` before parsing the blob", async () => {
    // Same fact carried rather than re-derived — the value came from an op that
    // already knows which half it made.
    add("a");
    await expect(
      execPeerAccept({ type: "sdp", data: ANSWER, meta: { which: "offer" } }, { name: "a" })
    ).rejects.toThrow(/is an offer/);
  });

  it("refuses an answer for a connection that is not expecting one", async () => {
    // Accepting twice is the usual cause, and Chromium's own "Called in wrong
    // state" says nothing about which cell to stop re-running.
    add("a", { signalingState: "stable" });
    await expect(
      execPeerAccept({ type: "sdp", data: ANSWER }, { name: "a" })
    ).rejects.toThrow(/already been applied/);

    add("b", { signalingState: "have-remote-offer" });
    await expect(
      execPeerAccept({ type: "sdp", data: ANSWER }, { name: "b" })
    ).rejects.toThrow(/Only a connection that made an offer/);
  });

  it("refuses text that is not SDP at all", async () => {
    add("a", { signalingState: "have-local-offer" });
    await expect(
      execPeerAccept({ type: "text", data: "hello" }, { name: "a" })
    ).rejects.toThrow(/expects SDP/);
  });
});

describe("peer.wait is the ICE outcome, in connStateReadout's words", () => {
  it("refuses a failed link with the verdict the panel shows", async () => {
    // One function, two surfaces. A second sentence here would be the seventh
    // defect of the class the representation boundary exists to prevent.
    add("a", { connectionState: "failed" });
    await expect(execPeerWait({ name: "a" })).rejects.toThrow(/Could not connect/);
    await expect(execPeerWait({ name: "a" })).rejects.toThrow(/TURN relay/);
  });

  it("returns the live channel handle once the channel is open", async () => {
    add("a");
    const out = await execPeerWait({ name: "a" });
    expect(out.type).toBe("channel");
    expect(out.data.link).toBe("a");
    expect(out.data.origin).toBe("peer");
    expect(out.data.state).toBe("open");
  });

  it("says what it was still waiting on when it times out", async () => {
    // "still connecting after 1s (channel closed)" is actionable; "timed out"
    // is not.
    add("slow", { connectionState: "connecting", channel: { readyState: "connecting" } });
    await expect(execPeerWait({ name: "slow", wait: 1000 })).rejects.toThrow(
      /still connecting after 1s \(channel connecting\)/
    );
  });
});

describe("peer.send refuses a channel that is not open", () => {
  it("names the step that would make it open", async () => {
    add("a", { channel: { readyState: "connecting" } });
    await expect(
      execPeerSend({ type: "text", data: "hi" }, { name: "a" })
    ).rejects.toThrow(/peer\.wait a first/);
  });

  it("passes the value through unchanged on success", async () => {
    const sent = [];
    add("a", { channel: { send: (t) => sent.push(t) } });
    const value = { type: "text", data: "ping", meta: { sensitive: false } };
    expect(await execPeerSend(value, { name: "a" })).toBe(value);
    expect(sent).toEqual(["ping"]);
  });
});

describe("peer.recv shapes its output on a parameter, before the run", () => {
  it("emits one message as text and several as a bundle", async () => {
    const link = add("a");
    link.holder.inbox.push(
      { from: "a", text: "one", ts: 1 },
      { from: "a", text: "two", ts: 2 }
    );
    const single = await execPeerRecv({ name: "a" });
    expect(single.type).toBe("text");
    expect(single.data).toBe("one");

    link.holder.inbox.push({ from: "a", text: "three", ts: 3 });
    const many = await execPeerRecv({ name: "a", count: "all" });
    expect(many.type).toBe("bundle");
    expect(many.data.parts.map((p) => p.data)).toEqual(["two", "three"]);
  });

  it("refuses a quorum link by name instead of reading a missing inbox", async () => {
    // The mesh's links share this inventory and deliver their traffic through
    // the session's own decryption path, so there is no inbox here to read.
    registerLink({
      id: "MESHPEER",
      origin: "quorum",
      role: "offerer",
      holder: { pc: holder().pc, channel: holder().channel },
    });
    await expect(execPeerRecv({ name: "MESHPEER" })).rejects.toThrow(
      /is a quorum connection/
    );
    await expect(execPeerRecv({ name: "MESHPEER" })).rejects.toThrow(/Use quorum\.recv/);
  });

  it("times out with the connection named", async () => {
    add("a");
    await expect(execPeerRecv({ name: "a", wait: 1000 })).rejects.toThrow(
      /peer\.recv a: no message within 1s/
    );
  });
});

describe("restartLink", () => {
  it("re-runs ICE on one link and survives an engine without restartIce", () => {
    const link = add("a");
    expect(restartLink("a")).toBe(true);
    expect(link.holder.pc.__restarted).toBe(1);

    add("old", { restartIce: undefined });
    expect(restartLink("old")).toBe(false);
    expect(restartLink("nope")).toBe(false);
  });
});

describe("linkOriginNote is the one wording of the difference", () => {
  it("distinguishes an identity-bound link from a direct one", () => {
    const q = linkOriginNote("quorum");
    expect(q.label).toBe("verified");
    expect(q.tone).toBe("brand");
    expect(q.why).toMatch(/DTLS fingerprints/);

    const p = linkOriginNote("peer");
    expect(p.label).toBe("unauthenticated");
    expect(p.tone).toBe("warn");
    // The sentence a reader has to come away with: encrypted is not the same
    // as knowing who is on the other end.
    expect(p.why).toMatch(/nothing here proves who is on the other end/);
    expect(p.why).toMatch(/quorum\.offer/);
  });

  it("treats an unknown origin as the unauthenticated one", () => {
    // Defaulting the other way would let a missing field read as verified.
    expect(linkOriginNote("").label).toBe("unauthenticated");
    expect(linkOriginNote(undefined).label).toBe("unauthenticated");
  });
});

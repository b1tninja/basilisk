/**
 * The layering rule, asserted against the source rather than trusted.
 *
 * "The session is only to be a layer on top of the built-in WebRTC
 * functionality." That is a claim about which module constructs and drives an
 * `RTCPeerConnection`, and it is the kind of claim that decays quietly: the
 * next handler wired inline inside `NotebookSession` will work perfectly and
 * nothing will complain. So the two halves are pinned here — no built-in driven
 * from the layers *above* `lib/webrtc/`, and no import of those layers from
 * `lib/webrtc/` itself.
 *
 * **Two directories sit above it, and both are checked.** `lib/notebook/` is
 * the session and its transport; `lib/quorum/` is what the name now means on
 * its own — the m-of-n threshold scheme (`vss`, `dkg*`), which runs *over* a
 * session it must not reach into. The threshold half satisfies this trivially
 * today, which is the point of asserting it: `dkg-session.js` coordinates a run
 * across peers, and the cheap way to make that work is to grab the connection.
 *
 * **Driving is not the only way to hold one.** The first extraction passed this
 * file and every other suite while `NotebookSession` still kept nine handles: the
 * driver returned a link and the session unwrapped it to `peer.pc`, then called
 * `signalingState`, `restartIce` and `close` on the built-in exactly as before.
 * A grep for `new RTCPeerConnection` said "done" because the constructor had
 * moved. So possession is asserted too — no `.pc` anywhere above `lib/webrtc/`,
 * and no `RTC*` symbol in that executable text at all.
 *
 * The docstrings in both directories *discuss* every symbol asserted absent —
 * that is what they are for — so comments are stripped before any of these
 * assertions look at a file, and line endings normalised so a Windows checkout
 * and CI agree.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** @param {string} rel */
const dir = (rel) => fileURLToPath(new URL(rel, import.meta.url));

/**
 * @param {string} rel
 * @returns {{ name: string, code: string }[]}
 */
function readModules(rel) {
  const base = dir(rel);
  return readdirSync(base)
    .filter((f) => f.endsWith(".js"))
    .map((name) => ({
      name: `${rel.replace("../", "")}${name}`,
      code: readFileSync(`${base}/${name}`, "utf8")
        .replace(/\r\n/g, "\n")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, ""),
    }));
}

/** Everything above `lib/webrtc/`: the session layer and the threshold layer. */
const ABOVE = [...readModules("../lib/notebook/"), ...readModules("../lib/quorum/")];
const WEBRTC = readModules("../lib/webrtc/");

describe("the layers above lib/webrtc drive no WebRTC built-in", () => {
  /**
   * Construction, negotiation and channel creation. Not `channel.send` or
   * `channel.readyState`: the frames on a session channel are sealed under a key
   * only that layer holds, so writing them is the session's own business (that
   * is the line commit 4fe3322 drew, and it is the same line).
   */
  const DRIVING = [
    /\bnew\s+RTCPeerConnection\b/,
    /\bonnegotiationneeded\b/,
    /\bondatachannel\b/,
    /\bonicecandidate\b/,
    /\bonconnectionstatechange\b/,
    /\bcreateDataChannel\b/,
    /\bsetLocalDescription\b/,
    /\bsetRemoteDescription\b/,
    /\baddIceCandidate\b/,
    /\bsignalingState\b/,
    /\ba=fingerprint\b/,
  ];

  it.each(ABOVE)("$name", ({ name, code }) => {
    for (const rx of DRIVING) {
      expect(code, `${name} drives ${rx}`).not.toMatch(rx);
    }
  });
});

describe("the layers above lib/webrtc hold no WebRTC handle", () => {
  /**
   * Possession, which is the half a `new RTCPeerConnection` grep misses.
   *
   * `.pc` is the exact shape the regression took: `peer.pc = link.pc` in
   * `_ensurePeerConnection`, and eight reads following from it. There is no
   * legitimate `.pc` in this layer — a peer's transport is a `PeerLink` and
   * every use of it is a method call — so the property name itself is the
   * assertion.
   *
   * `RTC*` catches the rest: a `RTCDataChannel` variable, an `RTCIceServer`
   * literal, a `typeof RTCPeerConnection` capability check. Type *annotations*
   * are exempt by construction — this runs on comment-stripped source, and the
   * JSDoc in these modules names the very symbols asserted absent, which is
   * what JSDoc is for.
   */
  const HOLDING = [/\.pc\b/, /\bRTC[A-Z]\w*/];

  it.each(ABOVE)("$name holds none", ({ name, code }) => {
    for (const rx of HOLDING) {
      expect(code, `${name} holds ${rx}`).not.toMatch(rx);
    }
  });

  it("would catch the handle coming back", () => {
    // The regression, verbatim, against the same matcher — so a green run
    // above is evidence about the source rather than about the regex.
    const relapse = "  peer.pc = link.pc;\n  closePeerLink(peer.pc);\n";
    expect(HOLDING.some((rx) => rx.test(relapse))).toBe(true);
  });
});

describe("lib/webrtc knows nothing about the layers above it", () => {
  it.each(WEBRTC)("$name imports no session layer", ({ name, code }) => {
    // The direction that matters: `lib/webrtc/` is the layer underneath, and an
    // import upward would put `peer.*` — which has no PGP audience and no relay
    // — back in the position of needing the module that implements both.
    expect(code, `${name} imports upward`).not.toMatch(
      /from\s+["'][^"']*(quorum|notebook)/
    );
  });
});

describe("the driver exists and is the only place the connection is made", () => {
  it("constructs exactly one RTCPeerConnection across lib/webrtc", () => {
    const makers = WEBRTC.filter((m) => /\bnew\s+RTCPeerConnection\b/.test(m.code));
    expect(makers.map((m) => m.name)).toEqual(["lib/webrtc/peer-link.js"]);
  });
});

/**
 * The layering rule, asserted against the source rather than trusted.
 *
 * "Quorum is only to be a layer on top of the built-in WebRTC functionality."
 * That is a claim about which module constructs and drives an
 * `RTCPeerConnection`, and it is the kind of claim that decays quietly: the
 * next handler wired inline inside `QuorumSession` will work perfectly and
 * nothing will complain. So the two halves are pinned here — no built-in driven
 * from `lib/quorum/`, and no import of `lib/quorum/` from `lib/webrtc/`.
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

const QUORUM = readModules("../lib/quorum/");
const WEBRTC = readModules("../lib/webrtc/");

describe("lib/quorum drives no WebRTC built-in", () => {
  /**
   * Construction, negotiation and channel creation. Not `channel.send` or
   * `channel.readyState`: the frames on a quorum channel are sealed under a key
   * only this layer holds, so writing them is the session's own business (that
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

  it.each(QUORUM)("$name", ({ name, code }) => {
    for (const rx of DRIVING) {
      expect(code, `${name} drives ${rx}`).not.toMatch(rx);
    }
  });
});

describe("lib/webrtc knows nothing about quorum", () => {
  it.each(WEBRTC)("$name imports no session layer", ({ name, code }) => {
    // The direction that matters: `lib/webrtc/` is the layer underneath, and an
    // import upward would put `peer.*` — which has no PGP audience and no relay
    // — back in the position of needing the module that implements both.
    expect(code, `${name} imports upward`).not.toMatch(/from\s+["'][^"']*quorum/);
  });
});

describe("the driver exists and is the only place the connection is made", () => {
  it("constructs exactly one RTCPeerConnection across lib/webrtc", () => {
    const makers = WEBRTC.filter((m) => /\bnew\s+RTCPeerConnection\b/.test(m.code));
    expect(makers.map((m) => m.name)).toEqual(["lib/webrtc/peer-link.js"]);
  });
});

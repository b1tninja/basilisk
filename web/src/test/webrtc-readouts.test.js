/**
 * The WebRTC panels, judged by the only question they are ever asked.
 *
 * These screens are where a user lands **after** a connection has failed, so a
 * panel that renders every field correctly and leaves "why did this not
 * connect, and what do I do next" unanswered has failed. Each assertion below
 * pins one sentence that was missing, or one number that was being drawn as a
 * measurement without having been measured.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  connStateReadout,
  sdpReadout,
  stunReachability,
  SDP_TRANSPORT_CLOSED,
} from "../lib/toolkit/artifact-readouts.js";
import { SHELF_META, TOOLBOX_META, listSteps } from "../lib/toolkit/registry.js";

/** Read a source file with line endings normalised — CI is LF, Windows is CRLF. */
function source(rel) {
  return readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8").replace(/\r\n/g, "\n");
}

/**
 * Comments are not code. Asserting a symbol is absent without stripping them
 * first passes on a file that still calls it and mentions it in prose, and
 * fails on a file that only mentions it — both wrong.
 */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

/** Every value `RTCPeerConnection.connectionState` is specified to take. */
const CONNECTION_STATES = [
  "new",
  "connecting",
  "connected",
  "disconnected",
  "failed",
  "closed",
];

describe("connStateReadout — the strip that could not draw a failure", () => {
  it("marks a stage for every state the browser can produce", () => {
    // The regression. `failed` was absent from the five-stage track, so
    // `indexOf` returned -1, no segment was lit and no label was bolded: a
    // failed peer connection drew pixel-identical to one that had never
    // started, on the one panel that exists for exactly that state.
    for (const state of CONNECTION_STATES) {
      const read = connStateReadout({ connectionState: state });
      const lit = read.stages.some((s) => s.state !== "ahead") || !!read.terminal;
      expect(lit, `${state} left the whole strip blank`).toBe(true);
      expect(read.headline, `${state} has no headline`).toBeTruthy();
    }
  });

  it("gives every non-working state a cause and every recoverable one a next step", () => {
    for (const state of ["new", "disconnected", "failed", "closed"]) {
      expect(connStateReadout({ connectionState: state }).why, `${state} says nothing`).toBeTruthy();
    }
    expect(connStateReadout({ connectionState: "failed" }).next).toMatch(/TURN/);
    expect(connStateReadout({ connectionState: "disconnected" }).next).toMatch(/restart/i);
  });

  it("says nothing when nothing is wrong", () => {
    const ok = connStateReadout({ connectionState: "connected", channelState: "open" });
    expect(ok.why).toBeNull();
    expect(ok.next).toBeNull();
    expect(ok.terminal).toBeNull();
  });

  it("separates the SCTP phase from a failure to find a route", () => {
    // "Connected" beside a channel that will not open is the one state where
    // both "it connected" and "nothing works" are true, and where advising a
    // TURN relay sends the reader after the wrong problem entirely.
    const sctp = connStateReadout({ connectionState: "connected", channelState: "connecting" });
    expect(sctp.headline).toMatch(/channel/i);
    expect(sctp.why).toMatch(/SCTP/);
    expect(sctp.next).not.toMatch(/TURN/);
  });

  it("draws outcomes as outcomes, not as later milestones", () => {
    // `disconnected` and `closed` used to sit in line after `connected`, which
    // said a healthy connection is progressing toward being closed.
    for (const state of ["disconnected", "failed", "closed"]) {
      const read = connStateReadout({ connectionState: state });
      expect(read.terminal?.name).toBe(state);
      expect(read.stages.map((s) => s.name)).toEqual(["new", "connecting", "connected"]);
      expect(read.stages.some((s) => s.state === "current")).toBe(false);
    }
  });
});

describe("stunReachability — a verdict from what the op actually measured", () => {
  it("never reports on relay, because stun.check never probes for one", () => {
    // `execStunCheck` refuses any server that is not `stun:`/`stuns:` and
    // builds its connection with no username and no credential, so it can
    // never attempt an allocation — its relay count is a constant, verified
    // against a live coturn that was relaying for two peers at the time
    // (b6a33a4). A "no TURN configured" verdict derived from it would be the
    // panel guessing on the screen a user reaches when a call has failed.
    const cases = [
      { candidates: { host: 4, srflx: 0 } },
      { candidates: { host: 1, srflx: 1 }, publicAddress: "203.0.113.9:1" },
      { candidates: { host: 1, srflx: 1, relay: 3 } },
      { candidates: {} },
    ];
    for (const data of cases) {
      const read = stunReachability(data);
      // The verdict and the cause are statements about what was measured, so
      // neither may name a candidate type this op cannot obtain. `next` may —
      // "only a TURN relay over TCP/TLS will get out" is advice about the
      // remedy, not a claim about a count.
      const measured = `${read.verdict} ${read.why}`;
      expect(measured, JSON.stringify(data)).not.toMatch(/\brelay\b/i);
      const said = `${measured} ${read.next || ""}`;
      expect(said, JSON.stringify(data)).not.toMatch(/no TURN (is )?configured/i);
      expect(said, JSON.stringify(data)).not.toMatch(/relay\s*[×x]\s*\d/i);
    }
  });

  it("tells host-only apart from nothing at all", () => {
    // The two need different fixes: host candidates with no srflx is a STUN
    // round trip that never completed, and no candidates at all is a config or
    // secure-context problem. One badge for both is the panel giving up.
    expect(stunReachability({ candidates: { host: 4, srflx: 0 } }).verdict).toMatch(/did not answer/i);
    expect(stunReachability({ candidates: { host: 0, srflx: 0 } }).verdict).toMatch(/nothing gathered/i);
    expect(stunReachability({ candidates: { host: 1, srflx: 1 } }).tone).toBe("brand");
  });

  it("treats an unreported mix as unreported, not as a mix of zeroes", () => {
    // The same mistake as the relay count, one level up: `stun.check` only
    // began counting candidates once the transport was driven against real
    // browsers, so an older result carries an address and no breakdown.
    // Reading that as "gathered nothing" printed a contradiction — `nothing
    // gathered` beside a discovered public address.
    const read = stunReachability({ ok: true, publicAddress: "203.0.113.9:60122" });
    expect(read.verdict).not.toMatch(/nothing gathered/i);
    expect(read.tone).toBe("brand");
    expect(read.why).toMatch(/not known|no candidate breakdown/i);
  });
});

describe("sdpReadout — the blob, and the transport that is already gone", () => {
  const OFFER = [
    "v=0",
    "o=- 1 2 IN IP4 127.0.0.1",
    "m=application 60476 UDP/DTLS/SCTP webrtc-datachannel",
    "a=candidate:1 1 udp 2113937151 4a11.local 60476 typ host generation 0",
    "a=candidate:2 1 udp 1677729535 99.105.33.21 60476 typ srflx raddr 0.0.0.0 rport 0",
    "a=fingerprint:sha-256 32:81:EB:EE:4A:8F:0B:63",
    "a=setup:actpass",
  ].join("\n");

  it("pulls out the three lines a human opens an SDP for", () => {
    const read = sdpReadout(OFFER);
    expect(read.fingerprint).toEqual({ algorithm: "sha-256", value: "32:81:EB:EE:4A:8F:0B:63" });
    expect(read.setup).toBe("actpass");
    expect(read.transport).toBe("application UDP/DTLS/SCTP");
    expect(read.candidates).toEqual([
      { type: "host", count: 1 },
      { type: "srflx", count: 1 },
    ]);
  });

  it("always states that the connection it describes is already closed", () => {
    // `rtc.offer` and `rtc.answer` each close their `RTCPeerConnection` in a
    // `finally` before returning. The blob is well-formed and its transport is
    // gone, so `sdp-hand-carried` and `sdp-to-clipboard` describe a flow that
    // cannot complete. The panel says so rather than letting a reader find out
    // by watching a handshake time out.
    for (const blob of [OFFER, "", "not an sdp at all"]) {
      const read = sdpReadout(blob);
      expect(read.liveTransport).toBe(false);
      expect(read.note).toBe(SDP_TRANSPORT_CLOSED);
    }
    expect(SDP_TRANSPORT_CLOSED).toMatch(/already closed/i);
    expect(SDP_TRANSPORT_CLOSED).toMatch(/cannot complete a handshake/i);
  });

  it("is total — a blob it cannot parse yields empty fields, never a throw", () => {
    const read = sdpReadout("garbage");
    expect(read.fingerprint).toBeNull();
    expect(read.setup).toBe("");
    expect(read.candidates).toEqual([]);
  });
});

describe("the panels themselves", () => {
  const widget = source("../toolkit/widgets/NetworkArtifact.tsx");
  const css = source("../css/toolkit.css");

  it("does not dim the sentence that carries the diagnosis", () => {
    // The absent-candidate rows and the non-nominated pair rows used to carry
    // `opacity-45` / `opacity-50`, which took their explanations down with the
    // badge: "none gathered — no TURN configured" measured 2.16:1 in light and
    // 2.39:1 in dark, making the panel's own diagnosis the least readable text
    // on it (WCAG 1.4.3). The badge fades; the words do not.
    const code = stripComments(widget);
    expect(code).not.toMatch(/opacity-4[05]|opacity-50/);
  });

  it("draws its badges on the shared tint token, not a hand-written alpha", () => {
    // `.net-badge` hard-coded 12%. `--tile-tint` is 12% in dark and 6% in
    // light, which is the entire reason it is a token — the light accents are
    // chosen to clear 4.5:1 on the plain surface, and a 12% wash of the accent
    // under its own text spends that margin. Measured: every one of the twenty
    // network badges sat between 3.96:1 and 4.20:1 in light while the
    // identically-hued `.artifact-badge` passed.
    const rules = css.slice(css.indexOf(".net-badge"), css.indexOf(".net-stage"));
    expect(rules).toMatch(/var\(--tile-tint\)/);
    expect(rules).not.toMatch(/\)\s+12%,\s*transparent/);
  });

  it("keeps the connection-state bar out of the accessibility tree", () => {
    // The bar is a picture of the headline above it. Read aloud it was five
    // stage words with a font weight as the only marker of which one was
    // current, which conveys nothing (WCAG 1.3.1).
    expect(widget).toMatch(/data-stage=/);
    expect(widget).toMatch(/aria-hidden/);
  });
});

describe("the WebRTC glyph vocabulary", () => {
  it("no longer signs a peer connection with a vault key", () => {
    // `TOOLBOX_META.webrtc`, `SHELF_META.peer` and `SHELF_META.channel` all
    // pointed at `agent`, and enumerating every step showed `agent` resolving
    // for exactly seven ops — every one of them WebRTC, and none of them an
    // `agent.*` op. The mark belonged to the toolbox that had never been
    // drawn, not to the one it was named after.
    expect(TOOLBOX_META.webrtc.glyph).toBe("webrtc");
    expect(SHELF_META.peer.glyph).toBe("peer");
    expect(SHELF_META.channel.glyph).toBe("channel");
    const wearingAgent = listSteps().filter((s) => s.glyph === "agent");
    expect(wearingAgent.map((s) => s.name)).toEqual([]);
  });

  it("lets the shelf be the single source of its ops' marks", () => {
    // The seven steps each declared `glyph: "agent"` explicitly, duplicating
    // what their shelf already said. A fact spelled in two places is a defect
    // already, whether or not the two currently agree — which is how the shelf
    // could be corrected and the ops keep the old mark.
    const registry = stripComments(source("../lib/toolkit/registry.js"));
    const byName = new Map(listSteps().map((s) => [s.name, s]));
    // The seven that wore `agent`. `rtc.certificate` shares the `peer` shelf
    // and keeps its own `genkey` mark on purpose — it mints key material, and
    // that is a real reason to differ from the shelf rather than a leftover.
    for (const name of ["quorum.offer", "quorum.join", "quorum.close", "rtc.offer", "rtc.answer"]) {
      expect(byName.get(name)?.glyph, name).toBe("peer");
    }
    for (const name of ["rtc.send", "rtc.recv"]) {
      expect(byName.get(name)?.glyph, name).toBe("channel");
    }
    expect(registry).not.toMatch(/glyph:\s*"agent",\s*\n\s*doc:/);
  });
});

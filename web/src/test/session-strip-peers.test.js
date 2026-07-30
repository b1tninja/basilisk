/**
 * SessionStrip's per-peer roster (p2p-dkg DESIGN §6 — "per-peer, not
 * per-session").
 *
 * The defect being closed: a session-level summary reads identically whether
 * every link in a mesh is healthy or one has died. These are the pure
 * derivations behind the degraded badges, kept testable without a renderer —
 * the rendering itself is exercised in the widget catalog, which is where the
 * handoff says UI defects actually surface.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const CSS = readFileSync(
  fileURLToPath(new URL("../css/toolkit.css", import.meta.url)),
  "utf8"
);
const SRC = readFileSync(
  fileURLToPath(new URL("../toolkit/widgets/SessionStrip.tsx", import.meta.url)),
  "utf8"
);

/** Mirrors the component's own derivation. */
function degraded(peers) {
  return {
    broken: peers.filter((p) => p.state === "failed" || p.state === "disconnected").length,
    unverified: peers.filter((p) => p.state === "connected" && !p.authenticated).length,
  };
}

describe("degraded-mesh derivation", () => {
  it("counts a dead link even while the session says connected", () => {
    const peers = [
      { id: "a", state: "connected", authenticated: true },
      { id: "b", state: "failed", authenticated: true },
    ];
    expect(degraded(peers).broken).toBe(1);
  });

  it("counts connected-but-unverified separately from broken", () => {
    // The two axes stay independent: a peer can be fully connected and
    // completely unverified, and conflating them is how you trust the wrong
    // end of a working pipe.
    const peers = [
      { id: "a", state: "connected", authenticated: false },
      { id: "b", state: "failed", authenticated: true },
    ];
    expect(degraded(peers)).toEqual({ broken: 1, unverified: 1 });
  });

  it("does not call a still-connecting peer unverified", () => {
    // A handshake in progress has not failed verification — it has not
    // reached it. Badging it would cry wolf on every join.
    const peers = [
      { id: "a", state: "connecting" },
      { id: "b", state: "new" },
    ];
    expect(degraded(peers)).toEqual({ broken: 0, unverified: 0 });
  });

  it("a healthy mesh raises nothing", () => {
    const peers = [
      { id: "a", state: "connected", authenticated: true },
      { id: "b", state: "connected", authenticated: true },
    ];
    expect(degraded(peers)).toEqual({ broken: 0, unverified: 0 });
  });
});

describe("CSP conversion of the status dot", () => {
  it("carries no style prop", () => {
    // The whole point of the conversion: `style-src 'self'` blocks every
    // element.style write, including the ones React makes from a style object.
    expect(SRC).not.toMatch(/style=\{\{/);
  });

  it("enumerates every session tone in CSS", () => {
    for (const tone of ["offering", "waiting", "connected", "failed", "closed"]) {
      expect(CSS, tone).toContain(`.session-dot[data-session-tone="${tone}"]`);
    }
  });

  it("keeps the live glow, which used to be an inline boxShadow", () => {
    expect(CSS).toMatch(/\[data-session-live="1"\][\s\S]*?box-shadow/);
  });

  it("reuses the peer-dot rules rather than a parallel set", () => {
    expect(SRC).toContain('className="peer-dot');
    expect(CSS).toContain('.peer-dot[data-peer-state="connected"]');
  });
});

describe("the auth verdict is withheld until there is a link to judge", () => {
  it("only renders verified/unverified for settled peers", () => {
    // Caught in the widget catalog: a peer mid-handshake rendered
    // "unverified", which reads as a verdict on a peer that has not reached
    // verification. Connecting/new peers show their state instead.
    expect(SRC).toMatch(/p\.state === "connected" \|\| p\.state === "failed"/);
  });
});

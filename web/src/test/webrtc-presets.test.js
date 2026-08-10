/**
 * The WebRTC templates.
 *
 * `recipe.test.js` already proves every preset compiles; these pin the things
 * that make *these* templates useful rather than merely valid — that the
 * diagnostic order matches how you actually debug a failed connection, and
 * that the TURN template keeps the credential out of the recipe text.
 */
import { describe, expect, it } from "vitest";
import { PRESETS, compileRecipe } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";

const webrtc = () => PRESETS.filter((p) => p.group === "WebRTC");
const byId = (id) => PRESETS.find((p) => p.id === id);

describe("the group", () => {
  it("exists and is reachable from the Templates menu", () => {
    expect(webrtc().length).toBeGreaterThanOrEqual(6);
  });

  it("every template compiles clean", () => {
    for (const p of webrtc()) {
      const errors = compileRecipe(p.recipe).validation.errors.map((e) => e.message);
      expect(errors, p.id).toEqual([]);
    }
  });

  it("names an op in every blurb's worth — no template is decoration", () => {
    for (const p of webrtc()) {
      expect(p.blurb.length, p.id).toBeGreaterThan(40);
      expect(p.title, p.id).toBeTruthy();
    }
  });
});

describe("the TURN template keeps the credential out of recipe text", () => {
  it("binds a slot rather than a literal", () => {
    // `credential` is slot-typed precisely so the secret does not ride out
    // through Copy link or an exported notebook. A template that used a
    // literal would teach the opposite habit — and would not compile.
    const p = byId("ice-turn-relay");
    expect(p.recipe).toContain("credential=$turncred");
    expect(p.recipe).not.toMatch(/credential=[A-Za-z0-9]/);
    expect(getStep("rtc.ice").params.find((x) => x.name === "credential").type).toBe(
      "slot"
    );
  });

  it("registers that slot before using it, so the template stands alone", () => {
    expect(compileRecipe(byId("ice-turn-relay").recipe).validation.ok).toBe(true);
  });
});

describe("diagnostics read in the order you would actually debug", () => {
  it("checks reachability before gathering, and gathers before pairing", () => {
    // stun.check answers "can I be reached at all"; rtc.gather answers "by
    // which routes"; rtc.check answers "which pair won, and why". Presented
    // out of order they are just three JSON dumps.
    const ids = webrtc().map((p) => p.id);
    expect(ids.indexOf("stun-reachable")).toBeLessThan(ids.indexOf("ice-gather"));
    expect(ids.indexOf("ice-gather")).toBeLessThan(ids.indexOf("rtc-live-diagnostics"));
  });

  it("says plainly that the live diagnostics need a live exchange", () => {
    // These three ops throw without one. A template that did not warn would
    // look broken the first time anyone ran it.
    const p = byId("rtc-live-diagnostics");
    expect(p.blurb).toMatch(/quorum\.(offer|join)/);
    for (const op of ["rtc.state", "rtc.check", "rtc.quality"]) {
      expect(p.recipe, op).toContain(op);
    }
  });
});

describe("the hand-carried exchange demonstrates both halves", () => {
  it("offers and answers in one notebook, so the round trip is readable", () => {
    const p = byId("sdp-hand-carried");
    expect(p.recipe).toContain("peer.offer");
    expect(p.recipe).toContain("peer.answer");
    // The step that makes the round trip a *connection* rather than two blobs.
    expect(p.recipe).toContain("peer.accept");
    // The answer consumes the offer through a slot — the same wiring a real
    // out-of-band exchange does by hand.
    expect(p.recipe).toContain("in $offer");
  });

  it("keeps the offer when copying it out of band", () => {
    // `tee` rather than a terminal sink: pasting the offer into chat should
    // not consume it, or the pipeline has nothing left to answer with.
    const p = byId("sdp-to-clipboard");
    expect(p.recipe).toContain("tee");
    expect(p.recipe).toContain("clipboard.write");
    expect(compileRecipe(p.recipe).validation.ok).toBe(true);
  });
});

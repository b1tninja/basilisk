/**
 * Mesh relay rules — the pure layer under channel-first signaling.
 *
 * The trust question is settled elsewhere (envelopes are sealed and
 * transcript-bound end to end); what these rules own is loops, floods, and
 * honesty about mesh capacity.
 */
import { describe, expect, it } from "vitest";
import {
  MAX_RELAY_HOPS,
  MESH_SOFT_CAP,
  classifyChannelFrame,
  createSeenSet,
  meshHealth,
  shouldRelay,
} from "../lib/notebook/relay.js";

const ME = "A".repeat(40);
const OTHER = "B".repeat(40);

describe("shouldRelay", () => {
  it("forwards frames for someone else, within the hop budget", () => {
    expect(shouldRelay({ to: OTHER, myFpr: ME, hops: 0 })).toBe(true);
    expect(shouldRelay({ to: OTHER, myFpr: ME, hops: MAX_RELAY_HOPS - 1 })).toBe(true);
  });

  it("never forwards its own frames or exhausted ones", () => {
    expect(shouldRelay({ to: ME, myFpr: ME, hops: 0 })).toBe(false);
    expect(shouldRelay({ to: "", myFpr: ME, hops: 0 })).toBe(false);
    expect(shouldRelay({ to: OTHER, myFpr: ME, hops: MAX_RELAY_HOPS })).toBe(false);
  });
});

describe("classifyChannelFrame", () => {
  it("recognizes envelope frames and defaults missing hops to zero", () => {
    expect(classifyChannelFrame(JSON.stringify({ v: 1, env: "-----ARMOR" }))).toEqual({
      kind: "envelope",
      env: "-----ARMOR",
      hops: 0,
    });
    expect(
      classifyChannelFrame(JSON.stringify({ v: 1, env: "x", hops: 2 })).hops
    ).toBe(2);
  });

  it("recognizes session traffic and rejects junk without throwing", () => {
    expect(classifyChannelFrame(JSON.stringify({ v: 1, blob: "ct" }))).toEqual({
      kind: "session",
      blob: "ct",
    });
    for (const junk of ["", "not json", "42", JSON.stringify({}), JSON.stringify({ env: "" })]) {
      expect(classifyChannelFrame(junk), junk).toBeNull();
    }
  });

  it("does not let a hostile hops value melt the budget", () => {
    expect(classifyChannelFrame(JSON.stringify({ env: "x", hops: -5 })).hops).toBe(0);
    expect(classifyChannelFrame(JSON.stringify({ env: "x", hops: "NaN" })).hops).toBe(0);
  });
});

describe("createSeenSet", () => {
  it("reports a repeat and stays bounded under flood", () => {
    const s = createSeenSet(3);
    expect(s.seen("a")).toBe(false);
    expect(s.seen("a")).toBe(true);
    s.seen("b");
    s.seen("c");
    s.seen("d"); // evicts "a"
    expect(s.seen("a")).toBe(false); // forgotten — bounded memory, not perfect memory
    expect(s.seen("d")).toBe(true);
  });
});

describe("meshHealth", () => {
  it("computes the quadratic honestly", () => {
    expect(meshHealth(3)).toMatchObject({ participants: 3, degree: 2, links: 3, overCap: false });
    expect(meshHealth(7).links).toBe(21); // the DESIGN §1 example
  });

  it("warns past the soft cap and says why", () => {
    const h = meshHealth(MESH_SOFT_CAP + 1);
    expect(h.overCap).toBe(true);
    expect(h.note).toMatch(/degrades|expect slow/i);
    expect(meshHealth(MESH_SOFT_CAP).overCap).toBe(false);
  });

  it("degenerate rooms do not produce nonsense", () => {
    expect(meshHealth(0)).toMatchObject({ participants: 0, degree: 0, links: 0 });
    expect(meshHealth(1).links).toBe(0);
  });
});

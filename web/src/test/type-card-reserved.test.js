/**
 * The "reserved" badge on a type card.
 *
 * It exists to tell a reader that a declared type is one no recipe can
 * currently obtain. It was unreachable for every type it was written for,
 * because it required no producers *and* no consumers — and the generic
 * sinks accept anything, so every type has consumers. The badge that
 * described the state was the one state it could never describe.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { consumersOf, listTypes, producersOf } from "../lib/toolkit/type-registry.js";

const CARD = readFileSync(
  fileURLToPath(new URL("../toolkit/widgets/TypeCard.tsx", import.meta.url)),
  "utf8"
);

describe("consumers cannot distinguish anything", () => {
  it("shows every declared type has the same generic sinks accepting it", () => {
    // This is why the old conjunction failed. `out`, `peek`, `inspect`, `tee`
    // and friends take any value, so "has no consumers" is only ever true for
    // `none` — which made the badge unreachable rather than rare.
    const counts = listTypes()
      .filter((t) => t.base !== "none")
      .map((t) => consumersOf(t.base).length);
    expect(Math.min(...counts)).toBeGreaterThan(0);
  });
});

describe("reserved keys on producers", () => {
  it("is derived from producers alone", () => {
    expect(CARD).toMatch(/const orphan = !producers\.length;/);
    expect(CARD).not.toMatch(/const orphan = !producers\.length && !consumers\.length/);
  });

  it("says what is actually true of a reserved type", () => {
    expect(CARD).toMatch(/no step produces one yet/);
  });

  it("catches the types a recipe genuinely cannot obtain", () => {
    // item, peer, host — declared, documented, and unmakeable. `item` is
    // reserved in its own doc text, so the badge agrees with the prose rather
    // than contradicting it.
    //
    // `channel` left this list when `peer.wait` gave it a producer (§56). That
    // is the assertion's whole job: a type stops being reserved the moment a
    // step can make one, and the card must stop saying otherwise.
    const unmakeable = listTypes()
      .filter((t) => !t.literal && producersOf(t.base).length === 0)
      .map((t) => t.base)
      .sort();
    expect(unmakeable).toEqual(["host", "item", "none", "peer"]);
  });

  it("does not claim a producible type is reserved", () => {
    for (const base of ["keypair", "session", "channel", "candidate", "sdp", "text", "bytes"]) {
      expect(producersOf(base).length, base).toBeGreaterThan(0);
    }
  });

  it("leaves `int` to the literal branch, which fires first", () => {
    // int has no producing step but can be written directly, so "reserved"
    // would be actively wrong for it.
    const int = listTypes().find((t) => t.base === "int");
    // `literal` is a descriptor ({form, placeholder, example, hint}), not a
    // boolean — the branch tests it for truthiness.
    expect(int.literal).toBeTruthy();
    expect(int.literal.form).toBe("int");
    expect(producersOf("int").length).toBe(0);
    // The literal branch precedes the orphan branch in the chain.
    expect(CARD.indexOf("meta.literal ?")).toBeLessThan(CARD.indexOf("orphan ?"));
  });
});

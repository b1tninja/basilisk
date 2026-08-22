/**
 * A name drawn in `GLYPH_PATHS` is the name that draws it.
 *
 * Two maps answer "what mark does this name wear": `KIND_GLYPHS`, which points
 * at lucide icons, and `GLYPH_PATHS`, which holds this project's own drawings.
 * `kindGlyph` consulted the first and fell through to the second, and that was
 * written down as a precedence rule with an example — `share` is `Users` here
 * and `shares` is an asset there — that is not a conflict at all. They are two
 * different strings and never met.
 *
 * Where names really did meet, the rule threw the drawn mark away silently.
 * Five did: `text`, `shares`, `recipients`, `inspect` and `channel` each had a
 * purpose-drawn asset that no consumer of `kindGlyph` could reach. The visible
 * results were `inspect` drawing the same `Binary` as `bytes` while a
 * magnifying glass sat unused, and one concept wearing two different marks in
 * one app — a `recipients` toolbox tab renders its asset through `Glyph`
 * directly, so the tab and the badge for the same idea disagreed.
 *
 * So the invariant is not a precedence order, which is a rule about which of
 * two answers wins. It is that there is only ever one answer: **no name
 * appears in both maps.** That is what makes the `||` in `kindGlyph` unable to
 * shadow anything, whichever way round it is written.
 */
import { describe, expect, it } from "vitest";
import { GLYPH_PATHS } from "../lib/toolkit/glyphs.js";
import { KIND_GLYPHS, kindGlyph } from "../toolkit/widgets/kind-glyphs";

/**
 * Marks still worn by more than one name, and the two are not the same case.
 *
 * `key-public` and `key-secret` are **deliberate and already argued
 * elsewhere**: they are this project's own key assets, and the axis they draw
 * is sensitivity rather than identity, so an SSH public key and an OpenPGP
 * public key wearing one bow is the design. `artifact-kinds-table.test.js`
 * pins that from the other direction — it checks the tint and the glyph pick
 * the same side of that axis — and this file must not contradict it.
 *
 * `Activity` is the open question. Nothing has decided whether a connection
 * state, a diagnostic and a statistic should be told apart, and unlike the
 * five names this file was written for, none of the three has a drawing being
 * thrown away — so there is nothing to recover, only a design call to make.
 *
 * Either way the list may only ever shrink, and it is a list rather than a
 * loose "some sharing is fine" rule so that a *new* collision fails instead of
 * quietly joining a crowd.
 */
const SHARED_MARKS = {
  "key-secret": ["key", "secret-key", "ssh-private"],
  "key-public": ["public-key", "ssh-public"],
  Activity: ["connstate", "diag", "stats"],
};

describe("the two glyph maps do not answer the same question", () => {
  it("finds the maps it is measuring", () => {
    // An empty sweep passes every assertion below it.
    expect(Object.keys(KIND_GLYPHS).length, "KIND_GLYPHS is empty").toBeGreaterThan(10);
    expect(Object.keys(GLYPH_PATHS).length, "GLYPH_PATHS is empty").toBeGreaterThan(20);
  });

  it("gives no name an entry in both maps", () => {
    const both = Object.keys(KIND_GLYPHS).filter((k) => GLYPH_PATHS[k]);
    expect(
      both,
      `these names are in KIND_GLYPHS and also drawn in GLYPH_PATHS, so the drawing is unreachable: ${both.join(", ")}`
    ).toEqual([]);
  });

  it("resolves every drawn name to its own drawing", () => {
    const wrong = [];
    for (const name of Object.keys(GLYPH_PATHS)) {
      const got = kindGlyph(name);
      if (got !== name) wrong.push(`${name} → ${typeof got === "string" ? got : "a lucide icon"}`);
    }
    expect(wrong, `a drawn name resolved to something other than its drawing: ${wrong.join(", ")}`).toEqual([]);
  });

  it("keeps the five that were being shadowed pointed at their own art", () => {
    // Named rather than swept, because "no overlap" above is also satisfied by
    // deleting the drawings — which would close the test and lose the marks.
    for (const name of ["text", "shares", "recipients", "inspect", "channel"]) {
      expect(GLYPH_PATHS[name], `${name} lost its drawing`).toBeTruthy();
      expect(kindGlyph(name), `${name} is shadowed again`).toBe(name);
    }
  });

  it("shares a mark only where it is written down", () => {
    /** @type {Record<string, string[]>} */
    const byIcon = {};
    for (const [name, icon] of Object.entries(KIND_GLYPHS)) {
      const id = icon?.displayName || icon?.name || String(icon);
      (byIcon[id] ||= []).push(name);
    }
    const shared = Object.fromEntries(
      Object.entries(byIcon)
        .filter(([, names]) => names.length > 1)
        .map(([id, names]) => [id, names.sort()])
    );
    expect(
      shared,
      "a mark is worn by more than one name and is not on the exemption list"
    ).toEqual(SHARED_MARKS);
  });

  it("keeps the exemption list honest — nothing on it has art of its own", () => {
    // The moment one of these names is drawn, it stops being an open design
    // question and becomes the shadowing defect this file exists to prevent.
    // The key rows pass this for a different reason than they look: their
    // *values* are asset ids, but no `key`, `secret-key`, `public-key`,
    // `ssh-private` or `ssh-public` is itself drawn, so nothing is shadowed.
    for (const names of Object.values(SHARED_MARKS)) {
      for (const name of names) {
        expect(GLYPH_PATHS[name], `${name} is drawn now, so it must leave KIND_GLYPHS`).toBeFalsy();
      }
    }
  });
});

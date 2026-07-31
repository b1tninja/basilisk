/**
 * One state, one treatment: an op that does not fit the caret.
 *
 * The shelf had three answers to the same question. A solo row deleted its
 * add button outright, so the row lost both its affordance and any statement
 * of why. A pair row kept both direction handles, painted them
 * `cursor-not-allowed opacity-40`, and left them fully live — clicking one
 * appended the step regardless, and it stayed in the tab order. A row where
 * neither direction fitted went to `opacity-[.32]` and its handles still
 * worked. So the same condition looked disabled and worked, looked disabled
 * and vanished, and looked enabled and worked, depending on which row you
 * happened to be on.
 *
 * Measured in the production build, light theme, before the change: the op
 * name in a dimmed row sat at 1.97:1 against the shelf background and its
 * "needs bytes" caption at 1.59:1 — the explanation of the state was the
 * least readable text on the screen.
 *
 * Source-level assertions, because the failure mode is presentational and
 * jsdom reports neither computed contrast nor drag behaviour.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELF = read("../toolkit/widgets/OpsShelf.tsx");
const TILE = read("../toolkit/widgets/OpsTile.tsx");
/** Comment-free copies — both files explain the old values in prose. */
const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const SHELF_CODE = strip(SHELF);
const TILE_CODE = strip(TILE);

describe("an op that doesn't fit still explains itself", () => {
  it("never dims a row by opacity into illegibility", () => {
    // .32 multiplied into the caption too. The colour step is applied to the
    // text and the opacity survives only on the glyph, which carries none.
    expect(SHELF_CODE).not.toMatch(/opacity-\[\.32\]/);
    expect(TILE_CODE).not.toMatch(/opacity-\[\.32\]/);
  });

  it("steps the name down to a token, not to a fraction", () => {
    expect(SHELF).toMatch(/const OPS_DIM_TEXT = "text-\[var\(--muted-foreground\)\]"/);
    expect(TILE).toMatch(/dim \? "text-\[var\(--muted-foreground\)\]"/);
  });

  it("keeps the solo control in place, disabled, rather than removing it", () => {
    // Removing it made rows shift sideways as the caret moved and left the
    // row unable to say anything about its own state.
    expect(SHELF_CODE).toMatch(/<AddButton\s+disabled=\{unfit\}/);
    expect(SHELF_CODE).not.toMatch(/!fit && tipFit \? null : \(/);
  });

  it("makes an unfitting direction handle genuinely inert", () => {
    expect(TILE).toMatch(/const forwardLive = hasForward && !needs\?\.forward;/);
    expect(TILE).toMatch(/const reverseLive = hasReverse && !needs\?\.reverse;/);
    expect(TILE).toMatch(/disabled=\{!forwardLive\}/);
    expect(TILE).toMatch(/disabled=\{!reverseLive\}/);
    expect(TILE).toMatch(/draggable=\{forwardLive\}/);
    expect(TILE).toMatch(/draggable=\{reverseLive\}/);
    // The click and drag handlers must be gated on the same predicate, not
    // on `hasForward` — that was the bug: styled disabled, wired live.
    expect(TILE).not.toMatch(/onClick=\{hasForward \?/);
    expect(TILE).not.toMatch(/onClick=\{\s*hasReverse \?/);
  });

  it("names the blocked state to a screen reader", () => {
    // `cursor-not-allowed` is invisible to assistive tech, and `disabled`
    // alone says nothing about why.
    expect(TILE).toMatch(/encode, unavailable: \$\{needs\.forward\}/);
    expect(TILE).toMatch(/decode, unavailable: \$\{needs\.reverse\}/);
  });

  it("states one reason once when both directions want the same input", () => {
    // "needs bytes" printed under each handle doubled the row height and the
    // noise for no extra fact.
    expect(TILE).toMatch(
      /const sharedNeed =\s*\r?\n?\s*needs\?\.forward && needs\.forward === needs\.reverse \? needs\.forward : null;/
    );
    expect(TILE).toMatch(/const splitNeeds = sharedNeed \? undefined : needs;/);
  });
});

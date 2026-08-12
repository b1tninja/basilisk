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

  it("keeps the solo control in place, refused, rather than removing it", () => {
    // Removing it made rows shift sideways as the caret moved and left the
    // row unable to say anything about its own state.
    //
    // `disabled={unfit}` until the refusal rule landed: the boolean turned the
    // button off and the sentence went out separately as a `title`, which is
    // unreachable by touch and by keyboard. Now the sentence *is* the off
    // switch, and `reasonId` points it at the row's own right-aligned caption
    // so the same words are not printed twice on one line.
    expect(SHELF_CODE).toMatch(/<AddButton\s+disabledReason=\{\s*unfit\s*$/m);
    expect(SHELF_CODE).toMatch(/reasonId=\{why\}/);
    expect(SHELF_CODE).not.toMatch(/<AddButton\s+disabled=/);
    expect(SHELF_CODE).not.toMatch(/!fit && tipFit \? null : \(/);
  });

  it("makes an unfitting direction handle genuinely inert", () => {
    expect(TILE).toMatch(/const forwardLive = hasForward && !needs\?\.forward;/);
    expect(TILE).toMatch(/const reverseLive = hasReverse && !needs\?\.reverse;/);
    // The `disabled` attribute is gone from both handles — it took them out of
    // the tab order, and with them the `aria-describedby` carrying the reason.
    // `useRefusal` supplies `aria-disabled` + `aria-describedby` together, so
    // the handle stays reachable and the caption under it is what is read.
    expect(TILE).not.toMatch(/disabled=\{!forwardLive\}/);
    expect(TILE).not.toMatch(/disabled=\{!reverseLive\}/);
    expect(TILE).toMatch(/\{\.\.\.forwardRefusal\.aria\}/);
    expect(TILE).toMatch(/\{\.\.\.reverseRefusal\.aria\}/);
    expect(TILE).toMatch(/draggable=\{forwardLive\}/);
    expect(TILE).toMatch(/draggable=\{reverseLive\}/);
    // The original bug was styled-disabled and wired-live, so the click has to
    // be stopped by the same thing that draws the refusal. `guard` is that
    // thing — and it *stops the event* rather than omitting a handler, which
    // an `aria-disabled` button needs because the click still bubbles.
    expect(TILE).toMatch(/forwardRefusal\.guard\(\(\) => onAppend\(forwardName/);
    expect(TILE).toMatch(/reverseRefusal\.guard\(\(\) => onAppend\(reverseName/);
    // A row with no direction at all draws an empty aligned square. That is an
    // omission, not a refusal (§33d): no sentence, no handler, and out of the
    // tab order, because it is aria-hidden and a focusable aria-hidden control
    // is a trap.
    expect(TILE).toMatch(/tabIndex=\{hasForward \? undefined : -1\}/);
    expect(TILE).toMatch(/tabIndex=\{hasReverse \? undefined : -1\}/);
  });

  it("names the blocked state to a screen reader", () => {
    // `cursor-not-allowed` is invisible to assistive tech, and `disabled`
    // alone says nothing about why.
    expect(TILE).toMatch(/encode, unavailable: \$\{needs\.forward\}/);
    expect(TILE).toMatch(/decode, unavailable: \$\{needs\.reverse\}/);
  });

  it("wires the accelerator its own badge advertises", () => {
    // The field showed a "⌘K" badge and nothing anywhere listened for the
    // key — a hint that was wrong about the key on every non-Apple machine
    // and attached to no behaviour on any of them.
    expect(SHELF_CODE).toMatch(/e\.key !== "k" && e\.key !== "K"/);
    expect(SHELF_CODE).toMatch(/!e\.metaKey && !e\.ctrlKey/);
    expect(SHELF_CODE).toMatch(/window\.addEventListener\("keydown", onKey\)/);
    expect(SHELF_CODE).toMatch(/searchRef\.current/);
    // …and spells it for the platform it is on.
    expect(SHELF_CODE).toMatch(/\? "⌘K"\s*\r?\n?\s*: "Ctrl K"/);
    expect(SHELF_CODE).toMatch(/aria-label=\{`Search toolkit \(\$\{searchAccel\}\)`\}/);
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

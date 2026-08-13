/**
 * Composing a placed notebook before a session exists.
 *
 * The complaint this answers is that nothing useful could be *assigned* until
 * the room was live, which made the assignment control useless at the one
 * moment somebody wants it: a ceremony is written first and run when the other
 * person is free. The peers now come from the draft audience — the recipient
 * picker in the session sheet — so choosing two people makes both of their keys
 * assignable immediately.
 *
 * That raised a question the live room never had to answer out loud, and the
 * answer has since changed. The peers were positions — `@peer2` — and a position
 * is not a name, so the room list and the assignment menu had to caption each
 * one with who held it. A peer is the key itself now, so the row and the
 * notebook say the same value and there is nothing to bind them together; what
 * a caption still supplies is the half a fingerprint cannot, which is *whose
 * key it is*. Both surfaces are asserted here: the room list draws each member
 * as a placard — the whole key through the product's fingerprint widget, never
 * abbreviated, with the name beside it — and the assignment menu says who each
 * peer is in words, or says that it cannot.
 *
 * Rendered with `react-dom/server`, which is what this suite can do in
 * `environment: "node"` — see `fingerprint.test.js`. Radix portals its menu
 * content, so a dropdown's *rows* are unreachable here; that is exactly why
 * `peerCaption` is exported and asserted directly rather than scraped, and why
 * the assignment menu itself is driven in `session-source.e2e.js`.
 */
import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SessionStart } from "../toolkit/widgets/SessionStart.tsx";
import { peerCaption } from "../toolkit/widgets/CellAssign.tsx";

const ADA = "AAAA111122223333444455556666777788889999";
const BEA = "BBBB111122223333444455556666777788889999";

/**
 * Fingerprint → the name this browser has for that key.
 *
 * This helper used to build fingerprint → `@peerN` out of the roster, which is
 * what the shell then passed as `labels`. The roster is identity-mapped now, so
 * that map would be every key pointing at itself and nothing would consume it —
 * the prop carries the *names* instead, from the trusted marks and the vault.
 */
function namesFor(entries) {
  return Object.fromEntries(entries);
}

describe("the caption under a label in the assignment menu", () => {
  it("names you as yourself", () => {
    expect(peerCaption({ label: ADA, self: true, fingerprint: ADA })).toContain("you");
  });

  it("names the key when this browser has a name for it", () => {
    expect(
      peerCaption({ label: BEA, fingerprint: BEA, name: "Ada Lovelace <ada@example.org>" })
    ).toBe("Ada Lovelace <ada@example.org>");
  });

  it("says the key is nameless rather than showing part of it", () => {
    const said = peerCaption({ label: BEA, fingerprint: BEA });
    expect(said).toContain("no name for this key");
    // The defect this whole component family exists to prevent: a dense row
    // filling the gap with characters off the key. Nothing in the sentence may
    // come from the fingerprint at all.
    expect(said.toUpperCase()).not.toContain(BEA.slice(0, 4));
    expect(said).not.toMatch(/[0-9A-F]{6}/i);
  });

  it("distinguishes a label the notebook names from one the room binds", () => {
    // Two different futures for the cell: one runs when the session opens, the
    // other waits for somebody who has not been invited. Same `@peerN` on
    // screen, so the difference has to be said.
    const bound = peerCaption({ label: BEA, fingerprint: BEA });
    // A `@peer1` left in a notebook written before a peer was a key is exactly
    // this state, and it is the commonest way to reach it now.
    const unbound = peerCaption({ label: "peer1" });
    expect(unbound).toContain("not in the room");
    expect(unbound).not.toBe(bound);
  });
});

describe("the room list draws a placard for every member", () => {
  const render = (props) =>
    renderToStaticMarkup(
      createElement(SessionStart, {
        role: "offer",
        onRole: () => {},
        keys: [],
        keyFingerprint: "",
        onKeyFingerprint: () => {},
        audience: [ADA, BEA],
        names: namesFor([]),
        onAudience: () => {},
        onPaste: () => {},
        issues: [],
        inviteUrl: null,
        recipe: "",
        onStart: () => {},
        ...props,
      })
    );

  it("marks every row with what a cell header would address", () => {
    // The whole key, which is now the same string the notebook writes. It used
    // to be `peer1`/`peer2` here and `@peer1`/`@peer2` there, bound together by
    // a numbering both sides had to agree about.
    const html = render({});
    expect(html).toContain(`data-session-member="${ADA}"`);
    expect(html).toContain(`data-session-member="${BEA}"`);
  });

  it("prints the whole key, and never a part of one", () => {
    const html = render({});
    // The full `Fingerprint`, not `variant="compact"`. Compact prints a name
    // carrying no bits of the key, which is right exactly when there is a name;
    // passing the fingerprint as that name would print the key while claiming
    // to print something that is not the key.
    expect(html).toContain('data-fingerprint="full"');
    expect(html).not.toContain('data-fingerprint="compact"');
    expect(html).not.toContain("…");
    // Grouped as `formatFingerprint` prints it, which is the spelling
    // `findFingerprints` is built to recover, so what is on screen pastes back
    // into the invite box and names the same key.
    expect(html).toContain(ADA.slice(0, 4));
    expect(html.replace(/\s|<[^>]*>/g, "")).toContain(ADA);
  });

  it("says a key is nameless rather than leaving the row unexplained", () => {
    expect(render({})).toContain("no name for this key in this browser");
    // Both sources the shell feeds this from: a trust mark, and the `names` map
    // it builds out of the trust marks and the vault's uids.
    expect(render({ trusted: [{ fingerprint: BEA, label: "Grace Hopper" }] })).toContain(
      "Grace Hopper"
    );
    expect(render({ names: namesFor([[BEA, "Ada Lovelace"]]) })).toContain("Ada Lovelace");
  });

  it("says what a header addresses, without promising a numbering", () => {
    // This used to warn that "they are numbered by fingerprint, so adding or
    // removing somebody renumbers the rest" — a true and alarming sentence
    // about a mechanism that no longer exists. Leaving it would be prose
    // describing a product that is not there, which is the defect `42875a2`
    // landed for. What replaced it is the fact that *is* still true.
    const html = render({});
    expect(html).not.toContain("numbered by fingerprint");
    expect(html).not.toContain("renumbers");
    expect(html).toContain("A cell header addresses one of these keys, in full");
    expect(html).toContain("Removing somebody leaves their cells assigned to nobody");
  });

  it("keeps the relabel note in a live region that exists before it speaks", () => {
    // A live region created at the moment of its first message is a message
    // some screen readers never announce, which would make the one narration of
    // a rewritten notebook the one nobody hears.
    expect(render({})).toContain('data-relabel-note=""');
    expect(render({ relabelNote: "One cell was placed on somebody" })).toContain(
      "One cell was placed on somebody"
    );
  });
});

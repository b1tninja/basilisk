/**
 * Composing a placed notebook before a session exists.
 *
 * The complaint this answers is that nothing useful could be *assigned* until
 * the room was live, which made the assignment control useless at the one
 * moment somebody wants it: a ceremony is written first and run when the other
 * person is free. The labels now come from the draft audience — the recipient
 * picker in the session sheet — so choosing two people hands out `peer1` and
 * `peer2` immediately.
 *
 * That raises a question the live room never had to answer out loud. A label is
 * a position, and a position is not a name: `@peer2` tells a reader assigning
 * work nothing about who they are assigning it to. The two halves of the answer
 * are asserted here — the room list names each member by the label a cell
 * header will address, drawn through the product's fingerprint widget so the
 * key behind it is one press away and never abbreviated; and the assignment
 * menu says who each label is in words, or says that it cannot.
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
import { roomRoster } from "../lib/notebook/roster.js";

const ADA = "AAAA111122223333444455556666777788889999";
const BEA = "BBBB111122223333444455556666777788889999";

/** Fingerprint → label, the way `ToolkitShell` inverts `composeWho.roster`. */
function labelsFor(audience) {
  const { roster } = roomRoster(audience);
  return Object.fromEntries(
    Object.entries(roster).map(([label, fpr]) => [fpr.toUpperCase(), label])
  );
}

describe("the caption under a label in the assignment menu", () => {
  it("names you as yourself", () => {
    expect(peerCaption({ label: "peer1", self: true, fingerprint: ADA })).toContain("you");
  });

  it("names the key when this browser has a name for it", () => {
    expect(
      peerCaption({ label: "peer2", fingerprint: BEA, name: "Ada Lovelace <ada@example.org>" })
    ).toBe("Ada Lovelace <ada@example.org>");
  });

  it("says the key is nameless rather than showing part of it", () => {
    const said = peerCaption({ label: "peer2", fingerprint: BEA });
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
    const bound = peerCaption({ label: "peer2", fingerprint: BEA });
    const unbound = peerCaption({ label: "peer4" });
    expect(unbound).toContain("not in the room");
    expect(unbound).not.toBe(bound);
  });
});

describe("the room list says which label each member holds", () => {
  const render = (props) =>
    renderToStaticMarkup(
      createElement(SessionStart, {
        role: "offer",
        onRole: () => {},
        keys: [],
        keyFingerprint: "",
        onKeyFingerprint: () => {},
        audience: [ADA, BEA],
        labels: labelsFor([ADA, BEA]),
        onAudience: () => {},
        onPaste: () => {},
        issues: [],
        inviteUrl: null,
        recipe: "",
        onStart: () => {},
        ...props,
      })
    );

  it("marks every row with the label a cell header would address", () => {
    const html = render({});
    expect(html).toContain('data-session-member="peer1"');
    expect(html).toContain('data-session-member="peer2"');
  });

  it("prints the label where the elided fingerprint would have gone", () => {
    const html = render({});
    // `variant="compact"` — the label is the visible text, and the whole value
    // is what the control copies. A truncation of the key would be neither.
    expect(html).toContain('data-fingerprint="compact"');
    expect(html).not.toContain("…");
  });

  it("says a key is nameless rather than leaving the row unexplained", () => {
    expect(render({})).toContain("no name for this key in this browser");
    expect(render({ trusted: [{ fingerprint: BEA, label: "Grace Hopper" }] })).toContain(
      "Grace Hopper"
    );
  });

  it("warns that the numbering moves before it moves", () => {
    // The one fact about these labels a reader cannot work out by looking: the
    // order is over key material, so it is neither the order they added people
    // in nor anything they chose.
    expect(render({})).toContain("numbered by fingerprint");
  });

  it("keeps the relabel note in a live region that exists before it speaks", () => {
    // A live region created at the moment of its first message is a message
    // some screen readers never announce, which would make the one narration of
    // a rewritten notebook the one nobody hears.
    expect(render({})).toContain('data-relabel-note=""');
    expect(render({ relabelNote: "cell 0 says @peer3" })).toContain("cell 0 says @peer3");
  });
});

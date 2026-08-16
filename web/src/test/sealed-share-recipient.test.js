/**
 * A sealed share tile says whose it is, and says the whole of it.
 *
 * ## What was there before
 *
 * `mode=separate` and `seal to=each` make **one artifact per recipient**, and
 * every one of them has carried `recipientFingerprint` — the whole forty
 * characters — since the fan-out shipped. Nothing read it. `88fcfd0` found it
 * while removing the tile's 8-hex truncation and wrote the finding down in
 * `engine.js`: "the artifact's own `recipientFingerprint` — the whole value,
 * already here — has no reader on any surface."
 *
 * That truncation fix consumed a *different* path. It rewrote the **ciphertext**
 * branch, where the label became `GPG ciphertext for <fingerprint>` and the
 * filename `encrypted-<fingerprint>.asc`, so for plain ciphertext the question
 * "who is this for" is answered twice over and the field is redundant.
 *
 * The **share** branch was left as it was, and it answers the question nowhere.
 * A sealed share is labelled `Share 2 (GPG)` and downloaded as `share-2.asc`;
 * the tile adds the index, the threshold and the set id. A dealer looking at
 * three sealed files, deciding which one to hand to which custodian, had the
 * index of each and nothing at all saying whose it is — and the index is
 * precisely the fact the envelope exists to keep from everybody but its holder.
 *
 * ## Why this is the dealer's tile and not a disclosure
 *
 * `sealed-share-envelope.test.js` establishes that the sealed *value* drops
 * `shareIndex` so a published envelope cannot tell the room which share went to
 * whom, and that the dealer's own tile keeps its labels because it is drawn on
 * "the machine entitled to know". This is that same side: an entry in the local
 * artifact list, on the machine that chose the recipients. Nothing here crosses
 * a wire.
 *
 * ## Division of proof
 *
 * That a *real* run puts the whole fingerprint on a real sealed share is
 * `scatter-deal.test.js`'s, which deals to a room and then finds each member's
 * private key **by** `art.recipientFingerprint` in order to open it. This file
 * owns the other half — that the value reaches a reader, and reaches it whole.
 */
import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { shareIdentity } from "../lib/toolkit/artifact-readouts.js";
import { ShareIdentity } from "../toolkit/widgets/ShareIdentity.tsx";

/** A v4 fingerprint, and a second one sharing its last eight characters. */
const FPR = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const TWIN = "91C7E6D5C4B3A29180716253443526176AD01388";

/** A sealed share as `gpg.encrypt`'s share branch builds one. */
const sealed = (over = {}) => ({
  label: "Share 2 (GPG)",
  filename: "share-2.asc",
  shareIndex: 2,
  recipientFingerprint: FPR,
  tags: ["encrypted", "openpgp", "blip39"],
  traits: { shareOf: 2, threshold: 2, sealedTo: FPR },
  ...over,
});

/**
 * The same share after the three projections that stand between the engine and
 * a tile: `cellOutputs` and the shell's two `OutputArtifact` mappings, each an
 * explicit field list that drops what it does not name. `traits` is the only
 * bag copied wholesale — `recipientFingerprint` is named by none of them.
 *
 * This is the shape a *reader* actually gets, and the first draft of this
 * feature failed it: the readout took the whole fingerprint off the named
 * field, every assertion below passed, and nothing rendered in the product,
 * because the field never arrived. A tile fact that lives outside `traits` is
 * the dead mechanism this file exists to close, one layer along.
 */
const projected = (artifact) => ({
  label: artifact.label,
  filename: artifact.filename,
  role: "share",
  tags: artifact.tags,
  traits: artifact.traits,
});

const render = (artifact) =>
  renderToStaticMarkup(createElement(ShareIdentity, { artifact }));

/** Everything a reader can actually see, tags stripped. */
const visible = (markup) => markup.replace(/<[^>]*>/g, " ");

describe("shareIdentity carries the recipient", () => {
  it("reads the whole fingerprint off the artifact", () => {
    expect(shareIdentity(sealed()).recipient).toBe(FPR);
  });

  it("upper-cases it, the way every other fingerprint surface spells one", () => {
    expect(shareIdentity(sealed({ recipientFingerprint: FPR.toLowerCase() })).recipient).toBe(
      FPR
    );
  });

  it("says nothing when the artifact names no recipient", () => {
    // The control. A share that was never sealed — a bare mnemonic tile — must
    // not grow an empty line, and the other four facts must be unaffected.
    const id = shareIdentity({ shareIndex: 2, tags: ["blip39"], traits: { shareOf: 2, threshold: 2 } });
    expect(id.recipient).toBe("");
    expect(id.index).toBe(2);
    expect(id.threshold).toBe(2);
    expect(id.flavour).toBe("BLIP39 mnemonic");
  });

  it("still returns null when there is nothing public to say", () => {
    // A recipient alone is not an identity: without an index, a threshold or a
    // set id there is no share tile to draw, and a stray fingerprint must not
    // conjure one.
    expect(shareIdentity({ recipientFingerprint: FPR })).toBeNull();
  });
});

describe("it survives the trip to a tile", () => {
  it("reads the recipient off an artifact projected the way a tile receives one", () => {
    // The assertion the first draft of this feature would have failed. Nothing
    // but `traits` survives, so the fact has to be in `traits`.
    expect(shareIdentity(projected(sealed())).recipient).toBe(FPR);
  });

  it("renders it from the projected shape, not only the engine's", () => {
    const text = visible(render(projected(sealed())));
    expect(text).toContain(FPR);
    expect(text).toMatch(/sealed to/i);
  });

  it("loses it when the fact lives only in the field the projections drop", () => {
    // Why `traits.sealedTo` exists, stated as behaviour: an artifact carrying
    // the whole value in `recipientFingerprint` alone reaches a tile with
    // nothing to say. This is the defect, reproduced.
    const named = sealed({ traits: { shareOf: 2, threshold: 2 } });
    expect(shareIdentity(named).recipient).toBe(FPR);
    expect(shareIdentity(projected(named)).recipient).toBe("");
    expect(visible(render(projected(named)))).not.toMatch(/sealed to/i);
  });
});

describe("the tile renders it, whole", () => {
  it("puts the recipient on the tile where a dealer reads it", () => {
    const text = visible(render(sealed()));
    expect(text).toContain(FPR);
    expect(text).toMatch(/sealed to/i);
  });

  it("prints no truncated form of it", () => {
    // The rule `88fcfd0` swept `src` for. Written against what a reader sees
    // rather than against a spelling: the assertion is that the only hex run on
    // the tile is the whole forty, so `slice(-8)`, `slice(0, 8)…` and an
    // ellipsis in the middle all fail it equally.
    const text = visible(render(sealed()));
    const runs = text.match(/[0-9A-F]{6,}/g) || [];
    expect(runs).toEqual([FPR]);
    expect(text).not.toMatch(/…/);
  });

  it("tells two keys sharing their last eight characters apart", () => {
    // The case the short key id cannot serve, and the reason the whole value is
    // the content here: two sealed shares whose fingerprints end alike land in
    // one folder, and the tile is where a sender picks between them.
    expect(FPR.slice(-8)).toBe(TWIN.slice(-8));
    const one = visible(render(sealed()));
    const two = visible(
      render(
        sealed({
          recipientFingerprint: TWIN,
          traits: { shareOf: 2, threshold: 2, sealedTo: TWIN },
        })
      )
    );
    expect(one).not.toBe(two);
    expect(one).toContain(FPR);
    expect(two).toContain(TWIN);
  });

  it("draws no recipient line for a share that was never sealed", () => {
    // The control for the renderer, matching the readout's own control above.
    const text = visible(render({ shareIndex: 2, tags: ["blip39"], traits: { shareOf: 2, threshold: 2 } }));
    expect(text).not.toMatch(/sealed to/i);
    expect(text).toContain("Share 2");
  });

  it("keeps the facts it already drew", () => {
    // The recipient is an addition, not a replacement: a tile that started
    // showing the holder and stopped showing which share it is would have
    // traded one gap for another.
    const text = visible(render(sealed({ traits: { shareOf: 2, threshold: 2, setId: "AB12" } })));
    expect(text).toContain("Share 2");
    expect(text).toContain("2 shares recover the secret");
    expect(text).toContain("set AB12");
    expect(text).toContain("encrypted share");
  });
});

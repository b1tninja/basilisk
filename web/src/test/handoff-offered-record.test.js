/**
 * The `offered` bound is a record of what went out, not a restatement of what
 * came back.
 *
 * `acceptCellResult` refuses a result for a cell this machine never handed to
 * that peer — "absence is not permission" — and `handoff-result.js` covers
 * that refusal firing, with real manifests, at `not-offered`. What nothing
 * covered was whether the *product* could ever reach it: the shell passed
 * `{manifest: doc.manifest, cell: doc.cell, to: by}`, every field read off the
 * document being judged, so the bound agreed with the claim by construction
 * and the refusal was unreachable however wrong the result was.
 *
 * Source assertions rather than a rendered run, for `run-offers.test.js`'s
 * reason: this logic lives inside `useCallback`s that node cannot mount, and
 * the thing being pinned is which value is passed, which the text states.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

const HOOK = readFileSync(new URL("../toolkit/useNotebook.ts", import.meta.url), "utf8");

describe("what this machine handed out is written down", () => {
  it("does not build the bound out of the document it is judging", () => {
    // Written as an absence because no spelling of it would be correct: any
    // field of the incoming document, used as the bound, agrees with itself.
    expect(HOOK).not.toMatch(/offered:\s*\[\{\s*manifest:\s*doc\.manifest/);
    expect(HOOK).not.toMatch(/offered:\s*\[\{[^}]*cell:\s*doc\.cell/);
  });

  it("feeds the bound from what this run actually sent", () => {
    expect(HOOK).toMatch(/offered:\s*offeredThisRun\(\)/);
    expect(HOOK).toMatch(/runRef\.current\?\.record\.sent\.values\(\)/);
  });

  it("keys the record by cell and peer, not by cell alone", () => {
    // `record.offers` keeps one verdict per cell (`noteOfferVerdicts`), so a
    // cell offered to two peers forgets the first — and that peer's honest
    // answer would come back to `not-offered`. `record.sent` is keyed by
    // `offerKey`, which is the pair.
    // Both writes, not just the first. The placeholder claimed before the
    // send and the real entry written after it must each carry the peer —
    // pinning only one let a mutation blank the peer on the entry that is
    // actually judged and survive.
    const writes = HOOK.match(/run\.record\.sent\.set\([^;]*\);/g) || [];
    expect(writes).toHaveLength(2);
    for (const w of writes) expect(w).toMatch(/cell: o\.cell,\s*peer: o\.peer/);
  });

  it("records the manifest the offer actually left under", () => {
    // Not the notebook as it stands at accept time: that would judge the
    // result against whatever is on screen now, which is the fabrication this
    // replaces wearing a different hat.
    expect(HOOK).toMatch(/manifest: await manifestDigest\(ctx\.manifest\)/);
    expect(HOOK).toMatch(/if \(r\.ok && r\.manifest\)/);
  });

  it("drops an entry whose send never happened", () => {
    // A refused send leaves an empty manifest behind. If that reached the
    // bound, a cell whose offer never left would admit a result claiming it
    // did — the same hole one layer down.
    expect(HOOK).toMatch(/\.filter\(\(o\) => o\.manifest\)/);
  });
});

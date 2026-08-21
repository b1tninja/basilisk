/**
 * One Inputs panel per machine — the rule, and the scope it is measured at.
 *
 * `validateRecipe` held three booleans, `sawInputShares`, `sawInputText` and
 * `sawDecryptGpg`, each raised once per *document* and each raising a sentence
 * that said "per pipeline". The copy was wrong in both directions at once:
 * stricter than a pipeline, because nothing reset the flag between cells, and
 * looser than the truth, because the scarce thing is a panel on a machine and
 * a document spans machines. What that cost was concrete —
 *
 *     @<bo>   input | out $a
 *     @<cara> input | out $b     → "Only one input step is supported per pipeline"
 *
 * — two peers, each reading their own Inputs panel on their own machine, could
 * not be written down. Every multi-peer notebook wanting two people to paste
 * anything was unwritable, in all three panels.
 *
 * `46da380` fixed a third of it from the other side: it narrowed *which*
 * decrypts count to those whose own declarations say they will reach for the
 * panel, so a `quorum.recv | gpg.decrypt` counts against nothing. That
 * unblocked the three-person ceremony without touching the scope, and said so.
 *
 * ## What this file pins
 *
 * The key is the cell's `@peer` header and nothing else — `placement.js` is the
 * authority on who runs what, and a compiler that re-derived placement from
 * dataflow would be a rival to it. Two consequences are pinned below because
 * they are the two a plausible implementation gets wrong:
 *
 * - **A headerless cell stands on every machine**, so it meets every placement
 *   there is, including another headerless cell and including a placed one. A
 *   rule that grouped by header string would let two headerless `input` cells
 *   compile, and they are the pair most likely to be written.
 * - **A fingerprint header is compared after case folding**, because
 *   `normalizePeerRef` upper-cases it and the roster, `peersSha` and this all
 *   have to be looking at one spelling.
 *
 * And the narrowing is pinned from both ends: a piped reader blocks nothing,
 * and a *key* panel need is not a content panel need — two steps reaching for
 * Inputs → OpenPGP for a key both want the same key, which is not a conflict.
 */
import { describe, expect, it } from "vitest";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { roomCeremony } from "../lib/toolkit/room-ceremony.js";

const BO = "83421F2C0B1E4D5A6F7089AB1234567890ABCDEF";
const CARA = "9F3D2E1C0B0A99887766554433221100FFEEDDCC";
const DAN = "1111222233334444555566667777888899990000";

/** Compile and hand back just the sentences. */
function errs(src) {
  return compileRecipe(src).validation.errors.map((e) => e.message);
}

/** The three cells, one per panel, that each read one whole panel. */
const READERS = [
  { panel: "text", cell: "input | out", noun: "Inputs → text" },
  { panel: "shares", cell: "shares | blip39 -d | out", noun: "Inputs → shares" },
  { panel: "gpg", cell: "gpg.decrypt | out", noun: "Inputs → OpenPGP" },
];

describe("two peers each read their own panel", () => {
  for (const r of READERS) {
    it(`${r.panel}: \`@bo ${r.cell.split(" ")[0]}\` beside \`@cara …\` compiles`, () => {
      const said = errs(`@${BO}\n${r.cell} $a\n\n@${CARA}\n${r.cell} $b`);
      // Asserted empty rather than `ok`, so a *different* refusal appearing
      // here cannot be mistaken for this one being fixed.
      expect(said).toEqual([]);
    });

    it(`${r.panel}: the same peer twice still refuses, naming the peer`, () => {
      const said = errs(`@${BO}\n${r.cell} $a\n\n@${BO}\n${r.cell} $b`).join("\n");
      expect(said).toContain(r.noun);
      expect(said).toContain(`\`@${BO}\``);
      expect(said).toContain("which is where this cell runs too");
    });
  }
});

describe("a headerless cell stands on every machine", () => {
  for (const r of READERS) {
    it(`${r.panel}: two headerless cells refuse — nobody named a peer`, () => {
      const said = errs(`${r.cell} $a\n\n${r.cell} $b`).join("\n");
      expect(said).toContain(r.noun);
      expect(said).toContain("neither cell names a peer, so both run on the same machine");
    });

    it(`${r.panel}: headerless above a placed cell refuses`, () => {
      const said = errs(`${r.cell} $a\n\n@${BO}\n${r.cell} $b`).join("\n");
      expect(said).toContain(`including \`@${BO}\``);
    });

    it(`${r.panel}: placed above a headerless cell refuses too`, () => {
      // The other order, because a rule that only looked backwards at named
      // placements would pass this one and fail the previous.
      const said = errs(`@${BO}\n${r.cell} $a\n\n${r.cell} $b`).join("\n");
      expect(said).toContain(`\`@${BO}\` among them`);
    });
  }

  it("a `@*` rendezvous cell is on every machine too", () => {
    // `@*` is separately refused by this build, so the panel sentence has to be
    // *there beside it* rather than instead of it.
    const said = errs(`@*\ninput | out $a\n\n@${BO}\ninput | out $b`).join("\n");
    expect(said).toContain("is a rendezvous");
    expect(said).toContain("Inputs → text is one panel per machine");
  });
});

describe("a fingerprint names one machine however it is typed", () => {
  it("folds case before comparing, and says the canonical spelling", () => {
    const said = errs(
      `@${BO.toLowerCase()}\ngpg.decrypt | out $a\n\n@${BO}\ngpg.decrypt | out $b`
    ).join("\n");
    expect(said).toContain("Inputs → OpenPGP is one panel per machine");
    // Upper case in the sentence, because that is the spelling the roster,
    // `peersSha` and `planRun` all use — the reader is told which peer they
    // actually named, not which characters they typed.
    expect(said).toContain(`\`@${BO}\``);
  });
});

describe("only a reader that will really reach for the panel counts", () => {
  it("a piped decrypt blocks nothing, even on the peer that pastes", () => {
    // `46da380`'s narrowing, asked from the strongest angle: both cells are on
    // one machine, and only one of them touches the panel.
    expect(
      errs(`@${BO}\nquorum.recv from=${CARA} | gpg.decrypt | out $a\n\n@${BO}\ngpg.decrypt | out $b`)
    ).toEqual([]);
  });

  it("a key= need is not a ciphertext need — one panel, two drawers", () => {
    // `gpg.sign` with no `key=` asks Inputs → OpenPGP for *a key*, and two
    // steps wanting the same key is not two steps wanting the same message.
    // This is the `param === null` filter; without it, signing and decrypting
    // in one notebook would refuse.
    expect(errs(`@${BO}\ngpg.decrypt | out $a\n\n@${BO}\ninput | utf8 | gpg.sign | out $b`)).toEqual(
      []
    );
  });

  it("panels do not block each other", () => {
    expect(errs(`@${BO}\ninput | out $a\n\n@${BO}\nshares | blip39 -d | out $b`)).toEqual([]);
  });
});

describe("the generated ceremony is unaffected", () => {
  it("still compiles at three, where 46da380 left it", () => {
    // The control. This one compiled before the scope moved — its decrypts are
    // all piped — so it is the case that must survive every mutation of the
    // rule, and a mutation that "fixes" the notebooks above by breaking this
    // one has not fixed anything.
    const cm = roomCeremony({ audience: [BO, CARA, DAN], self: BO });
    expect(cm.issues).toEqual([]);
    expect(errs(cm.text)).toEqual([]);
  });
});

/**
 * The shelf draws the type it names, and says which suite qualifies the ops.
 *
 * Two halves of one report — "perhaps it would be beneficial if the types had
 * glyphs or badges chips or tiles of some kind (for `needs bytes`)", and
 * wanting to see a module validated before its tools are used.
 *
 * ## 1. A considered vocabulary with no consumer
 *
 * `KIND_GLYPHS` records measuring ink mass at 12px to keep a public key and a
 * private one apart, and `OpsShelf.tsx` and `OpsTile.tsx` referenced it **zero
 * times**. So a reader met `bytes` as a pictogram on every artifact tile and
 * as the bare word `needs bytes` in the shelf that names it, and six of the
 * twenty types in the registry's own vocabulary had no mark at all.
 *
 * ## 2. Four suites, fourteen toolboxes, and one that is not what it looks
 *
 * `stepNameToSuite` answers `openpgp | webcrypto | sss | age | null`. `ssh`
 * answers **webcrypto**, because SSH's maths is SubtleCrypto and @noble and
 * that is what CAST exercises; `age` answers **age**, its own suite, since
 * CAST-15 runs the age project's published testkit vector rather than
 * borrowing WebCrypto's pass; `io`, `flow`, `encoding`,
 * `agent`, `hkp`, `webauthn`, `webrtc` and `quorum` answer **null**, which is
 * not "unverified" but "no self-test covers this at all". `CastDot` renders
 * nothing for the null case — correct for a status light, and indistinguishable
 * from a toolbox whose status simply has not arrived. The chip is what says it.
 *
 * These are source and registry claims. What the built page actually draws and
 * announces is `ops-type-and-suite.e2e.js`; this file is the half that can run
 * without a browser and that fails when a *type* is added with no mark.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { listSteps } from "../lib/toolkit/registry.js";
import { listTypes } from "../lib/toolkit/type-registry.js";
import { toolboxToSuite } from "../lib/toolkit/suite-gate.js";
import { GLYPH_PATHS } from "../lib/toolkit/glyphs.js";
import {
  KEY_GLYPH_TIERS,
  KIND_GLYPHS,
  glyphExists,
  kindGlyph,
} from "../toolkit/widgets/kind-glyphs.tsx";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELF = read("../toolkit/widgets/OpsShelf.tsx");
const TILE = read("../toolkit/widgets/OpsTile.tsx");

/**
 * Names that draw nothing because they are **not types**.
 *
 * `none` is never printed: a step declaring it takes no input, and the shelf
 * says "needs input" for that rather than naming a type.
 *
 * `any` is the absence of a constraint. The type registry does not list it,
 * the nine steps that declare it are the sinks and the pass-throughs, and a
 * pictogram for "anything" would have to look like something — whatever that
 * something was would be a claim these steps do not make. The shelf prints
 * "needs a value" for them, which names the caret's state instead.
 *
 * This list is closed on an argument, not on a backlog. A name added here
 * needs the argument, not the intention to get round to it.
 */
const NOT_A_TYPE = ["none", "any"];

/**
 * Types that exist and have no mark yet — the gap, written down.
 *
 * The shape `UNCLAIMED_ROLES` established in `artifact-kinds-table.test.js`:
 * **this list may only ever shrink**, and a type added to the registry
 * without a mark fails the sweep below rather than landing here quietly.
 *
 * Neither is reachable from the shelf's `needs …` caption, because no step
 * declares either on its own signature — `int` is a *parameter* type
 * (`random 32`, `sss.split threshold=3`) rather than a pipeline one, and
 * `host` says of itself "Reserved: … no step currently produces or consumes
 * one; addresses travel inside `endpoint` and `candidate` instead". They are
 * visible only on the Types tab, where they are now the two cards without a
 * pictogram. Recorded rather than filled: designing a mark is the measured
 * work the rest of this file is, and guessing two more would be the
 * "would-be-the-only-one-without-a-badge" reflex that put one `KeyRound` on
 * six key roles.
 */
const UNDRAWN_TYPES = ["int", "host"];

const UNMARKED_TYPES = [...NOT_A_TYPE, ...UNDRAWN_TYPES];

/** Every type name a step declares on either side of itself. */
function stepTypeVocabulary() {
  const seen = new Set();
  for (const s of listSteps()) {
    if (s.input) seen.add(s.input);
    if (s.output) seen.add(s.output);
  }
  return [...seen].sort();
}

describe("every type the shelf can name has a mark", () => {
  it("finds the vocabulary it is measuring", () => {
    // An empty sweep passes every assertion below it. Twenty types plus
    // `none` at the time of writing; the floor is well under that.
    const vocab = stepTypeVocabulary();
    expect(vocab.length, "the registry declares no types at all").toBeGreaterThan(15);
    expect(vocab, "the type this file was written for is gone").toContain("openpgp-key");
  });

  it("draws every declared type, or records why it does not", () => {
    const bare = stepTypeVocabulary()
      .filter((t) => !NOT_A_TYPE.includes(t))
      .filter((t) => !kindGlyph(t));
    expect(
      bare,
      `types the shelf can print with no glyph to print beside them: ${bare.join(", ")}`
    ).toEqual([]);
  });

  it("keeps the undrawn list honest — nothing on it is reachable from a row", () => {
    // The list above is an exemption, and an exemption is only safe while it
    // covers nothing a reader can meet in the shelf. If a step ever declares
    // `int` or `host` on its signature, the caption becomes reachable and the
    // exemption has to be spent rather than extended.
    const vocab = new Set(stepTypeVocabulary());
    const reachable = UNDRAWN_TYPES.filter((t) => vocab.has(t));
    expect(
      reachable,
      `an undrawn type is now on a step's signature and the shelf can print it: ${reachable.join(", ")}`
    ).toEqual([]);
  });

  it("draws every type the Types tab lists, or records why it does not", () => {
    // `TypeCard` renders `KindGlyph` from `meta.base`, so the two surfaces
    // share one map and a type added to the registry without a mark is blank
    // in both. `int`, `peer` and `host` are declared but carried by no step
    // signature, which is exactly the kind of entry that would be missed by a
    // sweep over `listSteps` alone.
    const bare = listTypes()
      .map((t) => t.base)
      .filter((t) => !UNMARKED_TYPES.includes(t))
      .filter((t) => !kindGlyph(t));
    expect(bare, `types with no glyph on their card: ${bare.join(", ")}`).toEqual([]);
  });

  it("keeps `any` unmarked, and says so where a reader can see it", () => {
    // The verdict, pinned in both directions: the map draws nothing for it,
    // and the shelf never asks a reader to read the word as a type. `needs
    // any` was on nine rows of the default page.
    expect(kindGlyph("any"), "`any` acquired a pictogram").toBe(null);
    expect(SHELF).not.toMatch(/`needs \$\{input\}`[\s\S]{0,80}any/);
    expect(SHELF, "the `any` branch stopped naming the caret's state").toMatch(
      /if \(input === "any"\)/
    );
    expect(SHELF).toMatch(/needs a value/);
  });
});

describe("the OpenPGP key is not the SSH key", () => {
  it("draws its own asset, and it is a real one", () => {
    expect(kindGlyph("openpgp-key")).toBe("key-openpgp");
    expect(glyphExists("key-openpgp")).toBe(true);
    expect(GLYPH_PATHS["key-openpgp"]).toBeTruthy();
  });

  it("shares a pictogram with no other key role", () => {
    // The defect the key split was written against, and the one an added key
    // role walks straight back into: `openpgp-public` and `openpgp-private`
    // once both declared the same glyph, and all six key roles once drew one
    // `KeyRound`. `ssh-public` and `ssh-private` already draw `key-public`
    // and `key-secret`, so an OpenPGP key reusing either would make three
    // concepts share two marks.
    const keyish = Object.entries(KIND_GLYPHS).filter(
      ([, g]) => typeof g === "string" && g.startsWith("key-")
    );
    const openpgp = KIND_GLYPHS["openpgp-key"];
    const shared = keyish
      .filter(([kind, g]) => kind !== "openpgp-key" && g === openpgp)
      .map(([kind]) => kind);
    expect(shared, `openpgp-key draws the same key as: ${shared.join(", ")}`).toEqual([]);
  });

  it("stays out of the badge's sensitivity axis, on purpose", () => {
    // `KEY_GLYPH_TIERS` is what `artifact-kinds-table.test.js` walks against
    // the kind table's `sensitivity`, and every entry in it must belong to a
    // role in `KEY_BADGE_KINDS`. `openpgp-key` is a *type* — no artifact role
    // wears it, and an OpenPGP key whose half is known arrives as
    // `openpgp-public` or `openpgp-private` and draws `key-public` /
    // `key-secret` there. Registering a tier here would assert agreement with
    // a tint that is never painted beside it.
    expect(KEY_GLYPH_TIERS["key-openpgp"]).toBeUndefined();
    expect(Object.keys(KEY_GLYPH_TIERS).sort()).toEqual([
      "key-pair",
      "key-public",
      "key-secret",
    ]);
  });

  it("fills its bow, which is the side that over-warns", () => {
    // `gpg.genkey` and `agent.unlock` produce secret halves; `agent.pub` and
    // `hkp.get` produce public ones. The type cannot tell, so the glyph picks
    // the neighbour it is safest to be mistaken for — the same argument that
    // puts plain `key` on `key-secret`. A hollow bow would put it beside
    // `key-public`, and reading a private key as a public one is the only
    // direction of that mistake that discloses anything.
    expect(GLYPH_PATHS["key-openpgp"]).toContain('fill="currentColor"');
  });
});

describe("the shelf prints the suite, never the module", () => {
  it("maps SSH to the suite that actually qualifies it", () => {
    // The one toolbox whose name is not its suite, and the reason the chip
    // says `CAST webcrypto` rather than repeating the header.
    expect(toolboxToSuite("ssh")).toBe("webcrypto");
    expect(toolboxToSuite("openpgp")).toBe("openpgp");
    expect(toolboxToSuite("webcrypto")).toBe("webcrypto");
    expect(toolboxToSuite("sss")).toBe("sss");
    // `age` is the fourth suite, and its own. The chip must read `CAST age`
    // rather than `CAST webcrypto`: CAST-15 ran age's published testkit
    // vector, and a chip naming WebCrypto would credit that pass to code the
    // vector never touched.
    expect(toolboxToSuite("age")).toBe("age");
  });

  it("keeps the null case a null, for every toolbox that has no suite", () => {
    // Eight of the fourteen, and it was eleven. `jose` and `otp` were on this
    // list beside `io` and `flow` as though they were encodings — and their
    // math is `crypto.subtle`, twelve calls in `jose-ops.js` and the HMAC
    // counter in `lib/otp/hotp.js`. They name `webcrypto` now, so a JWT and a
    // TOTP are refused under FIPS on the same terms as the `aes-gcm` cell
    // beside them, which is what they always should have been.
    //
    // `age` was the ninth and the one worth naming, on the grounds that no CAST
    // covered its third-party math. That was a description of a missing test,
    // not of an untestable one, and CAST-15 is that test — so `age` is off this
    // list and on the map. What remains here is genuinely uncovered.
    for (const tb of [
      "io",
      "flow",
      "encoding",
      "agent",
      "hkp",
      "webauthn",
      "webrtc",
      "quorum",
    ]) {
      expect(toolboxToSuite(tb), `${tb} acquired a CAST claim`).toBe(null);
    }
  });

  it("says the null case in words rather than rendering nothing", () => {
    // The cheap way to "add a chip" is to render it only where there is a
    // suite, which reproduces `CastDot`'s blind spot one element to the right:
    // no chip and no claim look identical. The chip is unconditional and the
    // null branch is a sentence.
    expect(SHELF).toMatch(/return suite \? `CAST \$\{suite\}` : "no CAST suite";/);
    expect(SHELF).toMatch(/<SuiteChip toolbox=\{toolbox\} \/>/);
  });

  it("is static, and not a second copy of the live status", () => {
    // `ToolkitShell` owns whether a suite is green this session and feeds
    // `castStatus` to the dot. The chip answers a different question — which
    // suite — and must not start answering the dot's, or the two marks drift
    // and the row carries a stale pass.
    const chip = SHELF.slice(SHELF.indexOf("function SuiteChip"));
    const body = chip.slice(0, chip.indexOf("\n}"));
    expect(body).not.toMatch(/castStatus|SuiteStatusMap|verified/);
    expect(SHELF).toMatch(/function suiteChipText\(toolbox: string\): string \{/);
  });
});

describe("the mark is decoration and the caption is the text", () => {
  it("carries the type beside the words rather than parsing it back out", () => {
    // A glyph recovered from the caption's prose would be a function of the
    // wording: a copy change would silently drop the art, which is the drift
    // this repo keeps finding. Both come from `step.input` at one call site.
    expect(SHELF).toMatch(/return \{ text: `needs \$\{input\}`, type: input \};/);
    expect(TILE).toMatch(/export type OpsNeed = \{/);
  });

  it("hides the glyph from the name computation", () => {
    // `KindGlyph` hides both vocabularies it can draw — lucide sets
    // `aria-hidden`, and `Glyph` does too — so a caption announces exactly
    // the words it announced before the art arrived. 191f2ed's whole subject
    // is controls whose ARIA says something other than the control.
    expect(TILE).toMatch(/<KindGlyph kind=\{need\.type\} size=\{12\}/);
    expect(TILE).toMatch(/<span className="whitespace-nowrap">\{need\.text\}<\/span>/);
  });

  it("still points the refused control at the caption it prints", () => {
    // `data-disabled-reason` is what `aria-describedby` resolves to, and it
    // moved into `NeedCaption` when the captions did. Losing it would leave
    // three refused controls describing themselves with nothing.
    expect(TILE).toMatch(/<span id=\{id\} data-disabled-reason/);
    const captions = SHELF.match(/<NeedCaption/g) || [];
    expect(captions.length, "the shelf stopped rendering its captions").toBeGreaterThan(1);
  });

  it("never spends the op's name to make room for the mark", () => {
    // 3ef6526 made the pair row wrap and left the solo rows on `min-w-0
    // truncate`, where eleven of them were already losing characters at the
    // panel's 160px minimum with no caret active. A name is not the give.
    expect(SHELF).toMatch(/"grow shrink-0 font-mono text-\[11\.5px\] font-medium"/);
    expect(SHELF).not.toMatch(/min-w-0 flex-1 truncate font-mono/);
  });
});

/**
 * A cell says who it runs for, and a peer is a name rather than a fingerprint.
 *
 * `@alice` at the head of a chain is grammar and nothing else — it names the
 * party a cell belongs to, and `publish` says the cell's `out` artifacts are
 * meant to leave the machine. Nothing runs differently for having read one.
 * The tests below therefore spend most of their effort on the two things that
 * are expensive to get wrong later: that a header survives every round trip a
 * recipe takes, and that a *fingerprint* can never be written as one.
 *
 * The fingerprint refusal is the reason this landed as grammar first. The peer
 * label grammar is shared with slots — `SLOT_LABEL_RE`, deliberately, so there
 * is one label rule and two sigils — and that rule has no length bound. A
 * 40-character hex fingerprint beginning `A`–`F` is therefore a *structurally
 * valid* peer label, while one beginning with a digit is not. Roughly 37% of
 * fingerprints parse: enough that it silently works for some users, rare
 * enough that casual testing says it does not work at all.
 *
 * It has to be refused because `notebook/room.js` derives the room from a
 * digest of the audience precisely so fingerprints never cross the wire, and
 * the manifest carries `audienceSha` rather than a list. A fingerprint written
 * as `@AABBCC…` rides out verbatim in a shared `#r=` link, and the room is a
 * function of exactly that audience.
 *
 * So the gate is not "is 40-hex rejected". It is: *derive* fingerprints the
 * way real ones are derived — digest hex — cover every leading character, and
 * require the refusal to be symmetric where the grammar is not. Reading the
 * pattern would miss the asymmetry; the sweep below cannot.
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  PRESETS,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
  validateRecipe,
} from "../lib/toolkit/recipe.js";
import {
  MAX_PEER_LABEL_LEN,
  PEER_WILDCARD,
  normalizePeerRef,
  normalizeSlotRef,
} from "../lib/toolkit/recipe-parse.js";
import {
  compactRecipeText,
  decodeSharePayload,
  encodeSharePayload,
  expandShareRecipe,
  hashForRecipe,
  recipeLooksSecret,
} from "../lib/toolkit/fragment.js";

const BODY = "genkey x25519 | out $kp";
const cellFor = (peer) => `@${peer}\n${BODY}`;
const errorsFor = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message);

/**
 * A chain without its char offsets. Compact and pretty spell the same cell at
 * different positions, so the offsets are the one thing that legitimately
 * differs across a `#r=` round trip.
 */
const shapeOf = (chain) => ({
  ...chain,
  headerStart: undefined,
  headerEnd: undefined,
  steps: (chain.steps || []).map((s) => ({ ...s, start: undefined, end: undefined })),
});

/**
 * Fingerprints, derived rather than typed.
 *
 * A v4 fingerprint is SHA-1 hex and a v6 / SHA-256 one is SHA-256 hex, so
 * digesting a counter produces the real shapes with real character
 * distributions — including, across enough of them, every possible leading
 * character. A long key id is the fingerprint's tail, and identifies its
 * holder just as well in fewer characters.
 */
const FINGERPRINTS = [];
for (let i = 0; i < 64; i++) {
  const sha1 = createHash("sha1").update(`peer-${i}`).digest("hex");
  const sha256 = createHash("sha256").update(`peer-${i}`).digest("hex");
  FINGERPRINTS.push(sha1.toUpperCase(), sha1, sha256.toUpperCase(), sha256);
  FINGERPRINTS.push(sha1.slice(-16).toUpperCase());
}

/** The ones a *label* grammar would happily accept — the actual hazard. */
const PARSEABLE_FINGERPRINTS = FINGERPRINTS.filter(
  (f) => normalizePeerRef(f).ok
);

describe("the hazard this file exists for is real", () => {
  it("lets a fingerprint through the label grammar, but only sometimes", () => {
    // If this ever became "none", the refusal below would be untestable
    // theatre; if it became "all", the asymmetry argument would be wrong.
    // Either way the file above needs rewriting rather than deleting.
    expect(PARSEABLE_FINGERPRINTS.length).toBeGreaterThan(0);
    expect(PARSEABLE_FINGERPRINTS.length).toBeLessThan(FINGERPRINTS.length);

    // …and the split is exactly "starts with a letter", which is the slot
    // label rule doing the deciding — not anything peers chose.
    for (const f of FINGERPRINTS) {
      expect(normalizePeerRef(f).ok, f).toBe(/^[A-Fa-f]/.test(f));
    }
  });
});

describe("a peer is named, not fingerprinted", () => {
  it("refuses every fingerprint shape the grammar would have accepted", () => {
    const accepted = PARSEABLE_FINGERPRINTS.filter(
      (f) => compileRecipe(cellFor(f)).validation.ok
    );
    expect(
      accepted.slice(0, 4),
      `${accepted.length} fingerprint-shaped peer labels compiled. A ` +
        `fingerprint in shared recipe text gives away the audience, and the ` +
        `room is derived from the audience — refuse them in validateRecipe.`
    ).toEqual([]);
  });

  it("says what to write instead", () => {
    // The remedy is the sentence, not the diagnosis. A rule that only lives in
    // prose drifts; this is the executable copy.
    const [message] = errorsFor(cellFor(PARSEABLE_FINGERPRINTS[0]));
    expect(message).toMatch(/named, not fingerprinted/);
    expect(message).toMatch(/@alice/);
    expect(message).toMatch(/audience/);
    expect(message).toMatch(/room is derived from the audience/);
  });

  it("refuses the same shape at share time, where nothing compiles", () => {
    // `hashForRecipe` builds a `#r=` link from text without ever compiling it,
    // so a compile-only refusal is made exactly where it does not matter.
    for (const f of PARSEABLE_FINGERPRINTS.slice(0, 8)) {
      const share = hashForRecipe(cellFor(f));
      expect(share.ok, f).toBe(false);
      expect(recipeLooksSecret(compactRecipeText(cellFor(f))), f).toBe(true);
    }
  });

  it("leaves a fingerprint alone in every position that is not a peer", () => {
    // The collateral half, and the one that would make this rule unusable if
    // it were wrong: a fingerprint is an ordinary public argument everywhere
    // except the position that names a person.
    const fpr = PARSEABLE_FINGERPRINTS[0];
    const asArgument = `hkp.get ${fpr} | out $pub`;
    expect(errorsFor(asArgument)).toEqual([]);
    expect(hashForRecipe(asArgument).ok).toBe(true);
    expect(recipeLooksSecret(asArgument)).toBe(false);

    const asRecipient = `input | gpg.encrypt to=${fpr}`;
    expect(hashForRecipe(asRecipient).ok).toBe(true);
  });

  it("still accepts the names people actually have", () => {
    // Without this the suite would pass by refusing everything.
    for (const name of ["alice", "mara", "okafor", "ops-team", "node_1", "d"]) {
      expect(compileRecipe(cellFor(name)).validation.ok, name).toBe(true);
    }
  });
});

describe("one label grammar, two sigils", () => {
  const LABELS = [
    "alice",
    "Alice",
    "ops-team",
    "node_1",
    "a",
    "all",
    "1abc",
    "-abc",
    "_abc",
    "a b",
    "",
    "aé",
  ];

  it("agrees with the slot grammar on what a label is", () => {
    // `normalizePeerRef` shares SLOT_LABEL_RE rather than restating it. If it
    // ever grew its own copy, the two would drift apart here first.
    for (const label of LABELS) {
      expect(normalizePeerRef(label).ok, label).toBe(
        normalizeSlotRef(`$${label}`).ok
      );
    }
  });

  it("keeps the rendezvous wildcard outside the label grammar", () => {
    // `@*` rather than `@all`: `*` cannot be a label, so the wildcard can
    // never collide with a participant who is actually called `all`.
    expect(normalizeSlotRef(`$${PEER_WILDCARD}`).ok).toBe(false);
    expect(normalizePeerRef(PEER_WILDCARD)).toEqual({
      ok: true,
      peer: PEER_WILDCARD,
    });
    expect(normalizePeerRef("all")).toEqual({ ok: true, peer: "all" });
    expect(parseRecipe(cellFor(PEER_WILDCARD)).ast.chains[0].peer).toBe("*");
    expect(parseRecipe(cellFor("all")).ast.chains[0].peer).toBe("all");
  });

  it("bounds a peer name, where a slot label is unbounded", () => {
    // A slot label is local to the recipe; a peer label is a person's name in
    // text that gets shared, so an unbounded one is an unbounded string riding
    // out in a link under a grammar that looks like it only holds names.
    const long = `a${"b".repeat(MAX_PEER_LABEL_LEN)}`;
    expect(normalizeSlotRef(`$${long}`).ok).toBe(true);
    expect(normalizePeerRef(long).ok).toBe(false);
    expect(normalizePeerRef(long.slice(0, MAX_PEER_LABEL_LEN)).ok).toBe(true);
  });
});

describe("the header round-trips", () => {
  const HEADERS = ["@alice", "@alice publish", "@*", "@* publish", "@ops-team"];

  for (const header of HEADERS) {
    it(`survives serialize and \`#r=\` unchanged: ${header}`, () => {
      const src = `${header}\n${BODY}`;
      const { ast } = parseRecipe(src);
      expect(serializeRecipe(ast)).toBe(src);

      // …and through the link, which is where a partial landing would show:
      // a header that parses locally and vanishes on share reads as a
      // placement nobody wrote.
      const link = encodeSharePayload(compactRecipeText(src));
      expect(link).not.toContain("%40");
      const back = parseRecipe(
        expandShareRecipe(decodeSharePayload(link))
      );
      expect(back.errors).toEqual([]);
      expect(back.ast.chains.map(shapeOf)).toEqual(ast.chains.map(shapeOf));
      expect(serializeRecipe(back.ast)).toBe(src);
    });
  }

  it("reads the compact spelling the link carries", () => {
    // Compact puts the header and the first step on one line; pretty gives the
    // header its own. Both are the same cell.
    const compact = parseRecipe("@alice publish random 32|out $x");
    const pretty = parseRecipe("@alice publish\nrandom 32 | out $x");
    expect(compact.errors).toEqual([]);
    expect(compact.ast.chains[0].peer).toBe("alice");
    expect(compact.ast.chains[0].publish).toBe(true);
    expect(serializeRecipe(compact.ast)).toBe(serializeRecipe(pretty.ast));
  });

  it("carries the whole exchange the design is written around", () => {
    const dh = `@alice
genkey x25519 | out $kpA

@alice publish
$kpA | :public | out $pubA

@bob
genkey x25519 | out $kpB

@bob publish
$kpB | :public | out $pubB

@alice
ecdh private=$kpA peer=$pubB | out $shared`;
    const { ast, validation } = compileRecipe(dh);
    expect(validation.errors).toEqual([]);
    expect(ast.chains.map((c) => [c.peer, !!c.publish])).toEqual([
      ["alice", false],
      ["alice", true],
      ["bob", false],
      ["bob", true],
      ["alice", false],
    ]);
    expect(serializeRecipe(ast)).toBe(dh);
    const share = hashForRecipe(dh);
    expect(share.ok).toBe(true);
    expect(share.hash.length).toBeLessThan(400);
  });
});

describe("the header is inert", () => {
  it("changes nothing about the steps under it", () => {
    // Grammar only: a parsed header must not move a single thing the compiler
    // says about the pipeline.
    const bare = compileRecipe(BODY);
    const owned = compileRecipe(`@alice publish\n${BODY}`);
    // Offsets aside — the header occupies characters — the steps are the same
    // steps, carrying the same params the registry filled in.
    expect(shapeOf(owned.ast.chains[0]).steps).toEqual(
      shapeOf(bare.ast.chains[0]).steps
    );
    expect(owned.validation.errors).toEqual(bare.validation.errors);
    expect(owned.validation.warnings).toEqual(bare.validation.warnings);
    expect(owned.validation.inputNeeds).toEqual(bare.validation.inputNeeds);
    expect(owned.validation.recipientSlots).toEqual(
      bare.validation.recipientSlots
    );
  });

  it("leaves every headerless recipe without one", () => {
    // The preset corpus is the standing differential: a chain that was never
    // given a peer must not acquire the fields, not even as undefined keys.
    for (const preset of PRESETS) {
      const { ast } = parseRecipe(preset.recipe);
      for (const chain of ast?.chains || []) {
        expect(Object.keys(chain), preset.id).toEqual(["steps"]);
      }
    }
  });
});

describe("the header refuses what it cannot mean", () => {
  it("takes one peer per cell", () => {
    expect(errorsFor("@alice\n@bob\nrandom 32 | out $x")[0]).toMatch(
      /already runs for `@alice`/
    );
  });

  it("refuses a header with no cell under it", () => {
    expect(errorsFor("@alice")[0]).toMatch(/no steps follow it/);
  });

  it("names both readings when a `|` follows the header", () => {
    // `@kp | export spki` is a peer with a stray pipe *or* a pre-swap slot at
    // a position that is no longer one. Without legacy evidence in the source
    // the parser cannot know, so the message carries both fixes.
    const [message] = errorsFor("@kp | export spki");
    expect(message).toMatch(/names the peer it runs for/);
    expect(message).toMatch(/\$kp/);
  });

  it("refuses `publish` with nothing to publish", () => {
    // A silently-not-published artifact is a ceremony that quietly did nothing.
    expect(errorsFor("@alice publish\nrandom 32 | inspect")[0]).toMatch(
      /has no `out`/
    );
  });

  it("refuses a hand-built AST that says publish without a peer", () => {
    // Unspellable in text, reachable through the AST, and it would serialize
    // to a recipe that no longer says it.
    const { ast } = parseRecipe(BODY);
    const forged = { ...ast, chains: [{ ...ast.chains[0], publish: true }] };
    expect(validateRecipe(forged).errors[0].message).toMatch(
      /needs a peer to go from/
    );
  });

  it("anchors its complaints to the header, not to step 0", () => {
    const src = cellFor(PARSEABLE_FINGERPRINTS[0]);
    const { ast } = parseRecipe(src);
    const [error] = validateRecipe(ast).errors;
    expect(error.start).toBe(ast.chains[0].headerStart);
    expect(error.end).toBe(ast.chains[0].headerEnd);
    expect(src.slice(error.start, error.end)).toBe(src.split("\n")[0]);
  });
});

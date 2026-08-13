/**
 * A cell says who it runs for, and a peer is a whole key rather than a part of
 * one.
 *
 * `@<fingerprint>` at the head of a chain is grammar and nothing else — it names
 * the party a cell belongs to, and `publish` says the cell's `out` artifacts are
 * meant to leave the machine. Nothing runs differently for having read one. The
 * tests below therefore spend most of their effort on the two things that are
 * expensive to get wrong later: that a header survives every round trip a recipe
 * takes, and that a *partial* key can never be written as one.
 *
 * ## This file used to assert the opposite, and the inversion is the point
 *
 * A peer was an invented label — `@peer1`, a position in the sorted audience —
 * and a fingerprint written in that position was refused, because a fingerprint
 * rides out verbatim in a shared `#r=` link and `notebook/room.js` derives the
 * room from a digest of exactly that audience. The reasoning was sound; what it
 * bought was a name that meant nothing to a reader and that moved under them
 * whenever the room changed size. The product now writes the key, and pays the
 * disclosure openly — see `recipeLinkDiscloses`, asserted below in the place the
 * old refusal stood.
 *
 * What did **not** invert is the refusal of a *piece* of a key. 8, 16 and 32 hex
 * characters are suffixes of a fingerprint, so each names more than one key: a
 * roster keyed by whole fingerprints cannot bind one, and a reader shown one has
 * compared part of a value believing they compared all of it. That is the same
 * defect `components/ui/fingerprint.tsx` exists to refuse, and the sweep below
 * is what keeps it refused while its neighbour was opened up.
 *
 * So the gate is not "is 40-hex accepted". It is: *derive* fingerprints the way
 * real ones are derived — digest hex — cover every leading character, and
 * require the answer to be symmetric where the grammar underneath is not. The
 * label grammar demands a leading letter and roughly two fingerprints in three
 * begin with a digit, so a rule that tested the name shape first would work for
 * some keys and not others. Reading the pattern would miss that; the sweep
 * cannot.
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
import { buildRunManifest } from "../lib/toolkit/manifest.js";
import {
  compactRecipeText,
  decodeSharePayload,
  encodeSharePayload,
  expandShareRecipe,
  hashForRecipe,
  recipeLinkDiscloses,
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
 * character.
 */
const FINGERPRINTS = [];
/** Suffixes of a real fingerprint: a short id, a long key id, and half of one. */
const KEY_IDS = [];
for (let i = 0; i < 64; i++) {
  const sha1 = createHash("sha1").update(`peer-${i}`).digest("hex");
  const sha256 = createHash("sha256").update(`peer-${i}`).digest("hex");
  FINGERPRINTS.push(sha1.toUpperCase(), sha1, sha256.toUpperCase(), sha256);
  KEY_IDS.push(sha1.slice(-16).toUpperCase(), sha1.slice(-16), sha1.slice(-32));
}

describe("a peer is a whole key", () => {
  it("takes every fingerprint, whatever it starts with", () => {
    // The asymmetry that made the old rule dangerous, asserted from the other
    // side. Both halves are named so that a grammar accepting nothing could not
    // pass this by accident: the corpus has to cover the leading characters,
    // *and* every member of it has to parse and compile.
    const leading = new Set(FINGERPRINTS.map((f) => f[0].toUpperCase()));
    expect(
      leading.size,
      "the corpus does not cover enough leading characters to see the asymmetry"
    ).toBeGreaterThan(10);
    for (const f of FINGERPRINTS) {
      expect(normalizePeerRef(f).ok, f).toBe(true);
      expect(compileRecipe(cellFor(f)).validation.ok, f).toBe(true);
    }
  });

  it("settles the case, because the roster is keyed upper", () => {
    // `peersSha` digests `{ peer: fingerprint }` and the fingerprint side is
    // `normalizeFingerprintInput`'s upper-case hex. A notebook that said
    // `@aabb…` on one machine and `@AABB…` on the other would be one intent
    // deriving two manifests, so the canonicaliser settles it once and the
    // serializer writes the settled spelling.
    for (const f of FINGERPRINTS.slice(0, 8)) {
      expect(normalizePeerRef(f).peer).toBe(f.toUpperCase());
      expect(normalizePeerRef(f.toLowerCase()).peer).toBe(f.toUpperCase());
    }
    const lower = FINGERPRINTS[1].toLowerCase();
    const { ast } = parseRecipe(cellFor(lower));
    expect(ast.chains[0].peer).toBe(lower.toUpperCase());
    expect(serializeRecipe(ast)).toContain(`@${lower.toUpperCase()}`);
  });
});

describe("a peer is not a piece of a key", () => {
  it("refuses every key-id shape the grammar would have accepted", () => {
    const accepted = KEY_IDS.filter((f) => compileRecipe(cellFor(f)).validation.ok);
    expect(
      accepted.slice(0, 4),
      `${accepted.length} partial-key peers compiled. A short id is a suffix ` +
        `of a fingerprint, so more than one key answers to it and no room can ` +
        `bind it — refuse them in validateRecipe.`
    ).toEqual([]);
  });

  it("says what to write instead", () => {
    // The remedy is the sentence, not the diagnosis. A rule that only lives in
    // prose drifts; this is the executable copy.
    const [message] = errorsFor(cellFor(KEY_IDS[0]));
    expect(message).toMatch(/part of a key rather than a key/);
    expect(message).toMatch(/more than one key answers to it/);
    expect(message).toMatch(/write the whole fingerprint/);
  });

  it("refuses it in the manifest too, where `peersSha` is committed", async () => {
    // The digest is what a partial key would corrupt: a roster key naming
    // several keys commits to none of them, and both ends would agree on a
    // `peersSha` that means nothing.
    await expect(
      buildRunManifest({
        title: "t",
        recipe: cellFor("alice"),
        cells: [],
        peers: { [KEY_IDS[0]]: FINGERPRINTS[0] },
      })
    ).rejects.toThrow(/part of a key/);
  });

  it("anchors its complaints to the header, not to step 0", () => {
    const src = cellFor(KEY_IDS[0]);
    const { ast } = parseRecipe(src);
    const [error] = validateRecipe(ast).errors;
    expect(error.start).toBe(ast.chains[0].headerStart);
    expect(error.end).toBe(ast.chains[0].headerEnd);
    expect(src.slice(error.start, error.end)).toBe(src.split("\n")[0]);
  });
});

describe("what a placed notebook's link gives away, said out loud", () => {
  it("no longer refuses to build one", () => {
    // `hashForRecipe` used to refuse this outright through `recipeLooksSecret`,
    // which is what let the Share sheet promise "No trust needed" about every
    // link it produced. The link is built now, and that is why the sentence
    // below has to exist at all.
    for (const f of FINGERPRINTS.slice(0, 8)) {
      expect(hashForRecipe(cellFor(f)).ok, f).toBe(true);
      expect(recipeLooksSecret(compactRecipeText(cellFor(f))), f).toBe(false);
    }
  });

  it("names the keys the link carries, and how many", () => {
    const two = `${cellFor(FINGERPRINTS[0])}\n\n@${FINGERPRINTS[4]}\n${BODY}`;
    const said = recipeLinkDiscloses(two);
    expect(said.peers).toEqual([
      FINGERPRINTS[0].toUpperCase(),
      FINGERPRINTS[4].toUpperCase(),
    ]);
    expect(said.sentence).toMatch(/2 keys/);
    expect(said.sentence).toMatch(/who is in the room/);
    // The half of the old promise that is still true, kept in the same sentence
    // so a reader is not left to work out which half survived.
    expect(said.sentence).toMatch(/reaches no server/);
  });

  it("says nothing about a notebook that names nobody", () => {
    // The failure mode this repo landed a fix for the same night (`42875a2`):
    // prose describing a product that does not exist. Most notebooks are
    // unplaced and disclose no audience, and a warning over them would be
    // exactly that — so the empty answer is asserted, not merely allowed.
    expect(recipeLinkDiscloses(BODY)).toEqual({ peers: [], sentence: "" });
    expect(recipeLinkDiscloses(cellFor("alice"))).toEqual({ peers: [], sentence: "" });
  });

  it("counts only the peer position, not every fingerprint in the text", () => {
    // The collateral half, and the one that would make the sentence useless if
    // it were wrong: a fingerprint is an ordinary public argument everywhere
    // except the position that names a person, and one in an argument says
    // nothing about who is in a room.
    const fpr = FINGERPRINTS[0];
    const asArgument = `hkp.get ${fpr} | out $pub`;
    expect(errorsFor(asArgument)).toEqual([]);
    expect(hashForRecipe(asArgument).ok).toBe(true);
    expect(recipeLinkDiscloses(asArgument).sentence).toBe("");

    const asRecipient = `input | gpg.encrypt to=${fpr}`;
    expect(hashForRecipe(asRecipient).ok).toBe(true);
    expect(recipeLinkDiscloses(asRecipient).sentence).toBe("");
  });
});

describe("a peer may still be a name", () => {
  it("still accepts the names people actually have", () => {
    // Nothing forces a hand-written notebook to speak in fingerprints, and a
    // `@peer1` written before this change still has to parse — `planRun` is
    // where it is told that nobody in the room answers to it, which is a
    // refusal naming a true state rather than a compile error naming a
    // grammar that has not changed.
    for (const name of ["alice", "mara", "okafor", "ops-team", "node_1", "d", "peer1"]) {
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

  it("agrees with the slot grammar on what a *name* is", () => {
    // `normalizePeerRef` shares SLOT_LABEL_RE rather than restating it. If it
    // ever grew its own copy, the two would drift apart here first.
    //
    // Peers are a strict superset now — a whole fingerprint is a peer — so the
    // agreement is asserted over the names, and the case the superset adds is
    // asserted beside it rather than left as a silent hole in this sweep.
    for (const label of LABELS) {
      expect(normalizePeerRef(label).ok, label).toBe(
        normalizeSlotRef(`$${label}`).ok
      );
    }
    const fpr = createHash("sha1").update("superset").digest("hex").toUpperCase();
    const digitFirst = `1${fpr.slice(1)}`;
    expect(normalizePeerRef(digitFirst).ok).toBe(true);
    expect(normalizeSlotRef(`$${digitFirst}`).ok).toBe(false);
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
    // A slot label is local to the recipe; a peer is a name in text that gets
    // shared, so an unbounded one is an unbounded string riding out in a link
    // under a grammar that looks like it only holds short things. The bound is
    // the length of a v6 fingerprint, which is the longest legal peer there is.
    const long = `a${"b".repeat(MAX_PEER_LABEL_LEN)}`;
    expect(normalizeSlotRef(`$${long}`).ok).toBe(true);
    expect(normalizePeerRef(long).ok).toBe(false);
    expect(normalizePeerRef(long.slice(0, MAX_PEER_LABEL_LEN)).ok).toBe(true);
    // The bound is exactly a v6 fingerprint and not a character less.
    const v6 = createHash("sha256").update("bound").digest("hex").toUpperCase();
    expect(v6).toHaveLength(MAX_PEER_LABEL_LEN);
    expect(normalizePeerRef(v6).ok).toBe(true);
  });
});

describe("the header round-trips", () => {
  // `publish=$kp` names the one `out` in BODY. It rides the same sweep as the
  // bare forms on purpose: the named header is the one that can quietly widen
  // if a trip drops the list, and a trip that dropped it would still produce a
  // header that parses.
  //
  // A fingerprint header is in the list because it is the *long* one, and the
  // compact `#r=` spelling is where a length problem would first show.
  const FPR = createHash("sha1").update("roundtrip").digest("hex").toUpperCase();
  const HEADERS = [
    "@alice",
    "@alice publish",
    "@alice publish=$kp",
    "@*",
    "@* publish",
    "@ops-team",
    `@${FPR}`,
    `@${FPR} publish=$kp`,
  ];

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
});

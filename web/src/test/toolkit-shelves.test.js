/**
 * Ops-drawer taxonomy shelves, conjugates, and glyphs.
 */
import { describe, expect, it } from "vitest";
import { GLYPH_PATHS, glyphHtml } from "../lib/toolkit/glyphs.js";
import { decodeTwinToken, pairTokenParts } from "../lib/toolkit/step-names.js";
import {
  SHELF_META,
  TOOLBOX_META,
  AES_MODE_PICKS,
  ENCODING_MODE_PICKS,
  OP_COLLECTIONS,
  collectionForStep,
  defaultCollapsedShelfKeys,
  formatDirectionForTip,
  getStep,
  KEY_FORMAT_META,
  KEY_FORMAT_PICKS,
  listDrawerRows,
  listOpCollections,
  listSteps,
  pairRowMatches,
  RSA_PADDING_PICKS,
} from "../lib/toolkit/registry.js";

describe("toolbox shelf taxonomy", () => {
  it("orders toolboxes WebCrypto → Encoding → I/O → Flow → OpenPGP → age → SSH → Agent → HKP → SSS → WebAuthn → OTP → WebRTC → Quorum → JOSE", () => {
    const ordered = Object.entries(TOOLBOX_META)
      .sort((a, b) => a[1].order - b[1].order)
      .map(([k]) => k);
    expect(ordered).toEqual([
      "webcrypto",
      "encoding",
      "io",
      "flow",
      "openpgp",
      // A peer of OpenPGP, next to it: both encrypt for someone else, with
      // different key types and different files.
      "age",
      // The formats block reads OpenPGP · age · SSH · Agent — message format
      // to file format to wire format to keystore (§29b).
      "ssh",
      "agent",
      "hkp",
      "sss",
      "webauthn",
      // Beside WebAuthn, not among the formats: both answer "set up my second
      // factor", and a user weighing a passkey against an authenticator app
      // should meet them together.
      "otp",
      "webrtc",
      // Directly after WebRTC because that is the layering, not because it is
      // a variety of it: quorum is session management for RTC peers, so a
      // reader who has just met `peer.offer` meets `quorum.offer` next.
      "quorum",
      "jose",
    ]);
  });

  it("assigns every step a known shelf with glyph meta", () => {
    for (const s of listSteps()) {
      expect(s.shelf, s.name).toBeTruthy();
      expect(SHELF_META[s.shelf], `${s.name} shelf ${s.shelf}`).toBeTruthy();
      expect(SHELF_META[s.shelf].glyph).toBeTruthy();
      expect(GLYPH_PATHS[SHELF_META[s.shelf].glyph]).toBeTruthy();
    }
  });

  it("gives every step an explicit glyph present in GLYPH_PATHS", () => {
    for (const s of listSteps()) {
      expect(s.glyph, s.name).toBeTruthy();
      expect(GLYPH_PATHS[s.glyph], `${s.name} glyph ${s.glyph}`).toBeTruthy();
    }
  });

  it("gives every toolbox a glyph", () => {
    for (const [tb, meta] of Object.entries(TOOLBOX_META)) {
      expect(meta.glyph, tb).toBeTruthy();
      expect(GLYPH_PATHS[meta.glyph], tb).toBeTruthy();
      expect(glyphHtml(meta.glyph)).toContain("<svg");
    }
  });

  it("places webcrypto ops on taxonomy shelves", () => {
    expect(getStep("digest")?.shelf).toBe("digest");
    expect(getStep("hkdf")?.shelf).toBe("kdf");
    expect(getStep("pbkdf2")?.shelf).toBe("kdf");
    expect(getStep("ecdh")?.shelf).toBe("agreement");
    expect(getStep("aes-gcm")?.shelf).toBe("aead");
    expect(getStep("aes-cbc")?.shelf).toBe("cipher");
    expect(getStep("rsa-oaep")?.shelf).toBe("rsa");
    expect(getStep("wrap")?.shelf).toBe("wrap");
  });

  it("seeds default-collapsed cipher/wrap/attestation shelves", () => {
    const keys = defaultCollapsedShelfKeys();
    expect(keys).toContain("webcrypto:cipher");
    expect(keys).toContain("webcrypto:wrap");
    expect(keys).toContain("webauthn:attestation");
    expect(keys).not.toContain("webcrypto:aead");
  });
});

describe("op collections", () => {
  it("lists the AES, RSA and encoding collections", () => {
    // `actionLabels` was asserted here too — `{ forward: "Encrypt", reverse:
    // "Decrypt" }` and its encoding twin. They are gone with `pairTileLabel`,
    // the only function that ever read them: a friendly-verb vocabulary of
    // twenty-four declarations across the registry, tried in `3ef6526` and
    // rejected because naming the buttons `Encrypt`/`Decrypt` made them
    // untypeable, then left in place shipping in the bundle and read by
    // nothing but this assertion.
    expect(listOpCollections().map((c) => c.id).sort()).toEqual([
      "aes",
      "encoding",
      "rsa",
    ]);
  });

  it("derives mode picks from OP_COLLECTIONS", () => {
    expect(AES_MODE_PICKS.map((m) => m.name)).toEqual([
      "aes-gcm",
      "aes-cbc",
      "aes-ctr",
    ]);
    expect(RSA_PADDING_PICKS.map((m) => m.name)).toEqual([
      "rsa-oaep",
      "rsa-pkcs1",
    ]);
    expect(ENCODING_MODE_PICKS.map((m) => m.name)).toEqual([
      "base64",
      "base64url",
      "base32",
    ]);
  });

  it("maps collection members to kitOnly steps", () => {
    for (const col of listOpCollections()) {
      for (const m of col.members) {
        expect(getStep(m.name)?.kitOnly, m.name).toBe(true);
        expect(collectionForStep(m.name)?.id).toBe(col.id);
      }
    }
  });

});

describe("conjugates and decode twins", () => {
  it("links sibling conjugates to existing steps", () => {
    for (const s of listSteps()) {
      if (!s.conjugate) continue;
      const rev = getStep(s.conjugate);
      expect(rev, s.name).toBeTruthy();
      expect(rev?.conjugateOf).toBe(s.name);
    }
    for (const s of listSteps()) {
      if (!s.conjugateOf) continue;
      const fwd = getStep(s.conjugateOf);
      expect(fwd?.conjugate).toBe(s.name);
    }
  });

  it("requires decodeTwin steps to expose a -d decode param", () => {
    for (const s of listSteps()) {
      if (!s.decodeTwin) continue;
      const decode = (s.params || []).find((p) => p.name === "decode" && p.flag === "-d");
      expect(decode, s.name).toBeTruthy();
    }
  });

  it("listDrawerRows pairs encode|-d and sign|verify", () => {
    const webcrypto = listSteps().filter((s) => s.toolbox === "webcrypto");
    const aead = webcrypto.filter((s) => s.shelf === "aead" && !s.kitOnly);
    const aeadRows = listDrawerRows(aead);
    expect(aeadRows).toHaveLength(0);

    const aesGcm = webcrypto.filter((s) => s.name === "aes-gcm");
    const aesRows = listDrawerRows(aesGcm);
    expect(aesRows).toHaveLength(1);
    expect(aesRows[0].decodeTwin).toBe(true);
    expect(aesRows[0].forward?.name).toBe("aes-gcm");

    const signShelf = webcrypto.filter((s) => s.shelf === "sign");
    const signRows = listDrawerRows(signShelf);
    expect(signRows).toHaveLength(1);
    expect(signRows[0].forward?.name).toBe("sign");
    expect(signRows[0].reverse?.name).toBe("verify");
    expect(signRows.some((r) => r.step?.name === "verify")).toBe(false);
  });

  it("omits conjugateOf partners from solo rows", () => {
    const keys = listSteps().filter((s) => s.toolbox === "webcrypto" && s.shelf === "keys");
    const rows = listDrawerRows(keys);
    const names = rows.flatMap((r) => {
      if (r.type === "solo") return [r.step?.name];
      return [r.forward?.name, r.reverse?.name];
    });
    expect(names).toContain("genkey");
    expect(names).toContain("export");
    expect(names).toContain("import");
    expect(rows.filter((r) => r.type === "solo" && r.step?.name === "import")).toHaveLength(0);
  });

  it("marks export/import kitOnly (Formats drawer, not Keys tiles)", () => {
    expect(getStep("export")?.kitOnly).toBe(true);
    expect(getStep("import")?.kitOnly).toBe(true);
    expect(getStep("genkey")?.kitOnly).toBeFalsy();
  });

  it("marks AES/RSA/encoding collection members kitOnly", () => {
    expect(getStep("aes-gcm")?.kitOnly).toBe(true);
    expect(getStep("aes-cbc")?.kitOnly).toBe(true);
    expect(getStep("aes-ctr")?.kitOnly).toBe(true);
    expect(getStep("rsa-oaep")?.kitOnly).toBe(true);
    expect(getStep("rsa-pkcs1")?.kitOnly).toBe(true);
    expect(getStep("base64")?.kitOnly).toBe(true);
    expect(getStep("base32")?.kitOnly).toBe(true);
    expect(AES_MODE_PICKS.map((m) => m.name)).toEqual(["aes-gcm", "aes-cbc", "aes-ctr"]);
  });
});

describe("key format kit", () => {
  it("orders PKCS#8 before SPKI and exposes openssl-flavored labels", () => {
    expect(KEY_FORMAT_PICKS[0]).toBe("pkcs8");
    expect(KEY_FORMAT_META.pkcs8.label).toMatch(/PKCS/);
    expect(KEY_FORMAT_META.spki.title).toMatch(/pubout|SPKI/i);
  });

  it("infers export vs import from the tip", () => {
    expect(formatDirectionForTip({ base: "keypair" })).toBe("export");
    expect(formatDirectionForTip({ base: "key", which: "public" })).toBe("export");
    expect(formatDirectionForTip({ base: "bytes", kind: "der" })).toBe("import");
    expect(formatDirectionForTip({ base: "text", encoding: "jwk" })).toBe("import");
    expect(formatDirectionForTip({ base: "none" })).toBe(null);
  });
});

/**
 * What a conjugate shelf row prints, now that its two directions are named
 * buttons rather than a pair of chevrons.
 *
 * The row used to print one of its two ops whole — `gpg.encrypt` beside a
 * square that runs `gpg.decrypt` — and the owner's call was that it should
 * print the family with `encrypt` and `decrypt` on the buttons. That only
 * works if the family actually separates the rows, so the collision sweep
 * below is the assertion this arrangement stands or falls on: four rows offer
 * `sign` / `verify` and three offer `encrypt` / `decrypt`, and the shelf tells
 * them apart by nothing else.
 */
describe("what a conjugate row prints", () => {
  /** Every browse-tree pair row, as the shelf builds it. */
  const pairRows = listDrawerRows(listSteps().filter((s) => !s.kitOnly)).filter(
    (r) => r.type === "pair"
  );
  /** The two recipe tokens a row's handles append, in `OpsTile`'s spelling. */
  const tokensOf = (row) => [
    row.forward.decodeTwin ? decodeTwinToken(row.forward, false) : row.forward.name,
    row.reverse ? row.reverse.name : decodeTwinToken(row.forward, true),
  ];

  it("finds the rows it is measuring", () => {
    // An empty sweep passes every assertion below it, so this is a sentinel
    // rather than a census. It was `toBe(22)` and had to be edited the first
    // time a pair was declared (`clipboard.read`/`clipboard.write`) — an exact
    // count on a growing set is a line people learn to bump without reading,
    // which is the failure `opsRegistryVersion`'s pin was rewritten to avoid.
    // A floor still catches the thing that matters: the sweep going empty, or
    // collapsing to a handful, because `listDrawerRows` stopped pairing.
    expect(pairRows.length).toBeGreaterThanOrEqual(20);
    // And the pair this sentinel exists for is named, so "not empty" cannot be
    // satisfied by twenty rows that are all something else.
    expect(pairRows.map((r) => r.forward.name)).toContain("gpg.encrypt");
  });

  it("splits a dotted pair into the family and the two directions", () => {
    expect(pairTokenParts("gpg.encrypt", "gpg.decrypt")).toEqual({
      stem: "gpg",
      forward: "encrypt",
      reverse: "decrypt",
    });
    expect(pairTokenParts("gpg.symencrypt", "gpg.symdecrypt").stem).toBe("gpg");
    // A stem has to leave both buttons something to print, so the token that
    // *is* the stem does not become one.
    expect(pairTokenParts("playbook", "playbook.verify")).toEqual({
      stem: "",
      forward: "playbook",
      reverse: "playbook.verify",
    });
    expect(pairTokenParts("wrap", "unwrap")).toEqual({
      stem: "",
      forward: "wrap",
      reverse: "unwrap",
    });
  });

  it("reassembles every button back into the op it appends", () => {
    // The property that keeps the column honest: nothing is abbreviated, and
    // nothing is a friendly verb. `pairTileLabel` would put `Build` on
    // `otp.uri`'s handle, which names no step — this asserts the buttons are
    // spelled out of the token and can be typed back into it.
    const wrong = [];
    for (const row of pairRows) {
      const [fwd, rev] = tokensOf(row);
      const parts = pairTokenParts(fwd, rev);
      const join = (tail) => (parts.stem ? `${parts.stem}.${tail}` : tail);
      if (join(parts.forward) !== fwd) wrong.push(`${fwd} → ${join(parts.forward)}`);
      if (join(parts.reverse) !== rev) wrong.push(`${rev} → ${join(parts.reverse)}`);
    }
    expect(wrong, `handles that do not spell their own op:\n  ${wrong.join("\n  ")}`).toEqual([]);
  });

  it("prints the family only where the two ops actually share one", () => {
    const familyOf = (name) => {
      const row = pairRows.find((r) => r.forward.name === name);
      return pairTokenParts(...tokensOf(row)).stem;
    };
    // The stem is what the pair has in common, and it is finer than the
    // toolbox in the one place that matters: `vss.split` and `sss.split` are
    // both toolbox `sss`, so a row labelled by its module would print `sss` +
    // `split` / `combine` twice and collide.
    expect(familyOf("vss.split")).toBe("vss");
    expect(familyOf("sss.split")).toBe("sss");
    expect(getStep("vss.split").toolbox).toBe(getStep("sss.split").toolbox);
    expect(familyOf("gpg.encrypt")).toBe("gpg");
    expect(familyOf("stream.seal")).toBe("stream");
    // …and nothing where they share nothing. Those rows sit under a section
    // that already names the toolbox they have in common, so the column would
    // only be repeating the header.
    expect(familyOf("wrap")).toBe("");
    expect(familyOf("pem")).toBe("");
    expect(familyOf("input")).toBe("");
  });

  it("leaves no two rows printing the same three words", () => {
    // The whole justification for dropping the full op name from the column.
    // `sign` / `verify` is offered by webcrypto, openpgp, ssh and jose; if the
    // family did not separate them the shelf would draw four identical rows.
    const seen = new Map();
    const collisions = [];
    for (const row of pairRows) {
      const [fwd, rev] = tokensOf(row);
      const parts = pairTokenParts(fwd, rev);
      const printed = [parts.stem, parts.forward, parts.reverse].join(" ");
      if (seen.has(printed)) collisions.push(`${printed} — ${seen.get(printed)} and ${fwd}`);
      seen.set(printed, fwd);
    }
    expect(collisions, `rows a reader cannot tell apart:\n  ${collisions.join("\n  ")}`).toEqual([]);
    // Not vacuous: the four `sign` / `verify` rows really are in the sweep, so
    // the assertion above had something to catch.
    const signRows = pairRows.filter((r) => pairTokenParts(...tokensOf(r)).forward === "sign");
    expect(signRows.map((r) => r.forward.name).sort()).toEqual([
      "gpg.sign",
      "jose.sign",
      "sign",
      "ssh.sign",
    ]);
  });

  it("lets a query for either half reach the row that draws it", () => {
    // `listDrawerRows` drops every step with `conjugateOf`, so a filter run
    // step by step used to delete the row whenever only its reverse matched:
    // typing `unwrap` rendered no `wrap` / `unwrap` row at all. Now that the
    // reverse handle prints `symdecrypt`, a name the shelf shows and cannot
    // find would be worse than one it never showed.
    const find = (q) =>
      listSteps()
        .filter((s) => pairRowMatches(s, (x) => x.name.includes(q)))
        .filter((s) => !s.conjugateOf)
        .map((s) => s.name);
    for (const q of ["gpg.decrypt", "symdecrypt", "unwrap", "otp.parse", "playbook.verify"]) {
      expect(find(q), `"${q}" reaches no row`).not.toEqual([]);
    }
    expect(find("symdecrypt")).toContain("gpg.symencrypt");
    expect(find("unwrap")).toContain("wrap");
    // `blip39.decode` is the only name on its row that is no step's `name`.
    expect(find("blip39.decode")).toContain("blip39");
    // The control: following a partner must not make every query match
    // everything. `genkey` has no conjugate and pulls nothing in with it.
    expect(find("gpg.genkey")).toEqual(["gpg.genkey"]);
  });
});

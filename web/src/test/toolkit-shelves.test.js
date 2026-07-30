/**
 * Ops-drawer taxonomy shelves, conjugates, and glyphs.
 */
import { describe, expect, it } from "vitest";
import { GLYPH_PATHS, glyphHtml } from "../lib/toolkit/glyphs.js";
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
  pairTileLabel,
  RSA_PADDING_PICKS,
} from "../lib/toolkit/registry.js";

describe("toolbox shelf taxonomy", () => {
  it("orders toolboxes WebCrypto → Encoding → I/O → Flow → OpenPGP → Agent → HKP → SSS → WebAuthn → WebRTC → JOSE", () => {
    const ordered = Object.entries(TOOLBOX_META)
      .sort((a, b) => a[1].order - b[1].order)
      .map(([k]) => k);
    expect(ordered).toEqual([
      "webcrypto",
      "encoding",
      "io",
      "flow",
      "openpgp",
      "agent",
      "hkp",
      "sss",
      "webauthn",
      "webrtc",
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
  it("lists AES, RSA, and encoding collections with action labels", () => {
    expect(listOpCollections().map((c) => c.id).sort()).toEqual([
      "aes",
      "encoding",
      "rsa",
    ]);
    expect(OP_COLLECTIONS.aes.actionLabels).toEqual({
      forward: "Encrypt",
      reverse: "Decrypt",
    });
    expect(OP_COLLECTIONS.encoding.actionLabels).toEqual({
      forward: "Encode",
      reverse: "Decode",
    });
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

  it("pairTileLabel prefers Encrypt/Decode over verb names", () => {
    const aes = getStep("aes-gcm");
    expect(pairTileLabel(aes, { pairRole: "forward" })).toBe("Encrypt");
    expect(pairTileLabel(aes, { decode: true, pairRole: "reverse" })).toBe(
      "Decrypt"
    );
    const b64 = getStep("base64");
    expect(pairTileLabel(b64, { pairRole: "forward" })).toBe("Encode");
    expect(pairTileLabel(b64, { decode: true })).toBe("Decode");
    const sign = getStep("sign");
    expect(pairTileLabel(sign, { pairRole: "forward" })).toBe("Sign");
    expect(pairTileLabel(getStep("verify"), { pairRole: "reverse" })).toBe(
      "Verify"
    );
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

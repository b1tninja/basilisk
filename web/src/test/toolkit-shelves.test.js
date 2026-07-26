/**
 * Ops-drawer taxonomy shelves, conjugates, and glyphs.
 */
import { describe, expect, it } from "vitest";
import { GLYPH_PATHS, glyphHtml } from "../lib/toolkit/glyphs.js";
import {
  SHELF_META,
  TOOLBOX_META,
  defaultCollapsedShelfKeys,
  getStep,
  listDrawerRows,
  listSteps,
} from "../lib/toolkit/registry.js";

describe("toolbox shelf taxonomy", () => {
  it("orders toolboxes WebCrypto → Encoding → I/O → Flow → OpenPGP → SSS → WebAuthn", () => {
    const ordered = Object.entries(TOOLBOX_META)
      .sort((a, b) => a[1].order - b[1].order)
      .map(([k]) => k);
    expect(ordered).toEqual([
      "webcrypto",
      "encoding",
      "io",
      "flow",
      "openpgp",
      "sss",
      "webauthn",
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
    const aead = webcrypto.filter((s) => s.shelf === "aead");
    const aeadRows = listDrawerRows(aead);
    expect(aeadRows).toHaveLength(1);
    expect(aeadRows[0].decodeTwin).toBe(true);
    expect(aeadRows[0].forward?.name).toBe("aes-gcm");

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
});

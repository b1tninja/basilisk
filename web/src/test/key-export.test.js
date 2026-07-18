/**
 * Vitest suite for private key export helpers (format conversion +
 * passphrase-lock enforcement).
 */
import { decryptKey, generateKey, readPrivateKey } from "openpgp";
import { beforeAll, describe, expect, it } from "vitest";
import {
  armoredToBinary,
  armoredToQrSvg,
  ensurePassphraseProtected,
  inspectPrivateKey,
  isArmoredKeyLocked,
  paperBackupHtml,
} from "../lib/key-export.js";

/** @type {string} */
let unlockedArmored;
/** @type {string} */
let lockedArmored;
/** @type {string} */
let fingerprint;

beforeAll(async () => {
  const unlocked = await generateKey({
    type: "curve25519",
    userIDs: [{ name: "Export Test", email: "export@example.com" }],
    format: "armored",
  });
  unlockedArmored = unlocked.privateKey;
  const key = await readPrivateKey({ armoredKey: unlockedArmored });
  fingerprint = key.getFingerprint().toUpperCase();

  const locked = await generateKey({
    type: "curve25519",
    userIDs: [{ name: "Locked Test", email: "locked@example.com" }],
    passphrase: "correct horse battery staple",
    format: "armored",
  });
  lockedArmored = locked.privateKey;
}, 30_000);

describe("isArmoredKeyLocked", () => {
  it("detects an unprotected key", async () => {
    expect(await isArmoredKeyLocked(unlockedArmored)).toBe(false);
  });

  it("detects a passphrase-protected key", async () => {
    expect(await isArmoredKeyLocked(lockedArmored)).toBe(true);
  });
});

describe("ensurePassphraseProtected", () => {
  it("returns an already-locked key unchanged", async () => {
    const out = await ensurePassphraseProtected(lockedArmored, "ignored");
    expect(out).toBe(lockedArmored);
  });

  it("locks an unprotected key with the given passphrase", async () => {
    const out = await ensurePassphraseProtected(unlockedArmored, "test-pass-123");
    expect(out).not.toBe(unlockedArmored);
    expect(await isArmoredKeyLocked(out)).toBe(true);

    // Same key, and the passphrase actually unlocks it
    const key = await readPrivateKey({ armoredKey: out });
    expect(key.getFingerprint().toUpperCase()).toBe(fingerprint);
    const dec = await decryptKey({ privateKey: key, passphrase: "test-pass-123" });
    expect(dec.isDecrypted()).toBe(true);
  });

  it("throws when the key is unprotected and no passphrase is given", async () => {
    await expect(ensurePassphraseProtected(unlockedArmored)).rejects.toThrow(
      /passphrase/i
    );
  });
});

describe("armoredToBinary", () => {
  it("round-trips to the same key", async () => {
    const binary = await armoredToBinary(lockedArmored);
    expect(binary).toBeInstanceOf(Uint8Array);
    expect(binary.length).toBeGreaterThan(100);
    const back = await readPrivateKey({ binaryKey: binary });
    const orig = await readPrivateKey({ armoredKey: lockedArmored });
    expect(back.getFingerprint()).toBe(orig.getFingerprint());
    // Binary export preserves at-rest passphrase protection
    expect(back.isDecrypted()).toBe(false);
  });
});

describe("armoredToQrSvg", () => {
  it("fits a Curve25519 private key in a single QR SVG", () => {
    const svg = armoredToQrSvg(lockedArmored);
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });
});

describe("inspectPrivateKey", () => {
  it("reports fingerprint, uid and locked state", async () => {
    const info = await inspectPrivateKey(lockedArmored);
    expect(info.fingerprint).toMatch(/^[0-9A-F]{40}$/);
    expect(info.uid).toContain("locked@example.com");
    expect(info.email).toBe("locked@example.com");
    expect(info.locked).toBe(true);

    const info2 = await inspectPrivateKey(unlockedArmored);
    expect(info2.locked).toBe(false);
    expect(info2.fingerprint).toBe(fingerprint);
  });
});

describe("paperBackupHtml", () => {
  it("embeds the armored key, fingerprint and import instructions", () => {
    const html = paperBackupHtml({
      armored: lockedArmored,
      fingerprint,
      uid: "Export Test <export@example.com>",
      expires: null,
    });
    expect(html).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    expect(html).toContain("gpg --import");
    expect(html).toContain(fingerprint.slice(0, 4));
    expect(html).toContain("<svg"); // QR embedded
  });

  it("escapes HTML in user-supplied fields", () => {
    const html = paperBackupHtml({
      armored: lockedArmored,
      fingerprint,
      uid: '<script>alert("x")</script>',
      expires: null,
    });
    expect(html).not.toContain('<script>alert("x")</script>');
  });
});

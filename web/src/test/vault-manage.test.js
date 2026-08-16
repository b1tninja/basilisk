/**
 * The vault's verbs, lifted out of `my-keys-mount.js`'s click handlers.
 *
 * The refusals had to be identical between the Keys tray and `/my-keys`, and
 * they were the half that could not be tested at all: each one lived inside a
 * `submit` listener beside a `setStatus` call. These are the same decisions as
 * functions — which is why they outlive the page. `/my-keys` is retired and the
 * tray is the only caller now, and the sentences are still asserted here rather
 * than in a browser.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKey } from "openpgp";
import { sanitizeFilename } from "../lib/zip-store.js";
import {
  EXPORT_FORMATS,
  exportRefusal,
  generateRefusal,
  importPrivateKey,
  importRefusal,
  passphraseRefusal,
} from "../lib/toolkit/vault-manage.js";
import { sessionClear, sessionGet, sessionList } from "../lib/vault-session.js";
import { listKeys } from "../lib/vault.js";

const STRONG = "correct horse battery staple frontier oyster";

beforeEach(async () => {
  sessionClear();
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

/** A real armored private key, since every path here parses one. */
async function makeKey({ passphrase = "" } = {}) {
  const { privateKey } = await generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name: "Ada", email: "ada@example.com" }],
    passphrase,
    format: "armored",
  });
  return privateKey;
}

describe("a refusal is a sentence, and every one of these is a state", () => {
  it("says why a weak passphrase is weak, in the estimator's own words", () => {
    const weak = passphraseRefusal("hunter2");
    expect(weak).toMatch(/bits/);
    expect(weak.length).toBeGreaterThan(30);
    expect(weak).toMatch(/[.!?]$/);
    expect(passphraseRefusal(STRONG)).toBe("");
  });

  it("names the address as the thing a keyserver searches by", () => {
    expect(generateRefusal({ email: "" })).toMatch(/keyserver search finds/);
    expect(generateRefusal({ email: "not-an-address" })).toMatch(/identified by an address/);
  });

  it("separates a blank passphrase from two that disagree", () => {
    const blank = generateRefusal({ email: "a@b.c", protection: "passphrase", passphrase: "" });
    expect(blank).toMatch(/no passphrase is typed/);
    const mismatch = generateRefusal({
      email: "a@b.c",
      protection: "passphrase",
      passphrase: STRONG,
      confirm: `${STRONG} x`,
    });
    expect(mismatch).toMatch(/two passphrases are different/);
    expect(
      generateRefusal({
        email: "a@b.c",
        protection: "passphrase",
        passphrase: STRONG,
        confirm: STRONG,
      })
    ).toBe("");
  });

  it("asks nothing of a passkey or device key it has no passphrase for", () => {
    for (const protection of ["passkey", "device"]) {
      expect(generateRefusal({ email: "a@b.c", protection })).toBe("");
    }
  });

  it("names what was pasted when it is not a private key", () => {
    expect(importRefusal({ armored: "-----BEGIN PGP PUBLIC KEY BLOCK-----" })).toMatch(
      /public key cannot sign or decrypt/
    );
  });

  it("says nothing about a passphrase before it has read the armor", () => {
    // `locked` is undefined until `inspectPrivateKey` has looked. Demanding a
    // passphrase then would be asking about a key nothing has seen.
    expect(importRefusal({ armored: `x PRIVATE KEY BLOCK y` })).toBe("");
  });

  it("demands protection for the vault and never for a session-only import", () => {
    const unprotected = { armored: "PRIVATE KEY BLOCK", locked: false };
    expect(importRefusal(unprotected)).toMatch(/openable private key in this browser's storage/);
    // The whole point of session-only is that nothing is written down, so
    // there is no stored key to protect and no passphrase to invent.
    expect(importRefusal({ ...unprotected, target: "session" })).toBe("");
  });

  it("refuses an export that would leave this browser unprotected", () => {
    expect(exportRefusal({ armorLocked: false })).toMatch(/an export leaves this browser/);
    expect(exportRefusal({ armorLocked: false, exportPassphrase: STRONG })).toBe("");
    // An already-locked key needs nothing typed — asking would be a refusal
    // naming a state the reader is not in.
    expect(exportRefusal({ armorLocked: true })).toBe("");
  });

  it("offers exactly the four formats the vault can write", () => {
    expect(EXPORT_FORMATS.map((f) => f.id)).toEqual(["asc", "gpg", "qr", "paper"]);
    expect(Object.isFrozen(EXPORT_FORMATS)).toBe(true);
  });
});

/**
 * What a backup is called, which is the only thing identifying it later.
 *
 * The name was `${fpr.slice(-8)}-private.asc`. A key backup is read months
 * after it is written, in a directory beside other backups, by somebody
 * deciding which key they are about to restore — and unlike every surface in
 * the app there is no hover, no menu, and no whole value anywhere on the line
 * to check the short one against. Two keys ending alike put two files in a
 * folder that no longer say which is which, which is the collision the short
 * id makes cheap.
 *
 * `downloadFile` is stubbed because it is the module's one browser act; the
 * name is the return value, so the decision is testable without one.
 */
vi.mock("../lib/key-export.js", async (importOriginal) => {
  const real = await importOriginal();
  return { ...real, downloadFile: () => {} };
});

describe("what an exported key is called", () => {
  it("names the file by the whole fingerprint, as gpg --export does", async () => {
    const { exportVaultKey } = await import("../lib/toolkit/vault-manage.js");
    const res = await importPrivateKey(await makeKey({ passphrase: STRONG }), {
      target: "vault",
    });
    const fpr = res.fingerprint;
    expect(fpr).toHaveLength(40);

    const { filename } = await exportVaultKey({
      fingerprint: fpr,
      format: "asc",
      exportPassphrase: STRONG,
      meta: { protection: "passphrase" },
    });
    expect(filename).toBe(`${fpr.toLowerCase()}-private.asc`);
    // Said as a property as well as a literal: the stem is the whole value and
    // not a tail of it. `-8` and `-16` both satisfy `endsWith`, and only one of
    // them is the fingerprint.
    expect(filename.split("-")[0]).toBe(fpr.toLowerCase());
    // And it survives the sanitizer the download path runs it through — 40 hex
    // characters plus a suffix is well inside its 180-character clamp and holds
    // nothing it rewrites.
    expect(sanitizeFilename(filename, "x")).toBe(filename);
  });
});

describe("importing for this session only", () => {
  it("puts the armor in the agent session and writes no vault record", async () => {
    const armored = await makeKey();
    const res = await importPrivateKey(armored, { target: "session" });
    expect(res.target).toBe("session");
    expect(sessionGet(res.fingerprint)).toBe(armored.trim());
    // `refreshVault` folds session entries into the notebook's key list, so
    // the consumer for this was already in place — what was missing was any
    // way to put one there.
    expect(await listKeys()).toEqual([]);
  });

  it("records whether the armor still owes a passphrase", async () => {
    // The one fact separating an open envelope from a usable key. Left
    // undefined, the chrome would have to guess, and guessing is what
    // `sessionPut` exists to stop.
    const locked = await importPrivateKey(await makeKey({ passphrase: STRONG }), {
      target: "session",
    });
    const open = await importPrivateKey(await makeKey(), { target: "session" });
    const byFpr = Object.fromEntries(sessionList().map((e) => [e.fingerprint, e.locked]));
    expect(byFpr[locked.fingerprint]).toBe(true);
    expect(byFpr[open.fingerprint]).toBe(false);
  });

  it("refuses a public key with the same sentence the box shows", async () => {
    await expect(
      importPrivateKey("-----BEGIN PGP PUBLIC KEY BLOCK-----", { target: "session" })
    ).rejects.toThrow(/public key cannot sign or decrypt/);
  });
});

describe("importing into the vault", () => {
  it("stores a passphrase-protected key as it stands", async () => {
    const armored = await makeKey({ passphrase: STRONG });
    const res = await importPrivateKey(armored, { target: "vault" });
    const rows = await listKeys();
    expect(rows.map((k) => k.fingerprint)).toEqual([res.fingerprint]);
    expect(rows[0].protection).toBe("passphrase");
    // Nothing lands in the agent session: importing is not unlocking.
    expect(sessionGet(res.fingerprint)).toBeNull();
  });

  it("refuses to write an unprotected key to storage", async () => {
    await expect(importPrivateKey(await makeKey(), { target: "vault" })).rejects.toThrow(
      /openable private key in this browser's storage/
    );
    expect(await listKeys()).toEqual([]);
  });

  it("protects an unlocked key with the passphrase it was given", async () => {
    const res = await importPrivateKey(await makeKey(), {
      target: "vault",
      passphrase: STRONG,
    });
    expect((await listKeys()).map((k) => k.fingerprint)).toEqual([res.fingerprint]);
  });
});

/**
 * Vitest suite for the browser key vault (IndexedDB + WebCrypto wrapping).
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import {
  collectKeyIds,
  deleteKey,
  derivePrfKek,
  expiryIsoFromPreset,
  listKeys,
  patchKeyMeta,
  protectionDowngradeMessage,
  purgeExpired,
  saveKey,
  sortKeysByLastUsed,
  touchKeyUsed,
  unlockKey,
  vaultKeyMatchesRecipients,
} from "../lib/vault.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { sessionClear, sessionGet } from "../lib/vault-session.js";

const SAMPLE_ARMORED = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Basilisk Test

xcLYBGTestKeyAAAAAAAAAExamplePrivateKeyMaterialForVaultTestsOnly=
-----END PGP PRIVATE KEY BLOCK-----`;

const FPR_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FPR_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

beforeEach(async () => {
  // Wipe vault DB between tests
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

describe("vault — device protection", () => {
  it("round-trips a device-only wrapped key", async () => {
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "Test <test@example.com>",
      email: "test@example.com",
      protection: "device",
      expires: null,
    });
    const keys = await listKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0].fingerprint).toBe(FPR_A);
    expect(keys[0].protection).toBe("device");

    const unlocked = await unlockKey(FPR_A);
    expect(unlocked).toBe(SAMPLE_ARMORED);
  });

  it("fails unlock on another origin's empty vault", async () => {
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "t",
      email: "t@example.com",
      protection: "device",
    });
    await expect(unlockKey(FPR_B)).rejects.toThrow(/not found/i);
  });
});

describe("vault — passphrase protection", () => {
  it("stores passphrase-locked armored inside device wrap", async () => {
    // The OpenPGP passphrase lock happens at generate time; vault just wraps the armored blob.
    const lockedArmored = SAMPLE_ARMORED.replace("Example", "PassphraseLocked");
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: lockedArmored,
      uid: "Alice <a@example.com>",
      email: "a@example.com",
      protection: "passphrase",
      expires: expiryIsoFromPreset("1w"),
    });
    const meta = (await listKeys())[0];
    expect(meta.protection).toBe("passphrase");
    expect(meta.expires).toBeTruthy();

    const out = await unlockKey(FPR_A, {});
    expect(out).toBe(lockedArmored);
  });
});

describe("vault — passkey (PRF) protection", () => {
  it("wraps with PRF-derived KEK and unlocks with same IKM", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "Bob <b@example.com>",
      email: "b@example.com",
      protection: "passkey",
      prfIkm: ikm,
    });

    await expect(unlockKey(FPR_A, {})).rejects.toThrow(/passkey/i);

    const out = await unlockKey(FPR_A, { prfIkm: ikm });
    expect(out).toBe(SAMPLE_ARMORED);
  });

  it("rejects unlock with wrong PRF IKM", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    const wrong = crypto.getRandomValues(new Uint8Array(32));
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "x",
      email: "x@example.com",
      protection: "passkey",
      prfIkm: ikm,
    });
    await expect(unlockKey(FPR_A, { prfIkm: wrong })).rejects.toThrow();
  });

  it("derivePrfKek produces a usable AES-GCM key", async () => {
    const ikm = new Uint8Array(32).fill(7);
    const kek = await derivePrfKek(ikm);
    expect(kek).toBeInstanceOf(CryptoKey);
    expect(kek.extractable).toBe(false);
    expect(kek.algorithm.name).toBe("AES-GCM");
  });
});

describe("vault — purge and delete", () => {
  it("purgeExpired removes past-due entries", async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 86400_000).toISOString();
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "old",
      email: "old@example.com",
      protection: "device",
      expires: past,
    });
    await saveKey({
      fingerprint: FPR_B,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "new",
      email: "new@example.com",
      protection: "device",
      expires: future,
    });
    const n = await purgeExpired();
    expect(n).toBe(1);
    const keys = await listKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0].fingerprint).toBe(FPR_B);
  });

  it("deleteKey removes the entry", async () => {
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "d",
      email: "d@example.com",
      protection: "device",
    });
    await deleteKey(FPR_A);
    expect(await listKeys()).toHaveLength(0);
  });
});

describe("vault — schema v2 publicArmored / lastUsedAt", () => {
  it("stores publicArmored and updates lastUsedAt on unlock", async () => {
    const { privateKey: armoredPrivate, publicKey: armoredPublic } =
      await generateKey({
        type: "ecc",
        curve: "curve25519",
        userIDs: [{ email: "v2@example.com" }],
        format: "armored",
      });
    const { readKey } = await import("openpgp");
    const pub = await readKey({ armoredKey: armoredPublic });
    const fpr = pub.getFingerprint().toUpperCase();

    await saveKey({
      fingerprint: fpr,
      armoredPrivate,
      publicArmored: armoredPublic,
      uid: "v2@example.com",
      email: "v2@example.com",
      protection: "device",
    });
    let meta = (await listKeys())[0];
    expect(meta.publicArmored).toContain("PUBLIC KEY");
    expect(meta.lastUsedAt).toBeNull();

    await touchKeyUsed(fpr);
    meta = (await listKeys())[0];
    expect(meta.lastUsedAt).toBeTruthy();

    sessionClear();
    const unlocked = await unlockVaultForUse(fpr);
    expect(unlocked.armored).toContain("PRIVATE KEY");
    expect(sessionGet(fpr)).toBeTruthy();
  }, 30_000);

  it("sortKeysByLastUsed orders newest first", () => {
    const sorted = sortKeysByLastUsed([
      {
        fingerprint: "A",
        uid: "",
        email: "",
        created: "2020-01-01T00:00:00.000Z",
        expires: null,
        protection: "device",
        lastUsedAt: "2020-01-01T00:00:00.000Z",
      },
      {
        fingerprint: "B",
        uid: "",
        email: "",
        created: "2020-01-01T00:00:00.000Z",
        expires: null,
        protection: "device",
        lastUsedAt: "2024-01-01T00:00:00.000Z",
      },
    ]);
    expect(sorted[0].fingerprint).toBe("B");
  });
});

describe("vault — protection downgrade on re-save", () => {
  it("refuses a passkey record re-saved as device, naming both protections", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "Bob <b@example.com>",
      email: "b@example.com",
      protection: "passkey",
      prfIkm: ikm,
    });

    await expect(
      saveKey({
        fingerprint: FPR_A,
        armoredPrivate: SAMPLE_ARMORED,
        uid: "Bob <b@example.com>",
        email: "b@example.com",
        protection: "device",
      })
    ).rejects.toThrow(protectionDowngradeMessage("passkey", "device"));

    // The stored record is untouched: still passkey, still needs the IKM.
    const meta = (await listKeys())[0];
    expect(meta.protection).toBe("passkey");
    await expect(unlockKey(FPR_A, {})).rejects.toThrow(/passkey/i);
    expect(await unlockKey(FPR_A, { prfIkm: ikm })).toBe(SAMPLE_ARMORED);
  });

  it("states the exact refusal, and names the remedy", () => {
    // The wording is the feature: both protections by name, and a way out
    // that is not "click it again harder".
    expect(protectionDowngradeMessage("passkey", "device")).toBe(
      "This key is already in the vault with passkey protection, and saving it with device protection would weaken it — delete it from My Keys first, or save it again with passkey protection."
    );
  });

  it("refuses passphrase → device too, not only passkey", async () => {
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "p",
      email: "p@example.com",
      protection: "passphrase",
    });
    await expect(
      saveKey({
        fingerprint: FPR_A,
        armoredPrivate: SAMPLE_ARMORED,
        uid: "p",
        email: "p@example.com",
        protection: "device",
      })
    ).rejects.toThrow(protectionDowngradeMessage("passphrase", "device"));
  });

  it("allows a re-save at the same protection", async () => {
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "s",
      email: "s@example.com",
      protection: "device",
    });
    const updated = SAMPLE_ARMORED.replace("Example", "Rewritten");
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: updated,
      uid: "s",
      email: "s@example.com",
      protection: "device",
      publicArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nZg==\n-----END PGP PUBLIC KEY BLOCK-----",
    });
    const keys = await listKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0].publicArmored).toContain("PUBLIC KEY");
    expect(await unlockKey(FPR_A)).toBe(updated);
  });

  it("allows an upgrade from device to passkey", async () => {
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "u",
      email: "u@example.com",
      protection: "device",
    });
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "u",
      email: "u@example.com",
      protection: "passkey",
      prfIkm: ikm,
    });
    expect((await listKeys())[0].protection).toBe("passkey");
    expect(await unlockKey(FPR_A, { prfIkm: ikm })).toBe(SAMPLE_ARMORED);
  });

  it("replaces when the caller says so, discarding the passkey binding", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "r",
      email: "r@example.com",
      protection: "passkey",
      prfIkm: ikm,
    });
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "r",
      email: "r@example.com",
      protection: "device",
      onConflict: "replace",
    });
    expect((await listKeys())[0].protection).toBe("device");
    expect(await unlockKey(FPR_A)).toBe(SAMPLE_ARMORED);
  });

  it("leaves the read-modify-write helpers alone", async () => {
    // patchKeyMeta and touchKeyUsed never rebuild the record and never touch
    // `protection`, so they do not go through the guard and must not start
    // failing on a passkey record.
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    await saveKey({
      fingerprint: FPR_A,
      armoredPrivate: SAMPLE_ARMORED,
      uid: "m",
      email: "m@example.com",
      protection: "passkey",
      prfIkm: ikm,
    });
    await patchKeyMeta(FPR_A, {
      publicArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nZg==\n-----END PGP PUBLIC KEY BLOCK-----",
      keyIds: ["DEADBEEFDEADBEEF"],
    });
    await touchKeyUsed(FPR_A);
    const meta = (await listKeys())[0];
    expect(meta.protection).toBe("passkey");
    expect(meta.publicArmored).toContain("PUBLIC KEY");
    expect(meta.keyIds).toContain("DEADBEEFDEADBEEF");
    expect(meta.lastUsedAt).toBeTruthy();
    expect(await unlockKey(FPR_A, { prfIkm: ikm })).toBe(SAMPLE_ARMORED);
  });

  it("rejects an unrecognized onConflict rather than falling back", async () => {
    await expect(
      saveKey({
        fingerprint: FPR_A,
        armoredPrivate: SAMPLE_ARMORED,
        uid: "z",
        email: "z@example.com",
        protection: "device",
        onConflict: /** @type {*} */ ("overwrite"),
      })
    ).rejects.toThrow(/onConflict/);
  });
});

describe("vault — expiry helpers", () => {
  it("expiryIsoFromPreset returns null for none", () => {
    expect(expiryIsoFromPreset("none")).toBeNull();
  });

  it("expiryIsoFromPreset returns future ISO for 1d", () => {
    const iso = expiryIsoFromPreset("1d");
    expect(iso).toBeTruthy();
    expect(Date.parse(iso)).toBeGreaterThan(Date.now());
  });
});

describe("vault — recipient key ID matching", () => {
  it("collectKeyIds returns primary and encryption subkey IDs", async () => {
    const { privateKey: armoredPrivate, publicKey: armoredPublic } =
      await generateKey({
        type: "ecc",
        curve: "curve25519",
        userIDs: [{ email: "match@example.com" }],
        format: "armored",
      });
    const ids = await collectKeyIds(armoredPrivate);
    expect(ids.length).toBeGreaterThanOrEqual(1);
    for (const id of ids) {
      expect(id).toMatch(/^[0-9A-F]{16}$/);
    }

    // Encrypt to the public key and confirm a recipient ID is in our list.
    const { createMessage, encrypt, readKey, readMessage } = await import(
      "openpgp"
    );
    const pub = await readKey({ armoredKey: armoredPublic });
    const enc = String(
      await encrypt({
        message: await createMessage({ text: "match me" }),
        encryptionKeys: pub,
        format: "armored",
      })
    );
    const msg = await readMessage({ armoredMessage: enc });
    const recipients = (msg.getEncryptionKeyIDs() || []).map((k) =>
      k.toHex().toUpperCase()
    );
    expect(recipients.some((r) => ids.includes(r))).toBe(true);

    const fpr = pub.getFingerprint().toUpperCase();
    await saveKey({
      fingerprint: fpr,
      armoredPrivate,
      uid: "match@example.com",
      email: "match@example.com",
      protection: "device",
    });
    const meta = (await listKeys()).find((k) => k.fingerprint === fpr);
    expect(meta?.keyIds?.length).toBeGreaterThanOrEqual(1);
    expect(vaultKeyMatchesRecipients(meta, recipients)).toBe(true);
    expect(vaultKeyMatchesRecipients(meta, ["DEADBEEFDEADBEEF"])).toBe(false);
  }, 30_000);

  it("legacy records without keyIds match via fingerprint suffix", () => {
    const fpr = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    const meta = {
      fingerprint: fpr,
      uid: "",
      email: "",
      created: "",
      expires: null,
      protection: /** @type {const} */ ("device"),
      keyIds: [fpr.slice(-16)],
    };
    expect(vaultKeyMatchesRecipients(meta, [fpr.slice(-16)])).toBe(true);
    expect(vaultKeyMatchesRecipients(meta, [fpr])).toBe(true);
  });
});

/**
 * Two passkeys, and the key that was wrapped under the first one.
 *
 * The vault kept its PRF metadata in a single row — one credential id, one
 * random salt, for the whole vault — so a second enrolment did not sit beside
 * the first, it replaced it. Every key already wrapped under the first
 * enrolment then asked the authenticator for a PRF over a salt nobody had
 * kept. That is not a lockout: the salt was 32 random bytes and it is gone, so
 * the wrapping key cannot be derived again by anyone, on any device.
 *
 * The metadata is now keyed by the fingerprint of the key it wraps, which is
 * the identity the key store already uses, so `unlockKey(fpr)` reads that key's
 * own enrolment rather than whichever one happens to be current.
 *
 * These tests run a fake authenticator that keys its PRF on the credential
 * *and* the salt, because a fake returning fixed bytes cannot tell two
 * enrolments apart and would pass on the broken code.
 */
import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createPasskeyPrf,
  deleteKey,
  getPasskeyPrf,
  prfEnrolmentMismatchMessage,
  prfEnrolmentMissingMessage,
  prfLegacyEnrolmentLostMessage,
  saveKey,
  unlockKey,
} from "../lib/vault.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { sessionClear } from "../lib/vault-session.js";
import { bytesToBase64Url } from "../lib/toolkit/encode.js";

const SAMPLE_ARMORED = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Basilisk Test

xcLYBGTestKeyAAAAAAAAAExamplePrivateKeyMaterialForVaultTestsOnly=
-----END PGP PRIVATE KEY BLOCK-----`;

const FPR_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FPR_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

/**
 * A fake authenticator whose PRF is a real HMAC over (credential secret, salt).
 *
 * The point of the fixture is that asking the wrong credential, or the right
 * credential with the wrong salt, produces different bytes — the property the
 * product depends on and the one the bug violated.
 */
function fakeAuthenticator() {
  /** @type {Map<string, { rawId: Uint8Array, secret: Uint8Array, salts: Uint8Array[] }>} */
  const creds = new Map();

  const asBytes = (v) => (v instanceof Uint8Array ? v : new Uint8Array(v));
  const idOf = (v) => bytesToBase64Url(asBytes(v));

  const prf = async (secret, salt) => {
    const key = await crypto.subtle.importKey(
      "raw",
      secret,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return crypto.subtle.sign("HMAC", key, salt);
  };

  const credentials = {
    /** @param {*} options */
    create: async (options) => {
      const rawId = crypto.getRandomValues(new Uint8Array(16));
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const salt = asBytes(options.publicKey.extensions.prf.eval.first);
      creds.set(idOf(rawId), { rawId, secret, salts: [salt] });
      const first = await prf(secret, salt);
      return {
        id: idOf(rawId),
        rawId: rawId.buffer.slice(0),
        type: "public-key",
        response: {},
        getClientExtensionResults: () => ({ prf: { results: { first } } }),
      };
    },
    /** @param {*} options */
    get: async (options) => {
      const allow = options.publicKey.allowCredentials || [];
      if (!allow.length) throw new Error("fake authenticator: no allowCredentials");
      // Answers with whichever offered credential it holds — first match,
      // standing in for the user picking a key at the prompt.
      const offered = allow.map((c) => idOf(c.id)).find((id) => creds.has(id));
      if (!offered) throw new Error("fake authenticator: no matching credential");
      const rec = creds.get(offered);
      const ext = options.publicKey.extensions?.prf || {};
      const salt = ext.evalByCredential
        ? ext.evalByCredential[offered]?.first
        : ext.eval?.first;
      if (!salt) throw new Error("fake authenticator: no PRF salt offered for this credential");
      rec.salts.push(asBytes(salt));
      const first = await prf(rec.secret, asBytes(salt));
      return {
        id: offered,
        rawId: rec.rawId.buffer.slice(0),
        type: "public-key",
        response: {},
        getClientExtensionResults: () => ({ prf: { results: { first } } }),
      };
    },
  };

  return {
    /** Every salt this credential has been asked to evaluate, in order. */
    saltsFor: (credentialId) => creds.get(idOf(credentialId))?.salts || [],
    install: () => {
      vi.stubGlobal("location", { hostname: "localhost", origin: "http://localhost" });
      vi.stubGlobal("navigator", { ...globalThis.navigator, credentials });
      vi.stubGlobal("PublicKeyCredential", {
        isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
      });
    },
  };
}

/** Read a row straight out of the vault's `kek` store. */
function kekRow(id) {
  return withKek("readonly", (store) => store.get(id));
}

/** Write a row straight into the vault's `kek` store, to stage pre-fix state. */
function putKekRow(row) {
  return withKek("readwrite", (store) => store.put(row));
}

function withKek(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("basilisk-vault", 3);
    open.onerror = () => reject(open.error);
    // Staging a legacy row may be the first thing to touch the database, so
    // this creates the schema the same way the vault does rather than opening
    // an empty database out from under it.
    open.onupgradeneeded = () => {
      const db = open.result;
      for (const [name, keyPath] of [
        ["keys", "fingerprint"],
        ["kek", "id"],
        ["pubkeys", "fingerprint"],
      ]) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name, { keyPath });
      }
    };
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction("kek", mode);
      const req = fn(tx.objectStore("kek"));
      req.onerror = () => reject(req.error);
      tx.oncomplete = () => {
        db.close();
        resolve(req.result);
      };
    };
  });
}

/**
 * @param {string} fingerprint
 * @param {{ prfIkm: Uint8Array, enrolment?: object }} prf
 * @param {{ bindEnrolment?: boolean }} [opts]
 */
function savePasskeyKey(fingerprint, prf, opts = {}) {
  const bind = opts.bindEnrolment !== false;
  return saveKey({
    fingerprint,
    armoredPrivate: SAMPLE_ARMORED,
    uid: "Test <test@example.com>",
    email: "test@example.com",
    protection: "passkey",
    prfIkm: prf.prfIkm,
    ...(bind ? { prfEnrolment: prf.enrolment } : {}),
  });
}

/** @type {ReturnType<typeof fakeAuthenticator>} */
let auth;

beforeEach(async () => {
  sessionClear();
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve(undefined);
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve(undefined);
  });
  auth = fakeAuthenticator();
  auth.install();
});

afterEach(() => {
  vi.unstubAllGlobals();
  sessionClear();
});

describe("two PRF enrolments", () => {
  it("unlocks a key wrapped under the first enrolment after a second one exists", async () => {
    const first = await createPasskeyPrf("first@example.com");
    await savePasskeyKey(FPR_A, first);

    const second = await createPasskeyPrf("second@example.com");
    await savePasskeyKey(FPR_B, second);

    // The older key first — the one the singleton row used to throw away.
    const a = await unlockVaultForUse(FPR_A, { skipSession: true });
    expect(a.armored).toBe(SAMPLE_ARMORED);
    const b = await unlockVaultForUse(FPR_B, { skipSession: true });
    expect(b.armored).toBe(SAMPLE_ARMORED);
  });

  it("keys the enrolment by the fingerprint it wraps, so a second one adds a row", async () => {
    const first = await createPasskeyPrf("first@example.com");
    await savePasskeyKey(FPR_A, first);
    const second = await createPasskeyPrf("second@example.com");
    await savePasskeyKey(FPR_B, second);

    const rowA = await kekRow(`prf:${FPR_A}`);
    const rowB = await kekRow(`prf:${FPR_B}`);
    expect(rowA?.credentialId).toBeTruthy();
    expect(rowB?.credentialId).toBeTruthy();
    // Different credentials, and — the part that was lost — different salts.
    expect(bytesToBase64Url(new Uint8Array(rowA.credentialId))).not.toBe(
      bytesToBase64Url(new Uint8Array(rowB.credentialId))
    );
    expect(bytesToBase64Url(new Uint8Array(rowA.firstSalt))).not.toBe(
      bytesToBase64Url(new Uint8Array(rowB.firstSalt))
    );
  });

  it("asks the authenticator for the salt that key was enrolled with", async () => {
    const first = await createPasskeyPrf("first@example.com");
    await savePasskeyKey(FPR_A, first);
    await createPasskeyPrf("second@example.com");

    await unlockVaultForUse(FPR_A, { skipSession: true });
    const salts = auth.saltsFor(first.enrolment.credentialId);
    expect(salts).toHaveLength(2);
    expect([...salts[1]]).toEqual([...salts[0]]);
  });

  it("drops a key's enrolment row when the key is deleted", async () => {
    const first = await createPasskeyPrf("first@example.com");
    await savePasskeyKey(FPR_A, first);
    expect(await kekRow(`prf:${FPR_A}`)).toBeTruthy();

    await deleteKey(FPR_A);
    expect(await kekRow(`prf:${FPR_A}`)).toBeUndefined();
  });

  it("says which key disagreed when a bound enrolment answers and does not open it", async () => {
    const first = await createPasskeyPrf("first@example.com");
    await savePasskeyKey(FPR_A, first);

    // Row and record are written in one transaction, so this state cannot
    // arise from a normal save — it is staged to pin what a reader is told if
    // the two ever disagree, instead of a bare OperationError.
    const other = await createPasskeyPrf("other@example.com");
    const salt = other.enrolment.firstSalt;
    await putKekRow({
      id: `prf:${FPR_A}`,
      fingerprint: FPR_A,
      credentialId: other.enrolment.credentialId,
      firstSalt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength),
    });

    await expect(unlockVaultForUse(FPR_A, { skipSession: true })).rejects.toThrow(
      prfEnrolmentMismatchMessage(FPR_A)
    );
  });

  it("refuses, naming the key, when the enrolment a key needs is not there", async () => {
    const first = await createPasskeyPrf("first@example.com");
    await savePasskeyKey(FPR_A, first, { bindEnrolment: false });

    await expect(getPasskeyPrf(FPR_A)).rejects.toThrow(prfEnrolmentMissingMessage(FPR_A));
  });
});

describe("vaults written before per-key enrolments", () => {
  /**
   * Stage the pre-fix shape: the singleton `prf-meta` row, and a passkey record
   * that does not say which enrolment wrapped it because nothing recorded that.
   */
  async function stageLegacyEnrolment(email) {
    const prf = await createPasskeyPrf(email);
    const salt = prf.enrolment.firstSalt;
    await putKekRow({
      id: "prf-meta",
      credentialId: prf.enrolment.credentialId,
      firstSalt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength),
    });
    return prf;
  }

  it("still unlocks a key that predates per-key enrolments", async () => {
    const legacy = await stageLegacyEnrolment("legacy@example.com");
    await savePasskeyKey(FPR_A, legacy, { bindEnrolment: false });

    const out = await unlockVaultForUse(FPR_A, { skipSession: true });
    expect(out.armored).toBe(SAMPLE_ARMORED);
  });

  it("keeps the legacy row when a new enrolment is added beside it", async () => {
    const legacy = await stageLegacyEnrolment("legacy@example.com");
    await savePasskeyKey(FPR_A, legacy, { bindEnrolment: false });

    const fresh = await createPasskeyPrf("new@example.com");
    await savePasskeyKey(FPR_B, fresh);

    expect(await kekRow("prf-meta")).toBeTruthy();
    expect((await unlockVaultForUse(FPR_A, { skipSession: true })).armored).toBe(
      SAMPLE_ARMORED
    );
    expect((await unlockVaultForUse(FPR_B, { skipSession: true })).armored).toBe(
      SAMPLE_ARMORED
    );
  });

  it("tells a stranded key's owner what happened instead of failing blankly", async () => {
    // The state a user who already hit this bug is in: the surviving `prf-meta`
    // describes the *second* passkey, and the first key's salt is gone.
    const lost = await stageLegacyEnrolment("lost@example.com");
    await savePasskeyKey(FPR_A, lost, { bindEnrolment: false });
    await stageLegacyEnrolment("survivor@example.com");

    await expect(unlockVaultForUse(FPR_A, { skipSession: true })).rejects.toThrow(
      prfLegacyEnrolmentLostMessage()
    );
  });
});

describe("the messages themselves", () => {
  it("says plainly that a lost enrolment is not recoverable", () => {
    const m = prfLegacyEnrolmentLostMessage();
    // Not "try again", not "reconnect your passkey": the salt was random and
    // was overwritten, so no authenticator can produce that PRF output again.
    expect(m).toMatch(/cannot be unlocked again/);
    expect(m).toMatch(/random salt/);
    expect(m).toMatch(/exported or paper backup/);
    expect(m).not.toMatch(/try again|retry/i);
  });

  it("names the key that is waiting on a missing enrolment", () => {
    expect(prfEnrolmentMissingMessage(FPR_A)).toContain(FPR_A);
  });
});

describe("direct unlock still takes raw PRF IKM", () => {
  it("does not need an enrolment when the caller supplies the key material", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    await savePasskeyKey(FPR_A, { prfIkm: ikm }, { bindEnrolment: false });
    expect(await unlockKey(FPR_A, { prfIkm: ikm })).toBe(SAMPLE_ARMORED);
  });
});

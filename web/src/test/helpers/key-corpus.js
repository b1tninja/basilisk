/**
 * The keys a directory has to have before searching it means anything.
 *
 * `quorum-room.js` mints two identities because a room *is* two identities.
 * A keyserver is not: `hkp.search` returning one row and `hkp.filter` narrowing
 * one row to one row would pass without either op doing any work. So this
 * builds a small population with deliberate *shape* — several keys sharing a
 * domain, one with two user ids, one that cannot encrypt, one expired, one
 * revoked, one still pending approval, and both key algorithms the reader has
 * to cope with.
 *
 * ## Generated, not checked in
 *
 * `web/src/test/fixtures/ssh/` exists because `ssh-keygen` is an external
 * binary and its output is worth pinning. Nothing here is external: `openpgp`
 * is already a dependency, and in node the whole corpus below — RSA-2048
 * included — costs about 200ms, measured. Checking armor in would buy no
 * speed and would import two hazards this repo has already paid for: a
 * `.gitattributes` that has to keep CRLF out of armored text (`586d666`), and
 * a README claiming a provenance nobody can re-derive.
 *
 * The cost is that fingerprints differ every run. Every assertion downstream
 * is therefore written against a *name* (`corpus.keys.alice.fingerprint`) or
 * against a user id, never against a literal hex string — which is how it
 * should read anyway.
 *
 * ## Expired and revoked are real, not decorated metadata
 *
 * A cert flagged "revoked" in a database while its armor says otherwise would
 * test the database's opinion, not the key. `grace` carries a real revocation
 * signature (`revokeKey`), and `frank` was generated with a creation date 400
 * days in the past and a 30-day validity, so it is genuinely expired in the
 * armor: `getExpirationTime()` returns a past instant and `getEncryptionKey()`
 * refuses with "Primary key is expired". Both are what the client's own reader
 * sees, whatever the directory claims alongside them.
 *
 * @module test/helpers/key-corpus
 */

import { generateKey, revokeKey } from "openpgp";

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * @typedef {object} CorpusKey
 * @property {string} id            stable name used by tests
 * @property {string} fingerprint   uppercase hex, 40 chars
 * @property {string} keyId         lowercase hex, 16 chars
 * @property {string[]} uids        raw user id strings, in key order
 * @property {string} email         primary uid's email
 * @property {string} armoredPublic
 * @property {string} armoredPrivate
 * @property {Date} created
 * @property {Date|null} expires    null when the key does not expire
 * @property {boolean} revoked
 * @property {boolean} encryptCapable
 * @property {string} algorithm     openpgp's own name (`eddsaLegacy`, `rsaEncryptSign`)
 * @property {number} bits
 * @property {"approved"|"pending"|"expired"|"rejected"} approvalState
 *   what the *directory* should record for it — a property of the fixture's
 *   intent, not of the key material.
 */

/**
 * @param {import("openpgp").Key} pub
 * @returns {Promise<boolean>}
 */
async function canEncrypt(pub) {
  try {
    await pub.getEncryptionKey();
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {string} id
 * @param {import("openpgp").Key} publicKey
 * @param {import("openpgp").PrivateKey} privateKey
 * @param {"approved"|"pending"|"expired"|"rejected"} approvalState
 * @returns {Promise<CorpusKey>}
 */
async function describe(id, publicKey, privateKey, approvalState) {
  const uids = publicKey.getUserIDs().map(String);
  const first = uids[0] || "";
  const m = first.match(/<([^>]+)>/);
  const exp = await publicKey.getExpirationTime();
  const info = publicKey.getAlgorithmInfo();
  return {
    id,
    fingerprint: publicKey.getFingerprint().toUpperCase(),
    keyId: publicKey.getKeyID().toHex().toLowerCase(),
    uids,
    email: m ? m[1] : first.includes("@") ? first : "",
    armoredPublic: publicKey.armor(),
    armoredPrivate: privateKey.armor(),
    created: publicKey.getCreationTime(),
    // `getExpirationTime()` answers `Infinity` for a key with no expiry and
    // `null` for one that is already invalid; both mean "no usable instant".
    expires: exp instanceof Date ? exp : null,
    revoked: await publicKey.isRevoked(),
    encryptCapable: await canEncrypt(publicKey),
    algorithm: String(info.algorithm || ""),
    // ed25519 has no `bits`; its conventional strength field in an HKP index
    // record is 256, which is what `gpg --list-keys` prints too.
    bits: Number(info.bits) || (info.curve ? 256 : 0),
    approvalState,
  };
}

/**
 * @typedef {object} KeyCorpus
 * @property {Record<string, CorpusKey>} keys  by id
 * @property {CorpusKey[]} list                in generation order
 * @property {(id: string) => CorpusKey} byId  throws on an unknown id
 */

/**
 * Build the corpus. ~200ms in node; generate once per suite in `beforeAll`.
 *
 * @returns {Promise<KeyCorpus>}
 */
export async function buildKeyCorpus() {
  const ecc = {
    /** @type {"ecc"} */ type: "ecc",
    /** @type {"curve25519Legacy"} */ curve: "curve25519Legacy",
    /** @type {"object"} */ format: "object",
  };

  // Two ordinary encrypt-capable keys on one domain — the pair that makes a
  // search return more than it can act on.
  const alice = await generateKey({
    ...ecc,
    userIDs: [{ name: "Alice Example", email: "alice@corp.test" }],
  });
  const bob = await generateKey({
    ...ecc,
    userIDs: [{ name: "Bob Example", email: "bob@corp.test" }],
  });

  // Two user ids on two domains: uid matching has to be a scan, not an
  // equality check on the primary.
  const carol = await generateKey({
    ...ecc,
    userIDs: [
      { name: "Carol Example", email: "carol@corp.test" },
      { name: "Carol Example (laptop)", email: "carol.alt@other.test" },
    ],
  });

  // RSA, so the reader is shown handling both algorithms rather than one.
  const dave = await generateKey({
    type: "rsa",
    rsaBits: 2048,
    userIDs: [{ name: "Dave Example", email: "dave@corp.test" }],
    format: "object",
  });

  // Signing-only: `subkeys: []` leaves an EdDSA primary with no ECDH subkey,
  // so `getEncryptionKey()` genuinely refuses. This is the case
  // `RecipientsCard`'s "cannot encrypt" row exists for.
  const erin = await generateKey({
    ...ecc,
    subkeys: [],
    userIDs: [{ name: "Erin Example", email: "erin@corp.test" }],
  });

  // Created 400 days ago, valid for 30: expired by the key's own signature.
  const frank = await generateKey({
    ...ecc,
    userIDs: [{ name: "Frank Example", email: "frank@corp.test" }],
    date: new Date(Date.now() - 400 * DAY_MS),
    keyExpirationTime: 30 * 24 * 60 * 60,
  });

  const graceRaw = await generateKey({
    ...ecc,
    userIDs: [{ name: "Grace Example", email: "grace@corp.test" }],
  });
  const graceRevoked = await revokeKey({
    key: graceRaw.publicKey,
    revocationCertificate: graceRaw.revocationCertificate,
    format: "object",
  });

  // Uploaded but unclaimed. The directory holds it; nothing has approved it.
  const heidi = await generateKey({
    ...ecc,
    userIDs: [{ name: "Heidi Example", email: "heidi@other.test" }],
  });

  const list = await Promise.all([
    describe("alice", alice.publicKey, alice.privateKey, "approved"),
    describe("bob", bob.publicKey, bob.privateKey, "approved"),
    describe("carol", carol.publicKey, carol.privateKey, "approved"),
    describe("dave", dave.publicKey, dave.privateKey, "approved"),
    describe("erin", erin.publicKey, erin.privateKey, "approved"),
    // `frank` and `grace` stay "approved" in the directory on purpose: the
    // interesting case is a server that has not yet noticed, so the client's
    // own reader is the thing that has to decide. Basilisk's `lookup_get`
    // 404s anything it has already marked `expired`, which would move the
    // decision to the server and test nothing about the page.
    describe("frank", frank.publicKey, frank.privateKey, "approved"),
    describe("grace", graceRevoked.publicKey, graceRaw.privateKey, "approved"),
    describe("heidi", heidi.publicKey, heidi.privateKey, "pending"),
  ]);

  /** @type {Record<string, CorpusKey>} */
  const keys = {};
  for (const k of list) keys[k.id] = k;

  return {
    keys,
    list,
    byId(id) {
      const k = keys[id];
      if (!k) {
        throw new Error(
          `key-corpus has no "${id}"; it has ${Object.keys(keys).join(", ")}`
        );
      }
      return k;
    },
  };
}

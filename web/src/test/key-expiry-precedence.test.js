/**
 * Which of the two expiry sources decides, when they disagree.
 *
 * `buildRecipient` has two places to learn that a key has expired: the
 * certificate's own `getExpirationTime()`, and the directory's `key_expiration`
 * out of `/api/v1/key/<fpr>`. `fa76818` made the second one legible and left
 * behind a control mutation that survived — **nothing asserted which one is
 * consulted first**, because every fixture in the suite has them agreeing.
 * A test that cannot fail is worse than none, so this file's entire job is to
 * make them disagree.
 *
 * The answer being pinned is that the **certificate wins**. The armor is
 * signed; `key_expiration` is a copy the server took off that same armor at
 * ingest and has held ever since, so the two can only disagree when the copy
 * is stale or wrong, and a stale copy must never overrule the thing it was
 * copied from.
 *
 * ## Why this runs in node against a stubbed fetch
 *
 * `hkp-directory.e2e.js` drives the real keyserver, which is the right harness
 * for everything else about this path — but the real server *derives*
 * `key_expiration` from the armor it was handed, so it cannot be made to
 * disagree with itself without reaching past the app and editing its database.
 * The disagreement is the fixture here, so it is built where it can be stated:
 * two responses that contradict each other, served to the shipped
 * `loadRecipientKey`. Nothing else about the function is stubbed — it is the
 * module the page loads, doing its two real requests.
 *
 * The device cache underneath is not stubbed either; there is no `indexedDB`
 * in node, so `cacheGet`/`cachePut` take their existing failure branches and
 * every call here is a cache miss that goes to the network.
 */

import { afterEach, describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import { loadRecipientKey } from "../lib/recipient-picker.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** The corpus's own key shape, so a failure here reads against the same keys. */
const ECC = Object.freeze({
  /** @type {"ecc"} */ type: "ecc",
  /** @type {"curve25519Legacy"} */ curve: "curve25519Legacy",
  /** @type {"object"} */ format: "object",
});

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/**
 * Answer `loadRecipientKey`'s two requests: the portal's JSON and the armor.
 *
 * They are served from separate arguments on purpose — that separation *is*
 * the fixture. The armor is the certificate; `meta` is what the directory
 * claims about it, and the two are free to contradict each other here in a way
 * the real server could never produce.
 *
 * @param {string} armored
 * @param {object} meta  the `/api/v1/key/<fpr>` body, minus the fingerprint
 */
function serveDisagreement(armored, meta) {
  globalThis.fetch = async (url) => {
    const s = String(url);
    if (s.includes("/api/v1/key/")) {
      return new Response(JSON.stringify(meta), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (s.includes("/pks/lookup")) return new Response(armored, { status: 200 });
    throw new Error(`unexpected request: ${s}`);
  };
}

/** @param {object} extra */
function approvedRecord(extra) {
  return {
    approval_state: "approved",
    revoked: false,
    approved_uids: [],
    ...extra,
  };
}

describe("the certificate outranks the directory on expiry", () => {
  it("armor that expired last month is expired, whatever the row says", async () => {
    // Generated 400 days ago with 30 days of validity — the corpus's `frank`,
    // built the same way, so this is a key openpgp genuinely refuses to
    // encrypt to with "Primary key is expired".
    const frank = await generateKey({
      ...ECC,
      userIDs: [{ name: "Frank Example", email: "frank@corp.test" }],
      date: new Date(Date.now() - 400 * DAY_MS),
      keyExpirationTime: 30 * 24 * 60 * 60,
    });
    const fingerprint = frank.publicKey.getFingerprint().toUpperCase();
    const stated = await frank.publicKey.getExpirationTime();
    expect(stated).toBeInstanceOf(Date);
    expect(/** @type {Date} */ (stated).getTime()).toBeLessThan(Date.now());

    // The directory is a year out of date in the generous direction: the most
    // dangerous shape, because believing it means offering a dead key as a
    // recipient.
    serveDisagreement(
      frank.publicKey.armor(),
      approvedRecord({
        fingerprint,
        key_expiration: new Date(Date.now() + 365 * DAY_MS).toISOString(),
      })
    );

    const r = await loadRecipientKey(fingerprint);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("Key is expired");
    // And the row it disagreed with is carried through untouched, so a caller
    // can still see what the directory thought.
    expect(Date.parse(r.keyExpiration)).toBeGreaterThan(Date.now());
  });

  it("armor that carries no expiry is not expired, whatever the row says", async () => {
    // The direction that was wrong. `subkeys: []` is the corpus's `erin`: an
    // EdDSA primary with no encryption subkey and no expiry at all, so
    // `getExpirationTime()` answers `Infinity` — an answer, not a silence.
    const erin = await generateKey({
      ...ECC,
      subkeys: [],
      userIDs: [{ name: "Erin Example", email: "erin@corp.test" }],
    });
    const fingerprint = erin.publicKey.getFingerprint().toUpperCase();
    expect(await erin.publicKey.getExpirationTime()).toBe(Infinity);

    serveDisagreement(
      erin.publicKey.armor(),
      approvedRecord({
        fingerprint,
        key_expiration: new Date(Date.now() - 30 * DAY_MS).toISOString(),
      })
    );

    const r = await loadRecipientKey(fingerprint);
    expect(r.valid).toBe(false);
    // Both of these are refusals, so a test that only checked `valid` would
    // pass either way. Which one is said is the whole question: this key's
    // defect is that it has no encryption subkey, and telling its holder it
    // expired points them at re-issuing a certificate that has not expired —
    // a remedy nobody can perform, about a state that is not true.
    expect(r.error).toBe("No encryption-capable subkey");
    expect(r.error).not.toBe("Key is expired");
  });

  it("armor that expires next year is not expired, whatever the row says", async () => {
    // The third thing `getExpirationTime()` can answer, and the one the two
    // specs above do not reach: a Date that has *not* passed. Signing-only
    // again, because that is what gets a live key as far as this question —
    // `getEncryptionKey()` has to refuse before either expiry source is read.
    const key = await generateKey({
      ...ECC,
      subkeys: [],
      userIDs: [{ name: "Ivan Example", email: "ivan@corp.test" }],
      keyExpirationTime: 365 * 24 * 60 * 60,
    });
    const fingerprint = key.publicKey.getFingerprint().toUpperCase();
    const stated = await key.publicKey.getExpirationTime();
    expect(stated).toBeInstanceOf(Date);
    expect(/** @type {Date} */ (stated).getTime()).toBeGreaterThan(Date.now());

    serveDisagreement(
      key.publicKey.armor(),
      approvedRecord({
        fingerprint,
        key_expiration: new Date(Date.now() - 30 * DAY_MS).toISOString(),
      })
    );

    const r = await loadRecipientKey(fingerprint);
    expect(r.valid).toBe(false);
    expect(r.error).toBe("No encryption-capable subkey");
  });
});

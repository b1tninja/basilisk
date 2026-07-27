/**
 * Device IndexedDB pubkey cache tests.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import {
  PUBKEY_CACHE_TTL_MS,
  cacheClear,
  cacheDelete,
  cacheGet,
  cacheList,
  cachePut,
  cacheRecordToSearchHit,
  cacheSearch,
  cacheTouch,
  isPubkeyCacheStale,
} from "../lib/pubkey-cache.js";

const FPR = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ARMORED = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZtestAAAAAAAAAExamplePublicKeyMaterialForCacheTestsOnly=
-----END PGP PUBLIC KEY BLOCK-----`;

beforeEach(async () => {
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

describe("pubkey-cache", () => {
  it("round-trips put/get/list/delete", async () => {
    const put = await cachePut({
      fingerprint: FPR,
      armored: ARMORED,
      uids: ["Alice <alice@example.com>"],
      email: "alice@example.com",
      name: "Alice",
      origin: "basilisk",
      approvalState: "approved",
    });
    expect(put?.fingerprint).toBe(FPR);
    const got = await cacheGet(FPR);
    expect(got?.email).toBe("alice@example.com");
    expect(got?.origin).toBe("basilisk");
    expect((await cacheList()).length).toBe(1);
    await cacheDelete(FPR);
    expect(await cacheGet(FPR)).toBeNull();
  });

  it("search matches email and fingerprint substring", async () => {
    await cachePut({
      fingerprint: FPR,
      armored: ARMORED,
      uids: ["Alice <alice@example.com>"],
      email: "alice@example.com",
      origin: "upstream",
      sourceKeyserver: "keys.openpgp.org",
    });
    const byEmail = await cacheSearch("alice@");
    expect(byEmail).toHaveLength(1);
    const byHex = await cacheSearch(FPR.slice(0, 16));
    expect(byHex).toHaveLength(1);
    expect(await cacheSearch("zzz")).toHaveLength(0);
  });

  it("touch updates lastUsedAt; clear empties store", async () => {
    await cachePut({
      fingerprint: FPR,
      armored: ARMORED,
      uids: [],
      origin: "import",
    });
    const before = (await cacheGet(FPR))?.lastUsedAt;
    await new Promise((r) => setTimeout(r, 5));
    await cacheTouch(FPR);
    const after = (await cacheGet(FPR))?.lastUsedAt;
    expect(after).toBeTruthy();
    expect(after >= before).toBe(true);
    await cacheClear();
    expect(await cacheList()).toHaveLength(0);
  });

  it("staleness and search-hit mapping", () => {
    const fresh = {
      fingerprint: FPR,
      armored: ARMORED,
      uids: ["Bob <bob@example.com>"],
      email: "bob@example.com",
      origin: "upstream",
      sourceKeyserver: "keys.openpgp.org",
      fetchedAt: new Date().toISOString(),
    };
    expect(isPubkeyCacheStale(fresh)).toBe(false);
    const stale = {
      ...fresh,
      fetchedAt: new Date(Date.now() - PUBKEY_CACHE_TTL_MS - 1000).toISOString(),
    };
    expect(isPubkeyCacheStale(stale)).toBe(true);
    const hit = cacheRecordToSearchHit(fresh);
    expect(hit.origin).toBe("upstream");
    expect(hit.source_keyserver).toBe("keys.openpgp.org");
    expect(hit.cached).toBe(true);
  });

  it("rejects private-looking empty armor and bad origin", async () => {
    expect(
      await cachePut({
        fingerprint: FPR,
        armored: "not a key",
        uids: [],
        origin: "basilisk",
      })
    ).toBeNull();
    expect(
      await cachePut({
        fingerprint: FPR,
        armored: ARMORED,
        uids: [],
        origin: /** @type {any} */ ("evil"),
      })
    ).toBeNull();
  });
});

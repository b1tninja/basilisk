/**
 * The five HKP surfaces, run against the keyserver this repo ships.
 *
 * `hkp.get`, `hkp.search`, `hkp.filter`, `hkp.cache` and the `key.publish`
 * action have shipped without ever meeting a directory in a test. Not for want
 * of trying: the only keyserver available was the public internet, which this
 * repo has consistently refused to depend on. `helpers/basilisk-server.js`
 * removes the excuse — it spawns `basilisk/serve.py` and proxies the page's
 * `/pks/*` and `/api/v1/*` at it, so the directory is same-origin by
 * construction and already inside `connect-src 'self'`.
 *
 * ## The server is the real one, and that is the whole point
 *
 * An earlier draft of this suite ran against `helpers/keyserver.js`, a
 * JavaScript reimplementation of `/pks/lookup`. It was deleted on purpose: two
 * implementations of one idea can disagree, and the one under test is never the
 * one users hit. Everything the stub used to *construct* — index bodies, the
 * search classifier, the short-key-id warning — is now something the server
 * emits and the test reads. Where the real bytes turn out to differ from what
 * the stub built, the assertion records the real bytes; several of those
 * differences are noted inline.
 *
 * ## Two halves, and why the first one is not a browser test
 *
 * The first `describe` drives the server from node over real HTTP, through the
 * same loopback proxy the page uses. Those are *wire-format* assertions — the
 * machine-readable index, the 501 for an op `serve.py` does not implement, the
 * exact body `/pks/add` replies with — and they exist because the second half
 * can only be read correctly once the wire is pinned down. They need no
 * browser, so they run wherever Python does.
 *
 * The second half is the point: the shipped ops, in a real browser context, at
 * a real origin, under the production CSP, with IndexedDB underneath them.
 *
 * ## What may skip
 *
 * No Python that can import `basilisk.serve` stands the whole file down; no
 * Chromium stands the browser half down. A Python that is present and a server
 * that will not start is a real failure and is reported as one —
 * `basiliskAvailability()` draws that line, not this file.
 *
 * ## Why the chunk is imported instead of the recipe being run
 *
 * `runRecipe` is bundled into the toolkit entry and its name does not survive
 * minification, so there is no `runRecipe` to reach from a test. The ops'
 * *own* chunk keeps its export names (`hkp-ops-<hash>.js` ends in
 * `export{… as execHkpGet, … as execHkpSearch, …}`), so the suite imports that
 * — and it imports the one the page's own chunks name, discovered by reading
 * them, rather than a hash pasted in here that a rebuild would rot.
 *
 * What that skips is `engine.js`'s four-line `case "hkp.get": …` switch, which
 * `npx vitest run` already covers in node. What it keeps is everything that
 * has never been covered: `recipient-picker.js`'s two-request resolve, the
 * IndexedDB cache tier, `buildRecipient`'s validity reading, the search-hit
 * mapping, and the network itself.
 *
 * ## Defects are results
 *
 * Several assertions below record behaviour that is *wrong*. They are written
 * as assertions, not comments, so that a fix flips them red and has to be
 * acknowledged. Each is labelled DEFECT with what it should do instead.
 * Nothing here changes production; that is a separate unit.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKey, readKey } from "openpgp";
import {
  chromiumAvailability,
  openPeers,
  serveDist,
  DIST_ROOT,
} from "../helpers/browser-peers.js";
import { buildKeyCorpus } from "../helpers/key-corpus.js";
import {
  basiliskAvailability,
  seedDirectory,
  startBasilisk,
} from "../helpers/basilisk-server.js";

const chromium = await chromiumAvailability();
const python = await basiliskAvailability();

if (!python.ok && python.kind === "broken") {
  it("runs the keyserver the HKP directory suite needs", () => {
    expect.unreachable(
      `python is installed but would not run the server: ${python.reason}`
    );
  });
} else if (!python.ok) {
  console.warn(
    `[hkp-directory.e2e] skipping — no python can import basilisk.serve (${python.reason})`
  );
}

if (!chromium.ok && chromium.kind === "broken") {
  it("launches the browser the HKP directory suite needs", () => {
    expect.unreachable(
      `chromium is installed but would not launch: ${chromium.reason}`
    );
  });
} else if (!chromium.ok) {
  console.warn(
    `[hkp-directory.e2e] skipping the browser half — chromium not installed (${chromium.reason})`
  );
}

/** One corpus for the whole file; ~100ms, and both halves want the same keys. */
const corpus = python.ok ? await buildKeyCorpus() : null;

/**
 * Start a server and put the corpus in it.
 *
 * `rejectRevoked: false` is not a convenience. `BASILISK_REJECT_REVOKED`
 * defaults on and `/pks/add` refuses `grace` outright — asserted below — so a
 * directory holding a key that was revoked *after* it was accepted is only
 * reachable with the switch off, and that is the state a client has to cope
 * with.
 *
 * @returns {Promise<{
 *   server: Awaited<ReturnType<typeof startBasilisk>>,
 *   seeded: Awaited<ReturnType<typeof seedDirectory>>,
 * }>}
 */
async function directoryWithCorpus() {
  const server = await startBasilisk({ python: python.python, rejectRevoked: false });
  try {
    const seeded = await seedDirectory(server, /** @type {any} */ (corpus).list);
    return { server, seeded };
  } catch (err) {
    await server.close();
    throw err;
  }
}

/**
 * The directory's own record for a fingerprint, or null.
 *
 * The stub had a `record()` accessor over its own map. Against a real server
 * the equivalent is the route the page itself reads.
 *
 * @param {string} origin
 * @param {string} fingerprint
 * @returns {Promise<any|null>}
 */
async function keyRecord(origin, fingerprint) {
  const r = await fetch(`${origin}/api/v1/key/${fingerprint}`);
  if (!r.ok) return null;
  return r.json();
}

/**
 * In-page: find and import the shipped ops chunk.
 *
 * A **string**, not a function, because Vitest rewrites `import()` in anything
 * it transforms into `__vite_ssr_dynamic_import__`, which does not exist in a
 * browser.
 *
 * The chunk is not guessed at and not read out of the build either: the
 * toolkit page `modulepreload`s its ops chunks, so the one the *page itself*
 * loaded is sitting in `performance.getEntriesByType("resource")` with its
 * current hash. That matters because the build emits two `hkp-ops-*.js` — one
 * for the main-thread graph and one for the crypto worker's — and the entry
 * chunk names both. Only the main-thread copy is preloaded, so taking the
 * loaded resource picks the right half without having to know why there are
 * two. Exactly one must be there; anything else fails loudly with what it saw.
 */
const LOAD_HKP = `(async () => {
  const loaded = [...new Set(
    performance.getEntriesByType("resource")
      .map((x) => new URL(x.name).pathname)
      .filter((n) => n.indexOf("/assets/hkp-ops-") === 0 && n.endsWith(".js"))
  )];
  if (loaded.length !== 1) {
    throw new Error(
      "expected the toolkit page to have loaded exactly one hkp-ops chunk, found " +
        JSON.stringify(loaded)
    );
  }
  const path = loaded[0];
  const mod = await import(path);
  const WANTED = [
    "execHkpGet", "execHkpSearch", "execHkpFilter", "execHkpCache",
    "publishArmoredKey",
  ];
  for (const name of WANTED) {
    if (typeof mod[name] !== "function") {
      throw new Error("the shipped hkp-ops chunk does not export " + name);
    }
  }
  window.__hkp = mod;
  return path;
})()`;

/**
 * Call a shipped op, resolving a thrown error into a value the test can read.
 *
 * A rejected `page.evaluate` reports the message and loses everything else;
 * several assertions below are specifically about *which* error a miss
 * produces, so the shape is kept.
 *
 * @param {import("playwright").Page} page
 * @param {string} op
 * @param {object} [params]
 * @param {object|null} [input]
 */
function callOp(page, op, params = {}, input = null) {
  return page.evaluate(
    async ({ op, params, input }) => {
      try {
        const fn = window.__hkp[op];
        const out = op === "execHkpFilter"
          ? await fn(input, params)
          : await fn(params);
        return { ok: true, value: out };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
    { op, params, input }
  );
}

/**
 * Publish through the shipped op, keeping a thrown error readable.
 * @param {import("playwright").Page} page
 * @param {string} armored
 */
function callPublish(page, armored) {
  return page.evaluate(async (key) => {
    try {
      return { ok: true, value: await window.__hkp.publishArmoredKey(key) };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }, armored);
}

// ---------------------------------------------------------------------------
// Half one: the wire, from node.
// ---------------------------------------------------------------------------

describe.skipIf(!python.ok)("the directory Basilisk actually serves", () => {
  /** @type {Awaited<ReturnType<typeof startBasilisk>>} */
  let basilisk;
  /** @type {Awaited<ReturnType<typeof seedDirectory>>} */
  let seeded;
  /** @type {{ origin: string, close: () => Promise<void> }} */
  let server;
  /**
   * Keys these specs add on top of the corpus. Counted rather than assumed, so
   * the `op=stats` assertion holds whatever order the specs run in — a suite
   * that seeds a server has enough ordering hazards without inviting one.
   */
  let added = 0;

  beforeAll(async () => {
    ({ server: basilisk, seeded } = await directoryWithCorpus());
    // Proxied, not addressed directly: every request below travels the path the
    // page's requests travel, so the counts the browser half reads are counts of
    // the same code.
    server = await serveDist(DIST_ROOT, basilisk.routes);
  });

  afterAll(async () => {
    await server?.close();
    await basilisk?.close();
  });

  it("took the whole corpus through the server's own ingest path", () => {
    // `seedDirectory` posts `/pks/add` then `/api/v1/dev/approve` — the two
    // calls `tests/helpers/hkp_client.py` makes for the Python e2e. Nothing is
    // written to SQLite behind the app's back, so the corpus has been through
    // the policy that runs in production.
    expect(seeded.refused).toEqual([]);
    expect(seeded.pending).toEqual(["heidi"]);
    expect(seeded.approved).toHaveLength(corpus.list.length - 1);
  });

  it("serves a key by full fingerprint and 404s one it does not hold", async () => {
    const alice = corpus.byId("alice");
    const hit = await fetch(
      `${server.origin}/pks/lookup?op=get&options=mr&search=0x${alice.fingerprint}`
    );
    expect(hit.status).toBe(200);
    expect(hit.headers.get("content-type")).toContain("application/pgp-keys");
    const served = await hit.text();

    // Not the bytes that were uploaded. `parse_armored_keytext` runs the
    // certificate through `strip_third_party_from_armored`, and
    // `armor_public_key` re-encodes it: 64-character base64 lines and no CRC-24
    // trailer, where openpgp.js emits 60 and does write one. RFC 9580 §6 makes
    // the checksum optional so nothing is broken, but a caller that expected to
    // get its own submission back byte for byte does not.
    expect(served).not.toBe(alice.armoredPublic);
    expect(alice.armoredPublic).toMatch(/\n=[A-Za-z0-9+/]{4}\n/);
    expect(served).not.toMatch(/\n=[A-Za-z0-9+/]{4}\n/);
    const bodyLine = (armor) =>
      armor.split("\n").find((l) => l && !l.startsWith("-----") && !l.startsWith("="));
    expect(bodyLine(alice.armoredPublic).length).toBe(60);
    expect(bodyLine(served).length).toBe(64);

    // The packet stream is untouched, which is the part that matters: the same
    // certificate comes back out.
    const round = await readKey({ armoredKey: served });
    expect(round.getFingerprint().toUpperCase()).toBe(alice.fingerprint);
    expect(round.getUserIDs().map(String)).toEqual(alice.uids);

    const miss = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${"A".repeat(40)}`
    );
    expect(miss.status).toBe(404);
    expect(await miss.text()).toBe("Not found");
  });

  it("resolves the hex lengths parse_search knows, and only those", async () => {
    const bob = corpus.byId("bob");
    const fpr = async (search) => {
      const r = await fetch(`${server.origin}/pks/lookup?op=get&search=${search}`);
      if (!r.ok) return r.status;
      return (await readKey({ armoredKey: await r.text() })).getFingerprint().toUpperCase();
    };

    // 16 hex — long key id.
    expect(await fpr(`0x${bob.keyId}`)).toBe(bob.fingerprint);
    // 8 hex — short key id, resolved through the fingerprint alias index.
    // `lookup_get` requires exactly one match, so a needle that hits several is
    // a 404 rather than a pick; that is what the collision warning is about.
    expect(await fpr(`0x${bob.keyId.slice(-8)}`)).toBe(bob.fingerprint);
    // 32 hex — a prefix or a suffix alias, not an arbitrary substring scan.
    expect(await fpr(`0x${bob.fingerprint.slice(0, 32)}`)).toBe(bob.fingerprint);
    expect(await fpr(`0x${bob.fingerprint.slice(-32)}`)).toBe(bob.fingerprint);
    expect(await fpr(`0x${bob.fingerprint.slice(4, 36)}`)).toBe(404);

    // 12 hex is not one of the lengths `parse_search` classifies (8/16/32/40/64),
    // so it falls through the hex branch entirely and is treated as a *name* —
    // and a name is never an HKP needle. A person shortening a fingerprint to a
    // length gpg prints happily gets "Not found" rather than "too ambiguous".
    expect(await fpr(`0x${bob.fingerprint.slice(0, 12)}`)).toBe(404);
    expect(await fpr("0xdeadbeef")).toBe(404);
  });

  it("reproduces lookup_index — one record, and only ever one", async () => {
    const carol = corpus.byId("carol");
    const r = await fetch(
      `${server.origin}/pks/lookup?op=index&options=mr&search=0x${carol.fingerprint}`
    );
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    const lines = (await r.text()).trim().split("\n");

    // `info:1:1` is a literal in `lookup_index`, not a count, and only the
    // first approved user id is ever emitted — carol has two.
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe("info:1:1");
    expect(lines[1]).toBe(`pub:255:0::::::20:${carol.fingerprint.toLowerCase()}`);
    expect(lines[2]).toBe(`uid:${carol.uids[0].length}:${carol.uids[0]}`);
    expect(carol.uids).toHaveLength(2);

    // A name is not an index needle at all, and a pending key has no index
    // record even though `op=get` still serves its armor.
    const byName = await fetch(`${server.origin}/pks/lookup?op=index&search=Example`);
    expect(byName.status).toBe(404);
    expect(await byName.text()).toBe("Not found");
    const pending = await fetch(
      `${server.origin}/pks/lookup?op=index&search=0x${corpus.byId("heidi").fingerprint}`
    );
    expect(pending.status).toBe(404);
  });

  it("DEFECT: that index body is not the format any HKP client parses", async () => {
    const carol = corpus.byId("carol");
    const body = await (
      await fetch(`${server.origin}/pks/lookup?op=index&search=0x${carol.fingerprint}`)
    ).text();
    const pub = body.split("\n")[1].split(":");

    // `draft-shaw-openpgp-hkp-00` §5.2:
    //   pub:<keyid>:<algo>:<keylen>:<created>:<expires>:<flags>
    // Seven fields, the identifier first. What Basilisk sends has ten, with the
    // fingerprint *last*, two literals (`255`, `0`) where the algorithm and key
    // length belong, and the fingerprint's byte length — 20 — in a tenth field
    // of its own invention. No created, no expires, no flags.
    expect(pub).toHaveLength(10);
    expect(pub[0]).toBe("pub");
    expect(pub[1]).toBe("255");
    expect(pub[2]).toBe("0");
    expect(pub.slice(3, 8)).toEqual(["", "", "", "", ""]);
    expect(pub[8]).toBe("20");
    expect(pub[9]).toBe(carol.fingerprint.toLowerCase());
    // The real algorithm and strength are known and simply not sent: carol is
    // EdDSA (22) at 256 bits.
    expect(carol.algorithm).toBe("eddsaLegacy");
    expect(carol.bits).toBe(256);

    // The uid line carries a character count and then the *raw* user id, where
    // the draft carries a URL-encoded one. So a user id containing a colon
    // shifts every field after it, and a parser splitting on ":" reads one more
    // field than exists. Demonstrated with a key whose name has a colon in it,
    // rather than argued.
    const colon = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      format: "object",
      userIDs: [{ name: "Olga: Example", email: "olga@corp.test" }],
    });
    const olga = {
      id: "olga",
      fingerprint: colon.publicKey.getFingerprint().toUpperCase(),
      uids: colon.publicKey.getUserIDs().map(String),
      armoredPublic: colon.publicKey.armor(),
      approvalState: /** @type {const} */ ("approved"),
    };
    expect(await seedDirectory(basilisk, [/** @type {any} */ (olga)])).toMatchObject({
      approved: ["olga"],
      refused: [],
    });
    added += 1;

    const olgaIndex = await (
      await fetch(`${server.origin}/pks/lookup?op=index&search=0x${olga.fingerprint}`)
    ).text();
    const uidLine = olgaIndex.split("\n")[2];
    expect(uidLine).toBe(`uid:${olga.uids[0].length}:${olga.uids[0]}`);
    expect(uidLine.split(":")).toHaveLength(4);
    expect(carol.uids[0]).not.toContain(":");

    // The one Python test over this surface asserts `"pub:" in r.text`, which
    // any of these forms satisfies — which is how it has survived. Reported,
    // not fixed; nothing in `web/src` requests `op=index`.
    expect(body).toContain("pub:");
  });

  it("cannot tell a revoked key from a live one in an index record", async () => {
    const alice = corpus.byId("alice");
    const grace = corpus.byId("grace");
    const index = async (k) =>
      (
        await (
          await fetch(`${server.origin}/pks/lookup?op=index&search=0x${k.fingerprint}`)
        ).text()
      )
        .split("\n")[1];

    const live = await index(alice);
    const revoked = await index(grace);
    expect(await keyRecord(server.origin, grace.fingerprint)).toMatchObject({
      revoked: true,
      approval_state: "approved",
    });

    // There is no flags field to carry `r`, so the two records are identical
    // apart from the fingerprint. A client reading only the index cannot tell
    // that one of these keys has been revoked. Should carry the draft's `r`
    // (and `e` for the expired key). Reported, not fixed.
    expect(revoked.replace(grace.fingerprint.toLowerCase(), alice.fingerprint.toLowerCase()))
      .toBe(live);
    expect(revoked).not.toContain(":r");
  });

  it("501s vindex, because serve.py implements index and get only", async () => {
    const alice = corpus.byId("alice");
    const vindex = await fetch(
      `${server.origin}/pks/lookup?op=vindex&options=mr&search=0x${alice.fingerprint}`
    );
    expect(vindex.status).toBe(501);
    expect(await vindex.text()).toBe("Unsupported operation");

    const nope = await fetch(`${server.origin}/pks/lookup?op=delete&search=x`);
    expect(nope.status).toBe(501);
  });

  it("answers op=stats, and rides GET CORS on the public lookup routes", async () => {
    const stats = (await (await fetch(`${server.origin}/pks/lookup?op=stats`)).json()).stats;
    // `store.stats()` counts by approval state and then merges the metrics
    // snapshot on top. There is no single "certs" total; `total` is the name.
    expect(stats.total).toBe(corpus.list.length + added);
    expect(stats.approved).toBe(corpus.list.length - 1 + added);
    expect(stats.pending).toBe(1);
    expect(stats.rejected).toBe(0);
    expect(stats.expired).toBe(0);

    const r = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${corpus.byId("alice").fingerprint}`
    );
    // Public key material is deliberately world-readable, and never paired
    // with credentials — `basilisk/hkp/cors.py`.
    expect(r.headers.get("access-control-allow-origin")).toBe("*");
    expect(r.headers.get("access-control-allow-credentials")).toBeNull();

    // The portal's search route is *not* on that list: it carries no
    // `Access-Control-Allow-Origin` at all, so it is same-origin only. The page
    // reaches it because it is same-origin; another site could read the armor
    // and not the directory metadata.
    const search = await fetch(`${server.origin}/api/v1/search?q=Example`);
    expect(search.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("searches by email exactly, and by name across the uid's name half", async () => {
    const byEmail = await (
      await fetch(`${server.origin}/api/v1/search?q=carol.alt@other.test`)
    ).json();
    expect(byEmail.reason).toBe("ok");
    expect(byEmail.results.map((r) => r.fingerprint)).toEqual([
      corpus.byId("carol").fingerprint,
    ]);

    // A domain fragment is not an email and is not a substring match either —
    // it is classified as a name, and no uid *name* contains "corp.test".
    const domain = await (
      await fetch(`${server.origin}/api/v1/search?q=corp.test`)
    ).json();
    expect(domain.reason).toBe("not_found");
    expect(domain.results).toEqual([]);

    const byName = await (
      await fetch(`${server.origin}/api/v1/search?q=Example`)
    ).json();
    expect(byName.reason).toBe("name");
    // Every approved key in the corpus shares the surname; the one pending
    // record does not appear, because name search is approved-only.
    expect(byName.results.length).toBe(corpus.list.length - 1 + added);
    expect(byName.results.map((r) => r.fingerprint)).not.toContain(
      corpus.byId("heidi").fingerprint
    );
  });

  it("reports a pending key as pending rather than as a result", async () => {
    const heidi = corpus.byId("heidi");
    const r = await (
      await fetch(`${server.origin}/api/v1/search?q=0x${heidi.fingerprint}`)
    ).json();
    expect(r.reason).toBe("pending");
    expect(r.results).toEqual([]);
    expect(r.fingerprint).toBe(heidi.fingerprint);

    // …and still serves its armor, which is what the claim flow needs — with
    // the user ids stripped out of it (`strip_uids_for_pending`), so an
    // unapproved address cannot be published by uploading it.
    const armor = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${heidi.fingerprint}`
    );
    expect(armor.status).toBe(200);
    const stripped = await readKey({ armoredKey: await armor.text() });
    expect(stripped.getFingerprint().toUpperCase()).toBe(heidi.fingerprint);
    expect(stripped.getUserIDs()).toEqual([]);
    expect(heidi.uids).toHaveLength(1);
  });

  it("carries the short-key-id warning the portal defines", async () => {
    const alice = corpus.byId("alice");
    const r = await (
      await fetch(`${server.origin}/api/v1/search?q=0x${alice.keyId.slice(-8)}`)
    ).json();
    expect(r.reason).toBe("short_keyid");
    expect(r.results.map((x) => x.fingerprint)).toEqual([alice.fingerprint]);
    // Asserted by substance rather than as a literal. The text lives in
    // `basilisk/portal/search.py`; a second copy of it here would be one more
    // thing that can disagree with the server, which is the mistake this suite
    // exists to stop repeating.
    expect(r.warning).toMatch(/collision-prone/);
    expect(r.warning).toMatch(/full fingerprint/);
  });

  it("accepts a submission on /pks/add and stores it as pending", async () => {
    const fresh = await generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "Ivan Example", email: "ivan@corp.test" }],
      format: "object",
    });
    const armored = fresh.publicKey.armor();
    const fpr = fresh.publicKey.getFingerprint().toUpperCase();

    const r = await fetch(`${server.origin}/pks/add`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `keytext=${encodeURIComponent(armored)}`,
    });
    expect(r.status).toBe(200);
    added += 1;
    const body = await r.text();

    // The claim URL is the only place the fingerprint appears, and there is no
    // `Fingerprint:` line. `publishArmoredKey` looks for one; see the browser
    // half. Note the host is the *server's* `BASILISK_BASE_URL`, not the origin
    // the request arrived on, so a proxied deployment hands back its own name.
    expect(body).toMatch(/^Ok\nClaim: http:\/\/[^/]+\/claim\/[0-9A-F]{40}\n$/);
    expect(body).not.toMatch(/[Ff]ingerprint:/);
    expect(body).toContain(fpr);
    expect(body).toContain(basilisk.origin);

    expect(await keyRecord(server.origin, fpr)).toMatchObject({
      approval_state: "pending",
      approved_uids: [],
    });
    // The proxy saw it as an add, which is how the browser half tells the two
    // publish branches apart.
    expect(basilisk.counts().add).toBeGreaterThanOrEqual(1);
  });

  it("refuses a revoked key on the upload policy that ships", async () => {
    // Why the fixture above sets `rejectRevoked: false`. On the default policy
    // `validate_cert_policy` turns `grace` away at the door, so a revoked key
    // can only be in a directory because it was revoked after approval.
    const strict = await startBasilisk({ python: python.python });
    try {
      const out = await seedDirectory(strict, [corpus.byId("grace")]);
      expect(out.approved).toEqual([]);
      expect(out.refused).toEqual([
        { id: "grace", status: 422, body: "Revoked keys cannot be uploaded" },
      ]);
      // Expiry is not policed the same way: an expired certificate is accepted
      // and stored with its expiration, and the client is left to notice.
      expect((await seedDirectory(strict, [corpus.byId("frank")])).approved).toEqual([
        "frank",
      ]);
      const frank = await keyRecord(strict.origin, corpus.byId("frank").fingerprint);
      expect(frank.approval_state).toBe("approved");
      expect(Date.parse(frank.key_expiration)).toBeLessThan(Date.now());
    } finally {
      await strict.close();
    }
  });

  it("did all of that without the server raising", () => {
    // The stub had a `faults()` list for its own internal inconsistencies. A
    // real server has a log: a traceback in it means a route answered 500 or
    // swallowed an exception, and either is worth failing over.
    expect(basilisk.log()).not.toMatch(/Traceback \(most recent call last\)/);
  });
});

// ---------------------------------------------------------------------------
// Half two: the shipped ops, in a browser.
// ---------------------------------------------------------------------------

describe.skipIf(!python.ok || !chromium.ok)(
  "the shipped HKP ops, against a directory",
  () => {
    /** @type {Awaited<ReturnType<typeof startBasilisk>>} */
    let basilisk;
    /** @type {Awaited<ReturnType<typeof openPeers>>} */
    let fixture;
    /** @type {import("playwright").Page} */
    let page;
    /** Set by the anonymous publish spec, read by the one after it. */
    let judyFingerprint = "";

    beforeAll(async () => {
      ({ server: basilisk } = await directoryWithCorpus());
      fixture = await openPeers({
        path: "/toolkit",
        count: 1,
        routes: basilisk.routes,
      });
      page = fixture.peers[0].page;
      const chunk = await page.evaluate(LOAD_HKP);
      expect(chunk).toMatch(/^\/assets\/hkp-ops-[A-Za-z0-9_-]+\.js$/);
    });

    afterAll(async () => {
      await fixture?.close();
      await basilisk?.close();
    });

    /** Start each group from an empty device cache and an empty request log. */
    async function clearCache() {
      const r = await callOp(page, "execHkpCache", { action: "clear" });
      expect(r.ok, r.error).toBe(true);
      basilisk.resetCounts();
    }

    describe("hkp.get", () => {
      it("fetches a key by fingerprint and reports it usable", async () => {
        await clearCache();
        const alice = corpus.byId("alice");
        const r = await callOp(page, "execHkpGet", { fpr: alice.fingerprint });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.type).toBe("openpgp-key");
        // `execHkpGet` hands on `pgpKey.armor()`, so what comes back is
        // openpgp.js's own encoding of the certificate the server served — which
        // round-trips to the armor the corpus generated, even though the bytes
        // on the wire in between did not (see the wire half).
        expect(r.value.data).toBe(alice.armoredPublic.trim());
        expect(r.value.meta.fingerprint).toBe(alice.fingerprint);
        expect(r.value.meta.valid).toBe(true);
        expect(r.value.meta.email).toBe("alice@corp.test");
        expect(r.value.meta.label).toBe(alice.uids[0]);
        expect(r.value.meta.origin).toBe("basilisk");

        // Two requests, not one: `loadRecipientKey` needs the portal's JSON as
        // well as the armor, and a pure HKP server would not satisfy it.
        const counts = basilisk.counts();
        expect(counts["lookup.get"]).toBe(1);
        expect(counts.key).toBe(1);
      });

      it("reports a miss rather than an empty key", async () => {
        await clearCache();
        const r = await callOp(page, "execHkpGet", { fpr: "B".repeat(40) });
        expect(r.ok).toBe(false);
        // `loadRecipientKey` issues the two requests through `Promise.all`, so
        // the message a person sees for a missing key is whichever rejection
        // lands first: the portal's own "Not found", or `fetchText`'s generic
        // "Request failed (404)". Both are reachable; neither names the key.
        expect(r.error).toMatch(/^(Not found|Request failed \(404\))$/);
        expect(basilisk.counts()["lookup.get"]).toBe(1);
        expect(basilisk.counts().key).toBe(1);
      });

      it("refuses a fingerprint too short to be one", async () => {
        const r = await callOp(page, "execHkpGet", { fpr: "abcdef" });
        expect(r.ok).toBe(false);
        expect(r.error).toContain("hkp.get requires fpr=");
      });

      it("reads a revoked key as revoked from the armor and the directory", async () => {
        await clearCache();
        const grace = corpus.byId("grace");
        const r = await callOp(page, "execHkpGet", { fpr: grace.fingerprint });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.meta.valid).toBe(false);
        expect(r.value.meta.err).toBe("Key is revoked");
      });

      it("refuses a signing-only key with the reason it has", async () => {
        await clearCache();
        const erin = corpus.byId("erin");
        const r = await callOp(page, "execHkpGet", { fpr: erin.fingerprint });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.meta.valid).toBe(false);
        expect(r.value.meta.err).toBe("No encryption-capable subkey");
      });

      it("DEFECT: calls an expired key a key with no encryption subkey", async () => {
        await clearCache();
        const frank = corpus.byId("frank");
        const r = await callOp(page, "execHkpGet", { fpr: frank.fingerprint });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.meta.valid).toBe(false);
        // `buildRecipient` classifies every `getEncryptionKey()` refusal as a
        // missing subkey. openpgp's own reason here is "Primary key is expired",
        // and the directory said so too — `key_expiration` is in the past on the
        // JSON this op already fetched. A person told "no encryption-capable
        // subkey" about a key that has one will go looking in the wrong place.
        // Should read "Key is expired". Reported, not fixed.
        expect(r.value.meta.err).toBe("No encryption-capable subkey");
        const record = await keyRecord(fixture.origin, frank.fingerprint);
        expect(Date.parse(record.key_expiration)).toBeLessThan(Date.now());
      });
    });

    describe("hkp.search and hkp.filter", () => {
      it("returns every approved key sharing a name, and no pending one", async () => {
        await clearCache();
        const r = await callOp(page, "execHkpSearch", { query: "Example" });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.type).toBe("recipients");
        const fprs = r.value.data.map((x) => x.fingerprint).sort();
        const approved = corpus.list
          .filter((k) => k.approvalState === "approved")
          .map((k) => k.fingerprint)
          .sort();
        expect(fprs).toEqual(approved);
        expect(fprs).not.toContain(corpus.byId("heidi").fingerprint);
        expect(basilisk.counts().search).toBe(1);
        // No HKP request at all: `hkp.search` reads the portal route only.
        expect(basilisk.counts()["lookup.get"]).toBeUndefined();
      });

      it("finds one key by its exact address, and by a second uid's address", async () => {
        await clearCache();
        const carol = corpus.byId("carol");
        const primary = await callOp(page, "execHkpSearch", {
          query: "carol@corp.test",
        });
        expect(primary.value.data.map((x) => x.fingerprint)).toEqual([
          carol.fingerprint,
        ]);

        // The second uid is what makes this more than an equality check on the
        // primary user id.
        const secondary = await callOp(page, "execHkpSearch", {
          query: "carol.alt@other.test",
        });
        expect(secondary.value.data.map((x) => x.fingerprint)).toEqual([
          carol.fingerprint,
        ]);
      });

      it("DEFECT: drops the user id, showing a fingerprint where a name belongs", async () => {
        await clearCache();
        const carol = corpus.byId("carol");
        const r = await callOp(page, "execHkpSearch", { query: "carol@corp.test" });
        const hit = r.value.data[0];

        // `recipientFromSearchHit` reads `row.label || row.uid || row.userLabel`
        // and `row.email`. `key_summary` sends none of those three: it sends
        // `approved_uids: [{ raw, name, email }]` and a `label` that is the
        // owner's friendly label, null until someone sets one. So every
        // directory hit arrives anonymous and falls back to its own fingerprint
        // — with the address it should have shown sitting in the same payload.
        const raw = await (
          await fetch(`${fixture.origin}/api/v1/search?q=carol@corp.test`)
        ).json();
        expect(raw.results[0].approved_uids[0].email).toBe("carol@corp.test");
        expect(raw.results[0].label).toBeNull();
        expect(raw.results[0].uid).toBeUndefined();
        expect(raw.results[0].email).toBeUndefined();

        expect(hit.email).toBe("");
        expect(hit.label).toBe(hit.fingerprint);
        expect(hit.fingerprint).toBe(carol.fingerprint);

        // `cacheRecordToSearchHit` does populate `email`, so the same key looks
        // right once it is in the device cache and wrong when it comes off the
        // wire — which is why this has survived: the second search of a session
        // reads better than the first. Reported, not fixed.
      });

      it("narrows a result set: the revoked key does not survive the filter", async () => {
        await clearCache();
        const found = await callOp(page, "execHkpSearch", { query: "Example" });
        const before = found.value.data.length;
        expect(before).toBe(corpus.list.length - 1);

        const filtered = await callOp(page, "execHkpFilter", {}, found.value);
        expect(filtered.ok, filtered.error).toBe(true);
        const after = filtered.value.data.map((x) => x.fingerprint);
        expect(after).not.toContain(corpus.byId("grace").fingerprint);
        expect(after).toHaveLength(before - 1);
        expect(filtered.value.meta.filtered).toBe(true);
      });

      it("narrows by origin, and keeps everything when both switches are off", async () => {
        await clearCache();
        const found = await callOp(page, "execHkpSearch", { query: "Example" });
        const all = found.value.data.length;

        const upstreamOnly = await callOp(
          page,
          "execHkpFilter",
          { origin: "upstream" },
          found.value
        );
        expect(upstreamOnly.value.data).toEqual([]);

        const basiliskOnly = await callOp(
          page,
          "execHkpFilter",
          { origin: "basilisk" },
          found.value
        );
        expect(basiliskOnly.value.data).toHaveLength(all - 1);

        const everything = await callOp(
          page,
          "execHkpFilter",
          { approved: false, encrypt: false },
          found.value
        );
        expect(everything.value.data).toHaveLength(all);
      });

      it("DEFECT: keeps a key that cannot encrypt through encrypt=true", async () => {
        await clearCache();
        const found = await callOp(page, "execHkpSearch", { query: "Example" });
        const filtered = await callOp(page, "execHkpFilter", { encrypt: true }, found.value);
        const kept = filtered.value.data.map((x) => x.fingerprint);

        // Both of these genuinely cannot encrypt — `hkp.get` says so two
        // describes above, from the armor. `hkp.filter` never sees armor:
        // `hkp.search` hits carry none, and `recipientFromSearchHit` derives
        // `encryptCapable` from approval state alone. So "Keep only
        // encrypt-capable keys" keeps a signing-only key and an expired one, and
        // only the *revoked* key is dropped — because revocation is the one
        // capability fact the directory's JSON reports.
        expect(kept).toContain(corpus.byId("erin").fingerprint);
        expect(kept).toContain(corpus.byId("frank").fingerprint);
        expect(kept).not.toContain(corpus.byId("grace").fingerprint);
      });

      it("reports a search that found nothing without inventing a reason", async () => {
        await clearCache();
        const r = await callOp(page, "execHkpSearch", { query: "Nobody" });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.data).toEqual([]);
        expect(r.value.meta.reason).toBe("not_found");
      });

      it("refuses an empty query", async () => {
        const r = await callOp(page, "execHkpSearch", { query: "  " });
        expect(r.ok).toBe(false);
        expect(r.error).toContain("hkp.search requires query=");
      });
    });

    describe("hkp.cache — the tier in front of the server", () => {
      /**
       * `/api/v1/key/<fpr>` is the honest network signal for these specs.
       *
       * `/pks/lookup?op=get` is not, and finding that out is what the spec
       * below is for: Basilisk sends the armor with
       * `Cache-Control: public, max-age=31536000, immutable`, so Chromium
       * answers a repeat request out of its own HTTP cache and the proxy never
       * sees it. The portal route carries no caching headers at all, so every
       * `loadRecipientKey` that actually reaches the network shows up as one
       * `key`.
       */
      const netGets = () => basilisk.counts().key;

      it("starts empty, fills on a miss, and is not consulted before the network", async () => {
        await clearCache();
        const listed = await callOp(page, "execHkpCache", { action: "list" });
        expect(listed.ok, listed.error).toBe(true);
        expect(listed.value.data).toEqual([]);
        expect(netGets()).toBeUndefined();

        const bob = corpus.byId("bob");
        const got = await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
        expect(got.ok, got.error).toBe(true);
        expect(netGets()).toBe(1);

        const after = await callOp(page, "execHkpCache", { action: "list" });
        expect(after.value.data.map((x) => x.fingerprint)).toEqual([bob.fingerprint]);
        // The cached row carries the uid the search path lost.
        expect(after.value.data[0].email).toBe("bob@corp.test");
      });

      it("a cache hit does not reach the network, and refresh= does", async () => {
        await clearCache();
        const bob = corpus.byId("bob");

        const first = await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
        expect(first.ok, first.error).toBe(true);
        const afterMiss = basilisk.counts();
        expect(afterMiss.key).toBe(1);

        // Second get, same fingerprint: served from IndexedDB. This is the
        // property nothing verified before — a cache that silently re-fetched
        // would have looked identical in every previous test.
        const cached = await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
        expect(cached.ok, cached.error).toBe(true);
        expect(cached.value.data).toBe(bob.armoredPublic.trim());
        expect(basilisk.counts()).toEqual(afterMiss);

        const refreshed = await callOp(page, "execHkpGet", {
          fpr: bob.fingerprint,
          refresh: true,
        });
        expect(refreshed.ok, refreshed.error).toBe(true);
        expect(netGets()).toBe(2);
      });

      it("DEFECT: refresh= cannot get new armor, because the armor is immutable for a year", async () => {
        await clearCache();
        // `dave`, because no other spec in this file fetches his armor. The
        // browser's HTTP cache is per-run and never cleared, so a key any
        // earlier spec had already resolved would make the counts below say
        // "zero" for an uninteresting reason.
        const dave = corpus.byId("dave");

        const headers = await (
          await fetch(
            `${fixture.origin}/pks/lookup?op=get&search=0x${dave.fingerprint}`
          )
        ).headers;
        // `_read_blob` sets this on every hit, keyed by the blob's digest.
        expect(headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
        expect(headers.get("etag")).toMatch(/^"[0-9a-f]{64}"$/);

        basilisk.resetCounts();
        expect((await callOp(page, "execHkpGet", { fpr: dave.fingerprint })).ok).toBe(true);
        expect(
          (await callOp(page, "execHkpGet", { fpr: dave.fingerprint, refresh: true })).ok
        ).toBe(true);

        // Two resolves, two portal reads — and one armor read. `forceRefresh`
        // skips the IndexedDB tier and reissues the request, and Chromium
        // answers it out of the HTTP cache without asking the server.
        //
        // The URL is not immutable. `/pks/lookup?op=get&search=0x<fpr>` is keyed
        // by fingerprint, and `ingest_keytext` → `refresh_approved` replaces the
        // blob behind it whenever the key is re-uploaded — a new subkey, a new
        // user id, **or a revocation**. So a browser that fetched a key once
        // will keep handing out the pre-revocation certificate for up to a year,
        // and the one control a person has for exactly this — "refresh" — cannot
        // dislodge it. `max-age` belongs on the digest-addressed blob, not on the
        // fingerprint-addressed lookup. Reported, not fixed.
        expect(basilisk.counts().key).toBe(2);
        expect(basilisk.counts()["lookup.get"]).toBe(1);
      });

      it("a cached key is searchable without the directory answering", async () => {
        await clearCache();
        const bob = corpus.byId("bob");
        await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
        basilisk.resetCounts();

        const r = await callOp(page, "execHkpSearch", { query: "bob@corp.test" });
        expect(r.value.data.map((x) => x.fingerprint)).toEqual([bob.fingerprint]);
        // The directory was still asked — the cache is a merge source, not a
        // short circuit, for search. Recorded so the difference from `hkp.get`
        // is explicit rather than assumed.
        expect(basilisk.counts().search).toBe(1);
        expect(basilisk.counts()["lookup.get"]).toBeUndefined();
      });

      it("clears", async () => {
        const bob = corpus.byId("bob");
        await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
        const cleared = await callOp(page, "execHkpCache", { action: "clear" });
        expect(cleared.value.type).toBe("text");
        expect(cleared.value.data).toBe("Pubkey cache cleared");
        const listed = await callOp(page, "execHkpCache", { action: "list" });
        expect(listed.value.data).toEqual([]);
      });
    });

    describe("key.publish", () => {
      it("submits anonymously to /pks/add and the key lands in the directory", async () => {
        await clearCache();
        const fresh = await generateKey({
          type: "ecc",
          curve: "curve25519Legacy",
          userIDs: [{ name: "Judy Example", email: "judy@corp.test" }],
          format: "object",
        });
        const armored = fresh.publicKey.armor();
        judyFingerprint = fresh.publicKey.getFingerprint().toUpperCase();
        expect(await keyRecord(fixture.origin, judyFingerprint)).toBeNull();

        const r = await callPublish(page, armored);
        expect(r.ok, r.error).toBe(true);

        // The write happened, anonymously: the page asked who it was at load,
        // /api/v1/me answered 401, `Auth` cached that, and the op therefore took
        // the /pks/add branch rather than /api/v1/me/keys.
        expect(
          basilisk.requests().some((x) => x.path === "/api/v1/me")
        ).toBe(true);
        expect(basilisk.counts().add).toBe(1);
        expect(basilisk.counts()["me.keys"]).toBeUndefined();
        expect(await keyRecord(fixture.origin, judyFingerprint)).toMatchObject({
          approval_state: "pending",
        });

        // DEFECT: `publishArmoredKey` parses the reply with
        // /[Ff]ingerprint:\s*([0-9A-Fa-f]{16,64})/, and Basilisk's `/pks/add`
        // answers "Ok\nClaim: <base>/claim/<fpr>" — no such label. So the match
        // fails, the fingerprint comes back empty, and `directoryUrl` degrades
        // to the bare lookup endpoint instead of a link to the key just
        // published. `useNotebook.publishArtifact` then writes that empty string
        // to `tile.publishedAs`. The fingerprint is right there in the claim
        // URL. Reported, not fixed.
        expect(r.value.fingerprint).toBe("");
        expect(r.value.directoryUrl).toBe(`${fixture.origin}/pks/lookup`);
        expect(r.value.directoryUrl).not.toContain(judyFingerprint);
      });

      it("a just-published key is fetchable but not yet usable", async () => {
        await clearCache();
        expect(judyFingerprint).toMatch(/^[0-9A-F]{40}$/);

        const r = await callOp(page, "execHkpGet", { fpr: judyFingerprint });
        expect(r.ok, r.error).toBe(true);
        expect(r.value.data).toContain("BEGIN PGP PUBLIC KEY BLOCK");
        // Pending, so not encryptable-to yet — which is the claim flow working,
        // not a failure.
        expect(r.value.meta.valid).toBe(false);
        expect(r.value.meta.err).toBe("Key is pending");
      });

      it("the signed-in path returns the fingerprint the anonymous one loses", async () => {
        // A fresh context: `Auth` caches the principal per page, and the page
        // above has already learned it is anonymous.
        basilisk.signIn({ email: "kim@corp.test", name: "Kim Example" });
        const context = await fixture.browser.newContext();
        const signedIn = await context.newPage();
        try {
          await signedIn.goto(`${fixture.origin}/toolkit`, { waitUntil: "load" });
          await signedIn.evaluate(LOAD_HKP);

          const fresh = await generateKey({
            type: "ecc",
            curve: "curve25519Legacy",
            userIDs: [{ name: "Kim Example", email: "kim@corp.test" }],
            format: "object",
          });
          const fpr = fresh.publicKey.getFingerprint().toUpperCase();

          const r = await callPublish(signedIn, fresh.publicKey.armor());
          expect(r.ok, r.error).toBe(true);
          expect(r.value.fingerprint).toBe(fpr);
          expect(r.value.directoryUrl).toBe(
            `${fixture.origin}/pks/lookup?op=get&search=0x${fpr}`
          );
          expect(basilisk.counts()["me.keys"]).toBeGreaterThanOrEqual(1);

          // And it is approved on arrival, not pending: the uid matches the
          // signed-in address, so `submit_claim` auto-claims it. That is the
          // real difference between the two doors, and the fingerprint is only
          // the visible half of it.
          expect(await keyRecord(fixture.origin, fpr)).toMatchObject({
            approval_state: "approved",
          });
        } finally {
          await context.close();
          basilisk.signIn(null);
        }
      });

      it("refuses to publish something that is not an armored key", async () => {
        const r = await callPublish(page, "hello");
        expect(r.ok).toBe(false);
        expect(r.error).toContain("not an armored public key");
      });
    });

    describe("the page itself", () => {
      it("did all of that inside its own Content-Security-Policy", async () => {
        const violations = await fixture.peers[0].cspViolations();
        expect(violations).toEqual([]);
      });

      it("left the server with nothing to complain about", () => {
        expect(basilisk.log()).not.toMatch(/Traceback \(most recent call last\)/);
      });
    });
  }
);

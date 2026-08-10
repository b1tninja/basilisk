/**
 * The five HKP surfaces, run against a keyserver for the first time.
 *
 * `hkp.get`, `hkp.search`, `hkp.filter`, `hkp.cache` and the `key.publish`
 * action have shipped without ever meeting a directory in a test. Not for want
 * of trying: the only keyserver available was the public internet, which this
 * repo has consistently refused to depend on. `helpers/keyserver.js` removes
 * the excuse — the ops resolve against `${location.origin}/pks/lookup`, so a
 * directory served by the same loopback server that serves `dist/` is
 * same-origin by construction and already inside `connect-src 'self'`.
 *
 * ## Two halves, and why the first one is not a browser test
 *
 * The first `describe` drives the fixture from node over real HTTP. Those are
 * *wire-format* assertions — the machine-readable index, the 501 for an op the
 * server does not implement, the exact body `/pks/add` replies with — and they
 * exist because a fixture that answers more helpfully than Basilisk does would
 * hide the defects the second half is here to find. They need no browser, so
 * they run even where one is absent.
 *
 * The second half is the point: the shipped ops, in a real browser context, at
 * a real origin, under the production CSP, with IndexedDB underneath them.
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
 * Four assertions below record behaviour that is *wrong*. They are written as
 * assertions, not comments, so that a fix flips them red and has to be
 * acknowledged. Each is labelled DEFECT with what it should do instead.
 * Nothing here changes production; that is a separate unit.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKey } from "openpgp";
import {
  chromiumAvailability,
  openPeers,
  serveDist,
  DIST_ROOT,
} from "../helpers/browser-peers.js";
import { buildKeyCorpus } from "../helpers/key-corpus.js";
import {
  createKeyserver,
  basiliskIndexBody,
  draftMrIndexBody,
  parseSearch,
  SHORT_KEYID_WARNING,
  uidParts,
} from "../helpers/keyserver.js";

const availability = await chromiumAvailability();

if (!availability.ok && availability.kind === "broken") {
  it("launches the browser the HKP directory suite needs", () => {
    expect.unreachable(
      `chromium is installed but would not launch: ${availability.reason}`
    );
  });
} else if (!availability.ok) {
  console.warn(
    `[hkp-directory.e2e] skipping the browser half — chromium not installed (${availability.reason})`
  );
}

/** One corpus for the whole file; ~200ms, and both halves want the same keys. */
const corpus = await buildKeyCorpus();

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

// ---------------------------------------------------------------------------
// Half one: the wire, from node.
// ---------------------------------------------------------------------------

describe("the local directory answers the way Basilisk's does", () => {
  /** @type {ReturnType<typeof createKeyserver>} */
  let keyserver;
  /** @type {{ origin: string, close: () => Promise<void> }} */
  let server;

  beforeAll(async () => {
    keyserver = createKeyserver();
    await keyserver.seed(corpus.list);
    server = await serveDist(DIST_ROOT, keyserver.routes);
  });

  afterAll(async () => {
    await server?.close();
  });

  it("serves a key by full fingerprint and 404s one it does not hold", async () => {
    const alice = corpus.byId("alice");
    const hit = await fetch(
      `${server.origin}/pks/lookup?op=get&options=mr&search=0x${alice.fingerprint}`
    );
    expect(hit.status).toBe(200);
    expect(hit.headers.get("content-type")).toContain("application/pgp-keys");
    expect(await hit.text()).toBe(alice.armoredPublic);

    const miss = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${"A".repeat(40)}`
    );
    expect(miss.status).toBe(404);
  });

  it("resolves a long key id, and refuses an ambiguous short one", async () => {
    const bob = corpus.byId("bob");
    const byKeyId = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${bob.keyId}`
    );
    expect(byKeyId.status).toBe(200);
    expect(await byKeyId.text()).toBe(bob.armoredPublic);

    // An 8-hex needle that matches nothing is a miss; the interesting property
    // is that a needle matching *several* is also a miss rather than a pick,
    // which is what the collision warning is about. The corpus will not
    // collide on its own, so the claim is made about the classifier: an 8-hex
    // search is a short key id and resolves through the alias index only.
    expect(parseSearch(`0x${bob.keyId.slice(-8)}`)).toEqual({
      kind: "short_keyid",
      ident: bob.keyId.slice(-8),
    });
    const short = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${bob.keyId.slice(-8)}`
    );
    expect(short.status).toBe(200);
    const nothing = await fetch(`${server.origin}/pks/lookup?op=get&search=0xdeadbeef`);
    expect(nothing.status).toBe(404);
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
    // first user id is ever emitted — carol has two.
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe("info:1:1");
    expect(lines[1]).toBe(
      `pub:255:0::::::20:${carol.fingerprint.toLowerCase()}`
    );
    expect(lines[2]).toBe(`uid:${carol.uids[0].length}:${carol.uids[0]}`);

    // A name is not an index needle at all.
    const byName = await fetch(`${server.origin}/pks/lookup?op=index&search=Example`);
    expect(byName.status).toBe(404);
    expect(await byName.text()).toBe("Not found");
  });

  it("DEFECT: that index body is not the format any HKP client parses", () => {
    const carol = corpus.byId("carol");
    const record = /** @type {any} */ (keyserver.record(carol.fingerprint));
    const served = basiliskIndexBody(record);
    const draft = draftMrIndexBody([record]);

    // `draft-shaw-openpgp-hkp-00` §5.2:
    //   pub:<keyid>:<algo>:<keylen>:<created>:<expires>:<flags>
    // Seven fields, fingerprint first. What Basilisk sends has ten, with the
    // fingerprint last and the fingerprint's *byte* length (20) sitting where
    // the key length in bits belongs.
    expect(served.split("\n")[1].split(":")).toHaveLength(10);
    const draftPub = draft.split("\n")[1].split(":");
    expect(draftPub).toHaveLength(7);
    expect(draftPub[1]).toBe(carol.fingerprint);
    expect(Number(draftPub[2])).toBe(22); // eddsaLegacy
    expect(Number(draftPub[3])).toBe(256); // bits, not bytes

    // And the uid line: a character count where the escaped uid belongs, then
    // the raw uid — so a user id containing a colon shifts every field after
    // it. The draft form URL-encodes, which is what makes that impossible.
    expect(served).toContain("<");
    expect(draft.split("\n")[2]).not.toContain("<");
    expect(served).not.toBe(draft);

    // The one Python test over this surface asserts `"pub:" in r.text`, which
    // both forms satisfy — which is how it has survived. Reported, not fixed;
    // nothing in `web/src` requests `op=index`.
    expect(served).toContain("pub:");
  });

  it("flags a revoked key r and an expired key e — in the draft form only", () => {
    const grace = /** @type {any} */ (keyserver.record(corpus.byId("grace").fingerprint));
    const frank = /** @type {any} */ (keyserver.record(corpus.byId("frank").fingerprint));
    expect(draftMrIndexBody([grace]).split("\n")[1].split(":")[6]).toBe("r");
    expect(draftMrIndexBody([frank]).split("\n")[1].split(":")[6]).toBe("e");

    // Basilisk's own body has no flags field at all: a revoked key and a live
    // one are byte-identical apart from the fingerprint. A client reading only
    // the index cannot tell them apart.
    expect(basiliskIndexBody(grace)).not.toContain(":r");
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
    const stats = await fetch(`${server.origin}/pks/lookup?op=stats`);
    expect(stats.status).toBe(200);
    expect((await stats.json()).stats.certs).toBe(corpus.list.length);

    const r = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${corpus.byId("alice").fingerprint}`
    );
    // Public key material is deliberately world-readable, and never paired
    // with credentials — `basilisk/hkp/cors.py`.
    expect(r.headers.get("access-control-allow-origin")).toBe("*");
    expect(r.headers.get("access-control-allow-credentials")).toBeNull();
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
    expect(byName.results).toHaveLength(7);
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

    // …and still serves its armor, which is what the claim flow needs.
    const armor = await fetch(
      `${server.origin}/pks/lookup?op=get&search=0x${heidi.fingerprint}`
    );
    expect(armor.status).toBe(200);
  });

  it("carries the short-key-id warning verbatim", async () => {
    const alice = corpus.byId("alice");
    const r = await (
      await fetch(`${server.origin}/api/v1/search?q=0x${alice.keyId.slice(-8)}`)
    ).json();
    expect(r.reason).toBe("short_keyid");
    expect(r.warning).toBe(SHORT_KEYID_WARNING);
    expect(r.results.map((x) => x.fingerprint)).toEqual([alice.fingerprint]);
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
    const body = await r.text();

    // Basilisk's reply, reproduced rather than improved: the claim URL is the
    // only place the fingerprint appears, and there is no `Fingerprint:` line.
    // `publishArmoredKey` looks for one; see the browser half.
    expect(body).toMatch(/^Ok\nClaim: http:\/\/[^/]+\/claim\/[0-9A-F]{40}\n$/);
    expect(body).not.toMatch(/[Ff]ingerprint:/);
    expect(body).toContain(fpr);

    expect(keyserver.submissions().at(-1)).toEqual({
      fingerprint: fpr,
      via: "/pks/add",
    });
    expect(keyserver.record(fpr)?.approvalState).toBe("pending");
  });

  it("keeps the fixture's own faults empty", () => {
    expect(keyserver.faults()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Half two: the shipped ops, in a browser.
// ---------------------------------------------------------------------------

describe.skipIf(!availability.ok)("the shipped HKP ops, against a directory", () => {
  /** @type {ReturnType<typeof createKeyserver>} */
  let keyserver;
  /** @type {Awaited<ReturnType<typeof openPeers>>} */
  let fixture;
  /** @type {import("playwright").Page} */
  let page;

  beforeAll(async () => {
    keyserver = createKeyserver();
    await keyserver.seed(corpus.list);
    fixture = await openPeers({
      path: "/toolkit",
      count: 1,
      routes: keyserver.routes,
    });
    page = fixture.peers[0].page;
    const chunk = await page.evaluate(LOAD_HKP);
    expect(chunk).toMatch(/^\/assets\/hkp-ops-[A-Za-z0-9_-]+\.js$/);
  });

  afterAll(async () => {
    await fixture?.close();
  });

  /** Start each group from an empty device cache. */
  async function clearCache() {
    const r = await callOp(page, "execHkpCache", { action: "clear" });
    expect(r.ok, r.error).toBe(true);
    keyserver.resetCounts();
  }

  describe("hkp.get", () => {
    it("fetches a key by fingerprint and reports it usable", async () => {
      await clearCache();
      const alice = corpus.byId("alice");
      const r = await callOp(page, "execHkpGet", { fpr: alice.fingerprint });
      expect(r.ok, r.error).toBe(true);
      expect(r.value.type).toBe("openpgp-key");
      // `execHkpGet` trims the armor before it becomes a pipeline value, so
      // the comparison is against the trimmed form rather than the key's own.
      expect(r.value.data).toBe(alice.armoredPublic.trim());
      expect(r.value.meta.fingerprint).toBe(alice.fingerprint);
      expect(r.value.meta.valid).toBe(true);
      expect(r.value.meta.email).toBe("alice@corp.test");
      expect(r.value.meta.label).toBe(alice.uids[0]);
      expect(r.value.meta.origin).toBe("basilisk");

      // Two requests, not one: `loadRecipientKey` needs the portal's JSON as
      // well as the armor, and a pure HKP server would not satisfy it.
      const counts = keyserver.counts();
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
      expect(keyserver.counts()["lookup.get"]).toBe(1);
      expect(keyserver.counts().key).toBe(1);
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
      expect(keyserver.counts().search).toBe(1);
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
      const alice = corpus.byId("alice");
      const r = await callOp(page, "execHkpSearch", { query: "carol@corp.test" });
      const hit = r.value.data[0];
      // `recipientFromSearchHit` reads `row.label || row.uid || row.userLabel`
      // and `row.email`. Basilisk's `key_summary` sends neither `uid` nor
      // `email`; it sends `approved_uids: [{ raw, name, email }]` and a `label`
      // that is the owner's friendly label, normally null. So every directory
      // hit arrives anonymous and falls back to its own fingerprint.
      //
      // `cacheRecordToSearchHit` does populate `email`, so the same key looks
      // right once it is in the device cache and wrong when it comes off the
      // wire — which is why this has survived: the second search of a session
      // reads better than the first. Reported, not fixed.
      expect(hit.email).toBe("");
      expect(hit.label).toBe(hit.fingerprint);
      expect(uidParts(corpus.byId("carol").uids[0]).email).toBe("carol@corp.test");
      // Not a claim about alice; named only so the corpus reference is honest.
      expect(alice.email).toBe("alice@corp.test");
    });

    it("narrows a result set: the revoked key does not survive the filter", async () => {
      await clearCache();
      const found = await callOp(page, "execHkpSearch", { query: "Example" });
      const before = found.value.data.length;
      expect(before).toBe(7);

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

      const upstreamOnly = await callOp(
        page,
        "execHkpFilter",
        { origin: "upstream" },
        found.value
      );
      expect(upstreamOnly.value.data).toEqual([]);

      const basilisk = await callOp(
        page,
        "execHkpFilter",
        { origin: "basilisk" },
        found.value
      );
      expect(basilisk.value.data).toHaveLength(6);

      const everything = await callOp(
        page,
        "execHkpFilter",
        { approved: false, encrypt: false },
        found.value
      );
      expect(everything.value.data).toHaveLength(7);
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
    it("starts empty, fills on a miss, and is not consulted before the network", async () => {
      await clearCache();
      const listed = await callOp(page, "execHkpCache", { action: "list" });
      expect(listed.ok, listed.error).toBe(true);
      expect(listed.value.data).toEqual([]);
      expect(keyserver.counts()["lookup.get"]).toBeUndefined();

      const bob = corpus.byId("bob");
      await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
      expect(keyserver.counts()["lookup.get"]).toBe(1);

      const after = await callOp(page, "execHkpCache", { action: "list" });
      expect(after.value.data.map((x) => x.fingerprint)).toEqual([bob.fingerprint]);
      // The cached row carries the uid the search path lost.
      expect(after.value.data[0].email).toBe("bob@corp.test");
    });

    it("a cache hit does not reach the network, and refresh= does", async () => {
      await clearCache();
      const bob = corpus.byId("bob");

      await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
      const afterMiss = keyserver.counts();
      expect(afterMiss["lookup.get"]).toBe(1);
      expect(afterMiss.key).toBe(1);

      // Second get, same fingerprint: served from IndexedDB. This is the
      // property nothing verified before — a cache that silently re-fetched
      // would have looked identical in every previous test.
      const cached = await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
      expect(cached.ok, cached.error).toBe(true);
      expect(cached.value.data).toBe(bob.armoredPublic.trim());
      expect(keyserver.counts()).toEqual(afterMiss);

      const refreshed = await callOp(page, "execHkpGet", {
        fpr: bob.fingerprint,
        refresh: true,
      });
      expect(refreshed.ok, refreshed.error).toBe(true);
      expect(keyserver.counts()["lookup.get"]).toBe(2);
      expect(keyserver.counts().key).toBe(2);
    });

    it("a cached key is searchable without the directory answering", async () => {
      await clearCache();
      const bob = corpus.byId("bob");
      await callOp(page, "execHkpGet", { fpr: bob.fingerprint });
      keyserver.resetCounts();

      const r = await callOp(page, "execHkpSearch", { query: "bob@corp.test" });
      expect(r.value.data.map((x) => x.fingerprint)).toEqual([bob.fingerprint]);
      // The directory was still asked — the cache is a merge source, not a
      // short circuit, for search. Recorded so the difference from `hkp.get`
      // is explicit rather than assumed.
      expect(keyserver.counts().search).toBe(1);
      expect(keyserver.counts()["lookup.get"]).toBeUndefined();
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
      const fpr = fresh.publicKey.getFingerprint().toUpperCase();
      expect(keyserver.record(fpr)).toBeNull();

      const r = await page.evaluate(
        async (key) => {
          try {
            return { ok: true, value: await window.__hkp.publishArmoredKey(key) };
          } catch (err) {
            return { ok: false, error: err instanceof Error ? err.message : String(err) };
          }
        },
        armored
      );
      expect(r.ok, r.error).toBe(true);

      // The write happened, anonymously: the page asked who it was at load,
      // /api/v1/me answered 401, `Auth` cached that, and the op therefore took
      // the /pks/add branch rather than /api/v1/me/keys.
      expect(
        keyserver.requests().some((x) => x.path === "/api/v1/me")
      ).toBe(true);
      expect(keyserver.counts().add).toBe(1);
      expect(keyserver.counts()["me.keys"]).toBeUndefined();
      expect(keyserver.submissions().map((s) => s.fingerprint)).toContain(fpr);
      expect(keyserver.record(fpr)?.approvalState).toBe("pending");

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
      expect(r.value.directoryUrl).not.toContain(fpr);
    });

    it("a just-published key is fetchable but not yet usable", async () => {
      await clearCache();
      const published = keyserver
        .records()
        .find((rec) => rec.uids.some((u) => u.includes("judy@corp.test")));
      expect(published).toBeTruthy();

      const r = await callOp(page, "execHkpGet", {
        fpr: /** @type {any} */ (published).fingerprint,
      });
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
      keyserver.signIn({ email: "kim@corp.test", name: "Kim Example" });
      const context = await fixture.browser.newContext();
      const signedIn = await context.newPage();
      await signedIn.goto(`${fixture.origin}/toolkit`, { waitUntil: "load" });
      await signedIn.evaluate(LOAD_HKP);

      const fresh = await generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ name: "Kim Example", email: "kim@corp.test" }],
        format: "object",
      });
      const fpr = fresh.publicKey.getFingerprint().toUpperCase();

      const r = await signedIn.evaluate(
        async (key) => {
          try {
            return { ok: true, value: await window.__hkp.publishArmoredKey(key) };
          } catch (err) {
            return { ok: false, error: err instanceof Error ? err.message : String(err) };
          }
        },
        fresh.publicKey.armor()
      );
      expect(r.ok, r.error).toBe(true);
      expect(r.value.fingerprint).toBe(fpr);
      expect(r.value.directoryUrl).toBe(
        `${fixture.origin}/pks/lookup?op=get&search=0x${fpr}`
      );
      expect(keyserver.submissions().at(-1)).toEqual({
        fingerprint: fpr,
        via: "/api/v1/me/keys",
      });

      await context.close();
      keyserver.signIn(null);
    });

    it("refuses to publish something that is not an armored key", async () => {
      const r = await page.evaluate(async () => {
        try {
          return { ok: true, value: await window.__hkp.publishArmoredKey("hello") };
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      });
      expect(r.ok).toBe(false);
      expect(r.error).toContain("not an armored public key");
    });
  });

  describe("the page itself", () => {
    it("did all of that inside its own Content-Security-Policy", async () => {
      const violations = await fixture.peers[0].cspViolations();
      expect(violations).toEqual([]);
    });

    it("left no fixture fault behind", () => {
      expect(keyserver.faults()).toEqual([]);
    });
  });
});

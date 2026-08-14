import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  computeLoadedModulesRoot,
  hashIntegrityLeaf,
  merkleRootHex,
  parseIntegrityAttr,
  shortModuleRoot,
} from "../lib/module-integrity.js";

describe("module-integrity", () => {
  it("parses SRI integrity tokens", () => {
    const leaves = parseIntegrityAttr(
      "sha384-abc+DEF/123= sha256-xyz=",
      "/assets/app.js"
    );
    expect(leaves).toHaveLength(2);
    expect(leaves[0]).toEqual({
      url: "/assets/app.js",
      alg: "sha384",
      digest: "abc+DEF/123=",
    });
    expect(leaves[1].alg).toBe("sha256");
  });

  it("builds a deterministic Merkle root independent of leaf order", async () => {
    const a = await hashIntegrityLeaf({
      url: "/a.js",
      alg: "sha384",
      digest: "aaa",
    });
    const b = await hashIntegrityLeaf({
      url: "/b.js",
      alg: "sha384",
      digest: "bbb",
    });
    const r1 = await merkleRootHex([a, b]);
    const r2 = await merkleRootHex([b, a]);
    expect(r1).toBe(r2);
    expect(r1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("promotes a single leaf to the root", async () => {
    const leaf = await hashIntegrityLeaf({
      url: "/solo.js",
      alg: "sha256",
      digest: "QQ==",
    });
    const root = await merkleRootHex([leaf]);
    expect(root).toBe(bytesToHex(leaf));
  });

  it("shortModuleRoot truncates hex", () => {
    expect(shortModuleRoot("abcdef0123456789ffff", 16)).toBe("abcdef0123456789");
    expect(shortModuleRoot("")).toBe("");
  });

  it("computeLoadedModulesRoot returns a self or none digest without DOM", async () => {
    const info = await computeLoadedModulesRoot({
      document: null,
      selfModuleUrl: import.meta.url,
    });
    expect(info.leafCount).toBeGreaterThanOrEqual(0);
    if (info.leafCount > 0) {
      expect(info.root).toMatch(/^[0-9a-f]{64}$/);
      expect(["self", "sri"]).toContain(info.source);
    } else {
      expect(info.source).toBe("none");
    }
  });

  it("pageKeyFromPath maps clean URLs", async () => {
    const { pageKeyFromPath } = await import("../lib/module-integrity.js");
    expect(pageKeyFromPath("/")).toBe("index.html");
    // Pages the build still produces. `/encrypt` and `/decrypt.html` stood
    // here until those two were retired into toolkit fragments; a pin key for
    // a page that ships no bytes is a key nothing can ever match.
    expect(pageKeyFromPath("/published")).toBe("published.html");
    expect(pageKeyFromPath("/preferences")).toBe("preferences.html");
    expect(pageKeyFromPath("/verify.html")).toBe("verify.html");
  });

  it("verifyModuleRootAgainstPins matches agreeing mirrors", async () => {
    const { verifyModuleRootAgainstPins } = await import(
      "../lib/module-integrity.js"
    );
    const root = "a".repeat(64);
    const pinDoc = {
      version: 1,
      algorithm: "sha256-merkle-v1",
      builtAt: new Date().toISOString(),
      pages: { "toolkit.html": { root, leafCount: 2 } },
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      /** @type {Response} */ ({
        ok: true,
        json: async () => pinDoc,
      });
    try {
      const r = await verifyModuleRootAgainstPins(root, {
        pageKey: "toolkit.html",
        document: null,
        pinUrls: ["/integrity/module-roots.json", "https://mirror.example/pin.json"],
        requirePins: true,
      });
      expect(r.ok).toBe(true);
      expect(r.matched).toBe(true);
      expect(r.fetched).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("verifyModuleRootAgainstPins fails closed on mismatch", async () => {
    const { verifyModuleRootAgainstPins } = await import(
      "../lib/module-integrity.js"
    );
    const pinDoc = {
      version: 1,
      algorithm: "sha256-merkle-v1",
      builtAt: new Date().toISOString(),
      pages: { "toolkit.html": { root: "b".repeat(64), leafCount: 2 } },
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      /** @type {Response} */ ({
        ok: true,
        json: async () => pinDoc,
      });
    try {
      const r = await verifyModuleRootAgainstPins("a".repeat(64), {
        pageKey: "toolkit.html",
        document: null,
        pinUrls: ["/integrity/module-roots.json"],
        requirePins: true,
      });
      expect(r.ok).toBe(false);
      expect(r.message).toMatch(/mismatch/i);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("verifyModuleRootAgainstPins refuses an empty pin list when pins are required", async () => {
    // The branch `requirePins` was written for and never reached: it was folded
    // into `required` and then discarded by a hardcoded `ok: true`, so the only
    // callers that passed the flag passed it alongside a non-empty list and
    // nothing noticed. An empty list is the interesting case — on a served page
    // it means the `basilisk-integrity-pins` meta is not in the bytes that
    // arrived, and deleting one attribute is the cheapest way to switch the
    // whole check off.
    const { verifyModuleRootAgainstPins } = await import("../lib/module-integrity.js");
    const r = await verifyModuleRootAgainstPins("a".repeat(64), {
      pageKey: "toolkit.html",
      document: null,
      pinUrls: [],
      requirePins: true,
    });
    expect(r.ok).toBe(false);
    expect(r.required).toBe(true);
    // Names the state that is true — a page with SRI and no pin — rather than
    // the dev-server wording, which would be a different and untrue claim.
    expect(r.message).toMatch(/names no integrity pin document/i);
    expect(r.message).not.toMatch(/dev \/ unsigned build/i);
  });

  it("verifyModuleRootAgainstPins still passes an empty pin list on an unpinned build", async () => {
    // The dev server and the node suite have no SRI at all, so nothing asks
    // them for pins. Tightening the required case must not turn those into
    // failures, or the refusal above would be indistinguishable from `npm run
    // dev` and would stop being read.
    const { verifyModuleRootAgainstPins } = await import("../lib/module-integrity.js");
    const r = await verifyModuleRootAgainstPins("a".repeat(64), {
      pageKey: "toolkit.html",
      document: null,
      pinUrls: [],
    });
    expect(r.ok).toBe(true);
    expect(r.required).toBe(false);
    expect(r.message).toMatch(/dev \/ unsigned build/i);
  });

  it("verifyModuleRootAgainstPins treats an empty pins meta as a demand, not a shrug", async () => {
    // A page that carries the meta with nothing in it has asked to be checked
    // and supplied nothing to check against. `required` already came out true
    // for that shape; the verdict did not.
    const { verifyModuleRootAgainstPins } = await import("../lib/module-integrity.js");
    const doc = {
      querySelector: (sel) =>
        sel === 'meta[name="basilisk-integrity-pins"]'
          ? { getAttribute: () => "   " }
          : null,
    };
    const r = await verifyModuleRootAgainstPins("a".repeat(64), {
      pageKey: "toolkit.html",
      document: /** @type {any} */ (doc),
    });
    expect(r.required).toBe(true);
    expect(r.ok).toBe(false);
  });

  it("the power-on self test is the caller that demands pins", async () => {
    // Asserted against the source because the branch only runs in a document
    // with real SRI attributes, which the node suite has no way to produce.
    // What matters is that the flag reaches the one caller that knows the page
    // carried SRI — the fix is worth nothing in a library nobody passes it to.
    const src = readFileSync(
      new URL("../lib/crypto-self-test.js", import.meta.url),
      "utf8"
    );
    const call = /verifyModuleRootAgainstPins\(([\s\S]*?)\);/.exec(src);
    expect(call, "the POST no longer calls verifyModuleRootAgainstPins").toBeTruthy();
    expect(call[1]).toMatch(/requirePins:\s*true/);
    expect(src).toMatch(/moduleIntegrity\.source === "sri"/);
  });

  it("verifyModuleRootAgainstPins detects disagreeing mirrors", async () => {
    const { verifyModuleRootAgainstPins } = await import(
      "../lib/module-integrity.js"
    );
    let n = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      n += 1;
      const root = n === 1 ? "a".repeat(64) : "c".repeat(64);
      return /** @type {Response} */ ({
        ok: true,
        json: async () => ({
          version: 1,
          algorithm: "sha256-merkle-v1",
          builtAt: new Date().toISOString(),
          pages: { "toolkit.html": { root, leafCount: 1 } },
        }),
      });
    };
    try {
      const r = await verifyModuleRootAgainstPins("a".repeat(64), {
        pageKey: "toolkit.html",
        document: null,
        pinUrls: ["/a.json", "/b.json"],
        requirePins: true,
      });
      expect(r.ok).toBe(false);
      expect(r.message).toMatch(/disagree/i);
      // In full, both of them. This branch leaves `expectedRoot` empty — there
      // is no single expected root — so the panel's "Pinned root" row does not
      // render and this sentence is the only place either value appears. A
      // truncated root there is a number nobody can take to a second machine.
      expect(r.message).toContain("a".repeat(64));
      expect(r.message).toContain("c".repeat(64));
      expect(r.expectedRoot).toBe("");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

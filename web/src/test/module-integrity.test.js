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
    expect(pageKeyFromPath("/encrypt")).toBe("encrypt.html");
    expect(pageKeyFromPath("/decrypt.html")).toBe("decrypt.html");
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
      pages: { "encrypt.html": { root, leafCount: 2 } },
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      /** @type {Response} */ ({
        ok: true,
        json: async () => pinDoc,
      });
    try {
      const r = await verifyModuleRootAgainstPins(root, {
        pageKey: "encrypt.html",
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
      pages: { "encrypt.html": { root: "b".repeat(64), leafCount: 2 } },
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      /** @type {Response} */ ({
        ok: true,
        json: async () => pinDoc,
      });
    try {
      const r = await verifyModuleRootAgainstPins("a".repeat(64), {
        pageKey: "encrypt.html",
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
          pages: { "encrypt.html": { root, leafCount: 1 } },
        }),
      });
    };
    try {
      const r = await verifyModuleRootAgainstPins("a".repeat(64), {
        pageKey: "encrypt.html",
        document: null,
        pinUrls: ["/a.json", "/b.json"],
        requirePins: true,
      });
      expect(r.ok).toBe(false);
      expect(r.message).toMatch(/disagree/i);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

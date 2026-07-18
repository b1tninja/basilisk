import { beforeEach, describe, expect, it } from "vitest";
import {
  clearTrust,
  getTrust,
  listTrusted,
  setTrust,
  sortByTrust,
  trustBadgeHtml,
  trustSortKey,
} from "../lib/trust.js";

/** Minimal localStorage for Node vitest. */
function installMemoryLocalStorage() {
  /** @type {Map<string, string>} */
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => {
      store.set(String(k), String(v));
    },
    removeItem: (k) => {
      store.delete(k);
    },
    clear: () => {
      store.clear();
    },
    key: (i) => [...store.keys()][i] ?? null,
    get length() {
      return store.size;
    },
  };
}

installMemoryLocalStorage();

beforeEach(() => {
  localStorage.clear();
});

describe("trust store", () => {
  it("set/get/clear trust levels", () => {
    const fpr = "ABB3A7283D5EE084295CF439FDBA0D5445AA8148";
    expect(getTrust(fpr)).toBeNull();
    setTrust(fpr, "trusted");
    expect(getTrust(fpr)?.level).toBe("trusted");
    setTrust(`abb3 a728 3d5e e084 295c f439 fdba 0d54 45aa 8148`, "marginal");
    expect(getTrust(fpr)?.level).toBe("marginal");
    clearTrust(fpr);
    expect(getTrust(fpr)).toBeNull();
  });

  it("listTrusted and sortByTrust", () => {
    const a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const c = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    setTrust(a, "never");
    setTrust(b, "trusted");
    setTrust(c, "marginal");
    const listed = listTrusted();
    expect(listed).toHaveLength(3);
    const sorted = sortByTrust([
      { fingerprint: a },
      { fingerprint: c },
      { fingerprint: b },
      { fingerprint: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" },
    ]);
    expect(sorted.map((x) => x.fingerprint[0])).toEqual(["B", "C", "D", "A"]);
    expect(trustSortKey(b)).toBe(0);
    expect(trustBadgeHtml(b)).toContain("trusted");
    expect(trustBadgeHtml("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")).toBe("");
  });

  it("rejects invalid level", () => {
    expect(() => setTrust("AA".repeat(20), /** @type {any} */ ("full"))).toThrow(
      /Invalid trust level/
    );
  });
});

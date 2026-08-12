import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_TOOLKIT_PREFS,
  getIdleClearMs,
  getToolkitPrefs,
  normalizeToolkitPrefs,
  setToolkitPrefs,
  TOOLKIT_PREFS_KEY,
} from "../lib/toolkit/prefs.js";

/**
 * Prefs live in localStorage, so the tests have to own one.
 *
 * The `try`/`catch` below used to be the whole story, which meant that on a
 * runtime without `localStorage` -- CI's Node 22 -- the clear silently did
 * nothing and `setToolkitPrefs` silently stored nothing, so these assertions
 * passed by reading defaults rather than by round-tripping. Green for the
 * wrong reason on one runtime and the right one on another.
 */
beforeAll(() => {
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
  };
});

beforeEach(() => {
  localStorage.removeItem(TOOLKIT_PREFS_KEY);
  setToolkitPrefs({ ...DEFAULT_TOOLKIT_PREFS });
});

describe("toolkit prefs", () => {
  it("normalizes invalid idle / mode / policy", () => {
    const p = normalizeToolkitPrefs({
      idleClearMinutes: 99,
      defaultEncryptMode: "nope",
      defaultEncryptPolicy: "maybe",
    });
    expect(p.idleClearMinutes).toBe(5);
    expect(p.defaultEncryptMode).toBe("separate");
    expect(p.defaultEncryptPolicy).toBe("ask");
  });

  it("persists round-trip", () => {
    setToolkitPrefs({
      idleClearMinutes: 15,
      defaultEncryptMode: "combined",
      defaultEncryptPolicy: "one",
      sessionOff: true,
      collapseAdvanced: false,
    });
    const p = getToolkitPrefs();
    expect(p.idleClearMinutes).toBe(15);
    expect(p.defaultEncryptMode).toBe("combined");
    expect(p.defaultEncryptPolicy).toBe("one");
    expect(p.sessionOff).toBe(true);
    expect(p.collapseAdvanced).toBe(false);
    expect(getIdleClearMs()).toBe(15 * 60 * 1000);
  });

  it("idle never → 0 ms", () => {
    setToolkitPrefs({ idleClearMinutes: 0 });
    expect(getIdleClearMs()).toBe(0);
  });
});

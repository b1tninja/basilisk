import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_TOOLKIT_PREFS,
  getIdleClearMs,
  getToolkitPrefs,
  normalizeToolkitPrefs,
  setToolkitPrefs,
  TOOLKIT_PREFS_KEY,
} from "../lib/toolkit/prefs.js";

beforeEach(() => {
  try {
    localStorage.removeItem(TOOLKIT_PREFS_KEY);
  } catch {
    /* ignore */
  }
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

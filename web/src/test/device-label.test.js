import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { getDeviceLabel, listDeviceLabels, setDeviceLabel } from "../lib/prefs.js";

// Stub localStorage for the Node.js test environment.
beforeAll(() => {
  const store = new Map();
  const keys = () => Array.from(store.keys());
  globalThis.localStorage = {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
    get length() { return store.size; },
    key: (i) => keys()[i] ?? null,
  };
});

const FPR = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
const FPR2 = "1111111111111111111111111111111111111111";

beforeEach(() => {
  localStorage.clear();
});

describe("getDeviceLabel", () => {
  it("returns empty string when no label is set", () => {
    expect(getDeviceLabel(FPR)).toBe("");
  });

  it("returns empty string for unknown fpr", () => {
    expect(getDeviceLabel("0000000000000000000000000000000000000000")).toBe("");
  });
});

describe("setDeviceLabel / getDeviceLabel round-trip", () => {
  it("stores and retrieves a label without keyref", () => {
    setDeviceLabel(FPR, "", "Blue YubiKey 5C");
    expect(getDeviceLabel(FPR)).toBe("Blue YubiKey 5C");
  });

  it("stores and retrieves a label with keyref", () => {
    setDeviceLabel(FPR, "OPENPGP.1", "Signing slot");
    expect(getDeviceLabel(FPR, "OPENPGP.1")).toBe("Signing slot");
  });

  it("keyref is included in the storage key so slots are independent", () => {
    setDeviceLabel(FPR, "OPENPGP.1", "Slot 1");
    setDeviceLabel(FPR, "OPENPGP.2", "Slot 2");
    expect(getDeviceLabel(FPR, "OPENPGP.1")).toBe("Slot 1");
    expect(getDeviceLabel(FPR, "OPENPGP.2")).toBe("Slot 2");
  });

  it("normalises fpr to uppercase for storage", () => {
    setDeviceLabel(FPR.toLowerCase(), "", "case test");
    expect(getDeviceLabel(FPR)).toBe("case test");
  });

  it("trims whitespace from label", () => {
    setDeviceLabel(FPR, "", "  Nitrokey backup  ");
    expect(getDeviceLabel(FPR)).toBe("Nitrokey backup");
  });

  it("truncates label to 200 characters", () => {
    setDeviceLabel(FPR, "", "X".repeat(300));
    expect(getDeviceLabel(FPR).length).toBe(200);
  });
});

describe("clearing labels", () => {
  it("removes label when empty string passed", () => {
    setDeviceLabel(FPR, "", "Temporary");
    setDeviceLabel(FPR, "", "");
    expect(getDeviceLabel(FPR)).toBe("");
  });

  it("removes label when null passed", () => {
    setDeviceLabel(FPR, "", "Temporary");
    setDeviceLabel(FPR, "", null);
    expect(getDeviceLabel(FPR)).toBe("");
  });

  it("removing one keyref slot does not affect others", () => {
    setDeviceLabel(FPR, "OPENPGP.1", "Keep me");
    setDeviceLabel(FPR, "OPENPGP.2", "Remove me");
    setDeviceLabel(FPR, "OPENPGP.2", "");
    expect(getDeviceLabel(FPR, "OPENPGP.1")).toBe("Keep me");
    expect(getDeviceLabel(FPR, "OPENPGP.2")).toBe("");
  });
});

describe("listDeviceLabels", () => {
  it("returns empty array when nothing stored", () => {
    expect(listDeviceLabels()).toEqual([]);
  });

  it("returns all stored labels", () => {
    setDeviceLabel(FPR, "", "Primary key card");
    setDeviceLabel(FPR2, "OPENPGP.1", "Travel backup");
    const labels = listDeviceLabels();
    expect(labels).toHaveLength(2);
    expect(labels.some((l) => l.fpr === FPR && l.label === "Primary key card")).toBe(true);
    expect(labels.some((l) => l.fpr === FPR2 && l.keyref === "OPENPGP.1" && l.label === "Travel backup")).toBe(true);
  });

  it("does not list entries that were cleared", () => {
    setDeviceLabel(FPR, "", "Gone");
    setDeviceLabel(FPR, "", "");
    expect(listDeviceLabels()).toEqual([]);
  });
});

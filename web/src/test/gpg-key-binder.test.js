/**
 * GpgKeyBinder expiry notes (§39b).
 *
 * The row rendering is not covered here (node env, no React renderer). The
 * expiry threshold is, because it decides whether a warning appears at all —
 * and a warning shown on every row is the same as no warning.
 */
import { describe, expect, it } from "vitest";
import { daysUntilExpiry, expiryNote } from "../toolkit/widgets/GpgKeyBinder";

const NOW = Date.UTC(2026, 6, 30);
const days = (n) => NOW + n * 86_400_000;

describe("daysUntilExpiry", () => {
  it("is null for a key that never expires", () => {
    expect(daysUntilExpiry(null, NOW)).toBeNull();
    expect(daysUntilExpiry(undefined, NOW)).toBeNull();
  });

  it("counts forward and backward", () => {
    expect(daysUntilExpiry(days(4), NOW)).toBe(4);
    expect(daysUntilExpiry(days(-1), NOW)).toBe(-1);
  });
});

describe("expiryNote", () => {
  it("says nothing about a key that never expires", () => {
    expect(expiryNote(null, NOW)).toBeNull();
  });

  it("stays quiet beyond a month", () => {
    // A key expiring in a year is not news. Warning on every row would train
    // people to ignore the row that matters.
    expect(expiryNote(days(365), NOW)).toBeNull();
    expect(expiryNote(days(31), NOW)).toBeNull();
  });

  it("warns inside a month, escalating inside a week", () => {
    expect(expiryNote(days(30), NOW)).toEqual({ text: "expires in 30 days", severity: "warn" });
    expect(expiryNote(days(7), NOW)).toEqual({ text: "expires in 7 days", severity: "error" });
    expect(expiryNote(days(1), NOW)).toEqual({ text: "expires in 1 day", severity: "error" });
  });

  it("distinguishes today from already expired", () => {
    // Signing with a key that expires today still works; one that expired
    // yesterday does not. Same colour, different sentence.
    expect(expiryNote(NOW, NOW)).toEqual({ text: "expires today", severity: "error" });
    expect(expiryNote(days(-1), NOW)).toEqual({ text: "expired", severity: "error" });
  });
});

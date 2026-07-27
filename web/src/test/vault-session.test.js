/**
 * In-memory vault agent session TTL.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  VAULT_SESSION_TTL_MS,
  sessionClear,
  sessionGet,
  sessionPut,
  sessionTouch,
} from "../lib/vault-session.js";

beforeEach(() => {
  sessionClear();
  vi.useFakeTimers();
});

afterEach(() => {
  sessionClear();
  vi.useRealTimers();
});

describe("vault-session", () => {
  it("stores and returns unlocked armor", () => {
    const fpr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    sessionPut(fpr, "-----BEGIN PGP PRIVATE KEY BLOCK-----\n…");
    expect(sessionGet(fpr)).toContain("PRIVATE KEY");
  });

  it("expires after TTL", () => {
    const fpr = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    sessionPut(fpr, "armored");
    vi.advanceTimersByTime(VAULT_SESSION_TTL_MS + 1);
    expect(sessionGet(fpr)).toBeNull();
  });

  it("sessionTouch extends TTL", () => {
    const fpr = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    sessionPut(fpr, "armored");
    vi.advanceTimersByTime(VAULT_SESSION_TTL_MS - 10_000);
    sessionTouch(fpr);
    vi.advanceTimersByTime(VAULT_SESSION_TTL_MS - 10_000);
    expect(sessionGet(fpr)).toBe("armored");
  });

  it("sessionClear wipes all entries", () => {
    sessionPut("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "a");
    sessionPut("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", "b");
    sessionClear();
    expect(sessionGet("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")).toBeNull();
    expect(sessionGet("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")).toBeNull();
  });
});

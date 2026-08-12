/**
 * In-memory vault agent session TTL.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  VAULT_SESSION_TTL_MS,
  sessionClear,
  sessionGet,
  sessionList,
  sessionPut,
  sessionTouch,
  vaultKindFromId,
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

  it("carries whether the armor still owes a passphrase", () => {
    // Two locks, and `vault.unlockKey` opens only the outer one. "unlocked"
    // beside a passphrase-protected key was a true statement about the vault
    // envelope and a false one about the key, and the run found out several
    // steps later in OpenPGP's own words.
    sessionPut("A".repeat(40), "armored", { locked: true });
    sessionPut("B".repeat(40), "armored", { locked: false });
    const byFpr = Object.fromEntries(sessionList().map((e) => [e.fingerprint, e.locked]));
    expect(byFpr["A".repeat(40)]).toBe(true);
    expect(byFpr["B".repeat(40)]).toBe(false);
  });

  it("says undefined when nobody established it, rather than false", () => {
    // `false` would be a claim that the key is ready to sign — exactly the
    // false claim this field exists to stop. Absence has to be distinguishable.
    sessionPut("C".repeat(40), "armored");
    expect(sessionList()[0].locked).toBeUndefined();
  });

  it("still hands out no armor", () => {
    sessionPut("D".repeat(40), "-----BEGIN PGP PRIVATE KEY BLOCK-----", { locked: false });
    expect(JSON.stringify(sessionList())).not.toMatch(/PRIVATE KEY/);
  });

  it("reads a kind off the id shape for keys the vault has no record of", () => {
    // A session-only key has no vault row to take a kind from, and defaulting
    // it to pgp would offer an ssh key as a candidate to sign a session invite.
    expect(vaultKindFromId("A".repeat(40))).toBe("pgp");
    expect(vaultKindFromId("SHA256:" + "a".repeat(43))).toBe("ssh");
    expect(vaultKindFromId("spki:SHA256:" + "a".repeat(43))).toBe("raw");
  });

  it("sessionClear wipes all entries", () => {
    sessionPut("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "a");
    sessionPut("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", "b");
    sessionClear();
    expect(sessionGet("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")).toBeNull();
    expect(sessionGet("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")).toBeNull();
  });
});

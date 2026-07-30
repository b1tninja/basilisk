/**
 * Session-only keys — minted in memory for e2e runs (or unlocked without
 * saving), never persisted to the vault. The property under test: the unlock
 * path resolves them by fingerprint exactly like vault keys, and a
 * fingerprint neither the session nor the vault knows still fails closed.
 */
import { afterEach, describe, expect, it } from "vitest";
import { sessionEvict, sessionPut } from "../lib/vault-session.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";

const FPR = "C0FFEE00".padEnd(40, "A");
const ARMORED = "-----BEGIN PGP PRIVATE KEY BLOCK----- (test)";

afterEach(() => {
  sessionEvict(FPR);
});

describe("unlockVaultForUse with a session-only key", () => {
  it("resolves from the session without requiring vault membership", async () => {
    sessionPut(FPR, ARMORED);
    const res = await unlockVaultForUse(FPR);
    expect(res.armored).toBe(ARMORED);
    expect(res.fingerprint).toBe(FPR);
    expect(res.protection).toBe("session");
  });

  it("still fails closed when neither session nor vault knows the key", async () => {
    await expect(unlockVaultForUse(FPR)).rejects.toThrow(/not found in vault/i);
  });

  it("skipSession bypasses the cache — per-run-only unlock stays honest", async () => {
    sessionPut(FPR, ARMORED);
    // With the cache skipped there is nothing else to resolve from here.
    await expect(unlockVaultForUse(FPR, { skipSession: true })).rejects.toThrow(
      /not found in vault/i
    );
  });
});

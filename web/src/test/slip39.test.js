/**
 * SLIP-39-inspired share tests (GF(256) Shamir + official wordlist + RS1024).
 * Wordlist provenance: satoshilabs/slips slip-0039/wordlist.txt
 * SHA-256: bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3
 */
import { describe, expect, it } from "vitest";
import { combineSecret, splitSecret } from "../lib/slip39/gf256.js";
import { combineShares, splitShares } from "../lib/slip39/slip39.js";
import { WORDLIST } from "../lib/slip39/wordlist.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("SLIP-39 wordlist", () => {
  it("has exactly 1024 unique words", () => {
    expect(WORDLIST.length).toBe(1024);
    expect(new Set(WORDLIST).size).toBe(1024);
  });

  it("matches known first/last entries", () => {
    expect(WORDLIST[0]).toBe("academic");
    expect(WORDLIST[1023]).toBe("zero");
  });
});

describe("GF(256) Shamir", () => {
  it("round-trips with K-of-N", () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const shares = splitSecret(secret, 2, 3);
    expect(shares).toHaveLength(3);
    const recovered = combineSecret([shares[0], shares[2]]);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it("fails to recover with K-1 distinct wrong combination length check", () => {
    const secret = new Uint8Array(16).fill(7);
    const shares = splitSecret(secret, 3, 3);
    // Combining only 2 of 3 when threshold is 3 yields wrong secret
    const wrong = combineSecret([shares[0], shares[1]]);
    expect(Array.from(wrong)).not.toEqual(Array.from(secret));
  });
});

describe("mnemonic shares", () => {
  it("round-trips a 32-byte secret (native size)", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { mnemonics, enveloped } = await splitShares(secret, {
      threshold: 2,
      shares: 3,
    });
    expect(enveloped).toBe(false);
    expect(mnemonics).toHaveLength(3);
    for (const m of mnemonics) {
      expect(m.split(/\s+/).length).toBeGreaterThan(10);
    }
    const recovered = await combineShares([mnemonics[0], mnemonics[2]]);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it("rejects combining fewer than threshold shares", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(16));
    const { mnemonics } = await splitShares(secret, { threshold: 3, shares: 3 });
    await expect(combineShares([mnemonics[0], mnemonics[1]])).rejects.toThrow(
      /at least 3/i
    );
  });

  it("rejects non-16/32-byte masters with guidance", async () => {
    const pem = "-----BEGIN PRIVATE KEY-----\n" + "A".repeat(200) + "\n-----END PRIVATE KEY-----\n";
    const secret = new TextEncoder().encode(pem);
    await expect(
      splitShares(secret, { threshold: 2, shares: 3 })
    ).rejects.toThrow(/export scalar|symencrypt/i);
  });

  it("passphrase masks prevent recovery without it", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const { mnemonics } = await splitShares(secret, {
      threshold: 2,
      shares: 2,
      passphrase: "correct horse",
    });
    const wrong = await combineShares(mnemonics);
    expect(Array.from(wrong)).not.toEqual(Array.from(secret));
    const ok = await combineShares(mnemonics, { passphrase: "correct horse" });
    expect(Array.from(ok)).toEqual(Array.from(secret));
  });
});

describe("toolkit sss|blip39 recipe", () => {
  it("foreach|out emits N share artifacts", async () => {
    const { ast, validation } = compileRecipe(
      "random 32 | sss threshold=2 shares=3 | blip39 | foreach | out name=share"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const shares = arts.filter((a) => a.shareIndex);
    expect(shares.length).toBe(3);
    const recovered = await combineShares([
      shares[0].content,
      shares[1].content,
    ]);
    expect(recovered.length).toBe(32);
  }, 30_000);
});

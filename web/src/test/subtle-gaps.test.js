import { describe, expect, it } from "vitest";
import { bytesToHex } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import {
  instantiateFormatPick,
  KEY_FORMAT_PICKS,
} from "../lib/toolkit/registry.js";
import { compileRecipe, parseRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { deriveAsTarget } from "../lib/toolkit/webcrypto-ops.js";

describe("derive as=aes-kw", () => {
  it("maps aes-kw/256 to AES-KW deriveKey target", () => {
    expect(deriveAsTarget("aes-kw/256")).toEqual({
      derived: { name: "AES-KW", length: 256 },
      usages: ["wrapKey", "unwrapKey"],
      alg: "aes-kw/256",
      lengthBits: 256,
    });
  });
});

describe("hmac sugar", () => {
  it("parses hmac / hmac.verify as sign / verify", () => {
    const { ast, errors } = parseRecipe(
      "genkey hmac/sha256 | out $k\n\ninput | utf8 | hmac key=$k | out $tag"
    );
    expect(errors).toEqual([]);
    expect(ast?.chains?.[1]?.steps?.some((s) => s.name === "sign")).toBe(true);
    expect(serializeRecipe(ast)).toContain("| sign key=$k |");
    expect(serializeRecipe(ast)).not.toMatch(/\|\s*hmac\s/);

    const v = parseRecipe("input | hmac.verify key=$k signature=$tag");
    expect(v.errors).toEqual([]);
    expect(v.ast?.steps?.[1]?.name).toBe("verify");
  });
});

describe("key format picks", () => {
  it("lists formats and instantiates export/import", () => {
    expect(KEY_FORMAT_PICKS).toContain("jwk");
    expect(instantiateFormatPick("export", "spki")).toEqual({
      name: "export",
      params: { format: "spki" },
    });
    expect(instantiateFormatPick("import", "jwk").name).toBe("import");
  });
});

describe("wrap mode=aes-gcm", () => {
  it("round-trips a CEK", async () => {
    const { ast, validation } = compileRecipe(`genkey aes/256 | out $kek
genkey aes/256 | out $cek
wrap mode=aes-gcm key=$kek target=$cek | encode hex | out $wrapped
in $wrapped | decode hex | unwrap mode=aes-gcm key=$kek | export raw | encode hex`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    const wrapped = out.find((a) => /wrapped/i.test(a.filename || a.label || ""));
    expect(wrapped?.content?.length).toBeGreaterThan(32);
    const raw = out[out.length - 1];
    expect(raw.content).toMatch(/^[0-9a-f]{64}$/);
  }, 30_000);
});

describe("hkdf as=aes-kw/256 wrap", () => {
  it("derives KEK and wraps", async () => {
    const { ast, validation } = compileRecipe(`random 32 | hkdf 32 as=aes-kw/256 | out $kek
genkey aes/256 | out $cek
wrap key=$kek target=$cek | encode hex | out $wrapped
in $wrapped | decode hex | unwrap key=$kek | export raw | encode hex`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out.some((a) => /^[0-9a-f]{64}$/.test(a.content || ""))).toBe(true);
    void bytesToHex;
  }, 30_000);
});

describe("x25519 ecdh preset compiles", () => {
  it("compiles genkey x25519 | ecdh", () => {
    const { validation } = compileRecipe(`genkey x25519 | out $local
genkey x25519 | out $peer
ecdh private=$local peer=$peer | hkdf 32 as=aes/256 | out $cek`);
    expect(validation.ok).toBe(true);
  });
});

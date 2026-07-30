import { describe, expect, it } from "vitest";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import {
  normalizeHashName,
  parseCtrLength,
  parseGcmTagLength,
} from "../lib/toolkit/webcrypto-ops.js";

describe("MDN param helpers", () => {
  it("normalizes hash names", () => {
    expect(normalizeHashName("sha-384")).toBe("SHA-384");
    expect(normalizeHashName("SHA512")).toBe("SHA-512");
  });

  it("parses GCM tagLength and CTR length", () => {
    expect(parseGcmTagLength(128)).toBe(128);
    expect(parseGcmTagLength("96")).toBe(96);
    expect(() => parseGcmTagLength(80)).toThrow(/tagLength/);
    expect(parseCtrLength(0)).toBe(64);
    expect(parseCtrLength(32)).toBe(32);
    expect(() => parseCtrLength(200)).toThrow(/length/);
  });
});

describe("aes/192 + hmac/sha384", () => {
  it("generates and uses AES-192", async () => {
    const { ast, validation } = compileRecipe(
      `genkey aes/192 | out @cek
input | utf8 | aes-gcm key=@cek | out @ct
in @ct | aes-gcm -d key=@cek | utf8 | out @plain`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "aes192-ok" } },
    });
    const plain = arts.find((a) => /plain/i.test(a.filename || a.label || ""));
    expect(String(plain?.content)).toBe("aes192-ok");
  }, 30_000);

  it("HMAC-SHA-384 sign/verify", async () => {
    const { ast, validation } = compileRecipe(
      `genkey hmac/sha384 | out @mac
input | utf8 | out @msg
in @msg | sign key=@mac | out @tag
in @msg | verify key=@mac signature=@tag | out @ok`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "hmac384" } },
    });
    const ok = arts.find((a) => /ok/i.test(a.filename || a.label || ""));
    expect(String(ok?.content)).toMatch(/^true$/i);
  }, 30_000);
});

describe("RSA hash=", () => {
  it("round-trips RSA-PSS with SHA-384", async () => {
    const { ast, validation } = compileRecipe(
      `genkey rsa/2048 hash=sha-384 | out @rk
input | utf8 | out @msg
in @msg | sign key=@rk | out @sig
in @msg | verify key=@rk signature=@sig | out @ok`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "rsa-hash" } },
    });
    const ok = arts.find((a) => /ok/i.test(a.filename || a.label || ""));
    expect(String(ok?.content)).toMatch(/^true$/i);
  }, 60_000);
});

describe("OAEP label=", () => {
  it("encrypt/decrypt with matching label", async () => {
    const { ast, validation } = compileRecipe(
      `genkey rsa/2048 usage=encrypt | out @rk
input | utf8 | rsa-oaep key=@rk label=ctx | encode hex | out @ct
in @ct | decode hex | rsa-oaep -d key=@rk label=ctx | utf8 | out @plain`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "labeled" } },
    });
    const plain = arts.find((a) => /plain/i.test(a.filename || a.label || ""));
    expect(String(plain?.content)).toBe("labeled");
  }, 60_000);

  it("fails when label mismatches", async () => {
    const { ast } = compileRecipe(
      `genkey rsa/2048 usage=encrypt | out @rk
input | utf8 | rsa-oaep key=@rk label=a | encode hex | out @ct
in @ct | decode hex | rsa-oaep -d key=@rk label=b | utf8`
    );
    await expect(
      runRecipe(ast, { inputs: { text: { value: "x" } } })
    ).rejects.toThrow();
  }, 60_000);
});

describe("GCM tagLength + CTR length", () => {
  it("round-trips aes-gcm tagLength=96", async () => {
    const { ast, validation } = compileRecipe(
      `genkey aes/256 | out @cek
input | utf8 | aes-gcm key=@cek tagLength=96 | out @ct
in @ct | aes-gcm -d key=@cek tagLength=96 | utf8 | out @plain`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "short-tag" } },
    });
    const plain = arts.find((a) => /plain/i.test(a.filename || a.label || ""));
    expect(String(plain?.content)).toBe("short-tag");
  }, 30_000);

  it("round-trips aes-ctr length=32", async () => {
    const { ast, validation } = compileRecipe(
      `genkey aes/256 | out @cek
input | utf8 | aes-ctr key=@cek length=32 | out @ct
in @ct | aes-ctr -d key=@cek length=32 | utf8 | out @plain`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "ctr-len" } },
    });
    const plain = arts.find((a) => /plain/i.test(a.filename || a.label || ""));
    expect(String(plain?.content)).toBe("ctr-len");
  }, 30_000);
});

describe("PSS saltLength + ECDSA hash=", () => {
  it("RSA-PSS saltLength=16 round-trip", async () => {
    const { ast, validation } = compileRecipe(
      `genkey rsa/2048 | out @rk
input | utf8 | out @msg
in @msg | sign key=@rk saltLength=16 | out @sig
in @msg | verify key=@rk signature=@sig saltLength=16 | out @ok`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "pss-salt" } },
    });
    const ok = arts.find((a) => /ok/i.test(a.filename || a.label || ""));
    expect(String(ok?.content)).toMatch(/^true$/i);
  }, 60_000);

  it("ECDSA hash=sha-512 override on P-256", async () => {
    const { ast, validation } = compileRecipe(
      `genkey ec/p256 | out @kp
input | utf8 | out @msg
in @msg | sign key=@kp hash=sha-512 | out @sig
in @msg | verify key=@kp signature=@sig hash=sha-512 | out @ok`
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "ecdsa-hash" } },
    });
    const ok = arts.find((a) => /ok/i.test(a.filename || a.label || ""));
    expect(String(ok?.content)).toMatch(/^true$/i);
  }, 30_000);
});

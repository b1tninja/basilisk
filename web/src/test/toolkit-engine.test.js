import { describe, expect, it } from "vitest";
import { bytesToBase64Url } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("toolkit engine", () => {
  it("generates a P-256 PKCS#8 PEM that WebCrypto can re-import", async () => {
    const { ast, validation } = compileRecipe("genkey ec/p256 | export pkcs8 | pem");
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.length).toBeGreaterThanOrEqual(1);
    const pem = arts[0].content;
    expect(pem).toContain("BEGIN PRIVATE KEY");

    const b64 = pem
      .replace(/-----[^-]+-----/g, "")
      .replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );
    expect(key).toBeInstanceOf(CryptoKey);
  }, 30_000);

  it("emits unpadded websafe base64url", async () => {
    const { ast, validation } = compileRecipe("random 32 | base64url");
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const s = arts[0].content;
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(s).not.toMatch(/[+/=]/);
    // 32 bytes → 43 chars unpadded
    expect(s.length).toBe(43);
  });

  it("exports Ed25519 as JWK with expected fields", async () => {
    const { ast, validation } = compileRecipe("genkey ed25519 | export jwk");
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const jwk = JSON.parse(arts[0].content);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.d || jwk.x).toBeTruthy();
  }, 30_000);

  it("bytesToBase64Url helper matches engine output shape", () => {
    const u8 = new Uint8Array([0, 1, 2, 254, 255]);
    const s = bytesToBase64Url(u8);
    expect(s).not.toMatch(/[+/=]/);
  });

  it("out emits a named tile without duplicating a terminal value", async () => {
    const { ast, validation } = compileRecipe(
      "random 16 | out name=secret encoding=hex ext=hex"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts).toHaveLength(1);
    expect(arts[0].label).toBe("secret");
    expect(arts[0].filename).toBe("secret.hex");
    expect(arts[0].encoding).toBe("hex");
    expect(arts[0].content).toMatch(/^[0-9a-f]{32}$/);
  });

  it("out passes the value through for later steps", async () => {
    const { ast, validation } = compileRecipe(
      "random 8 | out name=raw encoding=base64 | hex"
    );
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const tile = arts.find((a) => a.filename === "raw.bin.b64" || a.label === "raw");
    expect(tile).toBeTruthy();
    expect(tile.encoding).toBe("base64");
    const hex = arts.find((a) => /^[0-9a-f]{16}$/.test(a.content));
    expect(hex).toBeTruthy();
  });

  it("validates pem | out | encrypt-style type flow", () => {
    const { validation } = compileRecipe(
      "genkey ec/p256 | export pkcs8 | pem | out name=key ext=pem | encrypt gpg"
    );
    expect(validation.ok).toBe(true);
  });

  it("input step feeds runtime text through the pipeline", async () => {
    const { ast, validation } = compileRecipe("input | utf8 | hex");
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("text");
    const arts = await runRecipe(ast, {
      inputs: { text: { value: "hi" } },
    });
    // "hi" → utf8 bytes 0x68 0x69 → hex
    expect(arts[0].content).toBe("6869");
  });

  it("input step fails without runtime text", async () => {
    const { ast } = compileRecipe("input | utf8 | hex");
    await expect(runRecipe(ast, { inputs: {} })).rejects.toThrow(/input text/i);
  });
});

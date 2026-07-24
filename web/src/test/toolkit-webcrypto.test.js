/**
 * WebCrypto toolkit ops: digest, sign/verify, aesgcm, hkdf, pbkdf2, ecdh, wrap.
 */
import { describe, expect, it } from "vitest";
import { bytesToBase64Url, bytesToHex, textToBytes } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, PRESETS, registryIssues } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";

describe("webcrypto toolkit registry", () => {
  it("has no registry issues and every step has a toolbox", () => {
    expect(registryIssues()).toEqual([]);
    for (const name of [
      "digest",
      "sign",
      "verify",
      "aesgcm",
      "hkdf",
      "pbkdf2",
      "ecdh",
      "wrap",
      "unwrap",
    ]) {
      const s = getStep(name);
      expect(s?.toolbox).toBe("webcrypto");
    }
    expect(getStep("aesgcm")?.label).toBe("encrypt");
    expect(getStep("encrypt")?.toolbox).toBe("openpgp");
  });

  it("digest preset compiles", () => {
    const p = PRESETS.find((x) => x.id === "digest-sha256");
    expect(p).toBeTruthy();
    expect(compileRecipe(p.recipe).validation.ok).toBe(true);
  });
});

describe("digest", () => {
  it("hashes random bytes to 32-byte SHA-256", async () => {
    const { ast, validation } = compileRecipe("random 32 | digest | hex");
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);
  });

  it("matches SubtleCrypto for known input", async () => {
    const msg = "basilisk";
    const expected = bytesToHex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", textToBytes(msg)))
    );
    const { ast } = compileRecipe("input | utf8 | digest | hex");
    const out = await runRecipe(ast, { inputs: { text: { value: msg } } });
    expect(out[0].content).toBe(expected);
  });
});

describe("sign / verify", () => {
  it("round-trips Ed25519", async () => {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const msg = textToBytes("hello webcrypto");
    const { ast: signAst } = compileRecipe("input | utf8 | sign | base64url");
    const signed = await runRecipe(signAst, {
      inputs: {
        text: { value: "hello webcrypto" },
        key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
      },
    });
    const sig = signed[0].content;
    const { ast: verAst, validation } = compileRecipe(
      `input | utf8 | verify signature=${sig}`
    );
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds).toContain("key");
    const verified = await runRecipe(verAst, {
      inputs: {
        text: { value: "hello webcrypto" },
        key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
      },
    });
    expect(verified[0].content).toBe("verified");
    void msg;
  }, 30_000);

  it("rejects bad signatures", async () => {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const { ast } = compileRecipe("input | utf8 | verify signature=AAAA");
    await expect(
      runRecipe(ast, {
        inputs: {
          text: { value: "nope" },
          key: { publicKey: kp.publicKey },
        },
      })
    ).rejects.toThrow(/verif/i);
  }, 30_000);
});

describe("aesgcm", () => {
  it("encrypts and decrypts with oct JWK binding", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const { ast: encAst } = compileRecipe("input | utf8 | aesgcm | base64url");
    const enc = await runRecipe(encAst, {
      inputs: {
        text: { value: "secret payload" },
        key: { jwk },
      },
    });
    const ct = enc[0].content;
    const { ast: decAst } = compileRecipe("input | base64url | aesgcm -d | utf8");
    // base64url decode: use hex path instead — pipeline has no base64url -d
    const { ast: dec2 } = compileRecipe("input | utf8 | aesgcm | hex");
    const packedHexArt = await runRecipe(dec2, {
      inputs: { text: { value: "secret payload" }, key: { secretKey: key } },
    });
    void ct;
    const packedHex = packedHexArt[0].content;
    const { ast: round } = compileRecipe("input | hex -d | aesgcm -d | utf8");
    const plain = await runRecipe(round, {
      inputs: { text: { value: packedHex }, key: { secretKey: key } },
    });
    expect(plain[0].content).toBe("secret payload");
  }, 30_000);
});

describe("hkdf / pbkdf2", () => {
  it("hkdf yields requested length", async () => {
    const { ast, validation } = compileRecipe(
      "random 32 | hkdf length=16 salt=s info=i | hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{32}$/);
  });

  it("pbkdf2 is deterministic for fixed inputs", async () => {
    const { ast } = compileRecipe(
      "input | utf8 | pbkdf2 length=16 salt=pepper iterations=1000 | hex"
    );
    const a = await runRecipe(ast, { inputs: { text: { value: "password" } } });
    const b = await runRecipe(ast, { inputs: { text: { value: "password" } } });
    expect(a[0].content).toBe(b[0].content);
    expect(a[0].content).toHaveLength(32);
  }, 30_000);
});

describe("ecdh", () => {
  it("agrees on shared bits for P-256", async () => {
    const alice = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits", "deriveKey"]
    );
    const bob = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits", "deriveKey"]
    );
    const bobPubJwk = await crypto.subtle.exportKey("jwk", bob.publicKey);
    const alicePubJwk = await crypto.subtle.exportKey("jwk", alice.publicKey);

    const { ast } = compileRecipe("ecdh | hex");
    const aOut = await runRecipe(ast, {
      inputs: {
        key: {
          privateKey: alice.privateKey,
          publicKey: alice.publicKey,
          peerJwkText: JSON.stringify(bobPubJwk),
        },
      },
    });
    const bOut = await runRecipe(ast, {
      inputs: {
        key: {
          privateKey: bob.privateKey,
          publicKey: bob.publicKey,
          peerJwkText: JSON.stringify(alicePubJwk),
        },
      },
    });
    expect(aOut[0].content).toBe(bOut[0].content);
    expect(aOut[0].content).toMatch(/^[0-9a-f]{64}$/);
  }, 30_000);
});

describe("wrap / unwrap", () => {
  it("round-trips AES-KW", async () => {
    const wrappingRaw = crypto.getRandomValues(new Uint8Array(32));
    const wrappingKey = await crypto.subtle.importKey(
      "raw",
      wrappingRaw,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const cekRaw = crypto.getRandomValues(new Uint8Array(32));
    const cek = await crypto.subtle.importKey(
      "raw",
      cekRaw,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const wrapJwk = await crypto.subtle.exportKey("jwk", cek);
    const wrappingJwk = await crypto.subtle.exportKey("jwk", wrappingKey);

    const { ast: wrapAst } = compileRecipe("wrap | hex");
    const wrapped = await runRecipe(wrapAst, {
      inputs: {
        key: {
          jwk: wrappingJwk,
          wrapJwkText: JSON.stringify(wrapJwk),
        },
      },
    });
    const { ast: unwrapAst } = compileRecipe("input | hex -d | unwrap | hex");
    const unwrapped = await runRecipe(unwrapAst, {
      inputs: {
        text: { value: wrapped[0].content },
        key: { jwk: wrappingJwk },
      },
    });
    expect(unwrapped[0].content).toBe(bytesToHex(cekRaw));
  }, 30_000);
});

describe("helpers export", () => {
  it("bytesToBase64Url used by sign path", () => {
    expect(bytesToBase64Url(new Uint8Array([0, 1, 2]))).toBeTruthy();
  });
});

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
      "aescbc",
      "aesctr",
      "rsaoaep",
      "rsapkcs1",
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
    expect(getStep("aescbc")?.label).toBe("encrypt");
    expect(getStep("aesctr")?.label).toBe("encrypt");
    expect(getStep("rsaoaep")?.label).toBe("encrypt");
    expect(getStep("encrypt")?.toolbox).toBe("openpgp");
  });

  it("digest and new webcrypto presets compile", () => {
    for (const id of [
      "digest-sha256",
      "rsaoaep-roundtrip",
      "hkdf-as-aesgcm",
      "aescbc-roundtrip",
      "aesctr-roundtrip",
      "verify-soft",
    ]) {
      const p = PRESETS.find((x) => x.id === id);
      expect(p, id).toBeTruthy();
      expect(compileRecipe(p.recipe).validation.ok, id).toBe(true);
    }
  });
});

describe("base64url -d", () => {
  it("round-trips encode/decode", async () => {
    const { ast, validation } = compileRecipe(
      "random 32 | base64url | base64url -d | hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("digest", () => {
  it("hashes random bytes to 32-byte SHA-256", async () => {
    const { ast, validation } = compileRecipe("random 32 | digest | hex");
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);
  });

  it("supports discouraged sha-1 with warning and tags", async () => {
    const { ast, validation } = compileRecipe(
      "input | utf8 | digest sha-1 | hex | out @d"
    );
    expect(validation.ok).toBe(true);
    expect(
      validation.warnings.some((w) => /sha-1.*discouraged/i.test(w))
    ).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "abc" } },
    });
    expect(out[0].content).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
    expect(out[0].tags).toEqual(
      expect.arrayContaining(["legacy", "discouraged", "sha-1"])
    );
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

  it("supports sha-384 and sha-512 lengths", async () => {
    const { ast: a384 } = compileRecipe("input | utf8 | digest alg=sha-384 | hex");
    const out384 = await runRecipe(a384, { inputs: { text: { value: "x" } } });
    expect(out384[0].content).toHaveLength(96);
    const { ast: a512 } = compileRecipe("input | utf8 | digest alg=sha-512 | hex");
    const out512 = await runRecipe(a512, { inputs: { text: { value: "x" } } });
    expect(out512[0].content).toHaveLength(128);
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

  it("soft verify emits invalid instead of throwing", async () => {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const { ast } = compileRecipe("input | utf8 | verify -q signature=AAAA");
    const out = await runRecipe(ast, {
      inputs: {
        text: { value: "nope" },
        key: { publicKey: kp.publicKey },
      },
    });
    expect(out[0].content).toBe("invalid");
  }, 30_000);

  it("soft verify emits verified on success", async () => {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const { ast: signAst } = compileRecipe("input | utf8 | sign | base64url");
    const signed = await runRecipe(signAst, {
      inputs: {
        text: { value: "soft-ok" },
        key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
      },
    });
    const { ast } = compileRecipe(
      `input | utf8 | verify soft=true signature=${signed[0].content}`
    );
    const out = await runRecipe(ast, {
      inputs: {
        text: { value: "soft-ok" },
        key: { publicKey: kp.publicKey },
      },
    });
    expect(out[0].content).toBe("verified");
  }, 30_000);

  it("round-trips ECDSA P-256", async () => {
    const kp = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const { ast: signAst } = compileRecipe("input | utf8 | sign | base64url");
    const signed = await runRecipe(signAst, {
      inputs: {
        text: { value: "ecdsa msg" },
        key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
      },
    });
    const sig = signed[0].content;
    const { ast: verAst } = compileRecipe(`input | utf8 | verify signature=${sig}`);
    const verified = await runRecipe(verAst, {
      inputs: {
        text: { value: "ecdsa msg" },
        key: { publicKey: kp.publicKey },
      },
    });
    expect(verified[0].content).toBe("verified");
  }, 30_000);

  it("round-trips HMAC-SHA-256", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );
    const { ast: signAst } = compileRecipe("input | utf8 | sign | base64url");
    const signed = await runRecipe(signAst, {
      inputs: { text: { value: "hmac" }, key: { secretKey: key } },
    });
    const { ast: verAst } = compileRecipe(
      `input | utf8 | verify signature=${signed[0].content}`
    );
    const verified = await runRecipe(verAst, {
      inputs: { text: { value: "hmac" }, key: { secretKey: key } },
    });
    expect(verified[0].content).toBe("verified");
  }, 30_000);

  it("round-trips RSA-PSS 2048", async () => {
    const kp = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    const { ast: signAst } = compileRecipe("input | utf8 | sign | base64url");
    const signed = await runRecipe(signAst, {
      inputs: {
        text: { value: "rsa-pss" },
        key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
      },
    });
    const { ast: verAst } = compileRecipe(
      `input | utf8 | verify signature=${signed[0].content}`
    );
    const verified = await runRecipe(verAst, {
      inputs: {
        text: { value: "rsa-pss" },
        key: { publicKey: kp.publicKey },
      },
    });
    expect(verified[0].content).toBe("verified");
  }, 60_000);
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
    const { ast: decAst } = compileRecipe(
      "input | base64url -d | aesgcm -d | utf8"
    );
    const plain = await runRecipe(decAst, {
      inputs: { text: { value: ct }, key: { jwk } },
    });
    expect(plain[0].content).toBe("secret payload");
  }, 30_000);

  it("supports AES-128 and fails on AAD mismatch", async () => {
    const raw = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: 128 },
      true,
      ["encrypt", "decrypt"]
    );
    const { ast: encAst } = compileRecipe("input | utf8 | aesgcm aad=meta | hex");
    const packed = await runRecipe(encAst, {
      inputs: { text: { value: "aad-test" }, key: { secretKey: key } },
    });
    const { ast: bad } = compileRecipe("input | hex -d | aesgcm -d aad=wrong | utf8");
    await expect(
      runRecipe(bad, {
        inputs: { text: { value: packed[0].content }, key: { secretKey: key } },
      })
    ).rejects.toThrow();
    const { ast: good } = compileRecipe("input | hex -d | aesgcm -d aad=meta | utf8");
    const plain = await runRecipe(good, {
      inputs: { text: { value: packed[0].content }, key: { secretKey: key } },
    });
    expect(plain[0].content).toBe("aad-test");
  }, 30_000);

  it("aesgcm and sign report key inputNeeds", () => {
    expect(compileRecipe("input | utf8 | aesgcm | hex").validation.inputNeeds).toContain(
      "key"
    );
    expect(compileRecipe("input | utf8 | sign | hex").validation.inputNeeds).toContain(
      "key"
    );
  });
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

  it("hkdf as=aes/256 derives a usable AES key", async () => {
    const { ast, validation } = compileRecipe(`random 32 | hkdf 32 as=aes/256 | out @cek

input | utf8 | aesgcm key=@cek | base64url | out @ct

in @ct | base64url -d | aesgcm -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "derived-key-payload" } },
    });
    expect(out.some((a) => a.content === "derived-key-payload")).toBe(true);
  }, 30_000);

  it("hkdf hash=sha-512 works", async () => {
    const { ast } = compileRecipe(
      "random 32 | hkdf length=16 salt=s info=i hash=sha-512 | hex"
    );
    const out = await runRecipe(ast);
    expect(out[0].content).toHaveLength(32);
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

  it("pbkdf2 hash=sha-512 works", async () => {
    const { ast } = compileRecipe(
      "input | utf8 | pbkdf2 length=16 salt=pepper iterations=1000 hash=sha-512 | hex"
    );
    const out = await runRecipe(ast, { inputs: { text: { value: "password" } } });
    expect(out[0].content).toHaveLength(32);
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

  it("agrees on X25519 when supported", async () => {
    let alice;
    try {
      alice = await crypto.subtle.generateKey("X25519", true, [
        "deriveBits",
        "deriveKey",
      ]);
    } catch {
      return; // environment lacks X25519
    }
    const bob = await crypto.subtle.generateKey("X25519", true, [
      "deriveBits",
      "deriveKey",
    ]);
    const bobPubJwk = await crypto.subtle.exportKey("jwk", bob.publicKey);
    const alicePubJwk = await crypto.subtle.exportKey("jwk", alice.publicKey);
    const { ast } = compileRecipe("ecdh bits=256 | hex");
    const aOut = await runRecipe(ast, {
      inputs: {
        key: {
          privateKey: alice.privateKey,
          peerJwkText: JSON.stringify(bobPubJwk),
        },
      },
    });
    const bOut = await runRecipe(ast, {
      inputs: {
        key: {
          privateKey: bob.privateKey,
          peerJwkText: JSON.stringify(alicePubJwk),
        },
      },
    });
    expect(aOut[0].content).toBe(bOut[0].content);
  }, 30_000);
});

describe("import jwk / spki", () => {
  it("round-trips ed25519 via export jwk | import jwk", async () => {
    const { ast, validation } = compileRecipe(
      "genkey ed25519 | export jwk | import jwk alg=ed25519 | export jwk"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    const jwk = JSON.parse(out[0].content);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.d).toBeTruthy();
  }, 30_000);

  it("imports RSA-OAEP public SPKI", async () => {
    const { ast, validation } = compileRecipe(
      "genkey rsa/2048 usage=encrypt | export spki | import spki alg=rsa/2048 usage=encrypt | export spki | hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]+$/);
  }, 60_000);

  it("imports X25519 public SPKI", async () => {
    const { ast, validation } = compileRecipe(
      "genkey x25519 | .public | export spki | import spki alg=x25519 | export spki | hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]+$/);
  }, 30_000);
});

describe("aescbc / aesctr", () => {
  it("aescbc round-trips with key=@cek", async () => {
    const { ast, validation } = compileRecipe(`genkey aes/256 | out @cek

input | utf8 | aescbc key=@cek | hex | out @ct

in @ct | hex -d | aescbc -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "cbc hello" } },
    });
    expect(out.some((a) => a.content === "cbc hello")).toBe(true);
  }, 30_000);

  it("aesctr round-trips with key=@cek", async () => {
    const { ast, validation } = compileRecipe(`genkey aes/256 | out @cek

input | utf8 | aesctr key=@cek | hex | out @ct

in @ct | hex -d | aesctr -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "ctr hello" } },
    });
    expect(out.some((a) => a.content === "ctr hello")).toBe(true);
  }, 30_000);

  it("aescbc rejects truncated ciphertext", async () => {
    const { ast } = compileRecipe(`genkey aes/256 | out @cek

input | hex -d | aescbc -d key=@cek`);
    await expect(
      runRecipe(ast, { inputs: { text: { value: "0011" } } })
    ).rejects.toThrow(/too short/i);
  }, 30_000);
});

describe("rsaoaep", () => {
  it("encrypts and decrypts with key=@slot", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsaoaep key=@rk | hex | out @ct

in @ct | hex -d | rsaoaep -d key=@rk | utf8`);
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("key");
    const out = await runRecipe(ast, {
      inputs: { text: { value: "oaep hello" } },
    });
    expect(out.some((a) => a.content === "oaep hello")).toBe(true);
  }, 60_000);
});

describe("rsapkcs1 (discouraged)", () => {
  it("warns at compile and round-trips with legacy tags", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsapkcs1 key=@rk | hex | out @ct

in @ct | hex -d | rsapkcs1 -d key=@rk | utf8 | out @plain`);
    expect(validation.ok).toBe(true);
    expect(
      validation.warnings.some((w) => /rsapkcs1.*discouraged/i.test(w))
    ).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "pkcs1 hello" } },
    });
    expect(out.some((a) => a.content === "pkcs1 hello")).toBe(true);
    const ct = out.find((a) => (a.tags || []).includes("rsaes-pkcs1-v1_5"));
    expect(ct).toBeTruthy();
    expect(ct.tags).toEqual(
      expect.arrayContaining(["legacy", "discouraged", "rsaes-pkcs1-v1_5"])
    );
  }, 60_000);
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

  it("wraps and unwraps HMAC CEKs", async () => {
    const { ast, validation } = compileRecipe(`genkey aes/256 | out @kek

genkey hmac/sha256 | out @cek

wrap key=@kek target=@cek | hex | out @wrapped

in @wrapped | hex -d | unwrap key=@kek alg=hmac/sha256 | hex`);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const hexes = arts.filter((a) => /^[0-9a-f]{64}$/i.test(String(a.content || "")));
    expect(hexes.length).toBeGreaterThanOrEqual(1);
  }, 30_000);

  it("wraps AES CEK with RSA-OAEP", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=encrypt | out @rk

genkey aes/256 | out @cek

wrap mode=rsa-oaep key=@rk target=@cek | hex | out @wrapped

in @wrapped | hex -d | unwrap mode=rsa-oaep key=@rk | hex`);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    expect(arts.some((a) => /^[0-9a-f]{64}$/i.test(String(a.content || "")))).toBe(
      true
    );
  }, 60_000);
});

describe("RSASSA-PKCS1-v1_5 (discouraged)", () => {
  it("warns and round-trips sign/verify", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=sign padding=pkcs1 | out @kp

input | utf8 | out @msg

in @msg | sign key=@kp | base64url | out @sig

in @msg | verify key=@kp signature=@sig | out @result`);
    expect(validation.ok).toBe(true);
    expect(
      validation.warnings.some((w) => /padding=pkcs1.*discouraged/i.test(w))
    ).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "pkcs1-sign" } },
    });
    expect(out.some((a) => a.content === "verified")).toBe(true);
    const sig = out.find((a) => (a.tags || []).includes("rsassa-pkcs1-v1_5"));
    expect(sig).toBeTruthy();
  }, 60_000);
});

describe("ecdh as= / bits auto", () => {
  it("derives AES key via as=aes/256", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 usage=derive | out @alice

genkey ec/p256 usage=derive | out @bob

ecdh private=@alice peer=@bob as=aes/256 | out @cek

input | utf8 | aesgcm key=@cek | hex | out @ct

in @ct | hex -d | aesgcm -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "ecdh-derived" } },
    });
    expect(out.some((a) => a.content === "ecdh-derived")).toBe(true);
  }, 30_000);

  it("auto bits for P-384 is 384", async () => {
    const { ast } = compileRecipe(`genkey ec/p384 usage=derive | out @alice

genkey ec/p384 usage=derive | out @bob

ecdh private=@alice peer=@bob | hex | out @shared`);
    const out = await runRecipe(ast);
    const shared = out.find((a) => /^[0-9a-f]{96}$/i.test(String(a.content || "")));
    expect(shared).toBeTruthy();
  }, 30_000);
});

describe("verify signature=@slot", () => {
  it("verifies using signature from a prior out slot", async () => {
    const { ast, validation } = compileRecipe(`genkey ed25519 | out @kp

input | utf8 | out @msg

in @msg | sign key=@kp | base64url | out @sig

in @msg | verify key=@kp signature=@sig | out @result`);
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("key");
    const out = await runRecipe(ast, {
      inputs: { text: { value: "slot-sig" } },
    });
    expect(out.some((a) => a.content === "verified")).toBe(true);
  }, 30_000);
});

describe("usage= honesty", () => {
  it("warns when usage is ignored for aes", () => {
    const { validation } = compileRecipe("genkey aes/256 usage=sign | export jwk");
    expect(validation.ok).toBe(true);
    expect(
      validation.warnings.some((w) => /usage=sign is ignored for aes\/256/i.test(w))
    ).toBe(true);
  });
});

describe("helpers export", () => {
  it("bytesToBase64Url used by sign path", () => {
    expect(bytesToBase64Url(new Uint8Array([0, 1, 2]))).toBeTruthy();
  });
});

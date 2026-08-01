/**
 * WebCrypto toolkit ops: digest, sign/verify, aes-gcm, hkdf, pbkdf2, ecdh, wrap.
 */
import { describe, expect, it } from "vitest";
import { bytesToBase64Url, bytesToHex, textToBytes } from "../lib/toolkit/encode.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, PRESETS, registryIssues } from "../lib/toolkit/recipe.js";
import { getStep } from "../lib/toolkit/registry.js";
import {
  boundHashMessage,
  ED25519_HASH_MESSAGE,
  jwkAlgHashMessage,
} from "../lib/toolkit/webcrypto-ops.js";

describe("webcrypto toolkit registry", () => {
  it("has no registry issues and every step has a toolbox", () => {
    expect(registryIssues()).toEqual([]);
    for (const name of [
      "digest",
      "sign",
      "verify",
      "aes-gcm",
      "aes-cbc",
      "aes-ctr",
      "rsa-oaep",
      "rsa-pkcs1",
      "hkdf",
      "pbkdf2",
      "ecdh",
      "wrap",
      "unwrap",
    ]) {
      const s = getStep(name);
      expect(s?.toolbox).toBe("webcrypto");
    }
    expect(getStep("aes-gcm")?.label).toBeUndefined();
    expect(getStep("aes-gcm")?.toolbox).toBe("webcrypto");
    expect(getStep("aes-cbc")?.toolbox).toBe("webcrypto");
    expect(getStep("rsa-oaep")?.toolbox).toBe("webcrypto");
    expect(getStep("gpg.encrypt")?.toolbox).toBe("openpgp");
    // Bare encrypt is parse sugar (not a registry step); OpenPGP stays gpg.encrypt.
    expect(getStep("encrypt")).toBeNull();
  });

  it("digest and new webcrypto presets compile", () => {
    for (const id of [
      "digest-sha256",
      "rsa-oaep-roundtrip",
      "aes-gcm-roundtrip",
      "pbkdf2-aes-gcm",
      "hkdf-as-aes-gcm",
      "webauthn-prf-aes-gcm",
      "aes-cbc-roundtrip",
      "aes-ctr-roundtrip",
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
      "random 32 | base64url | base64url -d | encode hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("digest", () => {
  it("hashes random bytes to 32-byte SHA-256", async () => {
    const { ast, validation } = compileRecipe("random 32 | digest | encode hex");
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{64}$/);
  });

  it("supports discouraged sha-1 with warning and tags", async () => {
    const { ast, validation } = compileRecipe(
      "input | utf8 | digest sha-1 | encode hex | out @d"
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
    const { ast } = compileRecipe("input | utf8 | digest | encode hex");
    const out = await runRecipe(ast, { inputs: { text: { value: msg } } });
    expect(out[0].content).toBe(expected);
  });

  it("supports sha-384 and sha-512 lengths", async () => {
    const { ast: a384 } = compileRecipe("input | utf8 | digest alg=sha-384 | encode hex");
    const out384 = await runRecipe(a384, { inputs: { text: { value: "x" } } });
    expect(out384[0].content).toHaveLength(96);
    const { ast: a512 } = compileRecipe("input | utf8 | digest alg=sha-512 | encode hex");
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
    expect(verified[0].content).toBe("true");
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

  it("soft verify emits false instead of throwing", async () => {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const { ast } = compileRecipe("input | utf8 | verify -q signature=AAAA");
    const out = await runRecipe(ast, {
      inputs: {
        text: { value: "nope" },
        key: { publicKey: kp.publicKey },
      },
    });
    expect(out[0].content).toBe("false");
  }, 30_000);

  it("soft verify emits true on success", async () => {
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
    expect(out[0].content).toBe("true");
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
    expect(verified[0].content).toBe("true");
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
    expect(verified[0].content).toBe("true");
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
    expect(verified[0].content).toBe("true");
  }, 60_000);
});

// WebCrypto binds the digest into the key handle for RSA and HMAC — it lives in
// `key.algorithm.hash`, and the sign/verify params carry no field that could
// override it. SubtleCrypto does not complain about a hash it was handed and
// cannot use; it discards it. So a `hash=` that disagrees with the handle used
// to produce a signature under a digest the author never chose, silently, which
// is the worst direction for this to fail in. It is now refused by name.
describe("sign / verify: a hash= the key cannot honour", () => {
  /** @param {Promise<unknown>} p */
  async function messageOf(p) {
    try {
      await p;
      return null;
    } catch (err) {
      return String(err?.message || err);
    }
  }

  it("refuses a hash= that contradicts an RSA-PSS key, naming both digests", async () => {
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
    const inputs = {
      text: { value: "rsa-pss" },
      key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
    };
    const { ast } = compileRecipe("input | utf8 | sign hash=sha-512 | base64url");
    const msg = await messageOf(runRecipe(ast, { inputs }));
    expect(msg).toBe(boundHashMessage("RSA-PSS", "SHA-256", "SHA-512"));
    // Both the digest in force and the one asked for are in the sentence, and
    // the remedy is the parameter to move, not "unsupported".
    expect(msg).toContain("SHA-256");
    expect(msg).toContain("sha-512");

    // The same digest is not a conflict — it proceeds, silently.
    const { ast: same } = compileRecipe("input | utf8 | sign hash=sha-256 | base64url");
    const signed = await runRecipe(same, { inputs });
    expect(signed[0].content).toMatch(/^[A-Za-z0-9_-]+$/);
  }, 60_000);

  it("refuses a hash= that contradicts an HMAC key, on verify as well as sign", async () => {
    const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
      "sign",
      "verify",
    ]);
    const inputs = { text: { value: "hmac" }, key: { secretKey: key } };
    const { ast: signAst } = compileRecipe("input | utf8 | sign hash=sha-512 | base64url");
    expect(await messageOf(runRecipe(signAst, { inputs }))).toBe(
      boundHashMessage("HMAC", "SHA-256", "SHA-512")
    );

    const { ast: plain } = compileRecipe("input | utf8 | sign | base64url");
    const sig = (await runRecipe(plain, { inputs }))[0].content;
    // `-q` softens a bad signature, not a recipe that cannot mean what it says:
    // before this, the mismatched hash was dropped and verify answered `true`.
    const { ast: verAst } = compileRecipe(
      `input | utf8 | verify hash=sha-512 signature=${sig} -q`
    );
    expect(await messageOf(runRecipe(verAst, { inputs }))).toBe(
      boundHashMessage("HMAC", "SHA-256", "SHA-512")
    );
  }, 60_000);

  it("refuses hash= on Ed25519, which has no digest to pick", async () => {
    const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const inputs = {
      text: { value: "ed" },
      key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
    };
    const { ast } = compileRecipe("input | utf8 | sign hash=sha-256 | base64url");
    expect(await messageOf(runRecipe(ast, { inputs }))).toBe(ED25519_HASH_MESSAGE);
  }, 30_000);

  it("still lets ECDSA choose its digest — there the hash is a call-time param", async () => {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const inputs = {
      text: { value: "ecdsa" },
      key: { privateKey: kp.privateKey, publicKey: kp.publicKey },
    };
    const { ast } = compileRecipe("input | utf8 | sign hash=sha-512 | base64url");
    const sig = (await runRecipe(ast, { inputs }))[0].content;
    const { ast: same } = compileRecipe(
      `input | utf8 | verify hash=sha-512 signature=${sig} -q`
    );
    expect((await runRecipe(same, { inputs }))[0].content).toBe("true");
    // Proof the override reached the math rather than being cosmetic.
    const { ast: other } = compileRecipe(
      `input | utf8 | verify hash=sha-256 signature=${sig} -q`
    );
    expect((await runRecipe(other, { inputs }))[0].content).toBe("false");
  }, 30_000);
});

describe("import hash=: bound at import, so honoured there", () => {
  const rsaKey = () =>
    crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );

  it("refuses a hash= that contradicts the JWK's own alg member", async () => {
    const kp = await rsaKey();
    const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    expect(jwk.alg).toBe("PS256");
    const { ast } = compileRecipe("input | import jwk alg=rsa/2048 hash=sha-512 | out @k");
    let msg = null;
    try {
      await runRecipe(ast, { inputs: { text: { value: JSON.stringify(jwk) } } });
    } catch (err) {
      msg = String(err?.message || err);
    }
    expect(msg).toBe(jwkAlgHashMessage("PS256", "SHA-256", "SHA-512"));
  }, 60_000);

  it("honours hash= on a JWK that names no digest of its own", async () => {
    const kp = await rsaKey();
    const jwk = { ...(await crypto.subtle.exportKey("jwk", kp.privateKey)) };
    delete jwk.alg;
    const { ast } = compileRecipe("input | import jwk alg=rsa/2048 hash=sha-512 | out @k");
    const out = await runRecipe(ast, { inputs: { text: { value: JSON.stringify(jwk) } } });
    expect(JSON.parse(out[0].content).alg).toBe("PS512");
  }, 60_000);

  it("keeps the JWK's alg when no hash= is written (auto)", async () => {
    const kp = await rsaKey();
    const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const { ast } = compileRecipe("input | import jwk alg=rsa/2048 | out @k");
    const out = await runRecipe(ast, { inputs: { text: { value: JSON.stringify(jwk) } } });
    expect(JSON.parse(out[0].content).alg).toBe("PS256");
  }, 60_000);
});

describe("aes-gcm", () => {
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
    const { ast: encAst } = compileRecipe("input | utf8 | aes-gcm | base64url");
    const enc = await runRecipe(encAst, {
      inputs: {
        text: { value: "secret payload" },
        key: { jwk },
      },
    });
    const ct = enc[0].content;
    const { ast: decAst } = compileRecipe(
      "input | base64url -d | aes-gcm -d | utf8"
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
    const { ast: encAst } = compileRecipe("input | utf8 | aes-gcm aad=meta | encode hex");
    const packed = await runRecipe(encAst, {
      inputs: { text: { value: "aad-test" }, key: { secretKey: key } },
    });
    const { ast: bad } = compileRecipe("input | decode hex | aes-gcm -d aad=wrong | utf8");
    await expect(
      runRecipe(bad, {
        inputs: { text: { value: packed[0].content }, key: { secretKey: key } },
      })
    ).rejects.toThrow();
    const { ast: good } = compileRecipe("input | decode hex | aes-gcm -d aad=meta | utf8");
    const plain = await runRecipe(good, {
      inputs: { text: { value: packed[0].content }, key: { secretKey: key } },
    });
    expect(plain[0].content).toBe("aad-test");
  }, 30_000);

  it("aes-gcm and sign report key inputNeeds", () => {
    expect(compileRecipe("input | utf8 | aes-gcm | encode hex").validation.inputNeeds).toContain(
      "key"
    );
    expect(compileRecipe("input | utf8 | sign | encode hex").validation.inputNeeds).toContain(
      "key"
    );
  });
});

describe("hkdf / pbkdf2", () => {
  it("hkdf yields requested length", async () => {
    const { ast, validation } = compileRecipe(
      "random 32 | hkdf length=16 salt=s info=i | encode hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]{32}$/);
  });

  it("hkdf as=aes/256 derives a usable AES key", async () => {
    const { ast, validation } = compileRecipe(`random 32 | hkdf 32 as=aes/256 | out @cek

input | utf8 | aes-gcm key=@cek | base64url | out @ct

in @ct | base64url -d | aes-gcm -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "derived-key-payload" } },
    });
    expect(out.some((a) => a.content === "derived-key-payload")).toBe(true);
  }, 30_000);

  it("hkdf hash=sha-512 works", async () => {
    const { ast } = compileRecipe(
      "random 32 | hkdf length=16 salt=s info=i hash=sha-512 | encode hex"
    );
    const out = await runRecipe(ast);
    expect(out[0].content).toHaveLength(32);
  });

  it("pbkdf2 is deterministic for fixed inputs", async () => {
    const { ast } = compileRecipe(
      "input | utf8 | pbkdf2 length=16 salt=pepper iterations=1000 | encode hex"
    );
    const a = await runRecipe(ast, { inputs: { text: { value: "password" } } });
    const b = await runRecipe(ast, { inputs: { text: { value: "password" } } });
    expect(a[0].content).toBe(b[0].content);
    expect(a[0].content).toHaveLength(32);
  }, 30_000);

  it("pbkdf2 hash=sha-512 works", async () => {
    const { ast } = compileRecipe(
      "input | utf8 | pbkdf2 length=16 salt=pepper iterations=1000 hash=sha-512 | encode hex"
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

    const { ast } = compileRecipe("ecdh | encode hex");
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
    const { ast } = compileRecipe("ecdh bits=256 | encode hex");
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
      "genkey rsa/2048 usage=encrypt | export spki | import spki alg=rsa/2048 usage=encrypt | export spki | encode hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]+$/);
  }, 60_000);

  it("imports X25519 public SPKI", async () => {
    const { ast, validation } = compileRecipe(
      "genkey x25519 | :public | export spki | import spki alg=x25519 | export spki | encode hex"
    );
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    expect(out[0].content).toMatch(/^[0-9a-f]+$/);
  }, 30_000);

  it("round-trips armored public and private PEM", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 | tee
  - :public | export spki | pem | out @pub
| export pkcs8 | pem | out @priv

in @pub | der | import spki alg=ec/p256 | export spki | pem | out @pub2

in @priv | der | import pkcs8 alg=ec/p256 | export pkcs8 | pem | out @priv2`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast);
    const pub = out.find((a) => /@pub2|pub2/i.test(a.label || a.filename || ""));
    const priv = out.find((a) => /@priv2|priv2/i.test(a.label || a.filename || ""));
    const pubText = String(
      pub?.content || out.find((a) => /BEGIN PUBLIC KEY/.test(a.content))?.content || ""
    );
    const privText = String(
      priv?.content ||
        out.find((a) => /BEGIN PRIVATE KEY/.test(a.content))?.content ||
        ""
    );
    expect(pubText).toMatch(/BEGIN PUBLIC KEY/);
    expect(privText).toMatch(/BEGIN PRIVATE KEY/);
    expect(pubText).not.toMatch(/BEGIN PRIVATE KEY/);
  }, 30_000);
});

describe("aes-cbc / aes-ctr", () => {
  it("aes-cbc round-trips with key=@cek", async () => {
    const { ast, validation } = compileRecipe(`genkey aes/256 | out @cek

input | utf8 | aes-cbc key=@cek | encode hex | out @ct

in @ct | decode hex | aes-cbc -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "cbc hello" } },
    });
    expect(out.some((a) => a.content === "cbc hello")).toBe(true);
  }, 30_000);

  it("aes-ctr round-trips with key=@cek", async () => {
    const { ast, validation } = compileRecipe(`genkey aes/256 | out @cek

input | utf8 | aes-ctr key=@cek | encode hex | out @ct

in @ct | decode hex | aes-ctr -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "ctr hello" } },
    });
    expect(out.some((a) => a.content === "ctr hello")).toBe(true);
  }, 30_000);

  it("aes-cbc rejects truncated ciphertext", async () => {
    const { ast } = compileRecipe(`genkey aes/256 | out @cek

input | decode hex | aes-cbc -d key=@cek`);
    await expect(
      runRecipe(ast, { inputs: { text: { value: "0011" } } })
    ).rejects.toThrow(/too short/i);
  }, 30_000);
});

describe("rsa-oaep", () => {
  it("encrypts and decrypts with key=@slot", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-oaep key=@rk | encode hex | out @ct

in @ct | decode hex | rsa-oaep -d key=@rk | utf8`);
    expect(validation.ok).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("key");
    const out = await runRecipe(ast, {
      inputs: { text: { value: "oaep hello" } },
    });
    expect(out.some((a) => a.content === "oaep hello")).toBe(true);
  }, 60_000);
});

describe("rsa-pkcs1 (discouraged)", () => {
  it("warns at compile and round-trips with legacy tags", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-pkcs1 key=@rk | encode hex | out @ct

in @ct | decode hex | rsa-pkcs1 -d key=@rk | utf8 | out @plain`);
    expect(validation.ok).toBe(true);
    expect(
      validation.warnings.some((w) => /rsa-pkcs1.*discouraged/i.test(w))
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

    const { ast: wrapAst } = compileRecipe("wrap | encode hex");
    const wrapped = await runRecipe(wrapAst, {
      inputs: {
        key: {
          jwk: wrappingJwk,
          wrapJwkText: JSON.stringify(wrapJwk),
        },
      },
    });
    const { ast: unwrapAst } = compileRecipe(
      "input | decode hex | unwrap | export raw | encode hex"
    );
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

wrap key=@kek target=@cek | encode hex | out @wrapped

in @wrapped | decode hex | unwrap key=@kek alg=hmac/sha256 | export raw | encode hex`);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast);
    const hexes = arts.filter((a) => /^[0-9a-f]{64}$/i.test(String(a.content || "")));
    expect(hexes.length).toBeGreaterThanOrEqual(1);
  }, 30_000);

  it("wraps AES CEK with RSA-OAEP", async () => {
    const { ast, validation } = compileRecipe(`genkey rsa/2048 usage=encrypt | out @rk

genkey aes/256 | out @cek

wrap mode=rsa-oaep key=@rk target=@cek | encode hex | out @wrapped

in @wrapped | decode hex | unwrap mode=rsa-oaep key=@rk | export raw | encode hex`);
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
    expect(out.some((a) => a.content === "true")).toBe(true);
    const sig = out.find((a) => (a.tags || []).includes("rsassa-pkcs1-v1_5"));
    expect(sig).toBeTruthy();
  }, 60_000);
});

describe("ecdh as= / bits auto", () => {
  it("derives AES key via as=aes/256", async () => {
    const { ast, validation } = compileRecipe(`genkey ec/p256 usage=derive | out @alice

genkey ec/p256 usage=derive | out @bob

ecdh private=@alice peer=@bob as=aes/256 | out @cek

input | utf8 | aes-gcm key=@cek | encode hex | out @ct

in @ct | decode hex | aes-gcm -d key=@cek | utf8`);
    expect(validation.ok).toBe(true);
    const out = await runRecipe(ast, {
      inputs: { text: { value: "ecdh-derived" } },
    });
    expect(out.some((a) => a.content === "ecdh-derived")).toBe(true);
  }, 30_000);

  it("auto bits for P-384 is 384", async () => {
    const { ast } = compileRecipe(`genkey ec/p384 usage=derive | out @alice

genkey ec/p384 usage=derive | out @bob

ecdh private=@alice peer=@bob | encode hex | out @shared`);
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
    expect(out.some((a) => a.content === "true")).toBe(true);
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

/**
 * JOSE ops — RFC 7515 test vectors, round trips, and the refusals.
 *
 * The vectors matter more than the round trips do: a sign→verify pair that
 * agrees with itself proves only that the two halves share a bug. RFC 7515
 * Appendix A pins the wire format against an outside authority, which is what
 * catches a base64url variant, a signing-input separator, or an ECDSA
 * signature encoded as DER instead of raw r‖s.
 *
 * Note what cannot be pinned that way: A.1's compact serialization embeds a
 * header with CRLF and specific member order (`{"typ":"JWT",\r\n "alg":…}`),
 * which `JSON.stringify` will never reproduce. So the vectors are used for
 * *verification* — the direction that consumes bytes someone else produced —
 * and signing is checked by round trip. That is not a gap in coverage; it is
 * the only honest reading of a vector whose exact header is unreproducible.
 */
import { describe, expect, it } from "vitest";
import {
  claimTiming,
  decodeCompact,
  execJoseDecode,
  execJoseDecrypt,
  execJoseEncrypt,
  execJoseSign,
  execJoseVerify,
  joseAlgForKey,
} from "../lib/toolkit/jose-ops.js";

/* ─────────────────────────────── fixtures ─────────────────────────────── */

/** RFC 7515 A.1 — HS256. */
const A1 = {
  jwk: {
    kty: "oct",
    k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  },
  token:
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
};

/** RFC 7515 A.3 — ES256. */
const A3 = {
  jwk: {
    kty: "EC",
    crv: "P-256",
    x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    d: "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
  },
  token:
    "eyJhbGciOiJFUzI1NiJ9" +
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
};

/** A pipeline value that looks like a slot holding one CryptoKey. */
function keyValue(key, which) {
  return { type: "key", data: key, meta: { which } };
}

/** Bindings whose single slot `@k` resolves to `value`. */
function slotBindings(value, ref = "@k") {
  return { resolveSlot: (r) => (String(r) === ref ? value : null) };
}

function textValue(s) {
  return { type: "text", data: s, meta: {} };
}

async function importHs(jwk, hash = "SHA-256") {
  return crypto.subtle.importKey("jwk", { ...jwk, ext: true }, { name: "HMAC", hash }, true, [
    "sign",
    "verify",
  ]);
}

async function importEs(jwk, curve = "P-256", priv = true) {
  const alg = { name: "ECDSA", namedCurve: curve };
  if (priv) {
    return crypto.subtle.importKey("jwk", { ...jwk, ext: true }, alg, true, ["sign"]);
  }
  const { d, ...pub } = jwk;
  return crypto.subtle.importKey("jwk", { ...pub, ext: true }, alg, true, ["verify"]);
}

/** Both halves of a generated pair, as one slot value. */
async function pairValue(alg) {
  const pair = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  return { type: "keypair", data: pair, meta: {} };
}

/* ────────────────────────────── RFC vectors ────────────────────────────── */

describe("RFC 7515 test vectors", () => {
  it("A.1 — verifies the HS256 example against the RFC's own key", async () => {
    const key = await importHs(A1.jwk);
    const out = await execJoseVerify(
      textValue(A1.token),
      // The vector's `exp` is 2011; enforcing it would fail a signature check
      // that in fact succeeded, which is exactly the distinction the message
      // in that error draws.
      { key: "@k", expiry: "ignore" },
      slotBindings(keyValue(key, "secret"))
    );
    expect(out.meta.jose.verified).toBe(true);
    expect(out.meta.jose.header).toEqual({ typ: "JWT", alg: "HS256" });
    expect(out.meta.jose.claims).toEqual({
      iss: "joe",
      exp: 1300819380,
      "http://example.com/is_root": true,
    });
  });

  it("A.1 — a single flipped payload character fails the check", async () => {
    const key = await importHs(A1.jwk);
    const [h, p, s] = A1.token.split(".");
    const tampered = `${h}.${p.replace(/.$/, (c) => (c === "Q" ? "R" : "Q"))}.${s}`;
    await expect(
      execJoseVerify(
        textValue(tampered),
        { key: "@k", expiry: "ignore" },
        slotBindings(keyValue(key, "secret"))
      )
    ).rejects.toThrow(/verification failed|not a JSON object|base64url/);
  });

  it("A.3 — verifies the ES256 example (raw r‖s, not DER)", async () => {
    // The signature in A.3 is 64 bytes of concatenated r and s. A DER-encoded
    // ECDSA signature of the same values would be ~70 bytes and would fail
    // here, which is the point of keeping this vector.
    const pub = await importEs(A3.jwk, "P-256", false);
    const out = await execJoseVerify(
      textValue(A3.token),
      { key: "@k", expiry: "ignore" },
      slotBindings(keyValue(pub, "public"))
    );
    expect(out.meta.jose.verified).toBe(true);
    expect(out.meta.jose.header).toEqual({ alg: "ES256" });
    expect(out.meta.jose.claims.iss).toBe("joe");
  });

  it("A.3 — rejects the vector under the wrong key", async () => {
    const other = await pairValue({ name: "ECDSA", namedCurve: "P-256" });
    await expect(
      execJoseVerify(
        textValue(A3.token),
        { key: "@k", expiry: "ignore" },
        slotBindings(other)
      )
    ).rejects.toThrow(/verification failed/);
  });

  it("decodes both vectors without a key at all", async () => {
    for (const v of [A1, A3]) {
      const out = execJoseDecode(textValue(v.token));
      expect(out.meta.jose.verified).toBe(false);
      expect(out.meta.jose.claims.iss).toBe("joe");
      // The marker is in the emitted body too, not only in meta — a copied
      // artifact must carry the caveat with it.
      expect(JSON.parse(out.data).verified).toBe(false);
    }
  });
});

/* ──────────────────────────── decode semantics ──────────────────────────── */

describe("jose.decode", () => {
  it("labels every decoded token unverified, and leads with it", () => {
    const out = execJoseDecode(textValue(A1.token));
    const body = JSON.parse(out.data);
    expect(Object.keys(body)[0]).toBe("verified");
    expect(body.verified).toBe(false);
  });

  it("does not mark public claims sensitive — masking them would hide the answer", () => {
    const out = execJoseDecode(textValue(A1.token));
    expect(out.meta.sensitive).toBe(false);
  });

  it('reads an alg="none" token rather than refusing it', () => {
    // Inspection is exactly where an unsecured JWS should be visible. The
    // refusal belongs in `jose.verify`, and is asserted there.
    const header = btoa(JSON.stringify({ alg: "none" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "nobody" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const out = execJoseDecode(textValue(`${header}.${payload}.`));
    expect(out.meta.jose.header.alg).toBe("none");
    expect(out.meta.jose.claims).toEqual({ sub: "nobody" });
  });

  it("keeps a non-JSON JWS payload as text instead of inventing claims", () => {
    const seg = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const out = execJoseDecode(
      textValue(`${seg('{"alg":"HS256"}')}.${seg("not json at all")}.AAAA`)
    );
    expect(out.meta.jose.claims).toBeNull();
    expect(out.meta.jose.payloadText).toBe("not json at all");
  });

  it("recognizes a JWE by its five segments and says the payload is encrypted", () => {
    const seg = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const out = execJoseDecode(
      textValue(`${seg('{"alg":"dir","enc":"A256GCM"}')}..AAAA.BBBB.CCCC`)
    );
    expect(out.meta.jose.kind).toBe("jwe");
    expect(JSON.parse(out.data).payload).toMatch(/encrypted/);
  });

  it("rejects a serialization with the wrong segment count", () => {
    expect(() => decodeCompact("a.b")).toThrow(/3 segments.*or JWE.*got 2/s);
    expect(() => decodeCompact("")).toThrow(/empty token/);
  });

  it("rejects segments outside the base64url alphabet", () => {
    expect(() => decodeCompact("aGVsbG8=.b.c")).toThrow(/base64url/);
  });
});

/* ───────────────────────────── round trips ───────────────────────────── */

const ROUND_TRIPS = [
  { alg: "hs256", gen: { name: "HMAC", hash: "SHA-256" }, jose: "HS256" },
  { alg: "hs384", gen: { name: "HMAC", hash: "SHA-384" }, jose: "HS384" },
  { alg: "hs512", gen: { name: "HMAC", hash: "SHA-512" }, jose: "HS512" },
  { alg: "es256", gen: { name: "ECDSA", namedCurve: "P-256" }, jose: "ES256" },
  { alg: "es384", gen: { name: "ECDSA", namedCurve: "P-384" }, jose: "ES384" },
  { alg: "es512", gen: { name: "ECDSA", namedCurve: "P-521" }, jose: "ES512" },
  { alg: "eddsa", gen: { name: "Ed25519" }, jose: "EdDSA" },
  {
    alg: "rs256",
    gen: {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    jose: "RS256",
  },
  {
    alg: "ps256",
    gen: {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    jose: "PS256",
  },
];

describe("sign → verify round trips", () => {
  for (const rt of ROUND_TRIPS) {
    it(`${rt.alg} signs and verifies, and names ${rt.jose} in the header`, async () => {
      const isHmac = rt.gen.name === "HMAC";
      const value = isHmac
        ? keyValue(
            await crypto.subtle.generateKey(rt.gen, true, ["sign", "verify"]),
            "secret"
          )
        : await pairValue(rt.gen);
      const claims = '{"sub":"alice","iat":1700000000}';

      const signed = await execJoseSign(
        textValue(claims),
        { key: "@k", alg: rt.alg },
        slotBindings(value)
      );
      expect(signed.data.split(".")).toHaveLength(3);
      expect(signed.meta.jose.header.alg).toBe(rt.jose);
      // A signed token is a bearer credential.
      expect(signed.meta.sensitive).toBe(true);

      const verified = await execJoseVerify(
        textValue(signed.data),
        { key: "@k" },
        slotBindings(value)
      );
      expect(JSON.parse(verified.data)).toEqual({ sub: "alice", iat: 1700000000 });
      expect(verified.meta.jose.verified).toBe(true);
    }, 30_000);
  }

  it("alg=auto reads the algorithm off the key", async () => {
    const value = await pairValue({ name: "ECDSA", namedCurve: "P-384" });
    const signed = await execJoseSign(textValue("{}"), { key: "@k" }, slotBindings(value));
    expect(signed.meta.jose.header.alg).toBe("ES384");
  });

  it("carries typ and kid into the header, and omits typ when blank", async () => {
    const value = await pairValue({ name: "Ed25519" });
    const withKid = await execJoseSign(
      textValue("{}"),
      { key: "@k", kid: "2024-05" },
      slotBindings(value)
    );
    expect(withKid.meta.jose.header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "2024-05" });
    const bare = await execJoseSign(
      textValue("{}"),
      { key: "@k", typ: "" },
      slotBindings(value)
    );
    expect(bare.meta.jose.header).toEqual({ alg: "EdDSA" });
  });

  it("signs a non-JSON payload as a plain JWS", async () => {
    const value = await pairValue({ name: "Ed25519" });
    const signed = await execJoseSign(
      textValue("just some bytes"),
      { key: "@k" },
      slotBindings(value)
    );
    expect(signed.meta.jose.claims).toBeNull();
    const verified = await execJoseVerify(
      textValue(signed.data),
      { key: "@k" },
      slotBindings(value)
    );
    expect(verified.data).toBe("just some bytes");
  });
});

/* ─────────────────────────────── refusals ─────────────────────────────── */

describe("jose.verify refuses the classic mistakes", () => {
  it('refuses alg="none" outright', async () => {
    const seg = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const key = await importHs(A1.jwk);
    await expect(
      execJoseVerify(
        textValue(`${seg('{"alg":"none"}')}.${seg('{"sub":"admin"}')}.`),
        { key: "@k" },
        slotBindings(keyValue(key, "secret"))
      )
    ).rejects.toThrow(/refusing alg="none"/);
  });

  it("refuses to reinterpret an RSA public key as an HMAC secret", async () => {
    // Algorithm confusion (CVE-2015-9235 and its many descendants): an
    // attacker re-signs the token with HS256 using the *public* key as the
    // MAC secret. The key's own algorithm decides here, so the header's
    // claim is contradicted before any crypto runs.
    const pair = await pairValue({
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    });
    const seg = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    await expect(
      execJoseVerify(
        textValue(`${seg('{"alg":"HS256"}')}.${seg('{"sub":"admin"}')}.AAAA`),
        { key: "@k" },
        slotBindings(pair)
      )
    ).rejects.toThrow(/token says alg=HS256 but the bound key is PS256/);
  });

  it("refuses a token whose alg is not the one the recipe demanded", async () => {
    const value = await pairValue({ name: "ECDSA", namedCurve: "P-256" });
    const signed = await execJoseSign(textValue("{}"), { key: "@k" }, slotBindings(value));
    await expect(
      execJoseVerify(textValue(signed.data), { key: "@k", alg: "es384" }, slotBindings(value))
    ).rejects.toThrow(/ES384 was required but the token is ES256/);
  });

  it("refuses a JWE, pointing at jose.decrypt", async () => {
    const seg = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const key = await importHs(A1.jwk);
    await expect(
      execJoseVerify(
        textValue(`${seg('{"alg":"dir","enc":"A256GCM"}')}..A.B.C`),
        { key: "@k" },
        slotBindings(keyValue(key, "secret"))
      )
    ).rejects.toThrow(/use jose.decrypt/);
  });

  it("fails an expired token by default and reports why", async () => {
    const value = await pairValue({ name: "Ed25519" });
    const signed = await execJoseSign(
      textValue(JSON.stringify({ sub: "a", exp: 1300819380 })),
      { key: "@k" },
      slotBindings(value)
    );
    await expect(
      execJoseVerify(textValue(signed.data), { key: "@k" }, slotBindings(value))
    ).rejects.toThrow(/signature is valid but the token expired/);
    // …and still lets you look at it deliberately.
    const anyway = await execJoseVerify(
      textValue(signed.data),
      { key: "@k", expiry: "ignore" },
      slotBindings(value)
    );
    expect(anyway.meta.jose.timing.expired).toBe(true);
    expect(anyway.meta.jose.expiryChecked).toBe(false);
  });

  it("fails a token that is not valid yet", async () => {
    const value = await pairValue({ name: "Ed25519" });
    const nbf = Math.floor(Date.now() / 1000) + 3600;
    const signed = await execJoseSign(
      textValue(JSON.stringify({ sub: "a", nbf })),
      { key: "@k" },
      slotBindings(value)
    );
    await expect(
      execJoseVerify(textValue(signed.data), { key: "@k" }, slotBindings(value))
    ).rejects.toThrow(/not valid before/);
  });

  it("says so when no key slot was bound", async () => {
    await expect(
      execJoseVerify(textValue(A1.token), {}, { resolveSlot: () => null })
    ).rejects.toThrow(/key=@slot is required/);
  });

  it("refuses to sign with an algorithm the key cannot do", async () => {
    const value = await pairValue({ name: "ECDSA", namedCurve: "P-256" });
    await expect(
      execJoseSign(textValue("{}"), { key: "@k", alg: "hs256" }, slotBindings(value))
    ).rejects.toThrow(/alg=HS256 does not match the bound key \(ES256\)/);
  });
});

/* ──────────────────────────────── JWE ──────────────────────────────── */

describe("JWE round trips", () => {
  it("dir + A256GCM", async () => {
    const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    const b = slotBindings(keyValue(cek, "secret"));
    const jwe = await execJoseEncrypt(textValue('{"sub":"alice"}'), { key: "@k" }, b);
    const parts = jwe.data.split(".");
    expect(parts).toHaveLength(5);
    // `dir` carries no encrypted key — RFC 7516 §5.1 step 11.
    expect(parts[1]).toBe("");
    expect(JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")))).toEqual({
      alg: "dir",
      enc: "A256GCM",
    });
    const out = await execJoseDecrypt(textValue(jwe.data), { key: "@k" }, b);
    expect(out.data).toBe('{"sub":"alice"}');
    expect(out.meta.jose.claims).toEqual({ sub: "alice" });
    expect(out.meta.sensitive).toBe(true);
  });

  for (const enc of ["a128gcm", "a192gcm", "a256gcm"]) {
    it(`dir + ${enc} round trips with a matching key`, async () => {
      const bits = Number(enc.slice(1, 4));
      const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: bits }, true, [
        "encrypt",
        "decrypt",
      ]);
      const b = slotBindings(keyValue(cek, "secret"));
      const jwe = await execJoseEncrypt(textValue("secret payload"), { key: "@k", enc }, b);
      const out = await execJoseDecrypt(textValue(jwe.data), { key: "@k" }, b);
      expect(out.data).toBe("secret payload");
    });
  }

  for (const alg of ["a128kw", "a256kw"]) {
    it(`${alg} wraps a fresh CEK and unwraps it again`, async () => {
      const bits = alg === "a128kw" ? 128 : 256;
      const kek = await crypto.subtle.generateKey({ name: "AES-KW", length: bits }, true, [
        "wrapKey",
        "unwrapKey",
      ]);
      const b = slotBindings(keyValue(kek, "secret"));
      const jwe = await execJoseEncrypt(textValue("wrapped"), { key: "@k", alg }, b);
      // Unlike `dir`, the second segment now carries the wrapped CEK.
      expect(jwe.data.split(".")[1]).not.toBe("");
      const out = await execJoseDecrypt(textValue(jwe.data), { key: "@k" }, b);
      expect(out.data).toBe("wrapped");
    });
  }

  it("rsa-oaep-256 wraps to a public key and unwraps with the private half", async () => {
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["wrapKey", "unwrapKey"]
    );
    const b = slotBindings({ type: "keypair", data: pair, meta: {} });
    const jwe = await execJoseEncrypt(
      textValue("to the holder of the private key"),
      { key: "@k", alg: "rsa-oaep-256" },
      b
    );
    const out = await execJoseDecrypt(textValue(jwe.data), { key: "@k" }, b);
    expect(out.data).toBe("to the holder of the private key");
  }, 30_000);

  it("binds the protected header as AAD, so editing alg breaks the tag", async () => {
    const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    const b = slotBindings(keyValue(cek, "secret"));
    const jwe = await execJoseEncrypt(textValue("payload"), { key: "@k" }, b);
    const parts = jwe.data.split(".");
    // Re-encode the same *semantic* header with an added member: decryption
    // must fail even though alg/enc still say what they said.
    parts[0] = btoa(JSON.stringify({ alg: "dir", enc: "A256GCM", zip: "DEF" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    await expect(
      execJoseDecrypt(textValue(parts.join(".")), { key: "@k" }, b)
    ).rejects.toThrow(/authentication failed/);
  });

  it("fails on the wrong key rather than returning garbage", async () => {
    const mk = () =>
      crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
        "encrypt",
        "decrypt",
      ]);
    const jwe = await execJoseEncrypt(
      textValue("payload"),
      { key: "@k" },
      slotBindings(keyValue(await mk(), "secret"))
    );
    await expect(
      execJoseDecrypt(
        textValue(jwe.data),
        { key: "@k" },
        slotBindings(keyValue(await mk(), "secret"))
      )
    ).rejects.toThrow(/authentication failed/);
  });

  it("refuses a JWS, pointing at jose.verify", async () => {
    const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    await expect(
      execJoseDecrypt(
        textValue(A1.token),
        { key: "@k" },
        slotBindings(keyValue(cek, "secret"))
      )
    ).rejects.toThrow(/use jose.verify/);
  });

  it("refuses dir with a key of the wrong size for the enc", async () => {
    const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 128 }, true, [
      "encrypt",
      "decrypt",
    ]);
    await expect(
      execJoseEncrypt(
        textValue("x"),
        { key: "@k", enc: "a256gcm" },
        slotBindings(keyValue(cek, "secret"))
      )
    ).rejects.toThrow(/needs a 256-bit key, slot holds 128-bit/);
  });

  it("reports an enc it does not implement instead of guessing", async () => {
    const seg = (s) =>
      btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const cek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    await expect(
      execJoseDecrypt(
        textValue(`${seg('{"alg":"dir","enc":"A128CBC-HS256"}')}..A.B.C`),
        { key: "@k" },
        slotBindings(keyValue(cek, "secret"))
      )
    ).rejects.toThrow(/unsupported enc A128CBC-HS256/);
  });
});

/* ─────────────────────────────── helpers ─────────────────────────────── */

describe("claim timing", () => {
  it("reads exp / nbf / iat and evaluates them against a clock", () => {
    const t = claimTiming({ exp: 200, nbf: 150, iat: 100 }, 175_000);
    expect(t).toEqual({ exp: 200, nbf: 150, iat: 100, expired: false, notYetValid: false });
    expect(claimTiming({ exp: 200 }, 250_000).expired).toBe(true);
    expect(claimTiming({ nbf: 200 }, 100_000).notYetValid).toBe(true);
  });

  it("ignores non-numeric claims rather than coercing them", () => {
    // `"exp": "soon"` is a malformed token, not an expired one — coercing it
    // would turn a bad token into a confident verdict.
    const t = claimTiming({ exp: "soon", nbf: null });
    expect(t.exp).toBeNull();
    expect(t.expired).toBe(false);
  });

  it("has nothing to say about a token with no time claims", () => {
    expect(claimTiming({ sub: "a" })).toEqual({
      exp: null,
      nbf: null,
      iat: null,
      expired: false,
      notYetValid: false,
    });
  });
});

describe("joseAlgForKey", () => {
  it("maps each supported key to its JOSE name", async () => {
    const cases = [
      [{ name: "HMAC", hash: "SHA-256" }, "HS256"],
      [{ name: "HMAC", hash: "SHA-512" }, "HS512"],
      [{ name: "ECDSA", namedCurve: "P-256" }, "ES256"],
      [{ name: "ECDSA", namedCurve: "P-521" }, "ES512"],
      [{ name: "Ed25519" }, "EdDSA"],
    ];
    for (const [gen, want] of cases) {
      const k = await crypto.subtle.generateKey(gen, true, ["sign", "verify"]);
      expect(joseAlgForKey(k.privateKey || k), want).toBe(want);
    }
  });

  it("returns null for a key with no JWS meaning, so the caller can say so", async () => {
    const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ]);
    expect(joseAlgForKey(aes)).toBeNull();
  });
});

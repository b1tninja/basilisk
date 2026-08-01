/**
 * Exhaustive toolkit verb / param smoke catalog (Vitest — not CAST).
 * Lives under `src/test/helpers/` so production bundles never import it.
 *
 * Coverage gates:
 * - every `listSteps()` op appears in ≥1 case
 * - every enum param value is exercised by ≥1 compiled recipe AST
 * - bool/flag params exercised both ways where the op is used
 */

import { createMessage, encrypt as openpgpEncrypt, generateKey, readKey } from "openpgp";
import { runRecipe } from "../../lib/toolkit/engine.js";
import { setApprovalGate } from "../../lib/toolkit/approval-gate.js";
import { bytesToBase64, bytesToHex, textToBytes } from "../../lib/toolkit/encode.js";
import {
  compileRecipe,
  migrateRecipe,
  recipeChains,
} from "../../lib/toolkit/recipe.js";
import { getStep, listSteps } from "../../lib/toolkit/registry.js";
import { ZERO_AAGUID } from "../../lib/webauthn/attestation.js";

if (
  typeof process === "undefined" ||
  !(process.env?.VITEST || process.env?.VITEST_WORKER_ID)
) {
  throw new Error("verb-smoke.js is Vitest-only");
}

/**
 * @typedef {object} VerbSmokeCase
 * @property {string} id
 * @property {string} recipe
 * @property {"run"|"compile"|"skip"} mode
 * @property {string} [skipReason]
 * @property {string[]} [ops]  primary ops (for docs); coverage uses AST walk
 * @property {import("./engine.js").RuntimeBindings | (() => Promise<import("./engine.js").RuntimeBindings> | import("./engine.js").RuntimeBindings)} [bindings]
 * @property {(arts: import("./engine.js").ToolkitArtifact[]) => void} [assert]
 * @property {() => Promise<void>|void} [setup]
 * @property {number} [timeoutMs]
 */

/**
 * Tiny CBOR attestationObject { fmt: "none", authData }.
 * @param {Uint8Array} authData
 */
function encodeAttestation(authData) {
  const encText = (s) => {
    const b = new TextEncoder().encode(s);
    return new Uint8Array([0x60 | b.length, ...b]);
  };
  const encBytes = (b) => {
    if (b.length < 24) return new Uint8Array([0x40 | b.length, ...b]);
    return new Uint8Array([0x58, b.length, ...b]);
  };
  const fmt = encText("fmt");
  const none = encText("none");
  const adk = encText("authData");
  const ad = encBytes(authData);
  const out = new Uint8Array(1 + fmt.length + none.length + adk.length + ad.length);
  out[0] = 0xa2;
  let o = 1;
  out.set(fmt, o);
  o += fmt.length;
  out.set(none, o);
  o += none.length;
  out.set(adk, o);
  o += adk.length;
  out.set(ad, o);
  return out;
}

function sampleAttestationB64() {
  const withAaguid = new Uint8Array(55);
  withAaguid[32] = 0x41;
  for (let i = 0; i < 16; i++) withAaguid[37 + i] = i;
  return bytesToBase64(encodeAttestation(withAaguid));
}

/** @type {ReturnType<typeof generateKey> extends Promise<infer T> ? T : never | null} */
let cachedGpgKey = null;

/**
 * SPKI of the pair a `keypair` case just generated — set by that case's
 * `bindings` and read back by its `assert`, so the assertion compares against
 * the real key rather than a hard-coded fixture.
 * @type {string}
 */
let expectedSpkiHex = "";

async function ensureGpgKey() {
  if (cachedGpgKey) return cachedGpgKey;
  cachedGpgKey = await generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ email: "verb-smoke@example.com", name: "Verb Smoke" }],
    format: "armored",
  });
  return cachedGpgKey;
}

async function gpgBindings(text = "verb-smoke") {
  const k = await ensureGpgKey();
  return {
    inputs: {
      text: { value: text },
      gpg: {
        privateKeyArmored: k.privateKey,
        publicKeyArmored: k.publicKey,
        passphrase: "",
        armoredMessages: [],
      },
    },
    recipients: [await readKey({ armoredKey: k.publicKey })],
  };
}

/**
 * @param {import("./recipe.js").RecipeStep[]|undefined} steps
 * @param {(s: import("./recipe.js").RecipeStep) => void} fn
 */
function walkSteps(steps, fn) {
  for (const s of steps || []) {
    fn(s);
    if (s.body?.length) walkSteps(s.body, fn);
    for (const br of s.branches || []) {
      if (br.body?.length) walkSteps(br.body, fn);
    }
  }
}

/**
 * Extract `op.param=value` coverage keys from a compiled AST.
 * Missing enum/bool params credit the registry default.
 * @param {import("./recipe.js").RecipeAst|null} ast
 * @returns {Set<string>}
 */
export function coversFromAst(ast) {
  /** @type {Set<string>} */
  const keys = new Set();
  if (!ast) return keys;
  for (const c of recipeChains(ast)) {
    walkSteps(c.steps, (step) => {
      const name = String(step.name || "");
      if (!name) return;
      keys.add(`op:${name}`);
      const spec = getStep(name);
      if (!spec?.params?.length) return;
      for (const p of spec.params) {
        let raw = step.params?.[p.name];
        if (raw === undefined || raw === null || raw === "") {
          if (p.default !== undefined && p.default !== "") {
            raw = p.default;
          } else if (p.type === "bool" || p.type === "flag") {
            raw = false;
          } else {
            continue;
          }
        }
        if (p.type === "bool" || p.type === "flag") {
          keys.add(`${name}.${p.name}=${raw ? "true" : "false"}`);
        } else if (p.type === "enum") {
          keys.add(`${name}.${p.name}=${String(raw)}`);
        } else if (p.type === "int") {
          keys.add(`${name}.${p.name}=${String(raw)}`);
        }
      }
      if (step.foreachSelector) {
        keys.add(`foreach.selector=${step.foreachSelector}`);
      }
    });
  }
  return keys;
}

/**
 * @returns {VerbSmokeCase[]}
 */
function baseCases() {
  /** @type {VerbSmokeCase[]} */
  const cases = [
    // —— sources / I/O ——
    {
      id: "random.default",
      recipe: "random | encode hex | out @r",
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => /^[0-9a-f]{64}$/.test(String(x.content)))) {
          throw new Error("expected 32-byte hex");
        }
      },
    },
    {
      id: "random.length=16",
      recipe: "random 16 | encode hex | out @r",
      mode: "run",
    },
    {
      id: "bytes.hex",
      recipe: "bytes deadbeef | encode hex | out @b",
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === "deadbeef")) {
          throw new Error("expected the literal to survive the round trip");
        }
      },
    },
    {
      id: "bytes.encoding=hex",
      // A leading 0x is optional — the same four bytes either way.
      recipe: "bytes 0xdeadbeef encoding=hex | encode hex | out @b",
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === "deadbeef")) {
          throw new Error("expected 0x prefix to be stripped");
        }
      },
    },
    {
      id: "bytes.encoding=base64",
      // Quoted because base64 padding would otherwise read as `key=value`.
      recipe: 'bytes "aGVsbG8=" encoding=base64 | encode hex | out @b',
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === "68656c6c6f")) {
          throw new Error("expected base64 to decode to 'hello'");
        }
      },
    },
    {
      id: "bytes.encoding=utf8",
      recipe: "bytes hello encoding=utf8 | encode hex | out @b",
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === "68656c6c6f")) {
          throw new Error("expected utf8 text to encode to 'hello'");
        }
      },
    },
    // —— keypair (§31c): import an existing pair, the counterpart to genkey ——
    {
      id: "keypair.format=jwk",
      // Exports the pair we just imported and checks the public half comes
      // back byte-identical, so this really exercises the import rather than
      // just proving the step does not throw.
      recipe: "keypair jwk alg=ec/p256 | export spki | encode hex | out @pub",
      mode: "run",
      bindings: async () => {
        const kp = await crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"]
        );
        const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
        expectedSpkiHex = bytesToHex(spki);
        return {
          inputs: {
            keypair: {
              value: JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey)),
            },
          },
        };
      },
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === expectedSpkiHex)) {
          throw new Error("imported public half did not match the original");
        }
      },
    },
    {
      id: "keypair.format=pem",
      // Both halves together — PKCS#8 alone cannot yield SPKI.
      recipe: "keypair pem alg=ec/p256 | export spki | encode hex | out @pub",
      mode: "run",
      bindings: async () => {
        const kp = await crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"]
        );
        const armor = async (key, fmt, label) => {
          const der = new Uint8Array(await crypto.subtle.exportKey(fmt, key));
          const b64 = bytesToBase64(der).replace(/(.{64})/g, "$1\n");
          return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
        };
        expectedSpkiHex = bytesToHex(
          new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey))
        );
        return {
          inputs: {
            keypair: {
              value:
                (await armor(kp.privateKey, "pkcs8", "PRIVATE KEY")) +
                "\n" +
                (await armor(kp.publicKey, "spki", "PUBLIC KEY")),
            },
          },
        };
      },
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === expectedSpkiHex)) {
          throw new Error("imported public half did not match the original");
        }
      },
    },
    // The remaining alg/usage values are compile-only: they are the same enum
    // `import` already declares, and generating an RSA-4096 pair per value
    // would dominate the suite's runtime without testing anything the two
    // runs above do not already cover.
    ...["ec/p384", "ec/p521", "ed25519", "x25519", "rsa/2048", "rsa/3072", "rsa/4096"].map(
      (alg) => ({
        id: `keypair.alg=${alg}`,
        recipe: `keypair jwk alg=${alg} | out @kp`,
        mode: /** @type {const} */ ("compile"),
      })
    ),
    ...["auto", "sign", "derive", "encrypt"].map((usage) => ({
      id: `keypair.usage=${usage}`,
      recipe: `keypair jwk usage=${usage} | out @kp`,
      mode: /** @type {const} */ ("compile"),
    })),
    // —— to / from: one verb per base encoding, round-tripped ——
    ...[
      ["hex", "deadbeef"],
      ["base64", "3q2+7w=="],
      ["base64url", "3q2-7w"],
      ["base32", "32W353Y"],
    ].flatMap(([enc, expected]) => [
      {
        id: `to.encoding=${enc}`,
        recipe: `bytes deadbeef | to ${enc} | out @e`,
        mode: /** @type {const} */ ("run"),
        assert: (a) => {
          if (!a.some((x) => String(x.content).trim() === expected)) {
            throw new Error(`to ${enc} should encode deadbeef as ${expected}`);
          }
        },
      },
      {
        id: `from.encoding=${enc}`,
        // Round-trips back to the original bytes, so this tests the decode
        // rather than merely that the step runs.
        recipe: `bytes deadbeef | to ${enc} | from ${enc} | encode hex | out @rt`,
        mode: /** @type {const} */ ("run"),
        assert: (a) => {
          if (!a.some((x) => String(x.content).trim() === "deadbeef")) {
            throw new Error(`from ${enc} did not round-trip`);
          }
        },
      },
    ]),
    {
      // The twin steps and the `to`/`from` spelling are the same operation —
      // if they ever diverge, this crossing fails.
      id: "to/from.interop-with-twins",
      recipe: "bytes deadbeef | base64 | decode base64 | encode hex | out @rt",
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => String(x.content).trim() === "deadbeef")) {
          throw new Error("base64 twin and `from base64` disagree");
        }
      },
    },
    {
      id: "passphrase.diceware",
      recipe: "passphrase 6 | out @p",
      mode: "run",
    },
    {
      id: "passphrase.char",
      recipe: "passphrase mode=char length=20 | out @p",
      mode: "run",
    },
    {
      id: "input+utf8+text",
      recipe: "input | utf8 | encode hex | text note",
      mode: "run",
      bindings: { inputs: { text: { value: "hi" } } },
    },
    {
      id: "out.encoding=auto",
      recipe: "random 8 | out @a encoding=auto",
      mode: "run",
    },
    {
      id: "out.encoding=hex",
      recipe: "random 8 | out @b encoding=hex",
      mode: "run",
    },
    {
      id: "out.encoding=base64",
      recipe: "random 8 | out @c encoding=base64",
      mode: "run",
    },
    {
      id: "out.encoding=text",
      recipe: "input | out @d encoding=text",
      mode: "run",
      bindings: { inputs: { text: { value: "tile" } } },
    },
    {
      id: "qr",
      recipe: "input | qr",
      mode: "run",
      bindings: { inputs: { text: { value: "basilisk-qr" } } },
      assert: (a) => {
        if (!a.some((x) => /svg/i.test(String(x.mime || "")) || /<svg/i.test(String(x.content)))) {
          throw new Error("expected QR SVG artifact");
        }
      },
    },

    // —— encoding ——
    {
      id: "encoding.roundtrip",
      recipe:
        "random 24 | base64 | base64.decode | base64url | base64url.decode | encode hex | decode hex | base32 | base32.decode | encode hex | out @x",
      mode: "run",
    },
    {
      id: "lit.text-int-bool",
      recipe: `"hello world" | out @msg

0xff | out @n
255 | out @n2
true | out @ok
"1" | as bool | out @yes
"42" | as int | out @answer`,
      mode: "run",
      assert: (a) => {
        const msg = a.find((x) => /msg/i.test(String(x.label || x.filename || "")));
        if (!msg || String(msg.content) !== "hello world") {
          throw new Error("expected lit text hello world");
        }
        const ok = a.find((x) => /ok/i.test(String(x.label || x.filename || "")));
        if (!ok || String(ok.content) !== "true") {
          throw new Error("expected lit bool true");
        }
        const answer = a.find((x) =>
          /answer/i.test(String(x.label || x.filename || ""))
        );
        if (!answer || String(answer.content) !== "42") {
          throw new Error("expected as int → 42");
        }
      },
    },
    {
      id: "aes-gcm.keyBits",
      recipe: `genkey aes/128 | out @k128

genkey aes/192 | out @k192

genkey aes/256 | out @k256

"sized" | utf8 | aes-gcm keyBits=192 key=@k192 | encode hex | out @ct192

"sized" | utf8 | aes-128-gcm key=@k128 | encode hex | out @ct128

"sized" | utf8 | aes-256-gcm key=@k256 | encode hex | out @ct256

"sized" | utf8 | aes-128-cbc key=@k128 | encode hex | out @cbc

"sized" | utf8 | aes-256-cbc key=@k256 | encode hex | out @cbc256

"sized" | utf8 | aes-256-ctr key=@k256 | encode hex | out @ctr

"sized" | utf8 | aes-cbc keyBits=192 key=@k192 | encode hex | out @cbc192

"sized" | utf8 | aes-ctr keyBits=128 key=@k128 | encode hex | out @ctr128

"sized" | utf8 | aes-ctr keyBits=192 key=@k192 | encode hex | out @ctr192`,
      mode: "run",
    },
    {
      id: "rsa-oaep.hash-forms",
      recipe: `genkey rsa/2048 usage=encrypt hash=sha-256 | out @rk256

"oaep" | utf8 | RSA/ECB/OAEPWithSHA-256AndMGF1Padding key=@rk256 | encode hex | out @ct256

in @ct256 | decode hex | RSA/ECB/OAEPWithSHA-256AndMGF1Padding -d key=@rk256 | utf8 | out @pt`,
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "rsa-oaep.hash-enum",
      recipe: `genkey rsa/2048 usage=encrypt hash=sha-256 | out @rk

"x" | utf8 | rsa-oaep hash=sha-1 key=@rk | out @a

"x" | utf8 | rsa-oaep hash=sha-256 key=@rk | out @b

"x" | utf8 | rsa-oaep hash=sha-384 key=@rk | out @c

"x" | utf8 | rsa-oaep hash=sha-512 key=@rk | out @d`,
      mode: "compile",
    },
    {
      id: "pem.labels",
      recipe: `genkey ec/p256 | export pkcs8 | pem label="PRIVATE KEY" | out @priv

genkey ec/p256 | :public | export spki | pem label="PUBLIC KEY" | out @pub`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "pem.der",
      recipe:
        "genkey ec/p256 | export pkcs8 | pem | der | pem label=auto | out @again",
      mode: "run",
    },

    // —— webcrypto core ——
    {
      id: "digest.sha-256",
      recipe: "input | utf8 | digest sha-256 | encode hex | out @d256",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "digest.sha-384",
      recipe: "input | utf8 | digest alg=sha-384 | encode hex | out @d384",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "digest.sha-512",
      recipe: "input | utf8 | digest alg=sha-512 | encode hex | out @d512",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "digest.sha-1",
      recipe: "input | utf8 | digest alg=sha-1 | encode hex | out @d1",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "sign.verify.ed25519",
      recipe: `genkey ed25519 | out @kp

input | utf8 | out @msg | sign key=@kp | out @sig

in @msg | verify key=@kp signature=@sig | out @ok`,
      mode: "run",
      bindings: { inputs: { text: { value: "sign-me" } } },
      timeoutMs: 30_000,
    },
    {
      id: "verify.soft",
      recipe: `genkey ed25519 | out @kp

input | utf8 | out @msg | sign key=@kp | out @sig

in @msg | verify -q key=@kp signature=@sig | out @result`,
      mode: "run",
      bindings: { inputs: { text: { value: "soft-ok" } } },
      timeoutMs: 30_000,
    },
    {
      id: "aes-gcm.aad-slot",
      recipe: `"aad" | utf8 | out @aad

genkey aes/256 | out @cek

"hi" | utf8 | aes-gcm key=@cek aad=@aad | encode hex | out @ct

in @ct | decode hex | aes-gcm -d key=@cek aad=@aad | utf8 | out @pt`,
      mode: "run",
    },
    {
      id: "gpg.symencrypt.passphrase",
      recipe: `"pw" | out @pw

"secret" | utf8 | gpg.symencrypt mode=passphrase passphrase=@pw | out @msg

in @msg | gpg.symdecrypt mode=passphrase passphrase=@pw | utf8 | out @pt`,
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "gpg.symencrypt.profile-custom",
      recipe:
        "input | gpg.symencrypt mode=master name=env profile=custom cipher=aes128 aead=off s2k=iterated compression=zlib | out @env",
      mode: "run",
      bindings: { inputs: { text: { value: "sym-profile" } } },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.symencrypt.profile-modern",
      recipe:
        "input | gpg.symencrypt mode=master name=env profile=modern cipher=aes192 aead=gcm compression=zip | out @env",
      mode: "run",
      bindings: { inputs: { text: { value: "sym-profile" } } },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.symencrypt.profile-compatible",
      recipe: "input | gpg.symencrypt mode=master name=env profile=compatible aead=eax | out @env",
      mode: "run",
      bindings: { inputs: { text: { value: "sym-profile" } } },
      timeoutMs: 60_000,
    },
    {
      id: "import.raw.aes",
      recipe:
        "genkey aes/256 | export raw | import raw alg=aes/256 | export jwk | out @k",
      mode: "run",
    },
    {
      id: "import.pkcs8",
      recipe:
        "genkey ec/p256 | export pkcs8 | import pkcs8 alg=ec/p256 | export pkcs8 | pem | out @p",
      mode: "run",
    },
    {
      id: "aes-gcm.roundtrip",
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-gcm key=@cek | encode hex | out @ct

in @ct | decode hex | aes-gcm -d key=@cek | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "gcm" } } },
    },
    {
      id: "aes-gcm.tagLength=96",
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-gcm key=@cek tagLength=96 | encode hex | out @ct

in @ct | decode hex | aes-gcm -d key=@cek tagLength=96 | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "gcm96" } } },
    },
    {
      id: "wrap.tagLength=96",
      recipe: `genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek mode=aes-gcm tagLength=96 | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-gcm alg=aes/256 tagLength=96 | out @cek2`,
      mode: "run",
    },
    {
      id: "sign.verify.hash=sha-256",
      recipe: `genkey ec/p256 | out @kp

input | utf8 | out @msg | sign key=@kp hash=sha-256 | out @sig

in @msg | verify key=@kp signature=@sig hash=sha-256 | out @ok`,
      mode: "run",
      bindings: { inputs: { text: { value: "hash-sign" } } },
    },
    {
      id: "sign.verify.hash=sha-384",
      recipe: `genkey ec/p256 | out @kp

input | utf8 | out @msg | sign key=@kp hash=sha-384 | out @sig

in @msg | verify key=@kp signature=@sig hash=sha-384 | out @ok`,
      mode: "run",
      bindings: { inputs: { text: { value: "hash-sign" } } },
    },
    {
      id: "sign.verify.hash=sha-512",
      recipe: `genkey ec/p256 | out @kp

input | utf8 | out @msg | sign key=@kp hash=sha-512 | out @sig

in @msg | verify key=@kp signature=@sig hash=sha-512 | out @ok`,
      mode: "run",
      bindings: { inputs: { text: { value: "hash-sign" } } },
    },
    {
      id: "aes-cbc.roundtrip",
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-cbc key=@cek | encode hex | out @ct

in @ct | decode hex | aes-cbc -d key=@cek | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "cbc" } } },
    },
    {
      id: "aes-ctr.roundtrip",
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-ctr key=@cek length=64 | encode hex | out @ct

in @ct | decode hex | aes-ctr -d key=@cek length=64 | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "ctr" } } },
    },
    {
      id: "rsa-oaep.roundtrip",
      recipe: `genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-oaep key=@rk | encode hex | out @ct

in @ct | decode hex | rsa-oaep -d key=@rk | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "oaep" } } },
      timeoutMs: 60_000,
    },
    {
      id: "rsa-pkcs1.roundtrip",
      recipe: `genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-pkcs1 key=@rk | encode hex | out @ct

in @ct | decode hex | rsa-pkcs1 -d key=@rk | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "pkcs1" } } },
      timeoutMs: 60_000,
    },
    {
      id: "hkdf.bytes+hash",
      recipe: `random 32 | hkdf 32 hash=sha-256 salt=s info=i | encode hex | out @a

random 32 | hkdf 32 hash=sha-384 | encode hex | out @b

random 32 | hkdf 32 hash=sha-512 | encode hex | out @c`,
      mode: "run",
    },
    {
      id: "pbkdf2.bytes+hash",
      recipe: `passphrase mode=char length=16 | pbkdf2 32 iterations=1000 hash=sha-256 | encode hex | out @a

passphrase mode=char length=16 | pbkdf2 32 iterations=1000 hash=sha-384 | encode hex | out @b

passphrase mode=char length=16 | pbkdf2 32 iterations=1000 hash=sha-512 | encode hex | out @c`,
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "ecdh.x25519",
      recipe: `genkey x25519 | out @local

genkey x25519 | :public | out @peer

ecdh private=@local peer=@peer | encode hex | out @shared`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "wrap.unwrap.aes-kw",
      recipe: `genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek mode=aes-kw | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-kw alg=aes/256 | out @cek2`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "wrap.unwrap.aes-gcm",
      recipe: `genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek mode=aes-gcm tagLength=128 | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-gcm alg=aes/256 tagLength=128 | out @cek2`,
      mode: "run",
    },
    {
      id: "wrap.unwrap.aes-cbc",
      recipe: `genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek mode=aes-cbc | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-cbc alg=aes/256 | out @cek2`,
      mode: "run",
    },
    {
      id: "wrap.unwrap.aes-ctr",
      recipe: `genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek mode=aes-ctr length=64 | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-ctr alg=aes/256 length=64 | out @cek2`,
      mode: "run",
    },
    {
      id: "wrap.unwrap.rsa-oaep",
      recipe: `genkey rsa/2048 usage=encrypt | out @rk

genkey aes/256 | out @cek

wrap key=@rk target=@cek mode=rsa-oaep | out @wrapped

in @wrapped | unwrap key=@rk mode=rsa-oaep alg=aes/256 | out @cek2`,
      mode: "run",
      timeoutMs: 60_000,
    },

    // —— export / import formats ——
    {
      id: "export.import.jwk",
      recipe:
        "genkey ed25519 | export jwk | import jwk alg=ed25519 | export jwk | out @k",
      mode: "run",
    },
    {
      id: "export.import.scalar",
      recipe:
        "genkey ec/p256 | export scalar | import scalar alg=ec/p256 | export pkcs8 | pem | out @priv",
      mode: "run",
    },
    {
      id: "export.raw.aes",
      recipe: "genkey aes/256 | export raw | encode hex | out @raw",
      mode: "run",
    },
    {
      id: "export.d.alias",
      recipe: "genkey ec/p256 | export scalar | encode hex | out @d",
      mode: "run",
    },
    {
      id: "export.which=public",
      recipe: "genkey ec/p256 | export jwk which=public | out @j",
      mode: "compile",
    },
    {
      id: "import.spki",
      recipe:
        "genkey ec/p256 | :public | export spki | import spki alg=ec/p256 | export spki | pem | out @pub",
      mode: "run",
    },

    // —— VSS (verifiable sharing) ——
    // Real `run` cases: this is pure curve arithmetic with no browser API
    // behind it, so there is nothing to stub and no reason to compile-only.
    {
      id: "vss.split.verify.combine",
      recipe: `random 32 | vss.split threshold=2 shares=3 | out @shares

in @shares | vss.verify | vss.combine | encode hex | out @recovered`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "vss.split.blip39.foreach",
      // Emits the same `shares` shape as sss.split, so the existing
      // collection machinery composes untouched.
      recipe: `random 32 | vss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "vss.commitments.published.separately",
      // The realistic custodian flow: mnemonics go to people, commitments go
      // on a noticeboard, and the two are brought back together to verify.
      recipe: `random 32 | vss.split threshold=2 shares=3 | tee
  - vss.commitments | out @commitments
| out @shares

in @shares | vss.verify commitments=@commitments | vss.combine | encode hex | out @back`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "vss.scalar.roundtrip",
      recipe: `genkey ec/p256 | export scalar | vss.split threshold=2 shares=3 | out @s

in @s | vss.verify | out @checked`,
      mode: "run",
      timeoutMs: 30_000,
    },

    // —— SSS / BLIP39 / flow ——
    {
      id: "sss.blip39.foreach.at",
      recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share

random 32 | sss.split threshold=2 shares=3 | blip39 | at 1 | out @one

random 32 | sss.split threshold=2 shares=3 | blip39 | foreach :items
  - :value | out @item`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "sss.combine+shares",
      recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
      mode: "run",
      // recover path covered via shares source in follow-up case
    },
    {
      id: "shares.combine",
      recipe: "shares | blip39.decode | sss.combine | base64 | out @secret",
      mode: "run",
      bindings: async () => {
        const { ast } = compileRecipe(
          "random 32 | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out @share"
        );
        const arts = await runRecipe(ast);
        const mnemonics = arts
          .map((a) => String(a.content || "").trim())
          .filter((t) => t.split(/\s+/).length >= 12);
        return {
          inputs: {
            shares: {
              mnemonics: mnemonics.slice(0, 2),
            },
          },
        };
      },
      timeoutMs: 30_000,
    },
    {
      id: "in.select.as.peek.tee.inspect",
      recipe: `genkey ec/p256 | tee
  - :public | export spki | pem | out @public
  - :private | inspect format=hex
| peek keypair format=meta | export pkcs8 | pem | out @private

in @private | der | as opaque | encode hex | out @hex

genkey ec/p256 | :public | export spki | pem | out @pub2`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "inspect.format=text",
      recipe: "input | utf8 | inspect format=text | out @t",
      mode: "run",
      bindings: { inputs: { text: { value: "inspect" } } },
    },
    {
      id: "inspect.format=hex",
      recipe: "random 8 | inspect format=hex | out @hx",
      mode: "run",
    },
    {
      id: "inspect.format=hexdump",
      recipe: "random 8 | inspect format=hexdump | out @h",
      mode: "run",
    },
    {
      id: "inspect.format=jwk",
      recipe: "genkey aes/256 | export jwk | inspect format=jwk | out @j",
      mode: "run",
    },
    {
      id: "inspect.format=auto",
      recipe: "random 4 | inspect format=auto | out @a",
      mode: "run",
    },
    {
      id: "inspect.format=meta",
      recipe: "genkey ec/p256 | inspect format=meta | out @m",
      mode: "run",
    },
    {
      id: "as.casts",
      recipe: `random 32 | as master | encode hex | out @m

random 32 | as scalar | encode hex | out @s

random 32 | as opaque | encode hex | out @o

genkey ec/p256 | :public | export spki | as public | pem | out @pubpem

genkey ec/p256 | export pkcs8 | as private | pem | out @privpem

genkey ec/p256 | :public | export spki | pem | as key | export spki | out @pub2

genkey ec/p256 | export pkcs8 | pem | as keypair | export pkcs8 | out @priv2`,
      mode: "run",
      timeoutMs: 60_000,
    },

    // —— OpenPGP ——
    {
      id: "gpg.genkey",
      recipe: 'gpg.genkey email="verb@example.com" | out @priv',
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "gpg.inspect.summary",
      recipe: "input | gpg.inspect format=summary | out @sum",
      mode: "run",
      bindings: async () => {
        const b = await gpgBindings("inspect-me");
        const enc = compileRecipe("input | utf8 | gpg.encrypt policy=one");
        const arts = await runRecipe(enc.ast, b);
        return { inputs: { text: { value: String(arts[0]?.content || "") } } };
      },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.inspect.packets",
      recipe: "input | gpg.inspect format=packets | out @p",
      mode: "run",
      bindings: async () => {
        const b = await gpgBindings("inspect-me");
        const enc = compileRecipe("input | utf8 | gpg.encrypt policy=one");
        const arts = await runRecipe(enc.ast, b);
        return { inputs: { text: { value: String(arts[0]?.content || "") } } };
      },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.inspect.json",
      recipe: "input | gpg.inspect format=json | out @j",
      mode: "run",
      bindings: async () => {
        const b = await gpgBindings("inspect-me");
        const enc = compileRecipe("input | utf8 | gpg.encrypt policy=one");
        const arts = await runRecipe(enc.ast, b);
        return { inputs: { text: { value: String(arts[0]?.content || "") } } };
      },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.encrypt.separate",
      recipe: "input | utf8 | gpg.encrypt mode=separate policy=ask | out @ct",
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.encrypt.combined",
      recipe: "input | utf8 | gpg.encrypt mode=combined policy=one | out @ct",
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.encrypt.sign",
      recipe: "input | utf8 | gpg.encrypt -s policy=all | out @ct",
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.encrypt.profile-custom",
      recipe:
        "input | utf8 | gpg.encrypt policy=one profile=custom cipher=aes128 aead=off s2k=iterated compression=zlib | out @ct",
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.encrypt.profile-modern",
      recipe:
        "input | utf8 | gpg.encrypt policy=one profile=modern cipher=aes192 aead=gcm compression=zip | out @ct",
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.encrypt.profile-compatible",
      recipe: "input | utf8 | gpg.encrypt policy=one profile=compatible aead=eax | out @ct",
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.decrypt.source",
      recipe: "gpg.decrypt | out @plain",
      mode: "run",
      bindings: async () => {
        const b = await gpgBindings("decrypt-me");
        const enc = compileRecipe("input | utf8 | gpg.encrypt policy=one");
        const arts = await runRecipe(enc.ast, b);
        const armored = String(arts[0]?.content || "");
        return {
          inputs: {
            gpg: {
              ...b.inputs.gpg,
              armoredMessages: [armored],
            },
          },
        };
      },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.sign.verify.cleartext",
      recipe: `input | gpg.sign format=cleartext | out @signed

in @signed | gpg.verify | out @ok`,
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.sign.detached",
      recipe: `input | out @msg | gpg.sign format=detached | out @sig

in @msg | gpg.verify -q signature=@sig | out @ok`,
      mode: "run",
      bindings: gpgBindings,
      timeoutMs: 60_000,
    },
    {
      id: "gpg.symencrypt.decrypt",
      recipe: `input | gpg.symencrypt mode=master name=env | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
      mode: "run",
      bindings: {
        inputs: {
          text: { value: "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----" },
        },
      },
      timeoutMs: 60_000,
    },
    {
      id: "gpg.symdecrypt",
      recipe:
        "shares | blip39.decode | sss.combine | gpg.symdecrypt mode=master | utf8 | out @pem",
      mode: "run",
      bindings: async () => {
        const pem =
          "-----BEGIN PRIVATE KEY-----\nMIIBverbsmoke\n-----END PRIVATE KEY-----";
        const { ast } = compileRecipe(
          `input | gpg.symencrypt mode=master name=env | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out @share`
        );
        const arts = await runRecipe(ast, {
          inputs: { text: { value: pem } },
        });
        const mnemonics = arts
          .filter(
            (a) =>
              a.shareIndex ||
              a.role === "share" ||
              /^Share\s+\d+/i.test(a.label || "")
          )
          .map((a) => String(a.content || "").trim())
          .filter(Boolean);
        const envelope = arts.find((a) =>
          /BEGIN PGP MESSAGE/.test(String(a.content || ""))
        );
        return {
          inputs: {
            shares: {
              mnemonics: mnemonics.slice(0, 2),
              envelopeArmored: envelope ? String(envelope.content) : undefined,
            },
          },
        };
      },
      timeoutMs: 90_000,
    },

    // —— agent (device protection; fake-indexeddb in test file) ——
    {
      id: "agent.list",
      recipe: "agent.list | out @ring",
      mode: "run",
    },
    {
      id: "agent.save.device",
      recipe:
        'gpg.genkey email="save-smoke@example.com" | agent.save protection=device expiry=none | out @priv',
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "agent.save.passphrase",
      recipe:
        'gpg.genkey email="save-pass@example.com" | agent.save protection=passphrase | out @priv',
      mode: "run",
      bindings: {
        inputs: { gpg: { passphrase: "verb-smoke-pass" } },
      },
      timeoutMs: 60_000,
    },
    {
      id: "agent.save.passkey",
      recipe:
        'gpg.genkey email="save-pk@example.com" | agent.save protection=passkey | out @priv',
      mode: "run",
      timeoutMs: 60_000,
      assert: (arts) => {
        if (!arts.some((a) => /PRIVATE KEY/.test(String(a.content || "")))) {
          throw new Error("expected armored private after passkey save");
        }
      },
    },

    // —— HKP (mocked in test setup; fpr filled by listAllVerbSmokeCases) ——
    {
      id: "hkp.cache.list",
      recipe: "hkp.cache action=list format=json",
      mode: "run",
    },
    {
      id: "hkp.cache.clear",
      recipe: "hkp.cache action=clear",
      mode: "run",
    },
    {
      id: "hkp.search.filter.merge",
      recipe: `hkp.search "alice@example.com" format=recipients | out @recs

in @recs | hkp.filter approved=true encrypt=true | out @filt

hkp.search "bob@example.com" format=json | out @json`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "hkp.get",
      recipe: "hkp.get __FPR__ | out @bob",
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "hkp.get.refresh",
      recipe: "hkp.get __FPR__ refresh=true | out @bob",
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "recipients.merge",
      recipe: `hkp.search "alice@example.com" | out @a

hkp.search "bob@example.com" | out @b

in @a | recipients.merge with=@b | out @merged`,
      mode: "run",
      timeoutMs: 30_000,
    },

    // —— WebAuthn ——
    {
      id: "webauthn.caps",
      recipe: "webauthn.caps",
      mode: "run",
    },
    {
      id: "webauthn.create",
      // Tip without `out` so the engine auto-emits a tile for asserts.
      recipe: "webauthn.create user=verb-smoke | encode hex",
      mode: "run",
      assert: (arts) => {
        if (!arts.some((a) => /^[0-9a-f]{64}$/.test(String(a.content || "")))) {
          throw new Error("expected 32-byte PRF IKM to hex from webauthn.create");
        }
      },
    },
    {
      id: "webauthn.get",
      recipe: "webauthn.get",
      mode: "run",
      assert: (arts) => {
        const body = arts.map((a) => String(a.content || "")).join("\n");
        const start = body.indexOf("{");
        const json = JSON.parse(start >= 0 ? body.slice(start) : body);
        if (!json.id || json.clientExtensionResults == null) {
          throw new Error("expected assertion JSON from webauthn.get");
        }
      },
    },
    {
      id: "webauthn.prf",
      recipe: "webauthn.prf | encode hex",
      mode: "run",
      setup: async () => {
        // Ensure prf-meta exists (create may not have run yet if tests reorder).
        const { createPasskeyPrf } = await import("../../lib/vault.js");
        await createPasskeyPrf("verb-smoke-prf-setup");
      },
      assert: (arts) => {
        if (!arts.some((a) => /^[0-9a-f]{64}$/.test(String(a.content || "")))) {
          throw new Error("expected 32-byte PRF IKM to hex from webauthn.prf");
        }
      },
    },
    {
      id: "webauthn.attest.mds",
      recipe: `input | webauthn.attest | out @att

in @att | webauthn.mds | out @mds`,
      mode: "run",
      bindings: { inputs: { text: { value: sampleAttestationB64() } } },
    },
    {
      id: "webauthn.mds.aaguid",
      recipe: `input | webauthn.mds ${ZERO_AAGUID} | out @mds0`,
      mode: "run",
      bindings: { inputs: { text: { value: "{}" } } },
    },

    // ── Quorum toolbox (§21a) — rtc.ice is pure config and runs for real;
    // stun.check / quorum.* need WebRTC + live peers, so compile-only here.
    {
      id: "rtc.ice.defaults",
      recipe: "rtc.ice | out @ice",
      mode: "run",
      assert: (arts) => {
        const body = arts.map((a) => String(a.content || "")).join("\n");
        const json = JSON.parse(body.slice(body.indexOf("{")));
        if (!Array.isArray(json.iceServers) || json.iceServers.length < 2) {
          throw new Error("expected default STUN servers from rtc.ice");
        }
        if (!json.iceServers.every((s) => /^stuns?:/.test(String(s.urls)))) {
          throw new Error("default rtc.ice must be stun-only");
        }
      },
    },
    {
      id: "rtc.ice.turn",
      recipe: `passphrase | out @cred

rtc.ice stun=stun:stun.example.org:3478 turn=turn:relay.example.org:3478 username=u credential=@cred | out @ice`,
      mode: "run",
      assert: (arts) => {
        const body = arts.map((a) => String(a.content || "")).join("\n");
        const json = JSON.parse(body.slice(body.indexOf("{")));
        const turn = json.iceServers.find((s) => /^turns?:/.test(String(s.urls)));
        if (!turn || turn.username !== "u" || !turn.credential) {
          throw new Error("expected TURN entry with a resolved credential from rtc.ice");
        }
        if (turn.credential === "@cred") {
          throw new Error("rtc.ice credential=@slot was not resolved to its slot value");
        }
      },
    },
    {
      id: "stun.check.compile",
      recipe: "stun.check stun:stun.example.org:3478 timeout=1000 | out @nat",
      mode: "compile",
      skipReason: "needs RTCPeerConnection (main-thread browser only)",
    },
    {
      id: "quorum.exchange.compile",
      recipe: `gpg.genkey email="quorum-smoke@example.com" | out @me

quorum.offer to="${"A".repeat(40)},${"B".repeat(40)}" key=@me wait=5000 | out @session

rtc.recv wait=5000 | quorum.close | out @last`,
      mode: "compile",
      skipReason: "needs WebRTC mesh + a live peer",
    },
    {
      id: "quorum.join.send.compile",
      recipe: `gpg.genkey email="quorum-smoke@example.com" | out @me

quorum.join to="${"A".repeat(40)},${"B".repeat(40)}" key=@me | out @session

input | rtc.send | out @sent`,
      mode: "compile",
      skipReason: "needs WebRTC mesh + a live peer",
    },

    // ── WebRTC primitives (§23a/23b/29a/29d/30d) — every one needs a real
    // RTCPeerConnection (and several a live exchange), so all compile-only.
    {
      id: "rtc.gather.compile",
      recipe: `rtc.ice | out @ice

rtc.gather ice=@ice timeout=3000 | out @cands`,
      mode: "compile",
      skipReason: "needs RTCPeerConnection (main-thread browser only)",
    },
    {
      id: "rtc.check.compile",
      recipe: "rtc.check | out @pairs",
      mode: "compile",
      skipReason: "needs a live WebRTC exchange with a peer",
    },
    {
      id: "rtc.certificate.ecdsa.compile",
      recipe: "rtc.certificate ecdsa | out @id",
      mode: "compile",
      skipReason: "needs RTCPeerConnection.generateCertificate",
    },
    {
      id: "rtc.certificate.rsa.compile",
      recipe: "rtc.certificate rsa | out @id",
      mode: "compile",
      skipReason: "needs RTCPeerConnection.generateCertificate",
    },
    {
      id: "rtc.offer.answer.compile",
      recipe: `rtc.ice | out @ice

rtc.offer ice=@ice label=basilisk | out @offer

in @offer | rtc.answer ice=@ice | out @answer`,
      mode: "compile",
      skipReason: "needs RTCPeerConnection (main-thread browser only)",
    },
    {
      id: "rtc.state.compile",
      recipe: "rtc.state | out @state",
      mode: "compile",
      skipReason: "needs a live WebRTC exchange",
    },
    {
      id: "dkg.run.compile",
      recipe: `gpg.genkey email="dkg-smoke@example.com" | out @me

quorum.join to="${"A".repeat(40)},${"B".repeat(40)},${"C".repeat(40)}" key=@me | out @session

dkg.run threshold=2 | out @dkg`,
      mode: "compile",
      skipReason: "needs a live mesh with every participant present",
    },
    {
      id: "rtc.restart.compile",
      recipe: "rtc.restart | out @state",
      mode: "compile",
      skipReason: "needs a live WebRTC exchange",
    },
    {
      id: "rtc.stats.compile",
      recipe: "rtc.stats | out @bp",
      mode: "compile",
      skipReason: "needs a live WebRTC exchange",
    },
    {
      id: "rtc.quality.compile",
      recipe: "rtc.quality | out @quality",
      mode: "compile",
      skipReason: "needs a live WebRTC exchange",
    },

    // ── Run receipts — digests of what the run did, signable and checkable ──
    {
      id: "run.receipt",
      recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share

run.receipt "verb smoke ceremony" | out @receipt`,
      mode: "run",
      timeoutMs: 30_000,
      assert: (arts) => {
        const tile = arts.find((a) => /run-receipt/.test(String(a.content || "")));
        if (!tile) throw new Error("expected a run receipt tile");
        const receipt = JSON.parse(String(tile.content));
        if (receipt.label !== "verb smoke ceremony") {
          throw new Error("receipt did not take the label argument");
        }
        if (!receipt.cells?.length || !receipt.cells[0].outputs?.length) {
          throw new Error("receipt recorded no cell outputs");
        }
        // The invariant worth a smoke test: mnemonics went past this op and
        // none of them are in the receipt.
        const mnemonic = arts.find((a) => a.role === "share");
        if (mnemonic && String(tile.content).includes(String(mnemonic.content).trim())) {
          throw new Error("receipt leaked a share value");
        }
      },
    },
    {
      id: "run.verify",
      // Self-consistent by construction: the receipt is minted and checked
      // inside one run, so the comparison has something real to agree with. The
      // interesting failure paths (tampered digest, extra cell) are unit-tested
      // in run-receipt.test.js against the pure comparator.
      recipe: "run.receipt | run.verify | out @ok",
      mode: "run",
      assert: (arts) => {
        if (!arts.some((a) => String(a.content).trim() === "true")) {
          throw new Error("a receipt should verify against the run that minted it");
        }
      },
    },
    {
      id: "run.verify.soft",
      recipe: "run.receipt | run.verify -q | out @ok",
      mode: "run",
    },

    // ── Clipboard as a signaling channel (§32d) — both need the browser's
    // clipboard plus (for read) the UI's permission gate, so compile-only.
    {
      id: "qr.scan.compile",
      recipe: "file.read | qr.scan | out @invite",
      mode: "compile",
      skipReason: "needs BarcodeDetector + a file picker (main-thread browser only)",
    },
    {
      id: "qr.scan.all.compile",
      recipe: "file.read | qr.scan count=all | foreach\n  - out @code",
      mode: "compile",
      skipReason: "needs BarcodeDetector + a file picker (main-thread browser only)",
    },
    {
      id: "clipboard.read.compile",
      recipe: "clipboard.read | out @pasted",
      mode: "compile",
      skipReason: "needs navigator.clipboard + the UI permission gate",
    },
    {
      id: "clipboard.write.compile",
      recipe: "random 16 | encode base64 | clipboard.write | out @copied",
      mode: "compile",
      skipReason: "needs navigator.clipboard (main-thread browser only)",
    },

    // ── File I/O — both sides open a browser picker, so compile-only. The
    // real coverage lives in file-ops.test.js against a stubbed picker.
    {
      id: "file.read.compile",
      // The accept list is quoted: a bare token starting with `.` is a
      // selector to the parser, which is the correct reading everywhere else.
      recipe: 'file.read ".pem,.asc" as=text | out @loaded',
      mode: "compile",
      skipReason: "needs a file picker (main-thread browser only)",
    },
    {
      id: "file.read.bytes.compile",
      recipe: "file.read as=bytes | out @blob",
      mode: "compile",
      skipReason: "needs a file picker (main-thread browser only)",
    },
    {
      id: "file.read.auto.compile",
      recipe: "file.read as=auto | out @blob",
      mode: "compile",
      skipReason: "needs a file picker (main-thread browser only)",
    },
    {
      id: "file.save.compile",
      recipe: "random 32 | file.save name=key.bin mime=application/octet-stream | out @saved",
      mode: "compile",
      skipReason: "needs a save picker / download (main-thread browser only)",
    },

    // ── Chunked AEAD — pure WebCrypto, so this one genuinely runs.
    {
      id: "stream.seal.open",
      recipe: `genkey aes/256 | out @cek

"chunked payload" | utf8 | stream.seal key=@cek chunk=1024 | out @sealed

in @sealed | stream.open key=@cek | utf8 | out @opened`,
      mode: "run",
      assert(arts) {
        const opened = arts.find((a) => a.label?.includes("opened"));
        if (!opened || opened.content !== "chunked payload") {
          throw new Error(`stream round trip lost the payload: ${opened?.content}`);
        }
      },
    },

    // ── age (age-encryption.org/v1) — typage is pure JS + WebCrypto, so the
    // whole interop path runs here rather than being asserted by inspection.
    {
      id: "age.keygen.recipient.roundtrip",
      recipe: `age.keygen | out @id

in @id | age.recipient | out @pub

"age round trip" | utf8 | age.encrypt to=@pub | out @ct

in @ct | age.decrypt key=@id | utf8 | out @plain`,
      mode: "run",
      timeoutMs: 20000,
      assert(arts) {
        const plain = arts.find((a) => a.label?.includes("plain"));
        if (!plain || plain.content !== "age round trip") {
          throw new Error(`age round trip lost the payload: ${plain?.content}`);
        }
      },
    },
    // ── SSH (§29g) — every op, every enum value, and -q, in running
    // recipes. Byte-level interop with ssh-keygen is asserted separately
    // against checked-in fixtures (ssh-format.test.js); these prove the
    // registry surface composes.
    {
      id: "ssh.encode.decode.fingerprint",
      recipe: `genkey ed25519 | out @id

in @id | ssh.encode comment="verb@smoke" | out @pub

in @pub | ssh.decode | ssh.fingerprint | out @fp

in @id | ssh.fingerprint | out @fp2`,
      mode: "run",
      timeoutMs: 30_000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const pub = arts.find((a) => tok(a, "pub"));
        if (!pub || !String(pub.content).startsWith("ssh-ed25519 ")) {
          throw new Error(`ssh.encode did not emit a public line: ${pub?.content}`);
        }
        if (!String(pub.content).endsWith(" verb@smoke")) {
          throw new Error("ssh.encode dropped the comment");
        }
        const fp = arts.find((a) => tok(a, "fp"));
        const fp2 = arts.find((a) => tok(a, "fp2"));
        if (!String(fp?.content).startsWith("SHA256:")) {
          throw new Error(`ssh.fingerprint did not emit SHA256:…: ${fp?.content}`);
        }
        // The line's fingerprint and the live keypair's must agree — the
        // encode/decode pair round-tripped the same key.
        if (String(fp?.content) !== String(fp2?.content)) {
          throw new Error("fingerprint of decoded line differs from the source keypair");
        }
      },
    },
    {
      id: "ssh.encode.format=private.roundtrip",
      recipe: `genkey ec/p256 | out @id

in @id | ssh.encode format=private comment="verb@smoke" | out @pem

in @pem | ssh.decode | out @again

"private round trip" | utf8 | out @msg | ssh.sign key=@again | out @sig

in @id | ssh.encode | out @pub

in @msg | ssh.verify key=@pub signature=@sig | out @ok`,
      mode: "run",
      timeoutMs: 30_000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const pem = arts.find((a) => tok(a, "pem"));
        if (!String(pem?.content).includes("BEGIN OPENSSH PRIVATE KEY")) {
          throw new Error("ssh.encode format=private did not emit an openssh-key-v1 block");
        }
        const ok = arts.find((a) => tok(a, "ok"));
        if (String(ok?.content) !== "true") {
          throw new Error("signature made with the re-imported private key did not verify");
        }
      },
    },
    {
      // `ssh-rsa` names no digest, so the handle ssh.decode builds has to pick
      // one — and WebCrypto binds it for good at import. hash= is where the
      // user picks, and the generic sign/verify then honour it rather than
      // signing under an unasked-for digest.
      id: "ssh.decode.hash=sha256.rsa",
      recipe: `genkey rsa/2048 padding=pkcs1 | out @gen

in @gen | ssh.encode format=private | out @pem

in @pem | ssh.decode hash=sha256 | out @id

"rsa handle" | utf8 | out @msg | sign key=@id hash=sha-256 | base64url | out @sig

in @msg | verify key=@id signature=@sig hash=sha-256 | out @ok`,
      mode: "run",
      timeoutMs: 60_000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const ok = arts.find((a) => tok(a, "ok"));
        if (String(ok?.content) !== "true") {
          throw new Error("sha-256 sign/verify over an ssh.decode hash=sha256 handle failed");
        }
      },
    },
    {
      id: "ssh.sign.verify.namespace",
      recipe: `genkey ed25519 | out @id

in @id | ssh.encode | out @pub

"namespaced" | utf8 | out @msg | ssh.sign key=@id namespace=git | out @sig

in @msg | ssh.verify key=@pub signature=@sig namespace=git | out @ok

in @msg | ssh.verify -q key=@pub signature=@sig namespace=file | out @wrongns`,
      mode: "run",
      timeoutMs: 30_000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const ok = arts.find((a) => tok(a, "ok"));
        if (String(ok?.content) !== "true") throw new Error("git-namespace verify failed");
        // -q under the wrong namespace: false, not a throw — and never true.
        const wrong = arts.find((a) => tok(a, "wrongns"));
        if (String(wrong?.content) !== "false") {
          throw new Error(`namespace mismatch must soft-fail false, got: ${wrong?.content}`);
        }
      },
    },
    {
      id: "ssh.sign.hash=sha256.rsa",
      recipe: `genkey rsa/2048 | out @id

in @id | ssh.encode | out @pub

"rsa sshsig" | utf8 | out @msg | ssh.sign key=@id hash=sha256 | out @sig

in @msg | ssh.verify key=@pub signature=@sig | out @ok`,
      mode: "run",
      timeoutMs: 45_000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const ok = arts.find((a) => tok(a, "ok"));
        if (String(ok?.content) !== "true") throw new Error("rsa sha256 sshsig failed to verify");
      },
    },
    {
      id: "age.armor.passphrase",
      recipe: `"armored" | utf8 | age.encrypt passphrase="correct horse" armor=true | out @armored

in @armored | age.decrypt passphrase="correct horse" | utf8 | out @plain`,
      mode: "run",
      timeoutMs: 20000,
      assert(arts) {
        const armored = arts.find((a) => a.label?.includes("armored"));
        if (!armored?.content?.includes("BEGIN AGE ENCRYPTED FILE")) {
          throw new Error("age armor=true did not produce PEM-style armor");
        }
      },
    },
    {
      id: "age.encrypt.armor.false",
      recipe: `age.keygen | out @id2

in @id2 | age.recipient | out @pub2

"binary" | utf8 | age.encrypt to=@pub2 armor=false | out @bin`,
      mode: "run",
      timeoutMs: 20000,
    },
    // ── OTP (RFC 4226 / RFC 6238) ──
    // All real `run` cases: HMAC over a counter is pure SubtleCrypto, and the
    // `otpauth://` codec is string work, so nothing here needs a browser.
    {
      id: "otp.enrol.code.verify",
      recipe: `random 20 | tee
  - base32 | out @secret
| otp.uri issuer="Verb Smoke" account=smoke@example.com | tee
  - qr
| out @uri

in @secret | otp.code | out @code

in @code | otp.verify secret=@uri window=1 | out @ok`,
      mode: "run",
      timeoutMs: 20000,
      assert(arts) {
        // Exact labels, not the token match the other cases use: this recipe
        // emits a `qr`, whose tile is called "QR code" and would answer to a
        // search for "code".
        const tok = (a, n) => String(a.label || "") === n;
        const uri = arts.find((a) => tok(a, "uri"));
        if (!/^otpauth:\/\/totp\/Verb%20Smoke:smoke%40example\.com\?/.test(uri?.content)) {
          throw new Error(`otp.uri did not emit a Key URI: ${uri?.content}`);
        }
        // The URI is the shared secret plus a label, so the tile is masked —
        // the same contract `ssh.encode format=private` holds.
        if (!uri?.sensitive) throw new Error("otp.uri output was not marked sensitive");
        const code = arts.find((a) => tok(a, "code"));
        if (!/^\d{6}$/.test(String(code?.content))) {
          throw new Error(`otp.code did not emit six digits: ${code?.content}`);
        }
        const ok = arts.find((a) => tok(a, "ok"));
        if (String(ok?.content) !== "true") throw new Error("otp.verify rejected its own code");
        const qr = arts.find((a) => a.role === "qr");
        if (!qr?.revealable) throw new Error("a masked QR with no Reveal is a blank square");
      },
    },
    {
      id: "otp.hotp.counter.parse.fields",
      recipe: `random 20 | base32 | tee
  - out @secret
| otp.uri mode=hotp counter=3 algorithm=sha256 digits=8 issuer=Acme account=token-7 | out @uri

in @uri | tee
  - otp.parse secret | out @fsecret
| tee
  - otp.parse issuer | out @fissuer
| tee
  - otp.parse account | out @faccount
| tee
  - otp.parse algorithm | out @falgorithm
| tee
  - otp.parse digits | out @fdigits
| tee
  - otp.parse period | out @fperiod
| tee
  - otp.parse counter | out @fcounter
| otp.parse mode | out @fmode

in @secret | otp.code mode=hotp counter=3 algorithm=sha256 digits=8 | out @code

in @code | otp.verify -q secret=@secret mode=hotp counter=0 algorithm=sha256 digits=8 window=5 | out @resync`,
      mode: "run",
      timeoutMs: 20000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const at = (n) => String(arts.find((a) => tok(a, n))?.content);
        if (at("fmode") !== "hotp") throw new Error(`otp.parse mode: ${at("fmode")}`);
        if (at("fcounter") !== "3") throw new Error(`otp.parse counter: ${at("fcounter")}`);
        if (at("falgorithm") !== "SHA256") throw new Error(`otp.parse algorithm: ${at("falgorithm")}`);
        if (at("fdigits") !== "8") throw new Error(`otp.parse digits: ${at("fdigits")}`);
        if (at("fissuer") !== "Acme") throw new Error(`otp.parse issuer: ${at("fissuer")}`);
        if (at("faccount") !== "token-7") throw new Error(`otp.parse account: ${at("faccount")}`);
        if (at("fsecret") !== at("secret")) throw new Error("otp.parse lost the secret");
        // The look-ahead resynchronises a token pressed three times.
        if (at("resync") !== "true") throw new Error("hotp look-ahead did not resynchronise");
      },
    },
    {
      id: "otp.sha512.digits7.period60",
      recipe: `random 32 | base32 | tee
  - out @s3
| otp.uri algorithm=sha512 digits=7 period=60 issuer=Long account=ops@example.com | out @u3

in @s3 | otp.code algorithm=sha512 digits=7 period=60 at=1111111111 | out @c3

in @c3 | otp.verify secret=@s3 algorithm=sha512 digits=7 period=60 at=1111111111 window=0 | out @ok3`,
      mode: "run",
      timeoutMs: 20000,
      assert(arts) {
        const tok = (a, n) => String(a.label || "").split(/[^A-Za-z0-9]+/).includes(n);
        const c3 = arts.find((a) => tok(a, "c3"));
        if (!/^\d{7}$/.test(String(c3?.content))) {
          throw new Error(`digits=7 did not emit seven digits: ${c3?.content}`);
        }
        const u3 = arts.find((a) => tok(a, "u3"));
        if (!String(u3?.content).includes("period=60")) {
          throw new Error("otp.uri dropped period=60");
        }
        const ok3 = arts.find((a) => tok(a, "ok3"));
        if (String(ok3?.content) !== "true") throw new Error("sha512/7-digit verify failed");
      },
    },
    // ── JOSE (RFC 7515 / 7516 / 7519) ──
    // All real `run` cases: these are pure WebCrypto, so unlike the WebRTC and
    // clipboard ops there is nothing here that needs a browser the test does
    // not have. The per-algorithm matrices are below in `joseMatrix`.
    {
      id: "jose.decode",
      recipe: "input | jose.decode | out @claims",
      mode: "run",
      bindings: { inputs: { text: { value: RFC7515_A1_TOKEN } } },
      assert: (a) => {
        const body = JSON.parse(String(a[a.length - 1].content));
        if (body.verified !== false) throw new Error("decode must report unverified");
        if (body.claims?.iss !== "joe") throw new Error("expected the RFC 7515 A.1 claims");
      },
    },
    {
      id: "jose.decode.format=compact",
      recipe: "input | jose.decode compact | out @claims",
      mode: "run",
      bindings: { inputs: { text: { value: RFC7515_A1_TOKEN } } },
      assert: (a) => {
        const line = String(a[a.length - 1].content);
        if (line.includes("\n")) throw new Error("compact format must be one line");
      },
    },
    {
      id: "jose.verify.expiry=ignore",
      // Signature valid, `exp` long past: the default would refuse, and
      // `expiry=ignore` is how you look at an old token on purpose.
      recipe: `genkey ed25519 | out @k

'{"sub":"basilisk","exp":1300819380}' | jose.sign key=@k | out @token

@token | jose.verify key=@k expiry=ignore | out @claims`,
      mode: "run",
    },
  ];

  return cases;
}

/** RFC 7515 A.1 — the HS256 example, used as a decode fixture. */
const RFC7515_A1_TOKEN =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
  ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
  ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/**
 * JOSE algorithm matrices — one real sign→verify (or encrypt→decrypt) round
 * trip per enum value, since every one of them is a WebCrypto primitive and
 * a compile-only case would prove nothing about the wire format.
 * @returns {VerbSmokeCase[]}
 */
function joseMatrix() {
  /** JWS alg enum value → the `genkey` spelling that produces a matching key. */
  const SIGN_KEYS = {
    hs256: "genkey hmac/sha256",
    hs384: "genkey hmac/sha384",
    hs512: "genkey hmac/sha512",
    rs256: "genkey rsa/2048 usage=sign padding=pkcs1 hash=sha-256",
    ps256: "genkey rsa/2048 usage=sign padding=pss hash=sha-256",
    es256: "genkey ec/p256 usage=sign",
    es384: "genkey ec/p384 usage=sign",
    es512: "genkey ec/p521 usage=sign",
    eddsa: "genkey ed25519 usage=sign",
  };

  /** @type {VerbSmokeCase[]} */
  const out = [];

  const signAlgs = getStep("jose.sign")?.params?.find((p) => p.name === "alg")?.enum || [];
  for (const alg of signAlgs) {
    if (alg === "auto") {
      // `auto` is the default, so it is credited by any case that omits
      // `alg=` — but a case that *shows* it reading the key off an Ed25519
      // slot is the one worth having.
      out.push({
        id: "jose.sign.alg=auto",
        recipe: `genkey ed25519 | out @k

'{"sub":"basilisk"}' | jose.sign key=@k | out @token

@token | jose.verify key=@k | out @claims`,
        mode: "run",
        assert: (a) => {
          const token = a.find((x) => x.label === "token");
          if (!token) throw new Error("no token tile");
          const header = JSON.parse(
            Buffer.from(String(token.content).split(".")[0], "base64url").toString()
          );
          if (header.alg !== "EdDSA") throw new Error(`auto picked ${header.alg}, want EdDSA`);
        },
      });
      continue;
    }
    const gen = SIGN_KEYS[alg];
    if (!gen) continue;
    const rsa = gen.includes("rsa/");
    out.push({
      id: `jose.sign.alg=${alg}`,
      recipe: `${gen} | out @k

'{"sub":"basilisk","iat":1700000000}' | jose.sign key=@k alg=${alg} | out @token

@token | jose.verify key=@k alg=${alg} | out @claims`,
      mode: "run",
      timeoutMs: rsa ? 90_000 : 30_000,
      assert: (a) => {
        const claims = a.find((x) => x.label === "claims");
        if (!claims) throw new Error("no verified claims tile");
        if (JSON.parse(String(claims.content)).sub !== "basilisk") {
          throw new Error("round trip lost the payload");
        }
      },
    });
  }

  /** JWE alg enum value → the key that manages the CEK, and its slot name. */
  const JWE_KEYS = {
    dir: "genkey aes/256",
    a128kw: "genkey aes/128",
    a256kw: "genkey aes/256",
    "rsa-oaep-256": "genkey rsa/2048 usage=encrypt hash=sha-256",
  };
  const jweAlgs = getStep("jose.encrypt")?.params?.find((p) => p.name === "alg")?.enum || [];
  for (const alg of jweAlgs) {
    const gen = JWE_KEYS[alg];
    if (!gen) continue;
    out.push({
      id: `jose.encrypt.alg=${alg}`,
      recipe: `${gen} | out @k

'sealed by basilisk' | jose.encrypt key=@k alg=${alg} | out @jwe

@jwe | jose.decrypt key=@k | out @plain`,
      mode: "run",
      timeoutMs: alg.startsWith("rsa") ? 90_000 : 30_000,
      assert: (a) => {
        const plain = a.find((x) => x.label === "plain");
        if (String(plain?.content).trim() !== "sealed by basilisk") {
          throw new Error(`JWE round trip returned ${plain?.content}`);
        }
      },
    });
  }

  // `enc` needs a `dir` key of the matching size, which is the strictest
  // pairing — an A128GCM content key is 128 bits, not "whatever the slot has".
  const encs = getStep("jose.encrypt")?.params?.find((p) => p.name === "enc")?.enum || [];
  for (const enc of encs) {
    const bits = enc.slice(1, 4);
    out.push({
      id: `jose.encrypt.enc=${enc}`,
      recipe: `genkey aes/${bits} | out @cek

'sealed by basilisk' | jose.encrypt key=@cek enc=${enc} | out @jwe

@jwe | jose.decrypt key=@cek | out @plain`,
      mode: "run",
    });
  }

  return out;
}

/**
 * Expand genkey algorithm enum + usage/padding/hash corners.
 * @returns {VerbSmokeCase[]}
 */
function genkeyMatrix() {
  const algs = getStep("genkey")?.params?.find((p) => p.name === "alg")?.enum || [];
  /** @type {VerbSmokeCase[]} */
  const out = [];
  for (const alg of algs) {
    let recipe;
    if (alg.startsWith("aes/") || alg.startsWith("hmac/")) {
      recipe = `genkey ${alg} | export jwk | out @k`;
    } else if (alg.startsWith("rsa/")) {
      recipe = `genkey ${alg} hash=sha-256 | :public | export spki | pem | out @pub`;
    } else if (alg === "x25519") {
      recipe = `genkey ${alg} usage=derive | export jwk | out @k`;
    } else {
      recipe = `genkey ${alg} | export pkcs8 | pem | out @priv`;
    }
    out.push({
      id: `genkey.alg=${alg}`,
      recipe,
      mode: "run",
      timeoutMs: alg.startsWith("rsa/") ? 90_000 : 30_000,
    });
  }
  out.push({
    id: "genkey.rsa.padding=pkcs1",
    recipe:
      "genkey rsa/2048 usage=sign padding=pkcs1 hash=sha-256 | :public | export spki | pem | out @pub",
    mode: "run",
    timeoutMs: 60_000,
  });
  out.push({
    id: "genkey.rsa.hash=sha-384",
    recipe:
      "genkey rsa/2048 usage=encrypt hash=sha-384 | :public | export spki | pem | out @pub",
    mode: "run",
    timeoutMs: 60_000,
  });
  out.push({
    id: "genkey.rsa.hash=sha-512",
    recipe:
      "genkey rsa/2048 usage=encrypt hash=sha-512 | :public | export spki | pem | out @pub",
    mode: "run",
    timeoutMs: 60_000,
  });
  out.push({
    id: "genkey.usage=sign",
    recipe: "genkey ed25519 usage=sign | export jwk | out @k",
    mode: "run",
  });
  out.push({
    id: "genkey.usage=encrypt",
    recipe: "genkey aes/256 usage=encrypt | export jwk | out @k",
    mode: "run",
  });
  return out;
}

/**
 * HKDF / PBKDF2 / ECDH `as=` enum matrix (deriveKey targets).
 * @returns {VerbSmokeCase[]}
 */
function deriveAsMatrix() {
  const asEnum = getStep("hkdf")?.params?.find((p) => p.name === "as")?.enum || [];
  /** @type {VerbSmokeCase[]} */
  const out = [];
  for (const as of asEnum) {
    if (as === "bytes") continue; // covered in base
    out.push({
      id: `hkdf.as=${as}`,
      recipe: `random 32 | hkdf 32 as=${as} | export jwk | out @k`,
      mode: "run",
    });
    out.push({
      id: `pbkdf2.as=${as}`,
      recipe: `passphrase mode=char length=16 | pbkdf2 32 iterations=500 as=${as} | export jwk | out @k`,
      mode: "run",
      timeoutMs: 30_000,
    });
  }
  // ecdh as= — X25519 shared secret is 256 bits; skip HMAC-384/512 deriveKey.
  for (const as of asEnum) {
    if (as === "hmac/sha384" || as === "hmac/sha512") {
      // ECDH+HMAC deriveKey is not supported by Chromium/Node SubtleCrypto.
      out.push({
        id: `ecdh.as=${as}`,
        recipe: `genkey ec/p521 | out @local

genkey ec/p521 | :public | out @peer

ecdh private=@local peer=@peer as=${as} | export jwk | out @k`,
        mode: "compile",
      });
      continue;
    }
    if (as === "bytes") {
      out.push({
        id: "ecdh.as=bytes",
        recipe: `genkey x25519 | out @local

genkey x25519 | :public | out @peer

ecdh private=@local peer=@peer as=bytes | encode hex | out @shared`,
        mode: "run",
      });
      continue;
    }
    out.push({
      id: `ecdh.as=${as}`,
      recipe: `genkey x25519 | out @local

genkey x25519 | :public | out @peer

ecdh private=@local peer=@peer as=${as} | export jwk | out @k`,
      mode: "run",
    });
  }
  return out;
}

/**
 * unwrap.alg enum (wrapped key algorithm).
 * @returns {VerbSmokeCase[]}
 */
function unwrapAlgMatrix() {
  const algs = getStep("unwrap")?.params?.find((p) => p.name === "alg")?.enum || [];
  /** @type {VerbSmokeCase[]} */
  const out = [];
  for (const alg of algs) {
    const gen = alg.startsWith("aes-kw/")
      ? `random 32 | hkdf 32 as=${alg} | out @cek`
      : `genkey ${alg} | out @cek`;
    const kek = alg.startsWith("aes-kw/")
      ? `random 32 | hkdf 32 as=aes-kw/256 | out @kek`
      : `genkey aes/256 | out @kek`;
    out.push({
      id: `unwrap.alg=${alg}`,
      recipe: `${kek}

${gen}

wrap key=@kek target=@cek mode=aes-kw | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-kw alg=${alg} | out @cek2`,
      mode: "run",
      timeoutMs: 30_000,
    });
  }
  return out;
}

/**
 * AES-GCM tagLength corners not covered by base (104/112/120).
 * @returns {VerbSmokeCase[]}
 */
function gcmTagMatrix() {
  /** @type {VerbSmokeCase[]} */
  const out = [];
  for (const tag of ["104", "112", "120"]) {
    out.push({
      id: `aes-gcm.tagLength=${tag}`,
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-gcm key=@cek tagLength=${tag} | encode hex | out @ct

in @ct | decode hex | aes-gcm -d key=@cek tagLength=${tag} | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: `tag${tag}` } } },
    });
    out.push({
      id: `wrap.tagLength=${tag}`,
      recipe: `genkey aes/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek mode=aes-gcm tagLength=${tag} | out @wrapped

in @wrapped | unwrap key=@kek mode=aes-gcm alg=aes/256 tagLength=${tag} | out @cek2`,
      mode: "run",
    });
  }
  return out;
}

/**
 * PEM label enum leftovers (EC / RSA PRIVATE KEY).
 * @returns {VerbSmokeCase[]}
 */
function pemLabelMatrix() {
  return [
    {
      id: 'pem.label="EC PRIVATE KEY"',
      recipe:
        'genkey ec/p256 | export pkcs8 | pem label="EC PRIVATE KEY" | out @p',
      mode: "run",
    },
    {
      id: 'pem.label="RSA PRIVATE KEY"',
      recipe:
        'genkey rsa/2048 | export pkcs8 | pem label="RSA PRIVATE KEY" | out @p',
      mode: "run",
      timeoutMs: 60_000,
    },
  ];
}

/**
 * import format/alg/usage/padding/hash coverage.
 * @returns {VerbSmokeCase[]}
 */
function importMatrix() {
  /** @type {VerbSmokeCase[]} */
  const out = [
    {
      id: "import.format=d",
      recipe:
        "genkey ec/p256 | export scalar | import scalar alg=ec/p256 | export pkcs8 | pem | out @p",
      mode: "run",
    },
    {
      id: "import.usage=sign",
      recipe:
        "genkey ed25519 | export jwk | import jwk alg=ed25519 usage=sign | export jwk | out @k",
      mode: "run",
    },
    {
      id: "import.usage=derive",
      recipe:
        "genkey x25519 | export jwk | import jwk alg=x25519 usage=derive | export jwk | out @k",
      mode: "run",
    },
    {
      id: "import.usage=encrypt",
      recipe:
        "genkey aes/256 | export jwk | import jwk alg=aes/256 usage=encrypt | export jwk | out @k",
      mode: "run",
    },
    {
      id: "import.padding=pkcs1",
      recipe:
        "genkey rsa/2048 usage=sign padding=pkcs1 | export jwk | import jwk alg=rsa/2048 usage=sign padding=pkcs1 hash=sha-256 | export jwk | out @k",
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "import.hash=sha-384",
      recipe:
        "genkey rsa/2048 hash=sha-384 | export jwk | import jwk alg=rsa/2048 hash=sha-384 | export jwk | out @k",
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "import.hash=sha-512",
      recipe:
        "genkey rsa/2048 hash=sha-512 | export jwk | import jwk alg=rsa/2048 hash=sha-512 | export jwk | out @k",
      mode: "run",
      timeoutMs: 60_000,
    },
  ];
  for (const alg of [
    "ec/p384",
    "ec/p521",
    "x25519",
    "rsa/2048",
    "rsa/3072",
    "rsa/4096",
    "aes/128",
    "aes/192",
    "hmac/sha256",
    "hmac/sha384",
    "hmac/sha512",
  ]) {
    let recipe;
    if (alg.startsWith("aes/") || alg.startsWith("hmac/")) {
      recipe = `genkey ${alg} | export jwk | import jwk alg=${alg} | export jwk | out @k`;
    } else if (alg.startsWith("rsa/")) {
      recipe = `genkey ${alg} | export jwk | import jwk alg=${alg} | export jwk | out @k`;
    } else if (alg === "x25519") {
      recipe = `genkey ${alg} | export jwk | import jwk alg=${alg} | export jwk | out @k`;
    } else {
      // EC P-384/P-521: pkcs8 round-trip avoids JWK public-import usage mismatch
      recipe = `genkey ${alg} | export pkcs8 | import pkcs8 alg=${alg} | export pkcs8 | pem | out @k`;
    }
    out.push({
      id: `import.alg=${alg}`,
      recipe,
      mode: "run",
      timeoutMs: alg.startsWith("rsa/") ? 90_000 : 30_000,
    });
  }
  return out;
}

/**
 * foreach selector + agent expiry presets + gpg.encrypt modes.
 * @returns {VerbSmokeCase[]}
 */
function miscParamMatrix() {
  return [
    {
      id: "foreach:keys",
      recipe: `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach :keys
  - out @k`,
      mode: "run",
    },
    {
      id: "foreach:values",
      recipe: `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach :values
  - out @v`,
      mode: "run",
    },
    {
      id: "agent.save.expiry=1d",
      recipe:
        'gpg.genkey email="exp1d@example.com" | agent.save protection=device expiry=1d | out @p',
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "agent.save.expiry=1w",
      recipe:
        'gpg.genkey email="exp1w@example.com" | agent.save protection=device expiry=1w | out @p',
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "agent.save.expiry=1m",
      recipe:
        'gpg.genkey email="exp1m@example.com" | agent.save protection=device expiry=1m | out @p',
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "agent.save.expiry=1y",
      recipe:
        'gpg.genkey email="exp1y@example.com" | agent.save protection=device expiry=1y | out @p',
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "hkp.filter.flags",
      recipe: `hkp.search "alice@example.com" | hkp.filter approved=false encrypt=false | out @f`,
      mode: "run",
    },
    {
      id: "peek.format=auto",
      recipe: "random 8 | peek x format=auto | encode hex | out @h",
      mode: "run",
    },
    {
      id: "peek.format=hex",
      recipe: "random 8 | peek x format=hex | encode hex | out @h",
      mode: "run",
    },
    {
      id: "peek.format=text",
      recipe: "input | peek x format=text | out @t",
      mode: "run",
      bindings: { inputs: { text: { value: "peek" } } },
    },
    {
      id: "peek.format=hexdump",
      recipe: "random 8 | peek x format=hexdump | encode hex | out @h",
      mode: "run",
    },
    {
      id: "peek.format=jwk",
      recipe: "genkey aes/256 | export jwk | peek x format=jwk | out @j",
      mode: "run",
    },
    {
      id: "peek.format=meta",
      recipe: "genkey ec/p256 | peek x format=meta | export jwk | out @j",
      mode: "run",
    },
  ];
}

/**
 * Encrypt to the verb-smoke vault key, so `agent.decrypt` has real
 * ciphertext to open. Built with openpgp directly rather than through a
 * recipe: `gpg.encrypt` emits its ciphertext as an artifact and returns a
 * null-data value, which no later cell can read from a slot.
 * @param {string} text
 */
export async function encryptToVerbSmokeKey(text) {
  const k = await ensureGpgKey();
  const pub = await readKey({ armoredKey: k.publicKey });
  return openpgpEncrypt({
    message: await createMessage({ text }),
    encryptionKeys: pub,
  });
}

/**
 * Dynamic vault-dependent cases: agent.unlock / agent.pub / the boundary
 * ops, after the test setup has saved a device key.
 * @returns {Promise<VerbSmokeCase[]>}
 */
export async function agentUnlockCases() {
  const k = await ensureGpgKey();
  const pub = await readKey({ armoredKey: k.publicKey });
  const fpr = pub.getFingerprint().toUpperCase();
  // An ssh-kind key, minted and vaulted here so `agent.sign format=ssh` has
  // something to name. Building it at catalog time rather than in a `setup`
  // hook is what lets the recipe carry the literal SHA256: id.
  const { execAgentSave } = await import("../../lib/toolkit/agent-ops.js");
  const sshPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const sshSaved = await execAgentSave(
    { type: "keypair", data: sshPair, meta: { alg: "ed25519" } },
    { protection: "device", email: "verb-smoke@example.com" }
  );
  const sshId = sshSaved.meta.fingerprint;
  // Caller must have saved the pgp key into vault (test setup).
  return [
    {
      id: "agent.unlock",
      recipe: `agent.unlock ${fpr} | out @me`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "agent.pub",
      recipe: `agent.pub ${fpr} | out @pub`,
      mode: "run",
    },
    // Boundary ops (§26f). The approval gate is stubbed to approve once —
    // the gate's own semantics (deny, scoping, batching, expiry) are pinned
    // adversarially in approval-gate.test.js; what these cover is that the
    // ops compile, dispatch and produce real output through the registry.
    {
      id: "agent.sign",
      recipe: `"boundary smoke" | utf8 | agent.sign ${fpr} | out @sig`,
      mode: "run",
      timeoutMs: 60_000,
      setup: () => setApprovalGate(async () => "once"),
      assert: (arts) => {
        const sig = arts.find((a) => /sig/.test(String(a.label || "")));
        if (!String(sig?.content || "").includes("BEGIN PGP SIGNED MESSAGE")) {
          throw new Error(`agent.sign produced no OpenPGP signature: ${sig?.content}`);
        }
      },
    },
    {
      id: "agent.sign.mode=detached",
      recipe: `"detached smoke" | utf8 | agent.sign ${fpr} mode=detached | out @sig`,
      mode: "run",
      timeoutMs: 60_000,
      setup: () => setApprovalGate(async () => "once"),
      assert: (arts) => {
        const sig = arts.find((a) => /sig/.test(String(a.label || "")));
        if (!String(sig?.content || "").includes("BEGIN PGP SIGNATURE")) {
          throw new Error(`agent.sign mode=detached produced no signature: ${sig?.content}`);
        }
      },
    },
    {
      id: "agent.sign.format=gpg",
      recipe: `"explicit gpg" | utf8 | agent.sign ${fpr} format=gpg | out @sig`,
      mode: "run",
      timeoutMs: 60_000,
      setup: () => setApprovalGate(async () => "once"),
    },
    {
      id: "agent.sign.format=ssh",
      // The ssh key is minted and vaulted while the catalog is built, so the
      // recipe can name its SHA256: id literally — same shape as the HKP
      // fingerprint substitution above.
      recipe: `"explicit sshsig" | utf8 | agent.sign ${sshId} format=ssh namespace=git | out @sig`,
      mode: "run",
      timeoutMs: 60_000,
      setup: () => setApprovalGate(async () => "once"),
      assert: (arts) => {
        const sig = arts.find((a) => /sig/.test(String(a.label || "")));
        if (!String(sig?.content || "").includes("BEGIN SSH SIGNATURE")) {
          throw new Error(`agent.sign format=ssh produced no sshsig: ${sig?.content}`);
        }
      },
    },
    {
      id: "agent.decrypt",
      // Ciphertext arrives through `input`, as the design's own example
      // writes it — `gpg.encrypt` emits its ciphertext as an *artifact* and
      // returns a null-data value, so a slot cannot carry it to a later cell.
      recipe: `input | agent.decrypt ${fpr} | out @plain`,
      mode: "run",
      timeoutMs: 60_000,
      setup: () => setApprovalGate(async () => "once"),
      bindings: async () => ({
        inputs: { text: { value: await encryptToVerbSmokeKey("round trip") } },
      }),
      assert: (arts) => {
        const plain = arts.find((a) => /plain/.test(String(a.label || "")));
        if (String(plain?.content) !== "round trip") {
          throw new Error(`agent.decrypt lost the payload: ${plain?.content}`);
        }
      },
    },
  ];
}

/**
 * Full catalog (static). Prefer `listAllVerbSmokeCases` in tests (fills HKP fpr).
 * @returns {VerbSmokeCase[]}
 */
export function listVerbSmokeCases() {
  return [
    ...baseCases(),
    ...genkeyMatrix(),
    ...deriveAsMatrix(),
    ...unwrapAlgMatrix(),
    ...gcmTagMatrix(),
    ...pemLabelMatrix(),
    ...importMatrix(),
    ...miscParamMatrix(),
    ...joseMatrix(),
  ];
}

/**
 * Static catalog + HKP fingerprint + agent.unlock/pub (vault must be seeded).
 * @returns {Promise<VerbSmokeCase[]>}
 */
export async function listAllVerbSmokeCases() {
  const k = await ensureGpgKey();
  const pub = await readKey({ armoredKey: k.publicKey });
  const fpr = pub.getFingerprint().toUpperCase();
  const cases = listVerbSmokeCases().map((c) => {
    if (c.id === "hkp.get" || c.id === "hkp.get.refresh") {
      return {
        ...c,
        recipe: c.recipe.replace("__FPR__", fpr),
      };
    }
    return c;
  });
  return [...cases, ...(await agentUnlockCases())];
}

/**
 * @param {VerbSmokeCase} c
 */
export function compileVerbCase(c) {
  const src = migrateRecipe(c.recipe).recipe;
  return compileRecipe(src);
}

/**
 * @param {VerbSmokeCase} c
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 */
export async function runVerbCase(c, bindings) {
  if (c.mode === "skip") {
    return { skipped: true, reason: c.skipReason || "skipped" };
  }
  if (c.setup) await c.setup();
  const { ast, validation } = compileVerbCase(c);
  if (!ast || !validation.ok) {
    const msg = (validation.errors || []).map((e) => e.message).join(" · ");
    throw new Error(`${c.id}: compile failed — ${msg}`);
  }
  if (c.mode === "compile") {
    return { skipped: false, arts: [], validation };
  }
  let b = bindings;
  if (b == null) {
    b =
      typeof c.bindings === "function" ? await c.bindings() : c.bindings || {};
  }
  const arts = await runRecipe(ast, b);
  if (c.assert) c.assert(arts);
  return { skipped: false, arts, validation };
}

/**
 * Ops with no `op:name` coverage across cases.
 * @param {VerbSmokeCase[]} [cases]
 * @returns {string[]}
 */
export function uncoveredOps(cases = listVerbSmokeCases()) {
  /** @type {Set<string>} */
  const covered = new Set();
  for (const c of cases) {
    if (c.mode === "skip") continue;
    const { ast, validation } = compileVerbCase(c);
    if (!validation.ok || !ast) continue;
    for (const k of coversFromAst(ast)) {
      if (k.startsWith("op:")) covered.add(k.slice(3));
    }
  }
  return listSteps()
    .map((s) => s.name)
    .filter((n) => !covered.has(n));
}

/**
 * Cases that still use mode=skip (should be empty for exhaustive CI).
 * @param {VerbSmokeCase[]} [cases]
 * @returns {string[]}
 */
export function skippedVerbCases(cases = listVerbSmokeCases()) {
  return cases.filter((c) => c.mode === "skip").map((c) => c.id);
}

/**
 * Enum / bool param values not exercised.
 * @param {VerbSmokeCase[]} [cases]
 * @returns {string[]}
 */
export function uncoveredEnumParams(cases = listVerbSmokeCases()) {
  /** @type {Set<string>} */
  const covered = new Set();
  for (const c of cases) {
    if (c.mode === "skip") continue;
    const { ast, validation } = compileVerbCase(c);
    if (!validation.ok || !ast) continue;
    for (const k of coversFromAst(ast)) {
      if (!k.startsWith("op:")) covered.add(k);
    }
  }

  /** @type {string[]} */
  const gaps = [];
  for (const step of listSteps()) {
    for (const p of step.params || []) {
      if (p.type === "enum" && p.enum) {
        for (const v of p.enum) {
          const key = `${step.name}.${p.name}=${v}`;
          if (!covered.has(key)) gaps.push(key);
        }
      }
      if (p.type === "bool" || p.type === "flag") {
        for (const v of ["true", "false"]) {
          const key = `${step.name}.${p.name}=${v}`;
          const opUsed = [...covered].some((x) =>
            x.startsWith(`${step.name}.`)
          );
          if (opUsed && !covered.has(key)) gaps.push(key);
        }
      }
    }
  }
  return gaps;
}

export { ensureGpgKey, sampleAttestationB64 };

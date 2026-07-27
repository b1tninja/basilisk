/**
 * Exhaustive toolkit verb / param smoke catalog (Vitest — not CAST).
 * Lives under `src/test/helpers/` so production bundles never import it.
 *
 * Coverage gates:
 * - every `listSteps()` op appears in ≥1 case
 * - every enum param value is exercised by ≥1 compiled recipe AST
 * - bool/flag params exercised both ways where the op is used
 */

import { generateKey, readKey } from "openpgp";
import { runRecipe } from "../../lib/toolkit/engine.js";
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
      recipe: "random | hex | out @r",
      mode: "run",
      assert: (a) => {
        if (!a.some((x) => /^[0-9a-f]{64}$/.test(String(x.content)))) {
          throw new Error("expected 32-byte hex");
        }
      },
    },
    {
      id: "random.length=16",
      recipe: "random 16 | hex | out @r",
      mode: "run",
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
      recipe: "input | utf8 | hex | text note",
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
        "random 24 | base64 | base64 -d | base64url | base64url -d | hex | hex -d | base32 | base32 -d | der | hex | out @x",
      mode: "run",
    },
    {
      id: "pem.labels",
      recipe: `genkey ec/p256 | export pkcs8 | pem label="PRIVATE KEY" | out @priv

genkey ec/p256 | .public | export spki | pem label="PUBLIC KEY" | out @pub`,
      mode: "run",
      timeoutMs: 30_000,
    },
    {
      id: "pem.decode",
      recipe:
        "genkey ec/p256 | export pkcs8 | pem | pem -d | pem label=auto | out @again",
      mode: "run",
    },

    // —— webcrypto core ——
    {
      id: "digest.sha-256",
      recipe: "input | utf8 | digest sha-256 | hex | out @d256",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "digest.sha-384",
      recipe: "input | utf8 | digest alg=sha-384 | hex | out @d384",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "digest.sha-512",
      recipe: "input | utf8 | digest alg=sha-512 | hex | out @d512",
      mode: "run",
      bindings: { inputs: { text: { value: "digest" } } },
    },
    {
      id: "digest.sha-1",
      recipe: "input | utf8 | digest alg=sha-1 | hex | out @d1",
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

input | utf8 | aes-gcm key=@cek | hex | out @ct

in @ct | hex -d | aes-gcm -d key=@cek | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "gcm" } } },
    },
    {
      id: "aes-gcm.tagLength=96",
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-gcm key=@cek tagLength=96 | hex | out @ct

in @ct | hex -d | aes-gcm -d key=@cek tagLength=96 | utf8 | out @pt`,
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

input | utf8 | aes-cbc key=@cek | hex | out @ct

in @ct | hex -d | aes-cbc -d key=@cek | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "cbc" } } },
    },
    {
      id: "aes-ctr.roundtrip",
      recipe: `genkey aes/256 | out @cek

input | utf8 | aes-ctr key=@cek length=64 | hex | out @ct

in @ct | hex -d | aes-ctr -d key=@cek length=64 | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "ctr" } } },
    },
    {
      id: "rsa-oaep.roundtrip",
      recipe: `genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-oaep key=@rk | hex | out @ct

in @ct | hex -d | rsa-oaep -d key=@rk | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "oaep" } } },
      timeoutMs: 60_000,
    },
    {
      id: "rsa-pkcs1.roundtrip",
      recipe: `genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-pkcs1 key=@rk | hex | out @ct

in @ct | hex -d | rsa-pkcs1 -d key=@rk | utf8 | out @pt`,
      mode: "run",
      bindings: { inputs: { text: { value: "pkcs1" } } },
      timeoutMs: 60_000,
    },
    {
      id: "hkdf.bytes+hash",
      recipe: `random 32 | hkdf 32 hash=sha-256 salt=s info=i | hex | out @a

random 32 | hkdf 32 hash=sha-384 | hex | out @b

random 32 | hkdf 32 hash=sha-512 | hex | out @c`,
      mode: "run",
    },
    {
      id: "pbkdf2.bytes+hash",
      recipe: `passphrase mode=char length=16 | pbkdf2 32 iterations=1000 hash=sha-256 | hex | out @a

passphrase mode=char length=16 | pbkdf2 32 iterations=1000 hash=sha-384 | hex | out @b

passphrase mode=char length=16 | pbkdf2 32 iterations=1000 hash=sha-512 | hex | out @c`,
      mode: "run",
      timeoutMs: 60_000,
    },
    {
      id: "ecdh.x25519",
      recipe: `genkey x25519 | out @local

genkey x25519 | .public | out @peer

ecdh private=@local peer=@peer | hex | out @shared`,
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
      recipe: "genkey aes/256 | export raw | hex | out @raw",
      mode: "run",
    },
    {
      id: "export.d.alias",
      recipe: "genkey ec/p256 | export d | hex | out @d",
      mode: "run",
    },
    {
      id: "import.spki",
      recipe:
        "genkey ec/p256 | .public | export spki | import spki alg=ec/p256 | .public | export spki | pem | out @pub",
      mode: "run",
    },

    // —— SSS / BLIP39 / flow ——
    {
      id: "sss.blip39.foreach.at",
      recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share

random 32 | sss.split threshold=2 shares=3 | blip39 | at 1 | out @one

random 32 | sss.split threshold=2 shares=3 | blip39 | foreach .items
  - .value | out @item`,
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
      recipe: "shares | blip39 -d | sss.combine | base64 | out @secret",
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
  - .public | export spki which=public | pem | out @public
  - .private | inspect format=hex
| peek keypair format=meta | export pkcs8 | pem | out @private

in @private | pem -d | as opaque | hex | out @hex

genkey ec/p256 | .public | export spki which=public | pem | out @pub2`,
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
      recipe: `random 32 | as master | hex | out @m

random 32 | as scalar | hex | out @s

random 32 | as opaque | hex | out @o`,
      mode: "run",
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
      recipe: `input | gpg.symencrypt name=env | sss.split threshold=2 shares=3 | blip39 | foreach
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
        "shares | blip39 -d | sss.combine | gpg.symdecrypt | utf8 | out @pem",
      mode: "run",
      bindings: async () => {
        const pem =
          "-----BEGIN PRIVATE KEY-----\nMIIBverbsmoke\n-----END PRIVATE KEY-----";
        const { ast } = compileRecipe(
          `input | gpg.symencrypt name=env | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out @share`
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
      recipe: "webauthn.create user=verb-smoke | hex",
      mode: "run",
      assert: (arts) => {
        if (!arts.some((a) => /^[0-9a-f]{64}$/.test(String(a.content || "")))) {
          throw new Error("expected 32-byte PRF IKM hex from webauthn.create");
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
      recipe: "webauthn.prf | hex",
      mode: "run",
      setup: async () => {
        // Ensure prf-meta exists (create may not have run yet if tests reorder).
        const { createPasskeyPrf } = await import("../../lib/vault.js");
        await createPasskeyPrf("verb-smoke-prf-setup");
      },
      assert: (arts) => {
        if (!arts.some((a) => /^[0-9a-f]{64}$/.test(String(a.content || "")))) {
          throw new Error("expected 32-byte PRF IKM hex from webauthn.prf");
        }
      },
    },
    {
      id: "webauthn.attest.mds",
      recipe: `input | base64 -d | webauthn.attest | out @att

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
  ];

  return cases;
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
      recipe = `genkey ${alg} hash=sha-256 | .public | export spki | pem | out @pub`;
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
      "genkey rsa/2048 usage=sign padding=pkcs1 hash=sha-256 | .public | export spki | pem | out @pub",
    mode: "run",
    timeoutMs: 60_000,
  });
  out.push({
    id: "genkey.rsa.hash=sha-384",
    recipe:
      "genkey rsa/2048 usage=encrypt hash=sha-384 | .public | export spki | pem | out @pub",
    mode: "run",
    timeoutMs: 60_000,
  });
  out.push({
    id: "genkey.rsa.hash=sha-512",
    recipe:
      "genkey rsa/2048 usage=encrypt hash=sha-512 | .public | export spki | pem | out @pub",
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

genkey ec/p521 | .public | out @peer

ecdh private=@local peer=@peer as=${as} | export jwk | out @k`,
        mode: "compile",
      });
      continue;
    }
    if (as === "bytes") {
      out.push({
        id: "ecdh.as=bytes",
        recipe: `genkey x25519 | out @local

genkey x25519 | .public | out @peer

ecdh private=@local peer=@peer as=bytes | hex | out @shared`,
        mode: "run",
      });
      continue;
    }
    out.push({
      id: `ecdh.as=${as}`,
      recipe: `genkey x25519 | out @local

genkey x25519 | .public | out @peer

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

input | utf8 | aes-gcm key=@cek tagLength=${tag} | hex | out @ct

in @ct | hex -d | aes-gcm -d key=@cek tagLength=${tag} | utf8 | out @pt`,
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
        "genkey ec/p256 | export d | import d alg=ec/p256 | export pkcs8 | pem | out @p",
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
      id: "foreach.keys",
      recipe: `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach .keys
  - out @k`,
      mode: "run",
    },
    {
      id: "foreach.values",
      recipe: `random 16 | sss.split threshold=2 shares=3 | blip39 | foreach .values
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
      recipe: "random 8 | peek x format=auto | hex | out @h",
      mode: "run",
    },
    {
      id: "peek.format=hex",
      recipe: "random 8 | peek x format=hex | hex | out @h",
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
      recipe: "random 8 | peek x format=hexdump | hex | out @h",
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
 * Dynamic agent.unlock / agent.pub after saving a device key.
 * @returns {Promise<VerbSmokeCase[]>}
 */
export async function agentUnlockCases() {
  const k = await ensureGpgKey();
  const pub = await readKey({ armoredKey: k.publicKey });
  const fpr = pub.getFingerprint().toUpperCase();
  // Caller must have saved the key into vault (test setup).
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

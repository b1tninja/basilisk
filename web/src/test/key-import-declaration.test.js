/**
 * `import jwk` and `keypair` produce the key the recipe declared, or nothing.
 *
 * The measured defect: `input | import jwk alg=ec/p256 | export pkcs8 | encode
 * hex | out $k` compiled with **zero errors**, and an `oct` JWK ran through it
 * to `0000…` — 32 raw AES bytes, under a recipe that said pkcs8. The compiler
 * typed the tip from `alg=` (`genkeyOutputBase`) while `importBoundJwk` typed
 * it from `kty`, `crv` and `d`: the body decided, and the two disagreed for
 * every JWK that was not exactly what the recipe guessed.
 *
 * Three ways it disagreed, all silent:
 *
 *  - `alg=ec/p256` + an `oct` JWK → a `key/secret`, declared `keypair`;
 *    `export pkcs8` then fell through its own `meta.symmetric` catch and
 *    emitted raw key bytes labelled pkcs8.
 *  - `alg=aes/256` + an Ed25519 JWK → a `keypair`, declared `key/secret`.
 *  - `alg=ec/p521` + a P-256 JWK → a P-256 key, declared with the type's
 *    `alg` (and so `export scalar`'s declared `length: 66`) of a P-521 one.
 *
 * `alg=` and the new `which=` are the whole answer now, and the JWK may only
 * agree. What the *platform* says the imported key is — `CryptoKey.algorithm`,
 * read-only and filled in by the implementation — is what it is checked
 * against, so the mapping cannot drift the way a second hand-written table
 * would. That is `genkey-key-shape.test.js`'s method, pointed at import.
 */
import { describe, expect, it } from "vitest";
import { STEPS } from "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import {
  keyDeclarationMessage,
  noPrivateHalfMessage,
  runRecipe,
} from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { algTokenForKey, genkeyOutputBase } from "../lib/toolkit/types.js";
import { isCryptoKey } from "../lib/toolkit/webcrypto-ops.js";

/** `import`'s own `alg` enum — the list `algTokenForKey` has to cover. */
const IMPORT_ALGS = (() => {
  const step = STEPS.find((s) => s.name === "import");
  const param = step?.params?.find((p) => p.name === "alg");
  return /** @type {string[]} */ (param?.enum || []);
})();

/** Run a recipe and hand back the slot registry's view of it. */
async function run(recipe, inputs = {}) {
  const { ast, validation } = compileRecipe(recipe);
  expect(validation.errors.map((e) => e.message), recipe).toEqual([]);
  const slots = createSlotRegistry();
  const arts = await runRecipe(ast, { inputs }, { slotRegistry: slots });
  return { arts, slots };
}

/** Every CryptoKey a pipeline value holds, however it is packed. */
const keysOf = (value) => {
  const bag = value?.data;
  return isCryptoKey(bag)
    ? [bag]
    : [bag?.privateKey, bag?.publicKey, bag?.secretKey].filter((k) => isCryptoKey(k));
};

describe("algTokenForKey names every algorithm import can be asked for", () => {
  it("covers the enum, with no member left unnamed", () => {
    expect(IMPORT_ALGS.length).toBeGreaterThan(0);
  });

  for (const alg of IMPORT_ALGS) {
    it(
      `round-trips ${alg}: generated, exported as JWK, re-imported, and named back`,
      async () => {
        // Generated for real and read back off the platform — no reference to
        // Basilisk's own vocabulary except the token under test.
        const { slots } = await run(
          `genkey ${alg} | export jwk | import jwk alg=${alg} | out $k`
        );
        const value = slots.resolve("$k");
        expect(value.type, `${alg} tip base`).toBe(genkeyOutputBase(alg));
        const keys = keysOf(value);
        expect(keys.length, `${alg} produced no CryptoKey`).toBeGreaterThan(0);
        for (const k of keys) {
          expect(algTokenForKey(k), `${alg} vs ${k.algorithm?.name}`).toBe(alg);
        }
      },
      60_000
    );
  }
});

describe("import jwk refuses a JWK that is not what alg= declared", () => {
  const OCT = JSON.stringify({
    kty: "oct",
    k: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  const ED_PUBLIC = JSON.stringify({
    kty: "OKP",
    crv: "Ed25519",
    x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  });

  it("still compiles the recipe that used to lie, and now refuses at the run", async () => {
    const recipe = "input | import jwk alg=ec/p256 | export pkcs8 | encode hex | out $k";
    const { ast, validation } = compileRecipe(recipe);
    // The declaration was never the wrong part — `export pkcs8` is a perfectly
    // good thing to ask of the `keypair` this says it produces.
    expect(validation.errors).toEqual([]);
    await expect(runRecipe(ast, { inputs: { text: { value: OCT } } })).rejects.toThrow(
      keyDeclarationMessage(
        "import jwk",
        "ec/p256",
        "aes/256",
        "write alg=aes/256, or paste a ec/p256 key."
      )
    );
  });

  it("refuses an asymmetric JWK under a symmetric alg=", async () => {
    const { ast } = compileRecipe("input | import jwk alg=aes/256 | out $k");
    await expect(runRecipe(ast, { inputs: { text: { value: ED_PUBLIC } } })).rejects.toThrow(
      keyDeclarationMessage(
        "import jwk",
        "aes/256",
        "ed25519",
        "write alg=ed25519, or paste a aes/256 key."
      )
    );
  });

  it("refuses a curve other than the one named, which used to fix a wrong scalar length", async () => {
    const { slots } = await run("genkey ec/p256 | export jwk | out $j");
    const p256 = String(slots.resolve("$j").data);
    const { ast } = compileRecipe(
      "input | import jwk alg=ec/p521 | export scalar | encode hex | out $s"
    );
    await expect(runRecipe(ast, { inputs: { text: { value: p256 } } })).rejects.toThrow(
      keyDeclarationMessage(
        "import jwk",
        "ec/p521",
        "ec/p256",
        "write alg=ec/p256, or paste a ec/p521 key."
      )
    );
  }, 30_000);

  it("refuses a public-only JWK where a keypair was declared, naming which=public", async () => {
    const { ast } = compileRecipe("input | import jwk alg=ed25519 | out $k");
    await expect(runRecipe(ast, { inputs: { text: { value: ED_PUBLIC } } })).rejects.toThrow(
      noPrivateHalfMessage("import jwk")
    );
  });
});

describe("import jwk which=public is the declared way in for a public JWK", () => {
  it("types a key/public tip and produces one", async () => {
    const { slots } = await run(
      "genkey ed25519 | export jwk which=public | import jwk alg=ed25519 which=public | out $k"
    );
    const value = slots.resolve("$k");
    expect(value.type).toBe("key");
    expect(value.meta.which).toBe("public");
    expect(algTokenForKey(value.data)).toBe("ed25519");
  }, 30_000);

  it("refuses export pkcs8 off that tip at compile time, where it belongs", () => {
    const { validation } = compileRecipe(
      "genkey ed25519 | export jwk which=public | import jwk alg=ed25519 which=public | export pkcs8 | out $k"
    );
    expect(validation.errors.map((e) => e.message).join("\n")).toMatch(
      /"export pkcs8" needs a private key — tip is key\/ed25519\/public/
    );
  });

  it("is refused on a symmetric alg, which has no public half", () => {
    const { validation } = compileRecipe("input | import jwk alg=aes/256 which=public | out $k");
    expect(validation.errors.map((e) => e.message).join("\n")).toMatch(
      /is for asymmetric keys — aes\/256 is symmetric and has no public half/
    );
  });

  it("is refused on the DER formats, which already name their half", () => {
    const { validation } = compileRecipe("input | der | import pkcs8 which=public | out $k");
    expect(validation.errors.map((e) => e.message).join("\n")).toMatch(
      /"import pkcs8 which=public" is a contradiction/
    );
  });

  /**
   * `effectiveIo` feeds the caret and `inferParamDrivenType` feeds the type
   * walker; where they disagree an op gets offered after a step that produced
   * the other shape. `qr.scan` carries the same note.
   */
  it("agrees with effectiveIo on the shape, for every alg and half", () => {
    const step = STEPS.find((s) => s.name === "import");
    for (const alg of IMPORT_ALGS) {
      for (const which of ["private", "public"]) {
        const symmetric = genkeyOutputBase(alg) === "key";
        if (which === "public" && symmetric) continue;
        const expected = which === "public" || symmetric ? "key" : "keypair";
        expect(step.effectiveIo({ format: "jwk", alg, which }).output, `${alg} ${which}`).toBe(
          expected
        );
      }
    }
  });
});

/**
 * The same defect, a third time, on the `keypair` *source* step.
 *
 * Found while checking whether the class was closed, and measured before it
 * was: `keypair alg=ec/p256 | export pkcs8 | encode hex` compiled with zero
 * errors and emitted `0000…` — 32 raw AES bytes — when the Inputs panel held
 * an `oct` JWK, and `keypair alg=ed25519 format=pem | export pkcs8 | encode
 * hex` emitted `302a300506032b6570…`, SPKI DER, when the panel held a lone
 * PUBLIC KEY block. `inferSourceType` declared `keypair/private` in both
 * cases, and the step's own doc named the second one out loud: "an SPKI PEM
 * yields a public-key tip" — a run-time answer to a compile-time question.
 *
 * It goes through the same `importKey` as `import jwk` and now carries the
 * same declaration with it.
 */
describe("the keypair source step is held to alg= and which= too", () => {
  const panel = (value) => ({ keypair: { value } });
  const OCT = JSON.stringify({
    kty: "oct",
    k: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });

  /** SPKI / PKCS#8 PEM for a fresh key, the way the panel would be pasted. */
  async function pemBlocks(named = { name: "Ed25519" }, alg = "ed25519") {
    const kp = await crypto.subtle.generateKey(named, true, ["sign", "verify"]);
    const armor = async (key, fmt, label) => {
      const der = new Uint8Array(await crypto.subtle.exportKey(fmt, key));
      const b64 = Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n");
      return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
    };
    return {
      alg,
      publicPem: await armor(kp.publicKey, "spki", "PUBLIC KEY"),
      privatePem: await armor(kp.privateKey, "pkcs8", "PRIVATE KEY"),
    };
  }

  it("refuses an oct JWK under an asymmetric alg=, where pkcs8 used to emit raw key bytes", async () => {
    const { ast, validation } = compileRecipe(
      "keypair alg=ec/p256 | export pkcs8 | encode hex | out $k"
    );
    expect(validation.errors).toEqual([]);
    await expect(runRecipe(ast, { inputs: panel(OCT) })).rejects.toThrow(
      keyDeclarationMessage(
        "keypair jwk",
        "ec/p256",
        "aes/256",
        "write alg=aes/256, or paste a ec/p256 key."
      )
    );
  });

  it("refuses a lone PUBLIC KEY block where a keypair was declared, where pkcs8 used to emit SPKI", async () => {
    const { publicPem } = await pemBlocks();
    const { ast, validation } = compileRecipe(
      "keypair pem alg=ed25519 | export pkcs8 | encode hex | out $k"
    );
    expect(validation.errors).toEqual([]);
    await expect(runRecipe(ast, { inputs: panel(publicPem) })).rejects.toThrow(
      noPrivateHalfMessage("keypair pem")
    );
  }, 30_000);

  it("types which=public as a key/public tip and produces one", async () => {
    const { publicPem } = await pemBlocks();
    const { ast, validation } = compileRecipe(
      "keypair pem alg=ed25519 which=public | export spki | encode hex | out $pub"
    );
    expect(validation.errors).toEqual([]);
    const slots = createSlotRegistry();
    await runRecipe(ast, { inputs: panel(publicPem) }, { slotRegistry: slots });
    expect(String(slots.resolve("$pub").data)).toMatch(/^[0-9a-f]+$/);
    // The declared tip is what `export pkcs8` is refused against, before the run.
    const { validation: v2 } = compileRecipe(
      "keypair pem alg=ed25519 which=public | export pkcs8 | out $k"
    );
    expect(v2.errors.map((e) => e.message).join("\n")).toMatch(
      /"export pkcs8" needs a private key — tip is key\/ed25519\/public/
    );
  }, 30_000);

  it("still imports a full pair under the default, both formats", async () => {
    const { publicPem, privatePem } = await pemBlocks();
    for (const [recipe, value] of [
      ["keypair pem alg=ed25519 | export spki | encode hex | out $k", `${privatePem}\n${publicPem}`],
      [
        "keypair jwk alg=ed25519 | export pkcs8 | encode hex | out $k",
        await (async () => {
          const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
          return JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey));
        })(),
      ],
    ]) {
      const { ast, validation } = compileRecipe(recipe);
      expect(validation.errors, recipe).toEqual([]);
      const arts = await runRecipe(ast, { inputs: panel(value) });
      expect(String(arts.at(-1).content), recipe).toMatch(/^[0-9a-f]+$/);
    }
  }, 30_000);

  it("agrees with effectiveIo on the shape", () => {
    const step = STEPS.find((s) => s.name === "keypair");
    expect(step.effectiveIo({}).output).toBe("keypair");
    expect(step.effectiveIo({ which: "private" }).output).toBe("keypair");
    expect(step.effectiveIo({ which: "public" }).output).toBe("key");
  });
});

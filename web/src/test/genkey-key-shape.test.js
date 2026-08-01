/**
 * `genkey`'s declared shape, pinned to what WebCrypto actually returns.
 *
 * At compile time there is no key object, so `inferSourceType` has to *know*
 * that `aes/256` yields one key and `ed25519` yields two. That knowledge is a
 * hand-written table, and a hand-written table drifts: the enum grows an
 * algorithm, nobody adds the row, and the default silently claims it is a
 * keypair. That is the exact failure this unit was opened for — `genkey
 * aes/256` used to type `keypair/aes-256/private`, so an AES key was the
 * private half of a pair with no public one, and the tile drew it as such.
 *
 * So the table is not asserted against another table. It is asserted against
 * the platform: every algorithm in `genkey`'s own `alg` enum is generated for
 * real, and the shape the table declares is checked against `CryptoKey.type` —
 * `"secret" | "private" | "public"`, read-only on every key WebCrypto hands
 * back, with `"secret"` meaning symmetric. A row that drifts fails here, and a
 * new enum member with no row fails here too, before it can reach a tile.
 *
 * Three claims, deliberately separate:
 *
 *  1. **Totality** — the enum and the table cover each other exactly. No
 *     defaulting: an unlisted algorithm is a test failure, not a keypair.
 *  2. **Truth** — generating the algorithm yields the declared shape, judged
 *     by `key.type` and by whether `generateKey` resolved to a `CryptoKey` or
 *     a `CryptoKeyPair`.
 *  3. **Agreement** — `inferSourceType` (compile time) and
 *     `pipelineKeyHandles` (run time) reach the same verdict about the same
 *     algorithm, which is the invariant the two halves of the fix share.
 */
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { STEPS } from "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { GENKEY_KEY_SHAPES, inferSourceType } from "../lib/toolkit/types.js";
import { isCryptoKey, pipelineKeyHandles } from "../lib/toolkit/webcrypto-ops.js";
import { ARTIFACT_KINDS, FALLBACK_KIND } from "../toolkit/artifact-kinds/registry.tsx";
import { resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";

/** `genkey`'s own `alg` enum — the list the table has to cover. */
const GENKEY_ALGS = (() => {
  const step = STEPS.find((s) => s.name === "genkey");
  const param = step?.params?.find((p) => p.name === "alg");
  return /** @type {string[]} */ (param?.enum || []);
})();

/**
 * Generate for real and report what the platform says, with no reference to
 * Basilisk's own vocabulary beyond reaching the handles.
 * @param {string} alg
 */
async function generated(alg) {
  const { ast, validation } = compileRecipe(`genkey ${alg} | out @k`);
  expect(validation.errors, `genkey ${alg} should compile`).toEqual([]);
  const slots = createSlotRegistry();
  await runRecipe(ast, {}, { slotRegistry: slots });
  const value = slots.resolve("@k");
  const bag = value.data;
  /** Every CryptoKey the value holds, however it is packed. */
  const keys = isCryptoKey(bag)
    ? [bag]
    : [bag?.privateKey, bag?.publicKey, bag?.secretKey].filter((k) => isCryptoKey(k));
  return { value, keys, types: keys.map((k) => k.type).sort() };
}

describe("the genkey shape table covers its own enum", () => {
  it("has an entry for every algorithm the enum offers", () => {
    expect(GENKEY_ALGS.length).toBeGreaterThan(0);
    const missing = GENKEY_ALGS.filter((a) => !(a in GENKEY_KEY_SHAPES));
    expect(missing, "algorithms in genkey's enum with no declared shape").toEqual([]);
  });

  it("declares nothing the enum does not offer", () => {
    const extra = Object.keys(GENKEY_KEY_SHAPES).filter((a) => !GENKEY_ALGS.includes(a));
    expect(extra, "declared shapes for algorithms genkey cannot generate").toEqual([]);
  });

  it("declares only shapes the type system has", () => {
    for (const [alg, base] of Object.entries(GENKEY_KEY_SHAPES)) {
      expect(["key", "keypair"], `${alg}`).toContain(base);
    }
  });
});

describe("the declared shape is the one WebCrypto returns", () => {
  for (const alg of GENKEY_ALGS) {
    it(`${alg}`, async () => {
      const declared = GENKEY_KEY_SHAPES[alg];
      const { value, keys, types } = await generated(alg);
      expect(keys.length, `${alg} produced no CryptoKey`).toBeGreaterThan(0);

      if (declared === "key") {
        // `generateKey` fulfilled with a lone CryptoKey, and the platform's
        // own word for symmetric is `type === "secret"`.
        expect(types, `${alg} should be one secret key`).toEqual(["secret"]);
      } else {
        // A CryptoKeyPair: two handles, and neither of them symmetric.
        expect(types, `${alg} should be a private/public pair`).toEqual([
          "private",
          "public",
        ]);
      }
      // …and the value's own base agrees with the table.
      expect(value.type, `${alg} runtime value base`).toBe(declared);
    }, 60000);
  }
});

describe("compile time and run time reach the same verdict", () => {
  for (const alg of GENKEY_ALGS) {
    it(`${alg}`, async () => {
      const declared = GENKEY_KEY_SHAPES[alg];
      const compiled = inferSourceType("genkey", { alg });
      expect(compiled.base, `inferSourceType base for ${alg}`).toBe(declared);
      expect(compiled.alg).toBe(alg);

      const { value } = await generated(alg);
      const handles = pipelineKeyHandles(value);
      if (declared === "key") {
        // Routed by `key.type`, not by a name that starts with "AES".
        expect(handles.secretKey, `${alg} should route to secretKey`).toBeTruthy();
        expect(handles.privateKey, `${alg} must not be a private half`).toBeNull();
        expect(handles.publicKey).toBeNull();
        expect(compiled.which, `${alg} is neither half of anything`).toBe("secret");
      } else {
        expect(handles.privateKey, `${alg} should route to privateKey`).toBeTruthy();
        expect(handles.publicKey, `${alg} should route to publicKey`).toBeTruthy();
        expect(handles.secretKey, `${alg} is not symmetric`).toBeNull();
        expect(compiled.which).toBe("private");
      }
    }, 60000);
  }
});

describe("a symmetric key never claims to be a keypair", () => {
  const symmetric = GENKEY_ALGS.filter((a) => GENKEY_KEY_SHAPES[a] === "key");
  const asymmetric = GENKEY_ALGS.filter((a) => GENKEY_KEY_SHAPES[a] === "keypair");

  it("covers both families", () => {
    expect(symmetric.length).toBeGreaterThan(0);
    expect(asymmetric.length).toBeGreaterThan(0);
  });

  for (const alg of symmetric) {
    for (const src of [`genkey ${alg}`, `genkey ${alg} | out @k`]) {
      it(`${src} carries no keypair tag, no half`, async () => {
        const { ast, validation } = compileRecipe(src);
        expect(validation.errors).toEqual([]);
        const arts = await runRecipe(ast, {});
        expect(arts.length).toBeGreaterThan(0);
        for (const a of arts) {
          expect(a.role, `${src}: role`).toBe("secret-key");
          expect(a.tags || [], `${src}: tags`).not.toContain("keypair");
          expect(a.tags || [], `${src}: tags`).not.toContain("private");
          expect(a.tags || [], `${src}: tags`).not.toContain("public");
          expect(a.pipeType?.base, `${src}: pipeType`).toBe("key");
          expect(a.pipeType?.which, `${src}: which`).toBe("secret");
          // The badge is the role, so this is also the assertion that the
          // tile stops saying KEYPAIR about an AES key.
          expect(resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id).toBe(
            "secret-key"
          );
        }
      }, 60000);
    }
  }

  /**
   * The payoff, and the argument for keeping symmetry a *refinement*.
   *
   * `resolveStepType` already refused `export spki|pkcs8|scalar` for a
   * `which: "secret"` tip, with a sentence naming the two formats that do
   * work — and that branch was unreachable, because `genkey aes/256` typed
   * itself `keypair/…/private`. Nothing here is new code: an honest type made
   * four runtime failures into compile-time ones by turning existing dead
   * code live. That is the case for `which` over a third `IoType` base.
   */
  it("refuses asymmetric-only exports of a symmetric key, at compile time", () => {
    for (const alg of symmetric) {
      for (const format of ["pkcs8", "spki", "scalar"]) {
        const { validation } = compileRecipe(`genkey ${alg} | export ${format}`);
        const msg = validation.errors.map((e) => e.message || e).join("\n");
        expect(msg, `genkey ${alg} | export ${format}`).toMatch(
          /is for asymmetric keys/
        );
        // The refusal names the way out, not just the wall.
        expect(msg).toMatch(/use export raw or export jwk/);
      }
    }
  });

  it("still allows the two exports a symmetric key does have", () => {
    for (const alg of symmetric) {
      for (const format of ["jwk", "raw"]) {
        const { validation } = compileRecipe(`genkey ${alg} | export ${format}`);
        expect(validation.errors, `genkey ${alg} | export ${format}`).toEqual([]);
      }
    }
  });

  it("keeps asymmetric exports working", () => {
    for (const alg of asymmetric) {
      const { validation } = compileRecipe(`genkey ${alg} | export pkcs8`);
      expect(validation.errors, `genkey ${alg} | export pkcs8`).toEqual([]);
    }
  });

  for (const alg of asymmetric) {
    it(`genkey ${alg} still says keypair`, async () => {
      const { ast, validation } = compileRecipe(`genkey ${alg}`);
      expect(validation.errors).toEqual([]);
      const [tip] = await runRecipe(ast, {});
      expect(tip.role).toBe("keypair");
      expect(tip.tags).toContain("keypair");
      expect(tip.pipeType?.base).toBe("keypair");
    }, 60000);
  }
});

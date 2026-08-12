import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createMessage, encrypt, generateKey } from "openpgp";
import { dearmorToBytes } from "../lib/packet-map.js";
import {
  MESSAGING_STARTERS,
  TOOLKIT_HASH_MAX_LEN,
  compactRecipeText,
  decodeCiphertextSeed,
  encodeCiphertextSeed,
  encodeSharePayload,
  expandShareRecipe,
  hashForDecryptLink,
  hashForNotebook,
  hashForPreset,
  hashForRecipe,
  hashForStarter,
  parseToolkitHash,
  recipeLooksSecret,
  seedLooksSecret,
  splitCtParam,
  toolkitShareUrl,
} from "../lib/toolkit/fragment.js";
import { canonicalizeRecipe } from "../lib/toolkit/recipe.js";

describe("parseToolkitHash", () => {
  it("parses named starters", () => {
    expect(parseToolkitHash("#encrypt")).toEqual({
      kind: "starter",
      starter: "encrypt",
    });
    expect(parseToolkitHash("decrypt")).toEqual({
      kind: "starter",
      starter: "decrypt",
    });
    expect(parseToolkitHash("#symencrypt")).toEqual({
      kind: "starter",
      starter: "symencrypt",
    });
    expect(MESSAGING_STARTERS.encrypt.recipe).toContain("gpg.encrypt");
    expect(MESSAGING_STARTERS.decrypt.recipe).toBe("gpg.decrypt");
    expect(MESSAGING_STARTERS.symencrypt.recipe).toContain(
      "gpg.symencrypt mode=passphrase"
    );
    expect(MESSAGING_STARTERS.symencrypt.recipe).toContain("passphrase=$pw");
  });

  it("parses preset and recipe forms", () => {
    expect(parseToolkitHash("#t=hkp-search-encrypt")).toEqual({
      kind: "preset",
      id: "hkp-search-encrypt",
    });
    const recipe = "input | gpg.encrypt";
    const action = parseToolkitHash(`#r=${encodeURIComponent(recipe)}`);
    expect(action).toEqual({ kind: "recipe", recipe });
  });

  it("empty / unknown", () => {
    expect(parseToolkitHash("#")).toEqual({ kind: "empty" });
    expect(parseToolkitHash("#nope").kind).toBe("unknown");
  });
});

describe("compact share form", () => {
  it("minifies pipes and chains, and leaves a body's own form alone", () => {
    // This pinned `foreach{ - out $share }` until the compact form stopped
    // re-spelling bodies. Two reasons it had to change, and the second is why
    // the fix went further than the cases that failed to parse:
    //
    // 1. Joining body items with a space does not parse back the moment there
    //    is more than one of them — a step's argument loop runs past the `-`.
    //    `recipe-roundtrip.test.js` sweeps every preset for that now.
    // 2. Even for the single-item body here, which did parse, the brace
    //    spelling came back as `bodyForm: "brace"` and serialized as
    //    `foreach {\n  - out $share\n}`. `serializeRecipe` is what a manifest,
    //    a receipt and a handoff offer digest a cell with, so the same cell
    //    pasted as text and opened from a link digested two ways — a
    //    `cell-mismatch` between two peers holding one notebook.
    //
    // So the stem still minifies and the body is left exactly as written.
    const foreachPretty = `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`;
    expect(compactRecipeText(foreachPretty)).toBe(
      "random 32|sss.split|blip39.encode|foreach\n  - out $share"
    );

    const chained = `genkey ec/p256 | out $kp

in $kp | export spki | pem | out $pub`;
    const compact = compactRecipeText(chained);
    expect(compact).toBe(
      "genkey ec/p256|out $kp~$kp|export spki|pem|out $pub"
    );
    expect(compact).not.toContain("\n");
    expect(encodeSharePayload(compact)).toContain("|");
    expect(encodeSharePayload(compact)).toContain("~");
    expect(encodeSharePayload(compact)).not.toContain("%7C");
  });

  it("spends one fragment character on a slot, not three", () => {
    // `encodeURIComponent` escapes `$` to `%24`. Against a 6000-character
    // budget that is three characters per slot reference, on a language where
    // every value that crosses a cell boundary is one.
    const compact = "genkey ec/p256|out $kp~$kp|export spki|pem|out $pub";
    const encoded = encodeSharePayload(compact);
    expect(encoded).not.toContain("%24");
    expect((encoded.match(/\$/g) || []).length).toBe(3);
    expect(encoded.length).toBe(compact.length);

    // And it survives the whole `#r=` trip unchanged.
    const { hash } = hashForRecipe(compact);
    const action = parseToolkitHash(hash);
    expect(action.kind).toBe("recipe");
    if (action.kind !== "recipe") return;
    expect(expandShareRecipe(action.recipe)).toContain("out $kp");
    const { text, errors } = canonicalizeRecipe(expandShareRecipe(action.recipe));
    expect(errors).toEqual([]);
    expect(text).toContain("out $pub");
  });

  it("round-trips through hash and beautifies on load", () => {
    const pretty = `genkey ec/p256 | out $kp

in $kp | export spki | pem | out $pub`;
    const { hash, ok } = hashForRecipe(pretty);
    expect(ok).toBe(true);
    expect(hash.startsWith("#r=")).toBe(true);
    expect(hash).toContain("|");
    expect(hash).toContain("~");
    expect(hash.length).toBeLessThan(
      `#r=${encodeURIComponent(pretty)}`.length
    );

    const action = parseToolkitHash(hash);
    expect(action.kind).toBe("recipe");
    if (action.kind !== "recipe") return;
    const { text, errors } = canonicalizeRecipe(action.recipe);
    expect(errors).toEqual([]);
    expect(text).toBe(
      "genkey ec/p256 | out $kp\n\n$kp | export spki | pem | out $pub"
    );
  });

  it("expands ~ chains and accepts legacy pretty % encodings", () => {
    expect(expandShareRecipe("a|b~c|d")).toBe("a|b\n\nc|d");
    const legacy = `input | gpg.encrypt`;
    const action = parseToolkitHash(`#r=${encodeURIComponent(legacy)}`);
    expect(action).toEqual({ kind: "recipe", recipe: legacy });
  });
});

describe("ciphertext seed (ct)", () => {
  it("splits &ct= without breaking recipe = values", () => {
    expect(splitCtParam("decrypt&ct=abc")).toEqual({
      head: "decrypt",
      ct: "abc",
    });
    expect(splitCtParam("r=foo=bar&ct=xyz")).toEqual({
      head: "r=foo=bar",
      ct: "xyz",
    });
    expect(splitCtParam("decrypt")).toEqual({ head: "decrypt", ct: null });
  });

  it("hashForDecryptLink encodes and parseToolkitHash reseeds", async () => {
    const { privateKey, publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Share", email: "share@example.com" }],
      format: "object",
    });
    const armored = await encrypt({
      message: await createMessage({ text: "hello prefill" }),
      encryptionKeys: publicKey,
      format: "armored",
    });
    void privateKey;

    const enc = encodeCiphertextSeed(armored);
    expect(enc.ok).toBe(true);
    if (!enc.ok) return;

    const link = hashForDecryptLink(armored);
    expect(link.ok).toBe(true);
    expect(link.hash.startsWith("#decrypt&ct=")).toBe(true);
    expect(link.hash.length).toBeLessThanOrEqual(TOOLKIT_HASH_MAX_LEN);
    // Binary seed should beat raw armor in the fragment
    expect(link.hash.length).toBeLessThan(
      `#decrypt&ct=${encodeURIComponent(armored)}`.length
    );

    const action = parseToolkitHash(link.hash);
    expect(action.kind).toBe("starter");
    if (action.kind !== "starter") return;
    expect(action.starter).toBe("decrypt");
    expect(action.inputs?.ctArmored).toMatch(/BEGIN PGP MESSAGE/);
    // Round-trip bytes match
    const back = dearmorToBytes(action.inputs.ctArmored);
    expect(back).toEqual(dearmorToBytes(armored));
  }, 60_000);

  it("refuses private armor in ct seed", () => {
    const priv = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET\n-----END PGP PRIVATE KEY BLOCK-----";
    expect(seedLooksSecret(priv)).toBe(true);
    expect(encodeCiphertextSeed(priv).ok).toBe(false);
    expect(hashForDecryptLink(priv).ok).toBe(false);
  });

  it("parses #r=…&ct= beside a compact recipe", async () => {
    const { publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "R", email: "r@example.com" }],
      format: "object",
    });
    const armored = await encrypt({
      message: await createMessage({ text: "r+ct" }),
      encryptionKeys: publicKey,
      format: "armored",
    });
    const enc = encodeCiphertextSeed(armored);
    expect(enc.ok).toBe(true);
    if (!enc.ok) return;
    const hash = `#r=gpg.decrypt&ct=${enc.ct}`;
    const action = parseToolkitHash(hash);
    expect(action.kind).toBe("recipe");
    if (action.kind !== "recipe") return;
    expect(action.recipe).toBe("gpg.decrypt");
    expect(action.inputs?.ctArmored).toMatch(/BEGIN PGP MESSAGE/);
  }, 60_000);

  it("size spike: short and medium messages fit under the hash cap", async () => {
    const { publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Size", email: "size@example.com" }],
      format: "object",
    });
    const cases = [
      { label: "one-line", text: "hi" },
      {
        label: "paragraph",
        text: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(4),
      },
      { label: "1KB", text: "x".repeat(1024) },
    ];
    /** @type {Record<string, number>} */
    const sizes = {};
    for (const c of cases) {
      const armored = await encrypt({
        message: await createMessage({ text: c.text }),
        encryptionKeys: publicKey,
        format: "armored",
      });
      const link = hashForDecryptLink(armored);
      sizes[c.label] = link.hash.length;
      expect(link.ok, `${c.label} should fit`).toBe(true);
      expect(link.hash.length).toBeLessThanOrEqual(TOOLKIT_HASH_MAX_LEN);
      // Armor-in-URL would be larger
      expect(link.hash.length).toBeLessThan(armored.length + 20);
    }
    // Sanity: larger plaintext → larger (or equal) seed
    expect(sizes["1KB"]).toBeGreaterThan(sizes["one-line"]);
  }, 60_000);

  it("decodeCiphertextSeed rejects garbage", () => {
    const bad = decodeCiphertextSeed("!!!");
    // atob may throw or produce junk — either ok:false or empty-ish armor
    if (bad.ok) {
      expect(bad.armored).toContain("BEGIN PGP MESSAGE");
    } else {
      expect(bad.reason).toBeTruthy();
    }
  });
});

describe("hash writers", () => {
  it("round-trips starters and prefers short form", () => {
    expect(hashForStarter("encrypt")).toBe("#encrypt");
    expect(hashForNotebook(MESSAGING_STARTERS.encrypt.recipe).hash).toBe(
      "#encrypt"
    );
    expect(hashForPreset("p256-pem")).toBe("#t=p256-pem");
  });

  it("encodes full recipes under the size cap", () => {
    const r = hashForRecipe("random 8 | encode hex | out $x");
    expect(r.ok).toBe(true);
    expect(r.hash.startsWith("#r=")).toBe(true);
    expect(parseToolkitHash(r.hash)).toEqual({
      kind: "recipe",
      recipe: "random 8|encode hex|out $x",
    });
  });

  it("refuses private armor in the hash", () => {
    expect(
      recipeLooksSecret("-----BEGIN PGP PRIVATE KEY BLOCK-----\nxxx")
    ).toBe(true);
    const r = hashForRecipe(
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET\n-----END PGP PRIVATE KEY BLOCK-----"
    );
    expect(r.ok).toBe(false);
  });

  it("builds share URLs", () => {
    expect(
      toolkitShareUrl("#encrypt", {
        origin: "https://example.test",
        path: "/toolkit",
      })
    ).toBe("https://example.test/toolkit#encrypt");
    expect(
      toolkitShareUrl("#decrypt&ct=abc", {
        origin: "https://example.test",
        path: "/toolkit",
      })
    ).toBe("https://example.test/toolkit#decrypt&ct=abc");
  });
});

describe("the seed a link carries reaches the notebook", () => {
  const HOOK = readFileSync(
    fileURLToPath(new URL("../toolkit/useNotebook.ts", import.meta.url)),
    "utf8"
  );

  it("reads the field `attachCiphertextSeed` actually writes", () => {
    // The producer above writes `inputs.ctArmored`, and it is the only thing
    // that writes a seed at all. The hook read `inputs.ciphertext`, so a
    // `#decrypt&ct=…` link parsed correctly, produced the armor, and then
    // dropped it on the floor — the field stayed empty.
    expect(HOOK).toMatch(/action\.inputs\?\.ctArmored/);
    expect(HOOK).not.toMatch(/action\.inputs\?\.ciphertext/);
  });

  it("applies it whatever the link named, not only a starter", () => {
    // `attachCiphertextSeed` spreads `inputs` onto *any* action, so
    // `#preset=gpg-decrypt&ct=…` carries a ciphertext exactly as `#decrypt`
    // does. The read used to sit inside the starter branch, which returns
    // before the preset and recipe branches run.
    const body = HOOK.slice(HOOK.indexOf("const loadFromHash"));
    const handler = body.slice(0, body.indexOf("useEffect("));
    expect(handler.match(/seedCiphertext\(\)/g) || []).toHaveLength(3);
    for (const kind of ["starter", "preset", "recipe"]) {
      expect(handler).toContain(`action.kind === "${kind}"`);
    }
  });
});

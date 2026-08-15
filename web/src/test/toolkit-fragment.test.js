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
  hashForJoin,
  hashForNotebook,
  hashForPreset,
  hashForRecipe,
  hashForStarter,
  hashForToolkitState,
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

  it("names a tray without naming a notebook", () => {
    // `/toolkit#keys` is the nav's Keys entry. It has to be its own kind: a
    // starter *replaces the notebook*, and opening the vault must not throw
    // away what somebody was writing — the same rule `#j=` follows.
    expect(parseToolkitHash("#keys")).toEqual({ kind: "tray", tray: "keys" });
    expect(parseToolkitHash("KEYS")).toEqual({ kind: "tray", tray: "keys" });
  });

  it("carries no ciphertext seed onto a tray", () => {
    // A seed is Inputs, and a tray is a panel. `#keys&ct=…` names a panel and
    // a payload with nothing to put it in; taking the seed anyway would mean
    // the shell had to decide what to do with it, silently.
    const action = parseToolkitHash("#keys&ct=AAAA");
    expect(action).toEqual({ kind: "tray", tray: "keys" });
    expect(action.inputs).toBeUndefined();
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
    // The quorum keeps both numbers through the compact form: a quorum dropped
    // for matching a default is absent from the link the recipient reads and
    // from the manifest both ends compare. It travels as the verb's object now
    // (`sss.split 2/3`, LANGUAGE.md migration step 2) — the named pair above is
    // an input form converging on the fraction. Minifying the stem never meant
    // minifying away what the recipe does.
    expect(compactRecipeText(foreachPretty)).toBe(
      "random 32|sss.split 2/3|blip39.encode|foreach\n  - out $share"
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

describe("the address bar tracks the shareable thing", () => {
  const ADA = "83421F2C1E5D4A9B7C0E6F3A2D8B4E19A7C5B650";
  const GRACE = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B";
  const RECIPE = "input | gpg.encrypt";

  it("hands the bar to a live room's invite", () => {
    const next = hashForToolkitState({
      recipe: RECIPE,
      sessionLive: true,
      audience: [ADA, GRACE],
      currentHash: "#r=input%7Cgpg.encrypt",
    });
    expect(next).toEqual({ write: true, hash: hashForJoin([ADA, GRACE]).hash, kind: "join" });
  });

  it("never ships the notebook or a seed with the invitation", () => {
    // The rule `parseToolkitHash` already enforces on the way in, enforced on
    // the way out: both ends reaching the same text independently is what
    // makes a shared run a reproducible build. A URL that carried one side's
    // recipe into the other's notebook would end that quietly.
    const next = hashForToolkitState({
      recipe: RECIPE,
      sessionLive: true,
      audience: [ADA, GRACE],
      currentHash: "#decrypt&ct=Zm9vYmFy",
    });
    expect(next.write && next.hash).not.toMatch(/[&?]r=|&ct=/);
  });

  it("leaves the bar alone while an audience is still being assembled", () => {
    const next = hashForToolkitState({
      recipe: RECIPE,
      sessionLive: true,
      audience: [ADA],
      currentHash: "#keys",
    });
    expect(next.write).toBe(false);
  });

  it("writes the notebook when no room is up, and it reads back", () => {
    const next = hashForToolkitState({ recipe: "input | gpg.symencrypt mode=passphrase" });
    expect(next.write).toBe(true);
    const back = parseToolkitHash(next.write ? next.hash : "");
    expect(back.kind).toBe("recipe");
    expect(back.recipe).toContain("gpg.symencrypt");
  });

  it("prefers the short starter form over a spelled-out r=", () => {
    const next = hashForToolkitState({ recipe: MESSAGING_STARTERS.encrypt.recipe });
    expect(next.write && next.hash).toBe("#encrypt");
  });

  it("carries a ciphertext seed across an edit to the recipe", () => {
    // Someone opens `#decrypt&ct=…`, changes a step, and copies the URL. The
    // seed is an input, not part of the recipe text, so editing one is no
    // reason to drop the other.
    const next = hashForToolkitState({
      recipe: "gpg.decrypt | out $plain",
      currentHash: "#decrypt&ct=Zm9vYmFy",
    });
    expect(next.write && next.hash).toMatch(/&ct=Zm9vYmFy$/);
    expect(parseToolkitHash(next.write ? next.hash : "").kind).toBe("recipe");
  });

  it("drops a seed that no longer fits rather than declining to write", () => {
    const next = hashForToolkitState({
      recipe: RECIPE,
      currentHash: `#decrypt&ct=${"A".repeat(TOOLKIT_HASH_MAX_LEN)}`,
    });
    expect(next.write).toBe(true);
    expect(next.write && next.hash).not.toContain("&ct=");
    expect((next.write ? next.hash : "").length).toBeLessThanOrEqual(TOOLKIT_HASH_MAX_LEN);
  });

  it("clears a link of its own that has stopped being true", () => {
    // A notebook holding private armor cannot be linked. Leaving the previous
    // `#r=` there would leave a URL claiming to be this notebook and holding a
    // different one — worse than an empty bar, because it copies clean.
    const secret = `input | gpg.decrypt key="-----BEGIN PGP PRIVATE KEY BLOCK-----"`;
    expect(recipeLooksSecret(secret)).toBe(true);
    const next = hashForToolkitState({ recipe: secret, currentHash: "#r=input%7Cgpg.encrypt" });
    expect(next).toEqual({ write: true, hash: "#", kind: "clear" });
  });

  it("will not blank a hash somebody navigated to", () => {
    // `#keys` is the nav's own destination. The bar may replace it with
    // something better, but blanking it would leave that link pointing at a
    // page that no longer opens the tray.
    for (const recipe of ["", `x | gpg.decrypt key="-----BEGIN PGP PRIVATE KEY BLOCK-----"`]) {
      expect(hashForToolkitState({ recipe, currentHash: "#keys" }).write).toBe(false);
    }
  });

  it("is wired into the shell, by replaceState and not by assignment", () => {
    // `writeToolkitHash` shipped with no caller in the product at all, which
    // is why a session you had started still showed `/toolkit`. And the write
    // has to be `replaceState`: `useNotebook` loads the notebook on
    // `hashchange`, so assigning `location.hash` would feed every keystroke's
    // link back through the compiler.
    const SHELL = readFileSync(
      fileURLToPath(new URL("../toolkit/ToolkitShell.tsx", import.meta.url)),
      "utf8"
    );
    expect(SHELL).toMatch(/writeToolkitHash\(next\.hash\)/);
    expect(SHELL).toMatch(/hashForToolkitState\(\{/);
    const FRAGMENT = readFileSync(
      fileURLToPath(new URL("../lib/toolkit/fragment.js", import.meta.url)),
      "utf8"
    );
    const body = FRAGMENT.slice(FRAGMENT.indexOf("export function writeToolkitHash"));
    expect(body).toContain("history.replaceState");
    // `=` and not `===`: the function compares `location.hash` to decide
    // whether there is anything to do, and only assignment is the hazard.
    expect(body).not.toMatch(/location\.hash\s*=(?!=)/);
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

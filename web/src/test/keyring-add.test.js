/**
 * "Add to My Keys" against a real vault (§34d).
 *
 * The table tests next door prove the button's *gating* with stubs. This one
 * proves the thing the stubs cannot: that a body the notebook actually put on
 * a tile lands in IndexedDB, under the id the recipe path would have given it,
 * and that the vault's refusal to weaken a key reaches the click unaltered.
 *
 * Bodies come from real runs rather than fixtures on purpose. The tile reads
 * `artifact.content`, and a body invented here would pass while the mapped
 * shape the tile actually sees carried nothing.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { execAgentSave } from "../lib/toolkit/agent-ops.js";
import {
  ENCRYPTED_SSH_KEY_MESSAGE,
  addPrivateKeyToMyKeys,
  vaultAvailable,
} from "../lib/toolkit/keyring-service.js";
import { ENCRYPTED_KEY_MESSAGE } from "../lib/ssh/openssh-key-v1.js";
import { listKeys, protectionDowngradeMessage, saveKey } from "../lib/vault.js";
import { sessionClear } from "../lib/vault-session.js";

beforeEach(async () => {
  sessionClear();
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

/** The tile's own view of an artifact: whatever `content` and `traits` hold. */
async function tile(recipe, match) {
  const { ast } = compileRecipe(recipe);
  const arts = await runRecipe(ast, {});
  const art = arts.find((a) => match.test(a.label));
  if (!art) throw new Error(`no artifact matching ${match} in ${arts.map((a) => a.label)}`);
  return { content: art.content, alg: art.traits?.alg, traits: art.traits };
}

describe("the button stores what the tile is holding", () => {
  it("is offered at all only where a vault can exist", () => {
    expect(vaultAvailable()).toBe(true);
  });

  it("files an ed25519 private JWK as an ssh key with a listable public line", async () => {
    const priv = await tile("genkey ed25519 | out $kp", /private/);
    const res = await addPrivateKeyToMyKeys(priv);
    expect(res.kind).toBe("ssh");
    expect(res.already).toBe(false);
    expect(res.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    const [row] = await listKeys();
    expect(row.protection).toBe("device");
    expect(row.kind).toBe("ssh");
    expect(row.alg).toBe("ed25519");
    expect(row.publicLine).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5/);
  });

  it("files an x25519 private JWK as a raw key under an spki id", async () => {
    const priv = await tile("genkey x25519 | out $kp", /private/);
    const res = await addPrivateKeyToMyKeys(priv);
    expect(res.kind).toBe("raw");
    expect(res.fingerprint).toMatch(/^spki:SHA256:/);
    expect((await listKeys())[0].kind).toBe("raw");
  });

  it("gives a key the same id the recipe path would have given it", async () => {
    // The whole reason `vaultMaterialFromPrivateJwk` was lifted out of
    // `saveKeypairKind`: one key must not grow two rows depending on whether
    // it was stored by a click or by a line of recipe.
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const viaButton = await addPrivateKeyToMyKeys({
      content: JSON.stringify(jwk),
      alg: "ed25519",
    });
    const viaRecipe = await execAgentSave(
      { type: "keypair", data: pair, meta: { alg: "ed25519" } },
      { protection: "device" }
    );
    expect(viaButton.fingerprint).toBe(viaRecipe.meta.fingerprint);
    expect(await listKeys()).toHaveLength(1);
  });

  it("stores an armored OpenPGP private key under its own uid", async () => {
    const priv = await tile(
      'gpg.genkey name="Dana" email="dana@example.com" | out $k',
      /^k$/
    );
    expect(priv.content).toContain("PGP PRIVATE KEY BLOCK");
    const res = await addPrivateKeyToMyKeys(priv);
    expect(res.kind).toBe("pgp");
    expect(res.fingerprint).toBe(priv.traits.fingerprint);
    const [row] = await listKeys();
    expect(row.uid).toContain("dana@example.com");
    expect(row.kind).toBeUndefined(); // absent means pgp (§28a)
    expect(row.publicArmored).toContain("PGP PUBLIC KEY BLOCK");
  }, 60000);
});

describe("a second click is honest about what it did", () => {
  it("re-saves at equal protection and says the key was already there", async () => {
    // `putGuardingProtection` refuses only a *weakening* re-save, so device
    // over device goes through and overwrites the row. "Added" would be a
    // true statement about the write and a false one about the vault.
    const priv = await tile("genkey ed25519 | out $kp", /private/);
    const first = await addPrivateKeyToMyKeys(priv);
    expect(first.already).toBe(false);
    const second = await addPrivateKeyToMyKeys(priv);
    expect(second.already).toBe(true);
    expect(second.fingerprint).toBe(first.fingerprint);
    expect(await listKeys()).toHaveLength(1);
  });

  it("refuses to weaken a passkey-protected key, in the vault's own sentence", async () => {
    // The refusal is the point of passing no `onConflict`: one click may not
    // silently throw away a passkey binding. The message reaches the tile
    // through `runAction`'s catch, verbatim.
    const priv = await tile("genkey ed25519 | out $kp", /private/);
    const { fingerprint } = await addPrivateKeyToMyKeys(priv);
    await saveKey({
      fingerprint,
      armoredPrivate: "-----BEGIN OPENSSH PRIVATE KEY-----\nZg==\n-----END OPENSSH PRIVATE KEY-----\n",
      uid: "seeded",
      email: "",
      protection: "passkey",
      prfIkm: crypto.getRandomValues(new Uint8Array(32)),
      kind: "ssh",
      alg: "ed25519",
    });
    await expect(addPrivateKeyToMyKeys(priv)).rejects.toThrow(
      protectionDowngradeMessage("passkey", "device")
    );
    expect((await listKeys())[0].protection).toBe("passkey");
  });
});

describe("a body it cannot store is refused by name", () => {
  it("names the armor it was handed", async () => {
    await expect(
      addPrivateKeyToMyKeys({
        content: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      })
    ).rejects.toThrow(/an armored CERTIFICATE block/);
  });

  it("says a public JWK has no private half", async () => {
    const pub = await tile("genkey ed25519 | out $kp", /public/);
    await expect(addPrivateKeyToMyKeys(pub)).rejects.toThrow(
      /a public OKP JWK, with no private half/
    );
  });

  it("refuses an empty body rather than writing an empty row", async () => {
    await expect(addPrivateKeyToMyKeys({ content: "" })).rejects.toThrow(
      /no body to store/
    );
    expect(await listKeys()).toHaveLength(0);
  });

  /**
   * §29f (c). The codec's sentence points at Inputs → passphrase, which is
   * right in a recipe and wrong here: this door is handed `{ content, alg }`
   * and no bindings, so the panel it names is one it cannot read. A prompt is
   * a UI affordance that does not exist; until it does, the least the refusal
   * owes the user is not to send them somewhere that changes nothing.
   */
  it("does not send a protected OpenSSH key to a panel this button cannot read", async () => {
    const { ast } = compileRecipe(`"correct horse" | out $pw

genkey ed25519 | ssh.encode format=private passphrase=$pw | out $enc`);
    const arts = await runRecipe(ast, {});
    const enc = arts.find((a) => /enc/.test(String(a.label)));
    expect(String(enc.content)).toContain("BEGIN OPENSSH PRIVATE KEY");

    await expect(addPrivateKeyToMyKeys({ content: enc.content })).rejects.toThrow(
      ENCRYPTED_SSH_KEY_MESSAGE
    );
    // And it is not the codec's sentence wearing a different hat.
    await expect(addPrivateKeyToMyKeys({ content: enc.content })).rejects.not.toThrow(
      ENCRYPTED_KEY_MESSAGE
    );
    expect(await listKeys()).toHaveLength(0);
  });

  it("still stores an unprotected OpenSSH block, so the refusal is about the passphrase", async () => {
    const { ast } = compileRecipe("genkey ed25519 | ssh.encode format=private | out $bare");
    const arts = await runRecipe(ast, {});
    const bare = arts.find((a) => /bare/.test(String(a.label)));
    const res = await addPrivateKeyToMyKeys({ content: bare.content, alg: "ed25519" });
    expect(res.kind).toBe("ssh");
    expect((await listKeys())[0].publicLine).toMatch(/^ssh-ed25519 /);
  });
});

/**
 * Agent + HKP toolkit ops and gpg key=@slot compose.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKey } from "openpgp";
import { runRecipe } from "../lib/toolkit/engine.js";
import {
  compileRecipe,
  migrateRecipe,
  validateRecipe,
} from "../lib/toolkit/recipe.js";
import { recipeNeedsMainThread } from "../lib/toolkit/registry.js";
import { listKeys, saveKey } from "../lib/vault.js";
import { sessionClear } from "../lib/vault-session.js";

beforeEach(async () => {
  sessionClear();
  vi.unstubAllGlobals();
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase("basilisk-vault");
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
});

describe("agent toolbox", () => {
  it("agent.list / unlock / pub and gpg.sign key=@me", async () => {
    const { privateKey: armoredPrivate, publicKey: armoredPublic } =
      await generateKey({
        type: "ecc",
        curve: "curve25519",
        userIDs: [{ email: "agent@example.com" }],
        format: "armored",
      });
    const { readKey } = await import("openpgp");
    const pub = await readKey({ armoredKey: armoredPublic });
    const fpr = pub.getFingerprint().toUpperCase();

    await saveKey({
      fingerprint: fpr,
      armoredPrivate,
      publicArmored: armoredPublic,
      uid: "agent@example.com",
      email: "agent@example.com",
      protection: "device",
    });

    const list = compileRecipe("agent.list | out @ring");
    expect(list.validation.ok).toBe(true);
    const listArts = await runRecipe(list.ast, { inputs: {} });
    const listText = listArts.map((a) => String(a.content)).join("\n");
    expect(listText).toContain(fpr);

    const recipe = `agent.unlock ${fpr} | out @me
input | gpg.sign key=@me | out @signed

in @signed | gpg.verify key=@me | out @ok`;
    const { ast, validation } = compileRecipe(recipe);
    expect(validation.ok).toBe(true);
    expect(recipeNeedsMainThread(ast)).toBe(true);
    expect(validation.inputNeeds || []).not.toContain("gpg");
    expect(validation.inputNeeds || []).toContain("gpgPass");

    const arts = await runRecipe(ast, {
      inputs: {
        text: { value: "hello agent" },
        gpg: { passphrase: "", privateKeyArmored: "", armoredMessages: [] },
      },
    });
    const ok = arts.find((a) => /ok/i.test(a.filename || a.label || "")) || arts.at(-1);
    expect(String(ok.content)).toMatch(/verified/i);

    const pubRun = compileRecipe(`agent.pub ${fpr} | out @pub`);
    const pubArts = await runRecipe(pubRun.ast, { inputs: {} });
    expect(pubArts.map((a) => String(a.content)).join("\n")).toContain(
      "BEGIN PGP PUBLIC KEY"
    );
  }, 60_000);

  it("agent.save stores a generated key", async () => {
    const { ast, validation } = compileRecipe(
      `gpg.genkey email="save@example.com" | agent.save protection=device | out @priv`
    );
    expect(validation.ok).toBe(true);
    expect(recipeNeedsMainThread(ast)).toBe(true);
    const arts = await runRecipe(ast, { inputs: {} });
    expect(arts.map((a) => String(a.content)).join("\n")).toContain("PRIVATE KEY");
    const keys = await listKeys();
    expect(keys.length).toBeGreaterThanOrEqual(1);
    expect(keys[0].publicArmored).toContain("PUBLIC KEY");
  }, 60_000);

  it("migrates gpg.vault → agent.unlock", () => {
    expect(migrateRecipe("gpg.vault AABB | out @me").recipe).toContain(
      "agent.unlock"
    );
    expect(migrateRecipe("gpg.vault.pub AABB | out @p").recipe).toContain(
      "agent.pub"
    );
  });

  it("parses positional fingerprints that start with a digit", () => {
    const fpr = "8F" + "A".repeat(38);
    const { ast, validation } = compileRecipe(`hkp.get ${fpr} | out @bob`);
    expect(validation.ok).toBe(true);
    expect(ast?.chains?.[0]?.steps?.[0]?.params?.fpr).toBe(fpr);
  });

  it("validateRecipe exposes gpgPass for key=@slot sign", () => {
    const { ast } = compileRecipe(
      `agent.unlock ${"A".repeat(40)} | out @me
input | gpg.sign key=@me | out @signed`
    );
    const v = validateRecipe(ast);
    expect(v.inputNeeds || []).toContain("gpgPass");
  });
});

describe("hkp toolbox", () => {
  it("hkp.get uses loadRecipientKey stack", async () => {
    const { publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "bob@example.com" }],
      format: "armored",
    });
    const { readKey } = await import("openpgp");
    const pub = await readKey({ armoredKey: publicKey });
    const realFpr = pub.getFingerprint().toUpperCase();

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const u = String(url);
        if (u.includes("/api/v1/key/")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              approval_state: "approved",
              approved_uids: ["Bob <bob@example.com>"],
              key_id: realFpr.slice(-16),
              revoked: false,
            }),
          };
        }
        if (u.includes("/pks/lookup")) {
          return {
            ok: true,
            status: 200,
            text: async () => publicKey,
          };
        }
        throw new Error(`unexpected fetch ${u}`);
      })
    );

    const { ast, validation } = compileRecipe(`hkp.get ${realFpr} | out @bob`);
    expect(validation.ok).toBe(true);
    const arts = await runRecipe(ast, { inputs: {} });
    expect(arts.map((a) => String(a.content)).join("\n")).toContain(
      "BEGIN PGP PUBLIC KEY"
    );
    vi.unstubAllGlobals();
  }, 60_000);
});

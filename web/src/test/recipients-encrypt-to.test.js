/**
 * recipients / openpgp-key types, hkp.filter, gpg.encrypt to=@ / mode, session strip helpers.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKey, readKey } from "openpgp";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, unresolvedRecipients } from "../lib/toolkit/recipe.js";
import {
  filterRecipients,
  parseEncryptToToken,
  stepEncryptToBound,
} from "../lib/toolkit/recipients-ops.js";
import { formatType, inferSourceType } from "../lib/toolkit/types.js";
import { stepsAccepting } from "../lib/toolkit/registry.js";
import {
  sessionClear,
  sessionList,
  sessionPut,
} from "../lib/vault-session.js";

beforeEach(() => {
  sessionClear();
  vi.unstubAllGlobals();
});

describe("pipeline types", () => {
  it("inferSourceType for hkp.search / agent.unlock / agent.pub", () => {
    expect(formatType(inferSourceType("hkp.search"))).toBe("recipients");
    expect(formatType(inferSourceType("agent.unlock"))).toBe(
      "openpgp-key/private"
    );
    expect(formatType(inferSourceType("agent.pub"))).toBe("openpgp-key/public");
    expect(formatType(inferSourceType("hkp.get"))).toBe("openpgp-key/public");
  });

  it("stepsAccepting(recipients) includes filter/out, excludes stem gpg.encrypt", () => {
    const from = inferSourceType("hkp.search");
    const names = stepsAccepting(from).map((s) => s.name);
    expect(names).toContain("out");
    expect(names).toContain("hkp.filter");
    expect(names).toContain("recipients.merge");
    expect(names).not.toContain("gpg.encrypt");
  });

  it("stepsAccepting(openpgp-key/private) prefers out / agent.save", () => {
    const from = inferSourceType("agent.unlock");
    const names = stepsAccepting(from).map((s) => s.name);
    expect(names).toContain("out");
    expect(names).toContain("agent.save");
    expect(names).not.toContain("gpg.encrypt");
  });
});

describe("parseEncryptToToken / binder skip", () => {
  it("parses slot, email, fpr forms", () => {
    expect(parseEncryptToToken("$alices")).toEqual({
      kind: "slot",
      ref: "$alices",
    });
    expect(parseEncryptToToken("alice@example.org")).toEqual({
      kind: "email",
      query: "alice@example.org",
    });
    expect(parseEncryptToToken("email:bob@x.com")).toEqual({
      kind: "email",
      query: "bob@x.com",
    });
    const fpr = "A".repeat(40);
    expect(parseEncryptToToken(`fpr:${fpr}`)).toEqual({
      kind: "fpr",
      fingerprint: fpr,
    });
    expect(parseEncryptToToken(`0x${fpr}`)).toEqual({
      kind: "fpr",
      fingerprint: fpr,
    });
    expect(parseEncryptToToken(fpr)).toEqual({
      kind: "fpr",
      fingerprint: fpr,
    });
  });

  it("recipe parser accepts unquoted to=email", () => {
    const { ast, validation } = compileRecipe(
      `input | gpg.encrypt to=alice@example.org policy=ask`
    );
    expect(validation.ok).toBe(true);
    expect(ast?.chains?.[0]?.steps?.[1]?.params?.to).toBe("alice@example.org");
  });

  it("unresolvedRecipients skips binder when to= is set", () => {
    const withTo = compileRecipe(
      `hkp.search a | out $alices

input | gpg.encrypt to=$alices`
    );
    expect(withTo.validation.ok).toBe(true);
    expect(unresolvedRecipients(withTo.ast).slots).toBe(0);
    const enc = withTo.ast.chains
      .flatMap((c) => c.steps)
      .find((s) => s.name === "gpg.encrypt");
    expect(stepEncryptToBound(enc)).toBe(true);

    const binder = compileRecipe("input | gpg.encrypt");
    expect(unresolvedRecipients(binder.ast).slots).toBe(1);
  });
});

describe("hkp.filter", () => {
  it("drops unapproved / non-encrypt", () => {
    const list = [
      {
        fingerprint: "A".repeat(40),
        armoredPublic: "x",
        approvalState: "approved",
        encryptCapable: true,
      },
      {
        fingerprint: "B".repeat(40),
        armoredPublic: "y",
        approvalState: "pending",
        encryptCapable: true,
      },
      {
        fingerprint: "C".repeat(40),
        armoredPublic: "z",
        approvalState: "approved",
        encryptCapable: false,
      },
    ];
    expect(filterRecipients(list).map((r) => r.fingerprint[0])).toEqual(["A"]);
  });
});

describe("gpg.encrypt to=$slot", () => {
  it("encrypts via real out $slot pipeline (separate + combined)", async () => {
    const alice = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "alice@example.com" }],
      format: "armored",
    });
    const bob = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "bob@example.com" }],
      format: "armored",
    });
    const alicePub = await readKey({ armoredKey: alice.publicKey });
    const bobPub = await readKey({ armoredKey: bob.publicKey });
    const af = alicePub.getFingerprint().toUpperCase();
    const bf = bobPub.getFingerprint().toUpperCase();

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const u = String(url);
        if (u.includes("/api/v1/search")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              results: [
                {
                  fingerprint: af,
                  email: "alice@example.com",
                  uid: "Alice <alice@example.com>",
                  approval_state: "approved",
                  armoredKey: alice.publicKey,
                },
                {
                  fingerprint: bf,
                  email: "bob@example.com",
                  uid: "Bob <bob@example.com>",
                  approval_state: "approved",
                  armoredKey: bob.publicKey,
                },
              ],
            }),
          };
        }
        if (u.includes("/api/v1/key/")) {
          const fpr = u.split("/").pop()?.toUpperCase() || "";
          const armored =
            fpr === af ? alice.publicKey : fpr === bf ? bob.publicKey : "";
          return {
            ok: true,
            status: 200,
            json: async () => ({
              approval_state: "approved",
              approved_uids: ["x"],
              key_id: fpr.slice(-16),
              revoked: false,
            }),
            // loadRecipientKey may use json then pks
          };
        }
        if (u.includes("/pks/lookup")) {
          const q = decodeURIComponent(u.split("search=")[1] || "");
          const hex = q.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
          const armored =
            hex.includes(af) || af.endsWith(hex.slice(-16))
              ? alice.publicKey
              : bob.publicKey;
          return {
            ok: true,
            status: 200,
            text: async () => armored,
          };
        }
        throw new Error(`unexpected fetch ${u}`);
      })
    );

    const sep = compileRecipe(
      `hkp.search team | hkp.filter | out $alices

input | gpg.encrypt to=$alices mode=separate`
    );
    expect(sep.validation.ok).toBe(true);
    expect(unresolvedRecipients(sep.ast).slots).toBe(0);
    const sepArts = await runRecipe(sep.ast, {
      inputs: { text: { value: "hello separate" } },
    });
    const sepCipher = sepArts.filter((a) =>
      String(a.content).includes("BEGIN PGP MESSAGE")
    );
    expect(sepCipher.length).toBeGreaterThanOrEqual(2);

    const comb = compileRecipe(
      `hkp.search team | hkp.filter | out $alices

input | gpg.encrypt to=$alices mode=combined`
    );
    const combArts = await runRecipe(comb.ast, {
      inputs: { text: { value: "hello combined" } },
    });
    const combCipher = combArts.filter((a) =>
      String(a.content).includes("BEGIN PGP MESSAGE")
    );
    expect(combCipher.length).toBe(1);
  }, 90_000);

  it("email to= uses recipientResolutions", async () => {
    const { publicKey } = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "alice@example.com" }],
      format: "armored",
    });
    const pub = await readKey({ armoredKey: publicKey });
    const fpr = pub.getFingerprint().toUpperCase();

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) => {
        const u = String(url);
        if (u.includes("/api/v1/key/") || u.includes("/pks/lookup")) {
          if (u.includes("/api/v1/key/")) {
            return {
              ok: true,
              status: 200,
              json: async () => ({
                approval_state: "approved",
                approved_uids: ["Alice <alice@example.com>"],
                key_id: fpr.slice(-16),
                revoked: false,
              }),
            };
          }
          return {
            ok: true,
            status: 200,
            text: async () => publicKey,
          };
        }
        throw new Error(`unexpected ${u}`);
      })
    );

    const { ast, validation } = compileRecipe(
      `input | gpg.encrypt to=alice@example.org policy=one`
    );
    expect(validation.ok).toBe(true);
    expect(unresolvedRecipients(ast).slots).toBe(0);

    await expect(
      runRecipe(ast, {
        inputs: { text: { value: "hi" } },
        recipientResolutions: {},
      })
    ).rejects.toThrow(/look up recipients/i);

    const arts = await runRecipe(ast, {
      inputs: { text: { value: "hi" } },
      recipientResolutions: { "alice@example.org": [fpr] },
    });
    expect(
      arts.some((a) => String(a.content).includes("BEGIN PGP MESSAGE"))
    ).toBe(true);
  }, 60_000);
});

describe("sessionList for agent chrome", () => {
  it("lists metas without armor and clears on sessionClear", () => {
    sessionPut("A".repeat(40), "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake\n-----END PGP PRIVATE KEY BLOCK-----");
    const list = sessionList();
    expect(list).toHaveLength(1);
    expect(list[0].fingerprint).toBe("A".repeat(40));
    expect(JSON.stringify(list)).not.toMatch(/PRIVATE KEY/);
    sessionClear();
    expect(sessionList()).toHaveLength(0);
  });
});

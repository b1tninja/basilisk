/**
 * recipients / openpgp-key types, hkp.filter, gpg.encrypt to=@ / mode, session strip helpers.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKey, readKey } from "openpgp";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe, unresolvedRecipients } from "../lib/toolkit/recipe.js";
import {
  encryptUnverifiedCount,
  filterRecipients,
  parseEncryptToToken,
  recipientFromSearchHit,
  stepEncryptToBound,
} from "../lib/toolkit/recipients-ops.js";
import { formatType, inferSourceType } from "../lib/toolkit/types.js";
import { STEPS, stepsAccepting } from "../lib/toolkit/registry.js";
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

  it("keeps a row whose capability nobody could read, and counts it", () => {
    // The state that did not exist before: `null` is not `false`, so the filter
    // has no grounds to drop the row — and it is not `true` either, so the
    // result must not present it as checked. Both halves are asserted, because
    // either one alone is satisfied by collapsing back to a boolean.
    const list = [
      { fingerprint: "A".repeat(40), approvalState: "approved", encryptCapable: true },
      { fingerprint: "D".repeat(40), approvalState: "approved", encryptCapable: null },
      { fingerprint: "C".repeat(40), approvalState: "approved", encryptCapable: false },
    ];
    const kept = filterRecipients(list);
    expect(kept.map((r) => r.fingerprint[0])).toEqual(["A", "D"]);
    expect(encryptUnverifiedCount(kept)).toBe(1);
    expect(encryptUnverifiedCount(list.filter((r) => r.encryptCapable === true))).toBe(0);
  });

  it("reads the directory's expiry, and does not guess from its silence", () => {
    // `key_expiration` was in every `key_summary` payload and nothing on this
    // path read it, so the one expired key in the corpus went through a filter
    // asked to keep only keys that can encrypt. It is decided now — and only
    // in the direction the field can support: a row that states a past instant
    // is incapable, a row that states nothing has not said anything.
    const past = new Date(Date.now() - 86400000).toISOString();
    const future = new Date(Date.now() + 86400000).toISOString();
    const row = (extra) => ({
      fingerprint: "A".repeat(40),
      approval_state: "approved",
      origin: "basilisk",
      ...extra,
    });
    expect(recipientFromSearchHit(row({ key_expiration: past })).encryptCapable).toBe(false);
    expect(recipientFromSearchHit(row({ key_expiration: past })).valid).toBe(false);
    expect(recipientFromSearchHit(row({ key_expiration: future })).encryptCapable).toBeNull();
    expect(recipientFromSearchHit(row({ key_expiration: null })).encryptCapable).toBeNull();
    expect(recipientFromSearchHit(row({ key_expiration: "not a date" })).encryptCapable).toBeNull();
    // Revocation was already decidable and stays decided.
    expect(recipientFromSearchHit(row({ revoked: true })).encryptCapable).toBe(false);
  });

  it("says what it can promise, on the switch a person reads", () => {
    // The registry is the copy. It read "Keep only encrypt-capable keys" over a
    // result that kept a signing-only key and an expired one — a control lying
    // about its own name. A filter that cannot fully judge must not claim it
    // did, so the promise is now exactly the two facts the directory reports.
    const filter = STEPS.find((s) => s.name === "hkp.filter");
    const encrypt = filter.params.find((p) => p.name === "encrypt");
    expect(encrypt.doc).not.toMatch(/Keep only encrypt-capable/);
    expect(encrypt.doc).toMatch(/revoked, expired/);
    expect(encrypt.doc).toMatch(/unverified/);
    // And it names the op that *can* answer, rather than leaving the reader
    // with a limitation and no way past it.
    expect(encrypt.doc).toMatch(/hkp\.get/);
    expect(filter.doc).not.toMatch(/encrypt-capable/);
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

    /*
     * Which recipient each ciphertext is for, said whole.
     *
     * `mode=separate` makes one artifact per recipient and the label and
     * filename are the *only* things telling them apart — a sender picking
     * which file to hand to whom has nothing else on the tile. Both used to be
     * `fpr.slice(-8)`: `GPG ciphertext (6ad01388)` and `encrypted-6ad01388.asc`,
     * a 32-bit short key id doing the whole work of naming a recipient, in two
     * files that land in one folder.
     *
     * Written against the *behaviour* rather than the spelling, which is the
     * lesson from the slot label that never worked: a pin matching
     * `fingerprint.slice(-8)` survived a mutation because the code said
     * `fpr.slice(-8)`. So this asserts what a person can read — the whole
     * fingerprint present, and specifically the truncation absent as the only
     * hex on the line.
     */
    for (const fpr of [af, bf]) {
      const art = sepCipher.find((a) => a.recipientFingerprint === fpr);
      expect(art, `no separate ciphertext for ${fpr}`).toBeTruthy();
      expect(art.label).toContain(fpr);
      expect(art.filename).toBe(`encrypted-${fpr.toLowerCase()}.asc`);
      // The stem is the whole value, not a tail of it — `endsWith` is satisfied
      // by 8 and by 16 alike, and only one of them is the fingerprint.
      expect(art.filename.slice("encrypted-".length, -".asc".length)).toBe(
        fpr.toLowerCase()
      );
      expect(art.label).not.toMatch(/\(\s*[0-9a-f]{8}\s*\)/i);
    }

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

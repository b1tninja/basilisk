/**
 * The sealed envelope: a share that survives the room it was dealt in.
 *
 * ## What was there before
 *
 * A share travels `quorum.send` → `NotebookSession.sendChatTo`, under the
 * pairwise session key. That is transport encryption and it dies with the room:
 * what lands in the holder's slot is a bare mnemonic. There is no original GPG
 * envelope anywhere in this product to preserve — so an envelope has to be
 * *made*, and `gpg.encrypt` is the op that would make it.
 *
 * ## The trap that stopped it
 *
 * `gpg.encrypt` returned `{ type: "artifact", data: null }`. The armor went to
 * the run's artifact list; the pipe got a marker. Nothing wrong so far — the
 * engine reads that marker correctly, and `valueToArtifacts` and the
 * dangling-tip emitter both skip it on the base.
 *
 * `out` did not. `gpg.encrypt … | out $sealed` registered a slot whose runtime
 * value was **null**, while the type walk recorded `{base:"artifact"}` and
 * `publishability` projected that through `artifactMetaFromType`'s final
 * fallthrough to role `text` and answered **publishable: true**. So a `publish`
 * standing on it passed the plan, and a cell that had produced a perfectly good
 * ciphertext would have handed the room nothing.
 *
 * The suite had noticed and worked around it rather than fixing it:
 * `verb-smoke.js`'s `encryptToVerbSmokeKey` builds ciphertext with the openpgp
 * library directly, and says why in a comment — "`gpg.encrypt` emits its
 * ciphertext as an artifact and returns a null-data value, which no later cell
 * can read from a slot". The recipe language could not encrypt something and
 * then do anything with it.
 *
 * ## What is here now
 *
 * Two facts, and the second is the whole feature:
 *
 * 1. `artifact` means *the pipe is empty*, and nothing may name an empty pipe.
 *    `out`, `publish`, `tee`, `peek`, `clipboard.write` and `file.save` refuse
 *    it at compile time, on text, before a ceremony deals anything.
 * 2. `gpg.encrypt mode=combined` writes **exactly one** message however many
 *    recipients it has, so it has a value to hand on and hands it on as
 *    `text/armored/openpgp` — the spelling `gpg.symencrypt mode=passphrase`
 *    already uses for the same object. `mode=separate` writes one per recipient,
 *    a count no recipe text carries, and stays a sink.
 *
 * The output type is therefore a function of a literal in the recipe, which is
 * the determinism rule met rather than bent.
 */
import "fake-indexeddb/auto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decrypt, generateKey, readKey, readMessage, readPrivateKey } from "openpgp";
import { runRecipe } from "../lib/toolkit/engine.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { planRun, publishability, slotTypes } from "../lib/toolkit/plan.js";
import { getStep } from "../lib/toolkit/registry.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";
import { formatType, gpgEncryptOutput } from "../lib/toolkit/types.js";
import { decodeMnemonic } from "../lib/slip39/blip39.js";
import { combineShares } from "../lib/slip39/slip39.js";

const FPR_DEALER = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_HOLDER = "91C7E6D5C4B3A29180716253443526170819AABB";
const ROSTER = { mara: FPR_DEALER, okafor: FPR_HOLDER };

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * A holder's OpenPGP key, reachable the way `to=fpr:` reaches one.
 *
 * `loadRecipientKey` goes to the network for armor it does not have, so the
 * fetch is stubbed rather than a keyring being pre-seeded — the point under
 * test is the pipeline, and this is the shortest honest way to give it a real
 * recipient whose private half the test also holds.
 */
async function holderKey({ sign = false } = {}) {
  const { publicKey, privateKey } = await generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ email: "okafor@example.com" }],
    format: "armored",
    // A signing-only key: no encryption subkey for a message to be sealed to.
    ...(sign ? { subkeys: [{ sign: true }] } : {}),
  });
  const pub = await readKey({ armoredKey: publicKey });
  const fingerprint = pub.getFingerprint().toUpperCase();
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
            approved_uids: ["Okafor <okafor@example.com>"],
            key_id: fingerprint.slice(-16),
            revoked: false,
          }),
        };
      }
      if (u.includes("/pks/lookup")) {
        return { ok: true, status: 200, text: async () => publicKey };
      }
      throw new Error(`unexpected fetch ${u}`);
    })
  );
  return { fingerprint, publicKey, privateKey };
}

/** Three mnemonics of one 2-of-3 split, as a run of the language produces them. */
async function deal() {
  const { ast, validation } = compileRecipe(
    "random 32 | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out $share"
  );
  expect(validation.errors.map((e) => e.message)).toEqual([]);
  const arts = await runRecipe(ast);
  const shares = arts.filter((a) => a.shareIndex).map((a) => String(a.content));
  expect(shares).toHaveLength(3);
  return shares;
}

const errorsFor = (src) =>
  (compileRecipe(src).validation.errors || []).map((e) => e.message);

/* ─────────────────────────── 1. the trap, closed ────────────────────────── */

describe("an empty pipe cannot be named", () => {
  const SEP = "@mara\nrandom 16 | encode hex | gpg.encrypt to=fpr:AABB | out $sealed";

  it("refuses `out` after the mode that leaves nothing in the pipe", () => {
    const [first] = errorsFor(SEP);
    expect(first).toMatch(/^"out" needs a pipeline value, and the step before it left none/);
  });

  it("names a remedy that can be performed, and it is the one that works", () => {
    // The rule this file is held to: a refusal names a state that is true and
    // never a remedy that cannot be taken. So the sentence's own advice is
    // taken here, verbatim, and the result must compile.
    const [first] = errorsFor(SEP);
    expect(first).toContain("`mode=combined` writes exactly one and pipes it on as text");
    expect(errorsFor(SEP.replace("gpg.encrypt", "gpg.encrypt mode=combined"))).toEqual([]);
  });

  it("leaves no slot behind for anything downstream to ask about", () => {
    // The half of the trap that made it dangerous. A refusal that still
    // registered `$sealed` would leave `publishability` answering questions
    // about a value that does not exist, which is exactly what it was doing.
    expect(slotTypes(compileRecipe(SEP)).has("sealed")).toBe(false);
    expect(publishability(slotTypes(compileRecipe(SEP)).get("sealed"))).toEqual({
      known: false,
      publishable: false,
      role: "",
      publicHalf: false,
    });
  });

  it("refuses every step that names or moves a value, not only `out`", () => {
    // One rule, five steps. `file.save` is the one that would have written the
    // nothing to disk; `tee`, `peek` and `clipboard.write` are here because a
    // rule enforced at one door is a rule with four gaps.
    for (const step of ["clipboard.write", "file.save", "peek"]) {
      const src = `@mara\nrandom 16 | encode hex | gpg.encrypt to=fpr:AABB | ${step}`;
      expect(errorsFor(src)[0], step).toMatch(
        new RegExp(`^"${step.replace(".", "\\.")}" needs a pipeline value, and the step before it left none`)
      );
    }
    // `tee` is reached through its body — the walk enters it and refuses the
    // first step inside, which is the same rule one level down and the level
    // where a reader's cursor is.
    expect(
      errorsFor("@mara\nrandom 16 | encode hex | gpg.encrypt to=fpr:AABB | tee\n  - out $a")[0]
    ).toMatch(/^"out" needs a pipeline value, and the step before it left none/);
  });

  it("lets `publish` keep its own truer sentence, which fires first", () => {
    // `publish` is refused before the type walk reaches it, by the structural
    // rule that a claim has to stand behind an `out`. That sentence is *more*
    // specific than this file's — it names why `gpg.encrypt` cannot be
    // published rather than why its tip cannot be carried — so it is left
    // alone, and pinned here so a later edit cannot quietly replace one true
    // refusal with a vaguer one.
    expect(
      errorsFor("@mara\nrandom 16 | encode hex | gpg.encrypt to=fpr:AABB | publish")[0]
    ).toMatch(/`gpg\.encrypt` does not name one/);
  });

  it("says the same thing about `qr`, the other producer of an empty pipe", () => {
    // `artifact` is a property of the base, not a special case for one op —
    // `qr` returns the same marker for the same reason, and a rule written
    // around `gpg.encrypt` by name would have left this door open.
    expect(errorsFor("@mara\nrandom 16 | encode hex | qr | out $q")[0]).toMatch(
      /^"out" needs a pipeline value, and the step before it left none/
    );
  });
});

/* ──────────────────────── 2. the type, before the run ───────────────────── */

describe("what `gpg.encrypt` leaves in the pipe is knowable from the text", () => {
  it("is decided by `mode=` and by nothing else", () => {
    expect(gpgEncryptOutput({ mode: "combined" })).toEqual({
      base: "text",
      kind: "armored",
      encoding: "openpgp",
    });
    expect(gpgEncryptOutput({ mode: "separate" })).toEqual({ base: "artifact" });
    // The default is the fan-out, so a recipe that says nothing gets the sink.
    expect(gpgEncryptOutput({})).toEqual({ base: "artifact" });
  });

  it("reads the same in the caret as in the compiler", () => {
    // `effectiveIo` feeds the ops shelf and the tool card; `resolveStepType`
    // feeds the compiler. Two answers to "what comes out of this step" is the
    // defect `quorum.recv`'s own test pins for the same reason.
    for (const mode of ["combined", "separate", undefined]) {
      expect(getStep("gpg.encrypt").effectiveIo({ mode }).output, String(mode)).toBe(
        gpgEncryptOutput({ mode }).base
      );
    }
  });

  it("spells armor the way `gpg.symencrypt` already spells it", () => {
    // One object, one name. `gpg.symencrypt mode=passphrase` has emitted
    // `text/armored/openpgp` since it shipped, and a second producer of the
    // same armor inventing a second kind is how two vocabularies start.
    const src = `"hi" | utf8 | gpg.symencrypt mode=passphrase passphrase=$p | out $a`;
    void src;
    expect(formatType(gpgEncryptOutput({ mode: "combined" }))).toBe("text/armored/openpgp");
  });
});

/* ─────────────────────── 3. the envelope, end to end ────────────────────── */

describe("a share sealed to its holder", () => {
  it("lands in a named slot as real armor, and the plan lets it leave", async () => {
    const holder = await holderKey();
    const [share] = await deal();
    const src =
      `@mara\n"${share}" | gpg.encrypt mode=combined to=fpr:${holder.fingerprint} ` +
      `| out $sealed | publish`;
    const compiled = compileRecipe(src);
    expect(compiled.validation.errors.map((e) => e.message)).toEqual([]);

    // Before the run: the type walk knows what is in the slot, and the planner
    // answers the question that used to be answered about a null.
    const types = slotTypes(compiled);
    expect(formatType(types.get("sealed"))).toBe("text/armored/openpgp");
    expect(publishability(types.get("sealed")).publishable).toBe(true);
    const plan = planRun(compiled, { me: "mara", roster: ROSTER });
    expect(plan.refusals).toEqual([]);
    expect(plan.cells[0].publishes).toEqual(["sealed"]);

    // After the run: the slot holds the armor, not a marker.
    const registry = createSlotRegistry();
    await runRecipe(compiled.ast, {}, { slotRegistry: registry });
    const held = registry.resolve("$sealed");
    expect(held.type).toBe("text");
    expect(String(held.data)).toContain("-----BEGIN PGP MESSAGE-----");
  }, 60_000);

  /**
   * The disclosure this design turns on.
   *
   * A published envelope is read by the whole room. If the value carried
   * `shareIndex` outward, the room would learn which share went to whom, which
   * is the one fact a K-of-N split is keeping — so the sealed value drops it,
   * and the mnemonic *inside* keeps it. `encodeMnemonic` writes threshold,
   * share count, index and set id into the BLIP39 header before a single word
   * of data, so nothing had to be invented to carry them: only the holder, who
   * can open the envelope, reads them.
   *
   * The registry no longer takes a side: `out $sealed` binds its label
   * whatever meta the value carries (the old divert on `shareIndex` is gone),
   * so this drop stands on the disclosure argument alone — which is the
   * argument it always had, and why the assertion below survives the
   * registry change untouched.
   */
  it("keeps the share's index inside the envelope and off the value", async () => {
    const holder = await holderKey();
    // `at 2` is the one path that hands `gpg.encrypt` a value already carrying
    // `shareIndex` / `shareCount` / `threshold` — a mnemonic re-entering as
    // text has none, so sealing a literal would prove nothing about dropping
    // them.
    const src = [
      "random 32 | sss.split threshold=2 shares=3 | blip39 | out $set",
      "",
      `in $set | at 2 | gpg.encrypt mode=combined to=fpr:${holder.fingerprint} | out $sealed`,
    ].join("\n");
    const compiled = compileRecipe(src);
    expect(compiled.validation.errors.map((e) => e.message)).toEqual([]);
    const registry = createSlotRegistry();
    const arts = await runRecipe(compiled.ast, {}, { slotRegistry: registry });

    // The slot exists, and the value in it wears no share index — two separate
    // facts now that registration no longer depends on the meta, and the
    // second is the one the disclosure design turns on.
    expect(registry.labels()).toContain("sealed");
    const held = registry.resolve("$sealed");
    expect(held.meta.shareIndex).toBeUndefined();
    expect(held.meta.shareCount).toBeUndefined();
    expect(held.meta.threshold).toBeUndefined();
    expect(held.meta.sensitive).toBe(false);

    // The facts are not lost, they are inside: the plaintext says all three,
    // in the BLIP39 header, where only the holder reads them.
    const share2 = arts.filter((a) => a.shareIndex === 2).map((a) => String(a.content))[0];
    expect(decodeMnemonic(share2).index).toBe(2);
    expect(decodeMnemonic(share2).threshold).toBe(2);
    expect(decodeMnemonic(share2).shareCount).toBe(3);
  }, 60_000);

  it("still labels the dealer's own tile, on the machine entitled to know", async () => {
    // The tile is built from the *input* value's meta, before the sealed value
    // is made, so dropping the field from the value does not blank the tile.
    // Reached through `foreach`, because that is the shape that carries
    // `shareIndex` — a mnemonic re-entering as text has no index to carry, and
    // that limitation is real rather than an artefact of this test.
    const holder = await holderKey();
    const src =
      "random 32 | sss.split threshold=2 shares=3 | blip39 | foreach\n" +
      `  - gpg.encrypt mode=combined to=fpr:${holder.fingerprint}`;
    const arts = await runRecipe(compileRecipe(src).ast);
    const tiles = arts.filter((a) => a.role === "share");
    expect(tiles).toHaveLength(3);
    expect(tiles.map((a) => a.traits?.shareOf)).toEqual([1, 2, 3]);
    expect(tiles.map((a) => a.traits?.threshold)).toEqual([2, 2, 2]);
    // `ShareIdentity` reads `traits.shareOf` and prefers `encrypted` over
    // `blip39` for the flavour, so this tile says "encrypted share" rather
    // than telling a custodian to read words off armor.
    expect(tiles[0].tags).toContain("encrypted");
    expect(tiles.every((a) => a.sensitive === false)).toBe(true);
  }, 60_000);

  it("opens on the holder's key and recombines to the dealer's secret", async () => {
    const holder = await holderKey();
    const dealt = await deal();

    // Seal two of the three, each in its own cell, exactly as a dealer would.
    const src = [
      `@mara`,
      `"${dealt[0]}" | gpg.encrypt mode=combined to=fpr:${holder.fingerprint} | out $sealed1 | publish`,
      ``,
      `@mara`,
      `"${dealt[2]}" | gpg.encrypt mode=combined to=fpr:${holder.fingerprint} | out $sealed2 | publish`,
    ].join("\n");
    const compiled = compileRecipe(src);
    expect(compiled.validation.errors.map((e) => e.message)).toEqual([]);
    const registry = createSlotRegistry();
    await runRecipe(compiled.ast, {}, { slotRegistry: registry });

    // The holder's side. Their private key is in their vault, so the open
    // happens with the key rather than in the recipe — what is being proved
    // here is that what crossed is openable and is the share it claims to be.
    const priv = await readPrivateKey({ armoredKey: holder.privateKey });
    const opened = [];
    for (const label of ["$sealed1", "$sealed2"]) {
      const { data } = await decrypt({
        message: await readMessage({ armoredMessage: String(registry.resolve(label).data) }),
        decryptionKeys: priv,
      });
      opened.push(String(data));
    }
    expect(opened).toEqual([dealt[0], dealt[2]]);

    // And the recovered secret is the dealer's, from two shares that spent the
    // whole journey inside envelopes.
    const recovered = await combineShares(opened);
    const straight = await combineShares([dealt[0], dealt[2]]);
    expect(Array.from(recovered)).toEqual(Array.from(straight));
    expect(recovered).toHaveLength(32);
  }, 60_000);
});

/* ────────────────────────────── 4. the reverse ──────────────────────────── */

describe("the recovery cell can be written without leaving the language", () => {
  it("compiles envelope → plaintext → share set → secret", () => {
    // `agent.decrypt` is a transform (`text` → `text`), so it reads the slot
    // the envelope arrived in and hands the mnemonic on; `shares` collects it
    // off the pipe, which is what `dc5d7cb` made possible. Every link in that
    // chain is a compile-time type, which is why this is worth asserting as
    // text rather than only running it.
    const src = [
      `"-----BEGIN PGP MESSAGE-----" | out $sealed`,
      ``,
      `in $sealed | agent.decrypt | shares | blip39 -d | sss.combine | encode hex | out $secret`,
    ].join("\n");
    expect(errorsFor(src)).toEqual([]);
  });

  it("still discards a piped envelope, and now refuses further downstream", () => {
    // `gpg.decrypt` is a *source* with no `collects`, so `in $sealed |
    // gpg.decrypt` throws the envelope away and reads the Inputs tray instead.
    // That is the defect `dc5d7cb` fixed for `shares` and has still not been
    // fixed here — pinned as the state that is true rather than asserted away.
    expect(getStep("gpg.decrypt").collects).toBeUndefined();
    expect(getStep("shares").collects).toEqual(["text", "bundle"]);

    // What has changed is what happens next. This spelling used to compile
    // clean, because a decrypt claimed `shares` and `blip39 -d` was happy to
    // take it. A decrypt now yields plaintext, so the mnemonics have to be
    // collected before they can be decoded, and the compiler says so. The
    // discarded envelope is still silent; the type error is not.
    const src =
      `"x" | out $sealed\n\nin $sealed | gpg.decrypt | blip39 -d | sss.combine | out $secret`;
    const errors = errorsFor(src);
    expect(errors.join(" ")).toMatch(/blip39.*expects shares, got text/);
  });
});

/* ───────────────────────────── 5. what refuses ──────────────────────────── */

describe("what a seal refuses", () => {
  it("refuses a key that cannot encrypt, naming the key", async () => {
    const holder = await holderKey({ sign: true });
    const src = `@mara\n"hi" | gpg.encrypt mode=combined to=fpr:${holder.fingerprint} | out $sealed`;
    await expect(
      runRecipe(compileRecipe(src).ast, {}, { slotRegistry: createSlotRegistry() })
    ).rejects.toThrow(/encryption key/i);
  }, 60_000);

  it("refuses an envelope opened by the wrong key", async () => {
    const holder = await holderKey();
    const stranger = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ email: "nobody@example.com" }],
      format: "armored",
    });
    // `holderKey` re-stubs fetch, so seal to the holder while that stub stands.
    const src = `@mara\n"hi" | gpg.encrypt mode=combined to=fpr:${holder.fingerprint} | out $sealed`;
    const registry = createSlotRegistry();
    await runRecipe(compileRecipe(src).ast, {}, { slotRegistry: registry });
    const armored = String(registry.resolve("$sealed").data);
    await expect(
      decrypt({
        message: await readMessage({ armoredMessage: armored }),
        decryptionKeys: await readPrivateKey({ armoredKey: stranger.privateKey }),
      })
    ).rejects.toThrow(/decryption key/i);
  }, 60_000);
});

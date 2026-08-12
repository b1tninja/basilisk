/**
 * Recipe playbooks — the document, the two ops, and what a stranger can do
 * with one years later.
 *
 * The weight of this file is on refusals, for `manifest-attest.test.js`'s
 * reason: a reader that only ever passes proves nothing. Three groups of them:
 *
 * 1. **What the document may not carry.** `parsePlaybook` refuses any field
 *    outside `PLAYBOOK_FIELDS`, because "must not carry a fingerprint, a vault
 *    key id or an audience" is a property of the shape or it is a comment — and
 *    unlike a manifest, this document is *meant* to be handed to somebody who
 *    was never in the room.
 * 2. **What it may not say.** A playbook whose digest does not describe the
 *    recipe beside it is refused before anybody runs the recipe.
 * 3. **What may not open one.** There is no unverified read: `playbook.verify`
 *    refuses an unsigned document, a document signed by somebody else, and a
 *    document edited inside its cleartext wrapper. That last one is the reason
 *    the op parses out of the bytes OpenPGP hashed rather than unwrapping the
 *    armor a second time.
 *
 * The fourth thing under test is the seam nobody would notice breaking: the
 * ceremony's playbook names the **recovery**, not the ceremony. A playbook
 * carrying the notebook that produced it would tell a custodian to run
 * `random 32 | vss.split`, which mints a fresh secret rather than recovering
 * theirs — a booby trap dressed as an instruction, signed.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { generateKey } from "openpgp";
import { describe, expect, it } from "vitest";
import {
  PLAYBOOK_FIELDS,
  PLAYBOOK_KIND,
  PLAYBOOK_VERSION,
  assertPlaybookIntegrity,
  buildPlaybook,
  openSignedPlaybook,
  parsePlaybook,
  playbookDigest,
  playbookToJson,
  summarizePlaybook,
} from "../lib/toolkit/playbook.js";
import {
  listWorkspaces,
  parseWorkspaceFile,
  saveWorkspace,
} from "../lib/toolkit/workspace-store.js";
import { ceremonyCells, playbookRecipe, recoveryRecipe } from "../lib/toolkit/ceremony.js";
import { digestText, opsRegistryVersion } from "../lib/toolkit/receipt.js";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const RECIPE = "input | out $commitments\n\nshares | blip39.decode | vss.combine | out $master";

/** The notebook context `useNotebook`'s `buildBindings` hands an op. */
const notebook = (source, label = "") => ({ receipt: { recipeSource: source, label } });

/** One key, reused: generating an OpenPGP key is the slow part of this file. */
let cached = null;
async function key() {
  if (!cached) {
    cached = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Playbook Author", email: "author@example.com" }],
      format: "armored",
    });
  }
  return cached;
}

/** A second key, for "signed by somebody else". */
let cachedOther = null;
async function otherKey() {
  if (!cachedOther) {
    cachedOther = await generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name: "Somebody Else", email: "else@example.com" }],
      format: "armored",
    });
  }
  return cachedOther;
}

/** Bindings that give an op a vault key to sign and verify with. */
async function withKey(source, k) {
  const pair = k || (await key());
  return {
    ...notebook(source),
    inputs: {
      gpg: {
        privateKeyArmored: pair.privateKey,
        publicKeyArmored: pair.publicKey,
        passphrase: "",
        armoredMessages: [],
      },
    },
  };
}

/* ────────────────────────────── the document ────────────────────────────── */

describe("a playbook is a procedure and the prose to follow it", () => {
  it("carries the recipe itself, not only a digest of it", async () => {
    // The reason is the whole feature: in a recovery the reader has the
    // playbook and nothing else, so a digest would send them to find the text
    // somewhere they would then have to trust.
    const pb = await buildPlaybook({ title: "Board key recovery", recipeSource: RECIPE });
    expect(pb.recipeSource).toBe(RECIPE);
    expect(pb.recipeDigest).toBe(await digestText(RECIPE));
    expect(pb.kind).toBe(PLAYBOOK_KIND);
    expect(pb.v).toBe(PLAYBOOK_VERSION);
  });

  it("round-trips through its canonical JSON", async () => {
    const pb = await buildPlaybook({
      title: "Board key recovery",
      purpose: "Any 2 of the 3 cards.",
      splitId: "A1B2-C3D4",
      registry: opsRegistryVersion(),
      recipeSource: RECIPE,
    });
    expect(parsePlaybook(playbookToJson(pb))).toEqual(pb);
    expect(await playbookDigest(pb)).toMatch(/^[0-9a-f]{64}$/);
    expect(summarizePlaybook(pb)).toContain("A1B2-C3D4");
  });

  it("refuses to vouch for nothing", async () => {
    await expect(buildPlaybook({ title: "Empty" })).rejects.toThrow(
      /no recipe to write a playbook for/
    );
  });
});

/* ─────────────────── what it may not carry (the closed list) ─────────────── */

describe("the field list is enforced, not described", () => {
  it("refuses a field outside the list", async () => {
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    const forged = JSON.stringify({ ...pb, note: "hello" });
    expect(() => parsePlaybook(forged)).toThrow(/unexpected field note/);
  });

  it("refuses the field a fingerprint would arrive in", async () => {
    // Named separately from the case above because this is *why* the list is
    // closed. A playbook goes to people who were never in the room, and the
    // room is a digest of its audience.
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    const forged = JSON.stringify({
      ...pb,
      author: "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9",
    });
    expect(() => parsePlaybook(forged)).toThrow(/nowhere to carry/);
  });

  it("leaves no field a fingerprint fits through", async () => {
    // `splitId` is the one free-ish string, and it is narrow on purpose.
    await expect(
      buildPlaybook({
        title: "t",
        recipeSource: RECIPE,
        splitId: "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9",
      })
    ).rejects.toThrow(/not a split id/);
  });

  it("names every field it does carry, so the list cannot drift", async () => {
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    expect(Object.keys(pb).sort()).toEqual([...PLAYBOOK_FIELDS].sort());
  });

  it("refuses another Basilisk document read as a playbook", () => {
    expect(() =>
      parsePlaybook(JSON.stringify({ v: 2, kind: "basilisk.run-receipt" }))
    ).toThrow(/not a Basilisk recipe playbook/);
  });
});

/* ───────────────────── what it may not say about itself ──────────────────── */

describe("a playbook that contradicts itself is refused", () => {
  it("catches a digest that does not describe the recipe beside it", async () => {
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    const swapped = { ...pb, recipeSource: "random 32 | out $oops" };
    await expect(assertPlaybookIntegrity(swapped)).rejects.toThrow(
      /not the recipe its digest names/
    );
  });

  it("passes the one that agrees with itself", async () => {
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    await expect(assertPlaybookIntegrity(pb)).resolves.toBe(pb);
  });

  it("refuses a document with no procedure in it", async () => {
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    expect(() => parsePlaybook(JSON.stringify({ ...pb, recipeSource: "" }))).toThrow(
      /carries no recipe/
    );
  });
});

/* ─────────────────────────── the ops, end to end ─────────────────────────── */

describe("playbook / playbook.verify through the engine", () => {
  const SRC = `bytes deadbeef | encode hex | out $a

playbook "Thursday recovery" purpose="Paste the cards." | gpg.sign | out $signed

in $signed | playbook.verify | out $recipe`;

  it("writes one, signs it, and hands the recipe back", async () => {
    const { ast, validation } = compileRecipe(SRC);
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, await withKey(SRC));
    const recipe = arts.find((a) => a.label === "recipe");
    expect(recipe).toBeTruthy();
    // The procedure, not the envelope: this is what a reader pastes.
    expect(String(recipe.content)).toContain("out $a");
    expect(String(recipe.content)).not.toContain("recipe-playbook");
  }, 60_000);

  it("describes the whole notebook, not the cell it sits in", async () => {
    const { ast } = compileRecipe(SRC);
    const arts = await runRecipe(ast, await withKey(SRC));
    const signed = arts.find((a) => a.label === "signed");
    const pb = parsePlaybook(String(signed.content));
    expect(pb.title).toBe("Thursday recovery");
    expect(pb.recipeSource).toContain("out $a");
    expect(pb.registry).toBe(opsRegistryVersion());
  }, 60_000);

  it("refuses an unsigned playbook — there is no unverified open", async () => {
    // The property the whole design rests on. A reader who can open an
    // unsigned procedure has learned nothing about who wrote it, and the op
    // would be lending its name to that.
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    const src = "in $doc | playbook.verify | out $recipe";
    const { ast } = compileRecipe(`input | out $doc\n\n${src}`);
    const bindings = await withKey(src);
    await expect(
      runRecipe(ast, { ...bindings, inputs: { ...bindings.inputs, text: { value: playbookToJson(pb) } } })
    ).rejects.toThrow(/not an OpenPGP cleartext-signed document/);
  }, 60_000);

  it("refuses one signed by somebody else", async () => {
    const mine = await key();
    const theirs = await otherKey();
    const write = 'playbook "Theirs" | gpg.sign | out $signed';
    const { ast: writeAst } = compileRecipe(write);
    const signed = (await runRecipe(writeAst, await withKey(write, theirs))).find(
      (a) => a.label === "signed"
    );
    // Read back against a key that did not sign it.
    const read = "in $doc | playbook.verify | out $recipe";
    const { ast } = compileRecipe(`input | out $doc\n\n${read}`);
    const bindings = await withKey(read, mine);
    await expect(
      runRecipe(ast, {
        ...bindings,
        inputs: { ...bindings.inputs, text: { value: String(signed.content) } },
      })
      // Tightened from `/does not verify against that key|signature/`, which
      // matched every refusal alike. The two cases in this file are now told
      // apart — this one really is "signed by a key you did not give me", and
      // the next one is not — so each pins the sentence it should get. A
      // regex that both still match would be the old defect in a test.
    ).rejects.toThrow(/is not one of the keys you gave me/);
  }, 60_000);

  it("refuses one edited inside its cleartext wrapper", async () => {
    // The case that makes verify-and-parse one act rather than two. An armor
    // unwrapper reading the tampered body would hand back a procedure the
    // signature never covered.
    const write = 'playbook "Original" | gpg.sign | out $signed';
    const { ast: writeAst } = compileRecipe(write);
    const signed = (await runRecipe(writeAst, await withKey(write))).find(
      (a) => a.label === "signed"
    );
    const tampered = String(signed.content).replace("Original", "Tampered");
    expect(tampered).not.toBe(String(signed.content));
    const read = "in $doc | playbook.verify | out $recipe";
    const { ast } = compileRecipe(`input | out $doc\n\n${read}`);
    const bindings = await withKey(read);
    await expect(
      runRecipe(ast, {
        ...bindings,
        inputs: { ...bindings.inputs, text: { value: tampered } },
      })
      // The right key over the wrong bytes. It used to be reported as somebody
      // else's signature, which sent the reader looking for an impostor
      // instead of for the edit.
    ).rejects.toThrow(/not the document that signature covers/);
  }, 60_000);

  it("refuses to vouch for a procedure that will not run", async () => {
    const src = 'playbook "Broken" recipe="genkey nonsense-curve | out $k" | out $pb';
    const { ast } = compileRecipe(src);
    await expect(runRecipe(ast, notebook(src))).rejects.toThrow(
      /the procedure does not compile/
    );
  });

  it("takes a multi-cell procedure through the share-link spelling", async () => {
    // A quoted param cannot hold a newline — the string grammar has no escapes
    // — so `~` carries a multi-cell recipe the way a `#r=` payload does.
    const src = 'playbook "Two cells" recipe="random 32|out $a~in $a|encode hex|out $b" | out $pb';
    const { ast, validation } = compileRecipe(src);
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, notebook(src));
    const pb = parsePlaybook(String(arts.find((a) => a.label === "pb").content));
    expect(compileRecipe(pb.recipeSource).ast.chains).toHaveLength(2);
  });
});

/* ─────────────────────────── the ceremony's own ──────────────────────────── */

describe("the ceremony writes a playbook for the recovery, not for itself", () => {
  it("puts the cards stage in the run, between verify and receipt", () => {
    // The playbook is part of what the receipt records, so it is written first.
    expect(ceremonyCells({ threshold: 2, shares: 3 }).map((c) => c.stage)).toEqual([
      "split",
      "verify",
      "cards",
      "receipt",
    ]);
  });

  it("names a recovery that compiles on its own", () => {
    // A custodian has the commitments document out of the envelope and no cell
    // that produced it, so the procedure has to include somewhere to paste it.
    const recovery = recoveryRecipe();
    expect(compileRecipe(recovery).validation.errors).toEqual([]);
    expect(recovery).toContain("vss.verify");
    expect(recovery.indexOf("vss.verify")).toBeLessThan(recovery.indexOf("vss.combine"));
    expect(recovery).toContain("out $master");
  });

  it("does not tell a custodian to split a fresh secret", () => {
    // Left to default, `playbook` would vouch for the notebook it runs in —
    // which begins `random 32 | vss.split`. Following that literally destroys
    // nothing and recovers nothing, which is worse than an error.
    const cell = playbookRecipe({ threshold: 2, shares: 3, label: "Board key" });
    expect(cell).toContain("recipe=");
    expect(cell).not.toContain("vss.split");
    expect(cell).toContain("vss.combine");
  });

  it("carries the split label, so two envelopes can be told apart", () => {
    const cell = playbookRecipe({ threshold: 2, shares: 3, splitId: "A1B2-C3D4" });
    expect(cell).toContain("split=A1B2-C3D4");
    // …and omits it rather than writing an empty one when the split is not
    // verifiable, because there is then no split to name.
    expect(playbookRecipe({ threshold: 2, shares: 3 })).not.toContain("split=");
  });

  it("signs with the ceremony's key when one was chosen, and still writes one when not", () => {
    expect(playbookRecipe({ signWith: "me" })).toContain("gpg.sign key=$me");
    expect(playbookRecipe({})).not.toContain("gpg.sign");
    expect(playbookRecipe({})).toContain("out $playbook");
  });

  it("round-trips as recipe text, so it survives the notebook it is written in", () => {
    const cell = playbookRecipe({ threshold: 2, shares: 3, label: "Board key" });
    const once = serializeRecipe(compileRecipe(cell).ast);
    expect(serializeRecipe(compileRecipe(once).ast)).toBe(once);
  });
});

/* ─────────────────────── opening one from the library ───────────────────── */

/**
 * `openSignedPlaybook` is the surfaces' half of `playbook.verify`: a person
 * opening a file out of an envelope has a keyring, not a `key=$author`. Both
 * go through `verifiedCleartextOpenPgp`, so there is one answer to *which
 * bytes were signed*.
 *
 * The four outcomes are told apart on purpose. "I have no key for this" and
 * "this signature is bad" call for different actions, and only one of them is
 * alarming — a surface that collapsed them would cry wolf at every playbook
 * from somebody whose key you have not fetched yet.
 */
describe("opening a signed playbook against the keys you hold", () => {
  /** A signed playbook, and the armored public key that signed it. */
  async function signedBy(pair) {
    const write = 'playbook "Envelope" purpose="Recombine." | gpg.sign | out $signed';
    const { ast } = compileRecipe(write);
    const arts = await runRecipe(ast, await withKey(write, pair));
    return String(arts.find((a) => a.label === "signed").content);
  }

  it("names who signed it, not merely that somebody did", async () => {
    const pair = await key();
    const armored = await signedBy(pair);
    const opened = await openSignedPlaybook(armored, [
      { fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555", uid: "Playbook Author", publicArmored: pair.publicKey },
    ]);
    expect(opened.ok).toBe(true);
    expect(opened.playbook.title).toBe("Envelope");
    expect(opened.by.uid).toBe("Playbook Author");
  }, 60_000);

  it("tells a key you do not have from a signature that is wrong", async () => {
    const theirs = await otherKey();
    const mine = await key();
    const armored = await signedBy(theirs);
    const notYours = await openSignedPlaybook(armored, [
      { fingerprint: "F".repeat(40), uid: "Me", publicArmored: mine.publicKey },
    ]);
    expect(notYours.ok).toBe(false);
    expect(notYours.reason).toBe("not-yours");
    // The sentence has to say it is not proof of tampering, because it is not.
    expect(notYours.message).toMatch(/not proof/i);

    const noKeys = await openSignedPlaybook(armored, []);
    expect(noKeys.reason).toBe("no-keys");
  }, 60_000);

  it("refuses an unsigned document without pretending it failed a check", async () => {
    const pb = await buildPlaybook({ title: "t", recipeSource: RECIPE });
    const opened = await openSignedPlaybook(playbookToJson(pb), [
      { fingerprint: "F".repeat(40), publicArmored: (await key()).publicKey },
    ]);
    expect(opened.ok).toBe(false);
    expect(opened.reason).toBe("unsigned");
  }, 60_000);

  it("reports a good signature over a bad document as the document's fault", async () => {
    // Reached by signing something that is not a playbook: the signature
    // verifies and the parse does not, and blaming the key would send somebody
    // hunting for a key problem they do not have.
    const pair = await key();
    const write = '"not a playbook" | gpg.sign | out $signed';
    const { ast } = compileRecipe(write);
    const arts = await runRecipe(ast, await withKey(write, pair));
    const opened = await openSignedPlaybook(String(arts.find((a) => a.label === "signed").content), [
      { fingerprint: "F".repeat(40), publicArmored: pair.publicKey },
    ]);
    expect(opened.ok).toBe(false);
    expect(opened.reason).toBe("malformed");
  }, 60_000);
});

describe("the library stores a playbook without trusting its own storage", () => {
  it("imports a signed playbook as an entry whose recipe is a preview", async () => {
    const pair = await key();
    const write = 'playbook "Envelope" | gpg.sign | out $signed';
    const { ast } = compileRecipe(write);
    const arts = await runRecipe(ast, await withKey(write, pair));
    const armored = String(arts.find((a) => a.label === "signed").content);

    const parsed = parseWorkspaceFile(armored, { filename: "playbook.asc" });
    expect(parsed.ok).toBe(true);
    expect(parsed.workspace.title).toBe("Envelope");
    // Trimmed, not reformatted: the armor's trailing newline is outside the
    // signed text, and the stored document still verifies — which the next
    // case proves by opening it.
    expect(parsed.workspace.playbook).toBe(armored.trim());
    // The preview is the document's recipe — for the list to show a step
    // count, never for Load to run.
    expect(parsed.workspace.recipe).toContain("gpg.sign");
  }, 60_000);

  it("takes the recipe from the signature, not from the row beside it", async () => {
    // The property the whole design turns on. localStorage is XSS-*writable*,
    // so an attacker who can edit a row edits `recipe` — the field a naive
    // Load would use. Rewriting it here changes nothing about what opening the
    // entry produces, because the signature is what answers.
    const pair = await key();
    const write = 'playbook "Envelope" | gpg.sign | out $signed';
    const { ast } = compileRecipe(write);
    const arts = await runRecipe(ast, await withKey(write, pair));
    const armored = String(arts.find((a) => a.label === "signed").content);

    const parsed = parseWorkspaceFile(armored, {});
    const tampered = { ...parsed.workspace, recipe: "random 32 | out $oops" };
    const opened = await openSignedPlaybook(tampered.playbook, [
      { fingerprint: "F".repeat(40), uid: "Author", publicArmored: pair.publicKey },
    ]);
    expect(opened.ok).toBe(true);
    expect(opened.playbook.recipeSource).not.toContain("$oops");
    expect(opened.playbook.recipeSource).toContain("gpg.sign");
  }, 60_000);

  it("refuses a signed file that is not a playbook, saying which it was", () => {
    const signed = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      '{"v":2,"kind":"basilisk.run-receipt"}',
      "-----BEGIN PGP SIGNATURE-----",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    const parsed = parseWorkspaceFile(signed, {});
    expect(parsed.ok).toBe(false);
    expect(parsed.reason).toMatch(/not a playbook/);
  });

  it("keeps an ordinary saved recipe free of the field", () => {
    const storage = {
      _d: /** @type {Record<string,string>} */ ({}),
      getItem(k) {
        return this._d[k] ?? null;
      },
      setItem(k, v) {
        this._d[k] = String(v);
      },
    };
    const plain = saveWorkspace({ title: "Plain", recipe: "random 32 | out $a" }, storage);
    expect(plain.ok).toBe(true);
    expect("playbook" in plain.workspace).toBe(false);
    const withDoc = saveWorkspace(
      { title: "Doc", recipe: "random 32 | out $a", playbook: "-----BEGIN PGP SIGNED MESSAGE-----" },
      storage
    );
    expect(withDoc.ok).toBe(true);
    expect(withDoc.workspace.playbook).toBeTruthy();
    // …and it survives the store, which is what the list reads back.
    expect(listWorkspaces(storage).find((w) => w.title === "Doc")?.playbook).toBeTruthy();
  });
});

/* ──────────────────────────── an entry point ─────────────────────────────── */

/**
 * The recurring defect in this stack is a finished mechanism nothing can
 * reach — `CellAssign` exists because the `@peer` header was one. A playbook
 * op with no surface would be the same defect in a document that only matters
 * years after anybody would notice.
 *
 * Source assertions because the suite is `environment: "node"` and cannot
 * mount a component, and because what these catch is a *missing* wire, which
 * no rendering of the correct output would have shown.
 */
describe("the ceremony can reach the playbook, not only a recipe author", () => {
  const read = (rel) =>
    readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");

  it("runs the cards stage instead of only showing it", async () => {
    // `goNext` runs the next stage's cells when `runsCells` is true, so this
    // flag is the difference between a playbook that writes itself on entering
    // the stage and one nobody ever asks for.
    const { CEREMONY_STAGES } = await import("../lib/toolkit/ceremony.js");
    expect(CEREMONY_STAGES.find((s) => s.id === "cards").runsCells).toBe(true);
  });

  it("carries the tile from the kernel to the sheet", () => {
    const hook = read("../toolkit/useNotebook.ts");
    expect(hook).toContain('cards: cells.findIndex((c) => c.stage === "cards")');
    expect(hook).toContain('tileForSlot(outs(ceremonyCellIndex.cards), "playbook")');
    const shell = read("../toolkit/ToolkitShell.tsx");
    expect(shell).toContain("playbookText={nb.ceremonyView.playbookText}");
  });

  it("shows it at the cards stage, with a way to write one that failed", () => {
    const sheet = read("../toolkit/widgets/CeremonySheet.tsx");
    expect(sheet).toContain("ceremony-playbook");
    expect(sheet).toContain("Write the playbook");
    // The panel lives under `stage === "cards"`, not under the receipt: the
    // playbook goes in the envelope with the cards, and a person who stopped
    // at printing must still have been offered it.
    const cards = sheet.slice(sheet.indexOf('stage === "cards"'), sheet.indexOf('stage === "receipt"'));
    expect(cards).toContain("playbookText");
  });

  it("offers a playbook cell from the library, and does not sign behind anybody", () => {
    const shell = read("../toolkit/ToolkitShell.tsx");
    const start = shell.indexOf("const writePlaybookCell");
    expect(start).toBeGreaterThan(-1);
    const body = shell.slice(start, shell.indexOf("\n  };", start));
    // It writes a cell. The private key never comes near this function — the
    // recipe is what a person reads before pressing Run, and a button that
    // signed would be a signature nobody read one for.
    expect(body).toContain("appendRecipeCell");
    expect(body).toContain("gpg.sign");
    expect(body).not.toContain("signOpenPgp");
    expect(body).not.toContain("unlock");
  });

  it("verifies on load, and refuses to open what nothing vouches for", () => {
    const shell = read("../toolkit/ToolkitShell.tsx");
    const start = shell.indexOf("const loadWorkspaceEntry");
    expect(start).toBeGreaterThan(-1);
    const body = shell.slice(start, shell.indexOf("\n  };", start));
    expect(body).toContain("openSignedPlaybook");
    // A plain saved recipe still loads from `ws.recipe` — it is all there is,
    // and nobody signed anything about it. The assertion is about the other
    // branch: past the `!ws.playbook` guard, the preview must never be the
    // thing that loads, because that is the field XSS can rewrite.
    const signedBranch = body.slice(body.indexOf("setWorkspaceOpening"));
    expect(signedBranch).toContain("opened.playbook.recipeSource");
    expect(signedBranch).not.toContain("ws.recipe");
    // A failure stops the load and is kept on screen rather than thrown away.
    expect(body).toContain("if (!opened.ok || !opened.playbook) return;");
    expect(body).toContain("setPlaybookState");
  });

  it("lists an entry it could not verify, rather than hiding it", () => {
    // The coordinator's rule, and the reason: hiding a failing entry makes a
    // tampered playbook indistinguishable from one that was never saved.
    const shell = read("../toolkit/ToolkitShell.tsx");
    // No filter drops unverified rows from the list…
    expect(shell).toContain("{workspaces.map((ws) => {");
    // …and the row carries the failure and the signer, in the row itself.
    expect(shell).toContain("opened.message");
    // Was `opened.by.fingerprint.slice(-16)`. Sixteen hex characters is 64 bits
    // of the key that vouched for a playbook, printed on the row where somebody
    // decides whether to load one — the same "compare part of it and hope"
    // the short key ID warning on the search page is about. The whole
    // fingerprint is on the row now, as a control that copies all of it.
    expect(shell).toContain("<Fingerprint fpr={opened.by.fingerprint} />");
    expect(shell).toContain('data-verified={opened ? (opened.ok ? "yes" : "no") : "unchecked"}');
  });
});

/**
 * The Keys tray binds a recipient, and the run has to see it.
 *
 * `useNotebook.buildBindings` records what the binder produced as
 * `recipientKeysArmored` + `recipientFingerprints` — armor, because that is
 * what a `ResolvedRecipient` holds and what the worker message carries.
 *
 * The engine's `gpg.encrypt` reads `bindings.recipients`, which is parsed
 * openpgp `Key` objects. `executeToolkitRun` — the worker path — bridges the
 * two by calling `readKey` on the way in. The in-page kernel does not: it hands
 * `bindings` to `runRecipe` untouched.
 *
 * So a notebook run saw an empty recipient list no matter what the tray said,
 * and refused with "no recipients chosen" — advice to do the thing the person
 * had just done. These tests pin the bridge in the one place both paths meet.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKey } from "openpgp";
import { createKernel } from "../lib/toolkit/kernel.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { sessionClear } from "../lib/vault-session.js";

beforeEach(() => {
  sessionClear();
  vi.unstubAllGlobals();
});

/** One public key, in the armored form the binder hands the notebook. */
async function armoredRecipient() {
  const key = await generateKey({
    type: "ecc",
    curve: "curve25519",
    userIDs: [{ name: "Mara", email: "mara@example.com" }],
    format: "object",
  });
  return {
    armoredKey: key.publicKey.armor(),
    fingerprint: key.publicKey.getFingerprint().toUpperCase(),
  };
}

/**
 * Exactly what `buildBindings` puts in for a bound recipient — armor and
 * fingerprints, and deliberately no `recipients`. If the hook ever starts
 * parsing keys itself this fixture is what should change first.
 */
function bindingsFromTray(rec) {
  return {
    recipientKeysArmored: [rec.armoredKey],
    recipientFingerprints: [rec.fingerprint],
  };
}

describe("a recipient bound in the Keys tray reaches the run", () => {
  it("encrypts to it through the in-page kernel", async () => {
    const rec = await armoredRecipient();
    const kernel = createKernel();
    const compiled = compileRecipe("bytes deadbeef | gpg.encrypt");

    const artifacts = await kernel.runCell(
      0,
      compiled.ast.chains[0],
      bindingsFromTray(rec)
    );

    const armored = artifacts.map((a) => String(a.content || "")).join("\n");
    expect(armored).toContain("BEGIN PGP MESSAGE");
    kernel.destroy();
  });

  it("still refuses when the tray is empty, which is the case the message is for", async () => {
    const kernel = createKernel();
    const compiled = compileRecipe("bytes deadbeef | gpg.encrypt");

    await expect(kernel.runCell(0, compiled.ast.chains[0], {})).rejects.toThrow(
      /no recipients chosen/
    );
    kernel.destroy();
  });

  it("prefers parsed keys when a caller supplies them, so the worker path is unchanged", async () => {
    // `executeToolkitRun` sets `recipients` itself and does not set armor.
    // The bridge must not clobber that or the two paths would disagree about
    // who a run is encrypted to.
    const rec = await armoredRecipient();
    const { readKey } = await import("openpgp");
    const parsed = await readKey({ armoredKey: rec.armoredKey });

    const kernel = createKernel();
    const compiled = compileRecipe("bytes deadbeef | gpg.encrypt");
    const artifacts = await kernel.runCell(0, compiled.ast.chains[0], {
      recipients: [parsed],
      recipientFingerprints: [rec.fingerprint],
    });

    expect(artifacts.map((a) => String(a.content || "")).join("\n")).toContain(
      "BEGIN PGP MESSAGE"
    );
    kernel.destroy();
  });
});

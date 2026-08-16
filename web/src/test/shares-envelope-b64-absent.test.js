/**
 * The base64 envelope channel is gone, and nothing may quietly re-open it.
 *
 * `engine.js` carried a branch reading `inputs.shares.envelopeB64` and decoding
 * it into the legacy AES-GCM blob `combineRawShares` asks for when a decoded
 * share set carries `BLIP39_ENVELOPE_FLAG`. Two typedefs declared the field.
 * Nothing anywhere wrote it: the Inputs tray builds `inputs.shares` from the
 * share rows and an optional passphrase, so the decode could not run and the
 * declaration named a contract no caller could honour.
 *
 * It was deleted rather than wired because the format has no producer here
 * either — `splitRawShares` has set `flags = 0` since this code's first commit,
 * so no version of this product has ever dealt an enveloped set. Wiring meant
 * adding a tray field for a blob only some predecessor tool could have made,
 * feeding `aesGcmOpen`, which no test exercises.
 *
 * Two pins, because a deletion that only removes code is a deletion the next
 * reader undoes. The sweep is `88fcfd0`'s precedent — an absence asserted over
 * the whole app rather than over a list of files. The behavioural half is the
 * one that would catch a re-add spelled differently: a share set collected from
 * the tray is never enveloped, whatever the caller puts in the tray.
 *
 * `envelopeArmored` is deliberately *not* swept. It is a different object — an
 * OpenPGP `envelope.asc`, read by `resolveEnvelopeArmored` on the live
 * `gpg.symdecrypt` path and written by the smoke harnesses — and confusing the
 * two is how this branch survived as long as it did.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createSlotRegistry } from "../lib/toolkit/slot-registry.js";

const WEB_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SRC_ROOT = join(WEB_ROOT, "src");

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "node_modules" || name === "test") continue;
      walk(path, out);
    } else if (/\.(js|ts|tsx)$/.test(path)) {
      out.push(path);
    }
  }
  return out;
}

const rel = (path) => relative(WEB_ROOT, path).replace(/\\/g, "/");

describe("no source names a base64 envelope input", () => {
  it("has no `envelopeB64` left anywhere in the app", () => {
    // Comments are *not* stripped here, unlike the fingerprint sweep. The
    // deletion's own argument lives in a comment in `engine.js` and must not
    // mention the identifier it removed, or the argument becomes the thing it
    // argues against. Naming it in prose is exactly how a dead field grows a
    // second life as "the field we used to have".
    const left = walk(SRC_ROOT)
      .map((path) => ({ file: rel(path), text: readFileSync(path, "utf8") }))
      .filter((s) => /\benvelopeB64\b/.test(s.text))
      .map((s) => s.file);
    expect(left, left.join(", ")).toEqual([]);
  });

  it("still keeps the armored spelling, which is a different object", () => {
    // The control for the sweep above: `envelopeArmored` is live, so a sweep
    // that removed both would be over-broad and this catches that.
    const kept = walk(SRC_ROOT)
      .map((path) => ({ file: rel(path), text: readFileSync(path, "utf8") }))
      .filter((s) => /\benvelopeArmored\b/.test(s.text))
      .map((s) => s.file);
    expect(kept).toContain("src/lib/toolkit/engine.js");
  });
});

describe("a share set collected from the tray is never enveloped", () => {
  /** Three real mnemonics of one 2-of-3 split. */
  async function deal() {
    const { ast, validation } = compileRecipe(
      "random 32 | sss.split threshold=2 shares=3 | blip39 | foreach\n  - out $share"
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
    const arts = await runRecipe(ast, {});
    const shares = arts.filter((a) => a.shareIndex).map((a) => String(a.content));
    expect(shares).toHaveLength(3);
    return shares;
  }

  /** Collect two mnemonics through the `shares` source with the given tray. */
  async function collect(tray) {
    const compiled = compileRecipe("shares | out $s");
    expect(compiled.validation.errors.map((e) => e.message)).toEqual([]);
    const registry = createSlotRegistry();
    await runRecipe(compiled.ast, { inputs: { shares: tray } }, { slotRegistry: registry });
    return registry.resolve("$s");
  }

  it("ignores a base64 envelope handed to it, rather than decoding one", async () => {
    // The pin that survives a re-add spelled some other way. A caller supplying
    // the field gets the same value as a caller who does not: no envelope, and
    // `enveloped` false. If the branch comes back this is what fails.
    const mnemonics = (await deal()).slice(0, 2);
    const held = await collect({ mnemonics, envelopeB64: "QUJDREVGR0hJSktM" });
    expect(held.type).toBe("shares");
    expect(held.data.mnemonics).toEqual(mnemonics);
    expect(held.data.envelope).toBeNull();
    expect(held.data.enveloped).toBe(false);
    expect(held.meta.envelope).toBeNull();
  }, 60_000);

  it("says the same thing when no envelope is offered at all", async () => {
    // The control: the two trays must be indistinguishable downstream, which is
    // the whole claim. A test that only checked the first case would pass on an
    // engine that had simply stopped emitting `enveloped` entirely.
    const mnemonics = (await deal()).slice(0, 2);
    const held = await collect({ mnemonics });
    expect(held.data.envelope).toBeNull();
    expect(held.data.enveloped).toBe(false);
    expect(held.meta.envelope).toBeNull();
  }, 60_000);

  it("still carries the tray's passphrase, which shares the same object", async () => {
    // The other field on `inputs.shares`, asserted so that a future edit that
    // guts the tray read cannot pass by deleting more than it meant to.
    const mnemonics = (await deal()).slice(0, 2);
    const held = await collect({ mnemonics, passphrase: "hunter2" });
    expect(held.meta.passphrase).toBe("hunter2");
  }, 60_000);
});

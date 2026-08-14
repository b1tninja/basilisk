/**
 * Manifest attestations — the document, the op that emits one, and the check
 * that a set of them covers a manifest.
 *
 * The weight of this file is on the failures. A verifier that only ever passes
 * proves nothing, so every way an attestation can fail to cover a manifest gets
 * a test: an attestation whose digest is not this manifest's, an attestation
 * over a *different* manifest that is otherwise perfectly well formed, a signed
 * manifest edited inside its cleartext wrapper, an expected peer who never
 * attested, and an attester nobody expected.
 *
 * The second weight is on what the document may not carry. `parseAttestation`
 * refuses any field outside the four, because "must not carry fingerprints" is
 * a property of the shape or it is a comment.
 *
 * The third is the idiom: the manifest op emits text and the recipe signs it.
 * There is no signing function under test here, because there is none to test —
 * `run.manifest | gpg.sign key=$me` is the whole signing path, and the
 * round-trip below runs exactly that.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ATTESTATION_FIELDS,
  ATTESTATION_KIND,
  ATTESTATION_VERSION,
  attestationToJson,
  buildAttestation,
  manifestAttestedBy,
  parseAttestation,
  summarizeAttestation,
} from "../lib/toolkit/attest.js";
import {
  MANIFEST_VERSION,
  buildRunManifest,
  manifestDigest,
  manifestReproducibility,
  manifestToJson,
  parseManifest,
} from "../lib/toolkit/manifest.js";
import { digestText, opsRegistryVersion } from "../lib/toolkit/receipt.js";
import { compileRecipe, serializeRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const FPR_A = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_B = "91C7E6D5C4B3A29180716253443526170819AABB";

const SOURCE = "bytes deadbeef | encode hex | out $a\n\nin $a | out $b";

/** A two-peer manifest, and the two attestations that cover it. */
async function room(overrides = {}) {
  const manifest = await buildRunManifest({
    title: "Thursday key ceremony",
    recipeSource: SOURCE,
    cells: [
      { index: 0, recipe: "bytes deadbeef | encode hex | out $a" },
      { index: 1, recipe: "in $a | out $b" },
    ],
    peers: { mara: FPR_A, okafor: FPR_B },
    ...overrides,
  });
  const attestation = await buildAttestation({ manifest });
  return {
    manifest,
    entries: [
      { by: "mara", attestation },
      { by: "okafor", attestation: await buildAttestation({ manifest }) },
    ],
  };
}

/** Wrap text the way `gpg.sign` does, for the cases a real key is overkill for. */
const clearsign = (body) =>
  [
    "-----BEGIN PGP SIGNED MESSAGE-----",
    "Hash: SHA256",
    "",
    body,
    "-----BEGIN PGP SIGNATURE-----",
    "iQIzBAEBCgAdFiEE",
    "-----END PGP SIGNATURE-----",
  ].join("\n");

describe("the attestation as a value", () => {
  it("says which manifest and nothing else", async () => {
    const { manifest } = await room();
    const a = await buildAttestation({ manifest });
    expect(a.v).toBe(ATTESTATION_VERSION);
    expect(a.kind).toBe(ATTESTATION_KIND);
    expect(a.manifest).toBe(await manifestDigest(manifest));
    expect(Object.keys(a).sort()).toEqual([...ATTESTATION_FIELDS].sort());
    // The signature says who; the document must not, because a name field is
    // where a fingerprint ends up and a digest of the audience is the room key.
    const json = attestationToJson(a);
    expect(json).not.toContain(FPR_A);
    expect(json).not.toContain("mara");
  });

  it("takes the digest directly, for a peer who never held the manifest", async () => {
    const sha = await digestText("whatever");
    expect((await buildAttestation({ manifestSha: sha })).manifest).toBe(sha);
  });

  it("refuses to attest to something that is not a digest", async () => {
    await expect(buildAttestation({})).rejects.toThrow(/64 lowercase hex/);
    await expect(buildAttestation({ manifestSha: "cafe" })).rejects.toThrow(
      /64 lowercase hex/
    );
    await expect(buildAttestation({ manifestSha: "A".repeat(64) })).rejects.toThrow(
      /64 lowercase hex/
    );
  });

  it("round-trips through canonical JSON and through a cleartext signature", async () => {
    const { manifest } = await room();
    const a = await buildAttestation({ manifest });
    const json = attestationToJson(a);
    expect(parseAttestation(json)).toEqual(a);
    expect(parseAttestation(clearsign(json))).toEqual(a);
  });

  it("rejects text that is not an attestation", () => {
    expect(() => parseAttestation("")).toThrow(/attestation: empty/);
    expect(() => parseAttestation("hello")).toThrow(/not JSON/);
    expect(() => parseAttestation("[1,2]")).toThrow(/not a Basilisk/);
    expect(() =>
      parseAttestation(`{"kind":"basilisk.run-manifest","v":${MANIFEST_VERSION}}`)
    ).toThrow(/not a Basilisk manifest attestation/);
    expect(() => parseAttestation(`{"kind":"${ATTESTATION_KIND}","v":99}`)).toThrow(
      /unsupported version 99/
    );
    expect(() =>
      parseAttestation(
        `{"kind":"${ATTESTATION_KIND}","v":${ATTESTATION_VERSION},"manifest":"cafe","claimedAt":"x"}`
      )
    ).toThrow(/64 lowercase hex/);
  });

  it("refuses a field the document has no business carrying", async () => {
    // The enforcement of "no fingerprints": there is nowhere to put one, and a
    // document that made a place is a different document.
    const { manifest } = await room();
    const smuggled = {
      ...(await buildAttestation({ manifest })),
      signer: FPR_A,
      note: "on behalf of the board",
    };
    expect(() => parseAttestation(JSON.stringify(smuggled))).toThrow(
      /unexpected fields note, signer/
    );
    expect(() => parseAttestation(JSON.stringify(smuggled))).toThrow(
      /nowhere to carry a fingerprint/
    );
  });
});

describe("the check, when the room attested", () => {
  it("passes, counts the attesters, and still says what it cannot show", async () => {
    const { manifest, entries } = await room();
    const r = await manifestAttestedBy(manifest, entries);
    expect(r.mismatches).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.attested).toEqual(["mara", "okafor"]);
    expect(r.missing).toEqual([]);
    expect(r.digest).toBe(await manifestDigest(manifest));
    // The caveat is not optional decoration: a reader deciding whether to trust
    // this is the person who has to read it.
    expect(r.caveats.join("\n")).toMatch(/never evidence of when/);
    expect(r.caveats.join("\n")).toMatch(/mutual among the participants/);
    expect(summarizeAttestation(r)).toMatch(/manifest attested — 2 attesters/);
    expect(summarizeAttestation(r)).toMatch(/nothing here says when/);
  });

  it("says so when the expected set is empty, rather than passing quietly", async () => {
    // A manifest with no roster is what this build's `run.manifest` emits, and
    // "covered" over an empty set is a sentence with no content.
    const manifest = await buildRunManifest({ recipeSource: SOURCE });
    const r = await manifestAttestedBy(manifest, [
      { by: "mara", attestation: await buildAttestation({ manifest }) },
    ]);
    expect(r.ok).toBe(true);
    expect(r.caveats.join("\n")).toMatch(/coverage is vacuous/);
  });

  it("counts an attestation nobody authenticated toward nothing", async () => {
    const { manifest } = await room();
    const r = await manifestAttestedBy(manifest, [
      { attestation: await buildAttestation({ manifest }) },
    ]);
    expect(r.ok).toBe(false);
    expect(r.attested).toEqual([]);
    expect(r.missing).toEqual(["mara", "okafor"]);
    expect(r.caveats.join("\n")).toMatch(/no attester/);
  });
});

describe("the check, when it should fail", () => {
  it("catches an attestation whose digest is not this manifest's", async () => {
    const { manifest, entries } = await room();
    const bent = structuredClone(entries);
    bent[0].attestation.manifest = "0".repeat(64);
    const r = await manifestAttestedBy(manifest, bent);
    expect(r.ok).toBe(false);
    expect(r.mismatches).toContainEqual({
      path: "attestation from mara",
      field: "manifest",
      expected: await manifestDigest(manifest),
      actual: "0".repeat(64),
    });
    // And it is not counted as covering the manifest it does not name.
    expect(r.attested).toEqual(["okafor"]);
    expect(r.missing).toEqual(["mara"]);
    expect(summarizeAttestation(r)).toMatch(
      /manifest not attested at attestation from mara \(manifest\)/
    );
  });

  it("catches an attestation over a different manifest, well formed in every other way", async () => {
    // The realistic attack: a signature that verifies, over a document that is
    // a perfectly good attestation — of last week's notebook.
    const { manifest } = await room();
    const other = await buildRunManifest({
      title: "Thursday key ceremony",
      recipeSource: `${SOURCE}\n\ngpg.encrypt to=mallory | out $c`,
      cells: [{ index: 0, recipe: "gpg.encrypt to=mallory | out $c" }],
      peers: { mara: FPR_A, okafor: FPR_B },
    });
    expect(await manifestDigest(other)).not.toBe(await manifestDigest(manifest));
    const r = await manifestAttestedBy(manifest, [
      { by: "mara", attestation: await buildAttestation({ manifest: other }) },
      { by: "okafor", attestation: await buildAttestation({ manifest }) },
    ]);
    expect(r.ok).toBe(false);
    expect(r.mismatches.some((m) => m.field === "manifest")).toBe(true);
    expect(r.missing).toEqual(["mara"]);
  });

  it("catches a signed manifest edited inside its own wrapper", async () => {
    // The signature would fail too — but the digest binding catches it without
    // anyone having to hold a key, which is what makes the check offline.
    const { manifest, entries } = await room();
    const signed = clearsign(manifestToJson(manifest));
    const tampered = signed.replace("Thursday key ceremony", "Thursday kez ceremony");
    expect(tampered).not.toBe(signed);
    const reparsed = parseManifest(tampered);
    expect(reparsed.title).toBe("Thursday kez ceremony");
    const r = await manifestAttestedBy(reparsed, entries);
    expect(r.ok).toBe(false);
    expect(r.mismatches.filter((m) => m.field === "manifest")).toHaveLength(2);
    // And so nobody is left covering it — the edit costs the whole room, which
    // is what a digest over the whole document is for.
    expect(r.attested).toEqual([]);
    expect(r.missing).toEqual(["mara", "okafor"]);
    // Unedited, the same attestations cover the same document.
    expect((await manifestAttestedBy(parseManifest(signed), entries)).ok).toBe(true);
  });

  it("names a peer who never attested", async () => {
    const { manifest, entries } = await room();
    const r = await manifestAttestedBy(manifest, [entries[0]]);
    expect(r.ok).toBe(false);
    expect(r.missing).toEqual(["okafor"]);
    expect(r.mismatches).toContainEqual({
      path: "peer okafor",
      field: "attestation",
      expected: `an attestation over ${await manifestDigest(manifest)}`,
      actual: "",
    });
  });

  it("names an attester the manifest never listed", async () => {
    // The direction a count-them check waves through: two signatures over the
    // right digest, and one of them is from somebody else's room.
    const { manifest, entries } = await room();
    const r = await manifestAttestedBy(manifest, [
      ...entries,
      { by: "mallory", attestation: await buildAttestation({ manifest }) },
    ]);
    expect(r.ok).toBe(false);
    expect(r.mismatches).toContainEqual({
      path: "attestation from mallory",
      field: "unlisted",
      expected: "",
      actual: "mallory",
    });
  });

  it("catches an attestation of the wrong kind or envelope", async () => {
    const { manifest } = await room();
    const r = await manifestAttestedBy(manifest, [
      { by: "mara", attestation: /** @type {*} */ ({ kind: "basilisk.run-receipt", v: 2 }) },
    ]);
    expect(r.ok).toBe(false);
    expect(r.mismatches.map((m) => m.field)).toContain("kind");
    expect(r.mismatches.map((m) => m.field)).toContain("v");
  });
});

/**
 * The notebook's source, the way `useNotebook`'s `buildBindings` hands it over
 * — `bindings.receipt = { recipeSource, label }`. `run.manifest` reads the same
 * context `run.receipt` does, so a test that withheld it would be testing an
 * op the app never runs.
 * @param {string} source
 */
const notebook = (source, label = "") => ({ receipt: { recipeSource: source, label } });

describe("run.manifest through the engine", () => {
  it("emits the notebook's manifest, cells and all", async () => {
    const src = `@mara
bytes deadbeef | encode hex | out $a | publish

in $a | out $b

run.manifest "Thursday ceremony" | out $manifest`;
    const { ast, validation } = compileRecipe(src);
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, notebook(src));
    const tile = arts.find((a) => a.filename === "manifest.txt");
    expect(tile).toBeTruthy();

    const manifest = parseManifest(tile.content);
    expect(manifest.kind).toBe("basilisk.run-manifest");
    expect(manifest.title).toBe("Thursday ceremony");
    expect(manifest.toolchain.ops).toBe(opsRegistryVersion());
    expect(manifest.recipeDigest).toBe(await digestText(src));
    // The cells are read from the recipe in the spelling `appendRunLog`
    // records, so a manifest and a receipt of the same notebook compare equal.
    expect(manifest.cells.map((c) => c.index)).toEqual([0, 1, 2]);
    expect(manifest.cells[0].peer).toBe("mara");
    expect(manifest.cells[0].publish).toBe(true);
    expect(manifest.cells[1].peer).toBe("");
    expect(manifest.cells[1].recipe).toBe(
      serializeRecipe({ chains: [ast.chains[1]] })
    );
    for (const cell of manifest.cells) {
      expect(cell.recipeDigest).toBe(await digestText(cell.recipe));
    }
  });

  it("commits to no roster it does not have, rather than to a blank one", async () => {
    // The session layer that would carry a label→fingerprint binding does not
    // exist yet. An empty `peers` says that; labels bound to "" would look like
    // a commitment and be none.
    const src = "@mara\nrun.manifest | out $m";
    const { ast } = compileRecipe(src);
    const arts = await runRecipe(ast, notebook(src));
    const manifest = parseManifest(arts.find((a) => a.filename === "m.txt").content);
    expect(manifest.peers).toEqual([]);
    expect(manifest.peersSha).toMatch(/^[0-9a-f]{64}$/);
    // The cell still says who it runs for — that much the recipe does know.
    expect(manifest.cells[0].peer).toBe("mara");
  });

  it("falls back to the notebook title, as run.receipt falls back to its label", async () => {
    const src = "run.manifest | out $m";
    const { ast } = compileRecipe(src);
    const arts = await runRecipe(ast, notebook(src, "Board key"));
    expect(parseManifest(arts.find((a) => a.filename === "m.txt").content).title).toBe(
      "Board key"
    );
  });

  it("declares the run non-reproducible rather than flattering it", async () => {
    // Nothing in this build reads a pool or a pinned `t0`, so `local`/`free` is
    // the true reading and `buildRunManifest`'s fail-closed default is right.
    const src = "run.manifest | out $m";
    const { ast } = compileRecipe(src);
    const arts = await runRecipe(ast, notebook(src));
    const manifest = parseManifest(arts.find((a) => a.filename === "m.txt").content);
    expect(manifest.entropy.mode).toBe("local");
    expect(manifest.clock.mode).toBe("free");
    expect(manifestReproducibility(manifest).reproducible).toBe(false);
  });

  it("leaves run.receipt's document alone", async () => {
    // The bar: no existing path changes shape. The registry version moves when
    // an op is added — that is what it is for — and nothing else does.
    const { ast } = compileRecipe("bytes deadbeef | out $a\n\nrun.receipt | out $r");
    const arts = await runRecipe(ast);
    const receipt = JSON.parse(arts.find((a) => a.role === "receipt").content);
    expect(receipt.kind).toBe("basilisk.run-receipt");
    expect(receipt.registry).toBe(opsRegistryVersion());
    expect(Object.keys(receipt).sort()).toEqual([
      "cells",
      "createdAt",
      "kind",
      "label",
      "recipeDigest",
      "recipeSource",
      "registry",
      "v",
    ]);
  });
});

describe("run.attest through the engine", () => {
  it("attests to the digest of the manifest it was handed", async () => {
    const src = 'run.manifest "T" | out $m\n\nin $m | run.attest | out $att';
    const { ast, validation } = compileRecipe(src);
    expect(validation.errors).toEqual([]);
    const arts = await runRecipe(ast, notebook(src));
    const manifest = parseManifest(arts.find((a) => a.filename === "m.txt").content);
    const attestation = parseAttestation(
      arts.find((a) => a.filename === "att.txt").content
    );
    expect(attestation.manifest).toBe(await manifestDigest(manifest));
    expect((await manifestAttestedBy(manifest, [{ by: "mara", attestation }])).ok).toBe(
      true
    );
  });

  it("refuses text that is not a manifest", async () => {
    const { ast } = compileRecipe("input | run.attest | out $att");
    await expect(
      runRecipe(ast, { inputs: { text: { value: "not a manifest" } } })
    ).rejects.toThrow(/not JSON|not a Basilisk/);
    // A receipt is the near miss worth refusing by name.
    const { ast: mint } = compileRecipe("run.receipt | out $r");
    const receipt = (await runRecipe(mint)).find((a) => a.role === "receipt").content;
    await expect(
      runRecipe(ast, { inputs: { text: { value: receipt } } })
    ).rejects.toThrow(/not a Basilisk run manifest/);
  });
});

describe("signing is a recipe step", () => {
  it(
    "round-trips manifest → op → gpg.sign → parse with an identical digest",
    async () => {
      const src = `gpg.genkey email=basilisk@example.org | out $me

run.manifest "Thursday ceremony" | out $plain

in $plain | gpg.sign key=$me | out $signed`;
      const { ast, validation } = compileRecipe(src);
      expect(validation.errors).toEqual([]);
      const arts = await runRecipe(ast, notebook(src));

      const plain = arts.find((a) => a.filename === "plain.txt").content;
      const signed = arts.find((a) => a.filename === "signed.txt").content;
      expect(signed).toMatch(/^-----BEGIN PGP SIGNED MESSAGE-----/);
      expect(signed).toContain("-----BEGIN PGP SIGNATURE-----");

      // `unwrapCleartext` was parameterised on the noun for exactly this: the
      // signed form is the one you hand back, so it must parse.
      const before = parseManifest(plain);
      const after = parseManifest(signed);
      expect(await manifestDigest(after)).toBe(await manifestDigest(before));
      expect(manifestToJson(after)).toBe(manifestToJson(before));

      // And an attestation built over either one covers the other.
      const attestation = await buildAttestation({ manifest: after });
      expect((await manifestAttestedBy(before, [{ by: "mara", attestation }])).ok).toBe(
        true
      );
    },
    60_000
  );

  it("has no signing function to reach for a key", () => {
    // `receipt.js` has none and `manifest.js` has none, because a grant is
    // minted by a human clicking Run, never by a module. This module must not
    // be where that rule breaks.
    const code = readFileSync(
      fileURLToPath(new URL("../lib/toolkit/attest.js", import.meta.url)),
      "utf8"
    )
      .replace(/\r\n/g, "\n")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/[^\n]*/g, "");
    expect(code).not.toMatch(/signOpenPgp|decryptKey|readPrivateKey|createSignature/);
    expect(code).not.toMatch(/\bfunction sign\w*\(/);
    // And no second answer to "which bytes were signed".
    expect(code).not.toMatch(/crypto\.subtle|TextEncoder/);
    expect(code).toMatch(/from "\.\/receipt\.js"/);
  });
});

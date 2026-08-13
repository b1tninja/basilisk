/**
 * Run manifests — the commitment made before a run, and the check that a
 * receipt honours it.
 *
 * The property worth most of this file is the negative one. A check that only
 * ever passes proves nothing, so every dimension the manifest *pins* gets a
 * test that departs from it and a test that the departure is named: the recipe,
 * the cell list, the cell text, the op registry, the receipt envelope, each
 * pinned runtime input, an input that was never pinned at all, and a pinned
 * clock a receipt predates.
 *
 * The second property is that none of this is a second implementation. A
 * manifest and a receipt that canonicalised JSON differently would agree in
 * every test written by the person who wrote both and disagree in production,
 * so the shared-machinery rule is asserted against the source.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CLOCK_MODES,
  ENTROPY_MODES,
  MANIFEST_VERSION,
  audienceDigest,
  buildRunManifest,
  cellKind,
  manifestDigest,
  manifestHonouredBy,
  manifestReproducibility,
  manifestToJson,
  parseManifest,
  peersDigest,
  summarizeHonour,
} from "../lib/toolkit/manifest.js";
import {
  RECEIPT_VERSION,
  buildRunReceipt,
  canonicalJson,
  digestText,
  opsRegistryVersion,
} from "../lib/toolkit/receipt.js";
import { compileRecipe, recipeChains, serializeRecipe } from "../lib/toolkit/recipe.js";
import { createKernel } from "../lib/toolkit/kernel.js";

const FPR_A = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_B = "91C7E6D5C4B3A29180716253443526170819AABB";
/** Roughly 37% of fingerprints begin A–F, and those parse as peer labels. */
const FPR_LETTER_FIRST = "D2C1B0A94F2AC1B39D8E7C6A5B4938271605F4E3";

const SOURCE = "bytes deadbeef | encode hex | out $a\n\nin $a | out $b";

/** A manifest and a receipt that agree, built from the same cell texts. */
async function agreeing(overrides = {}) {
  const cells = [
    { index: 0, recipe: "bytes deadbeef | encode hex | out $a" },
    { index: 1, recipe: "in $a | out $b" },
  ];
  const manifest = await buildRunManifest({
    title: "Thursday key ceremony",
    recipeSource: SOURCE,
    cells,
    peers: { mara: FPR_A, okafor: FPR_B },
    entropy: { mode: "none" },
    clock: { mode: "pinned", t0: "2026-08-01T00:00:00.000Z" },
    inputs: [{ cell: 0, channel: "text", digest: "a".repeat(64) }],
    ...overrides,
  });
  const receipt = await buildRunReceipt({
    label: "Thursday key ceremony",
    createdAt: "2026-08-02T00:00:00.000Z",
    recipeSource: SOURCE,
    cells: cells.map((c) => ({
      ...c,
      startedAt: "2026-08-02T00:00:00.000Z",
      inputs: c.index === 0 ? [{ channel: "text", digest: "a".repeat(64) }] : [],
      outputs: [{ label: `o${c.index}`, digest: "c".repeat(64), length: 4 }],
    })),
  });
  return { manifest, receipt };
}

describe("the manifest as a value", () => {
  it("survives canonical JSON and comes back with the same digest", async () => {
    const { manifest } = await agreeing();
    const json = manifestToJson(manifest);
    const back = parseManifest(json);
    expect(manifestToJson(back)).toBe(json);
    expect(await manifestDigest(back)).toBe(await manifestDigest(manifest));
  });

  it("is a receipt minus the outputs — a commitment, not a prediction", async () => {
    const { manifest } = await agreeing();
    expect(manifest.v).toBe(MANIFEST_VERSION);
    expect(manifest.kind).toBe("basilisk.run-manifest");
    expect(manifest.recipeDigest).toBe(await digestText(SOURCE));
    expect(manifest.toolchain.ops).toBe(opsRegistryVersion());
    expect(manifest.toolchain.receipt).toBe(RECEIPT_VERSION);
    expect(manifestToJson(manifest)).not.toContain("outputs");
    for (const cell of manifest.cells) {
      expect(cell.recipeDigest).toBe(await digestText(cell.recipe));
    }
  });

  it("finds the payload inside an OpenPGP cleartext signature", async () => {
    const { manifest } = await agreeing();
    const signed = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      manifestToJson(manifest),
      "-----BEGIN PGP SIGNATURE-----",
      "iQIzBAEBCgAdFiEE",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    expect(parseManifest(signed).recipeDigest).toBe(manifest.recipeDigest);
  });

  it("rejects text that is not a manifest", () => {
    expect(() => parseManifest("")).toThrow(/manifest: empty/);
    expect(() => parseManifest("hello")).toThrow(/not JSON/);
    expect(() => parseManifest('{"kind":"basilisk.run-receipt","v":2}')).toThrow(
      /not a Basilisk run manifest/
    );
    expect(() => parseManifest('{"kind":"basilisk.run-manifest","v":99}')).toThrow(
      /unsupported version 99/
    );
  });

  it("tells a v1 manifest what changed, rather than that a digest disagrees", async () => {
    // The bump this unit made, from the reader's side. A v1 manifest of a
    // notebook with a blank cell in it numbers its cells differently, so the
    // same integer names a different cell — and a document refused with a bare
    // version number sends somebody looking for a changed recipe. `RECEIPT_VERSION
    // = 2` is the precedent and it made exactly this argument.
    const { manifest } = await agreeing();
    const asV1 = JSON.stringify({ ...manifest, v: 1 });
    expect(() => parseManifest(asV1)).toThrow(/unsupported version 1/);
    expect(() => parseManifest(asV1)).toThrow(/numbers every cell the way the notebook does/);
    expect(() => parseManifest(asV1)).toThrow(/Rebuild the manifest/);
    // Not a mismatch complaint, which is the failure mode the bump exists to
    // prevent: the bytes are fine, the numbering is not.
    expect(() => parseManifest(asV1)).not.toThrow(/mismatch|does not match/);
  });

  it("derives a cell's kind from the one field that decides it", () => {
    expect(cellKind({ peer: "" })).toBe("witnessed");
    expect(cellKind({ peer: "mara" })).toBe("placed");
    expect(cellKind({ peer: "*" })).toBe("rendezvous");
    expect(cellKind({})).toBe("witnessed");
  });
});

describe("peersSha, never fingerprints", () => {
  it("carries labels and a digest of the binding, and no fingerprint at all", async () => {
    const { manifest } = await agreeing();
    const json = manifestToJson(manifest);
    expect(manifest.peers).toEqual(["mara", "okafor"]);
    expect(json).not.toContain(FPR_A);
    expect(json).not.toContain(FPR_B);
    expect(json).not.toContain(FPR_A.toLowerCase());
    expect(manifest.peersSha).toMatch(/^[0-9a-f]{64}$/);
    expect(manifest.audienceSha).toMatch(/^[0-9a-f]{64}$/);
  });

  it("digests the binding independently of the order the room was assembled", async () => {
    const one = await peersDigest({ mara: FPR_A, okafor: FPR_B });
    const other = await peersDigest({ okafor: FPR_B, mara: FPR_A });
    expect(one).toBe(other);
    // Whitespace and 0x prefixes are how fingerprints are actually pasted.
    expect(await peersDigest({ mara: `0x${FPR_A.toLowerCase()}`, okafor: FPR_B })).toBe(one);
    expect(await peersDigest({ mara: FPR_B, okafor: FPR_A })).not.toBe(one);
  });

  it("is not the room key, because a digest of the audience is admission", async () => {
    // `notebook/room.js` derives the room from SHA-256 of
    // `${rpId}|${audience.join("|")}`. Publishing the same digest under the
    // same preimage would hand the room to anyone holding the manifest, so
    // both manifest digests are domain-separated.
    const roomPreimage = `localhost|${[FPR_A, FPR_B].sort().join("|")}`;
    const roomish = await digestText(roomPreimage);
    const audience = await audienceDigest([FPR_A, FPR_B]);
    expect(audience).not.toBe(roomish);
    expect(audience).not.toBe(await digestText(canonicalJson([FPR_A, FPR_B].sort())));
    expect(audience).not.toBe(await peersDigest({ mara: FPR_A, okafor: FPR_B }));
  });

  it("takes a fingerprint as a peer, and refuses a piece of one", async () => {
    // A peer *is* a key now, so the peer column of the roster holds
    // fingerprints and both sides of `peersSha`'s binding are the same value.
    // The first of these used to reject.
    await expect(
      buildRunManifest({ peers: { [FPR_LETTER_FIRST]: FPR_A } })
    ).resolves.toBeTruthy();
    await expect(
      buildRunManifest({
        peers: { [FPR_LETTER_FIRST]: FPR_LETTER_FIRST },
        cells: [{ index: 0, peer: FPR_LETTER_FIRST }],
      })
    ).resolves.toBeTruthy();

    // What did not change: a *part* of a key. A short id is a suffix of a
    // fingerprint, so several keys answer to it — a digest over a roster keyed
    // by one commits to none of them, which is the whole value of `peersSha`.
    // Both halves of the asymmetry, because two key ids in three begin with a
    // digit and the old rule answered differently for those.
    await expect(
      buildRunManifest({ peers: { D2C1B0A94F2AC1B3: FPR_A } })
    ).rejects.toThrow(/part of a key rather than a key/);
    await expect(
      buildRunManifest({ peers: { "42C1B0A94F2AC1B3": FPR_A } })
    ).rejects.toThrow(/part of a key rather than a key/);
    await expect(buildRunManifest({ peers: { "not a name": FPR_A } })).rejects.toThrow(
      /Invalid peer/
    );
  });
});

describe("what a manifest declares rather than pins", () => {
  it("calls a run reproducible only when nothing outside it is read", async () => {
    const { manifest } = await agreeing();
    expect(manifestReproducibility(manifest)).toEqual({ reproducible: true, reasons: [] });
  });

  it("names each dependency that makes a run unreproducible", async () => {
    const { manifest } = await agreeing({
      entropy: { mode: "local" },
      clock: { mode: "free" },
      network: [{ cell: 0, host: "keys.openpgp.org", path: "/vks/v1/by-fingerprint/4F2A" }],
      vault: [{ cell: 1, keyId: FPR_A, kind: "pgp", use: "sign" }],
    });
    const { reproducible, reasons } = manifestReproducibility(manifest);
    expect(reproducible).toBe(false);
    expect(reasons.join("\n")).toMatch(/entropy: local/);
    expect(reasons.join("\n")).toMatch(/clock: free/);
    expect(reasons.join("\n")).toMatch(/keys\.openpgp\.org/);
    expect(reasons.join("\n")).toMatch(/vault: cell 1 reaches key/);
  });

  it("treats an undeclared or unknown entropy mode as local, not as none", async () => {
    // Fail closed, the same way `slot` does: omission must not buy the safe
    // reading. Nothing else in this build can contradict the declaration.
    const omitted = await buildRunManifest({ clock: { mode: "pinned", t0: 1_786_320_000_000 } });
    expect(omitted.entropy.mode).toBe("local");
    expect(manifestReproducibility(omitted).reproducible).toBe(false);
    const nonsense = await buildRunManifest({ entropy: { mode: "harmless" } });
    expect(manifestReproducibility(nonsense).reasons[0]).toMatch(/not a declared mode/);
  });

  it("says a pool is declared, audited, and still not fed to anything", async () => {
    // Every op now declares whether its randomness may be seeded, so a pooled
    // run *can* be refused — `op-entropy-declared.test.js` covers that half.
    // What is still missing is the other one: no op reads a pool, so a run that
    // says `pool` draws locally anyway and is not reproducible for that reason.
    const m = await buildRunManifest({ entropy: { mode: "pool", digest: "5b".repeat(32) } });
    expect(manifestReproducibility(m).reasons[0]).toMatch(/no op reads a pool yet/);
    expect(ENTROPY_MODES).toEqual(["none", "pool", "local"]);
    expect(CLOCK_MODES).toEqual(["pinned", "free"]);
  });

  it("keeps a vault key id whole rather than shortening it into a collision", async () => {
    const m = await buildRunManifest({ vault: [{ cell: 0, keyId: FPR_A, kind: "pgp", use: "sign" }] });
    expect(m.vault[0].keyId).toBe(FPR_A);
  });
});

describe("the check, when the run honoured the manifest", () => {
  it("passes, and says how much it looked at and what it could not check", async () => {
    const { manifest, receipt } = await agreeing();
    const result = manifestHonouredBy(manifest, receipt);
    expect(result.mismatches).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.checked).toBeGreaterThan(6);
    expect(result.declared).toEqual([]);
    expect(summarizeHonour(result)).toMatch(/manifest honoured — \d+ facts matched/);
  });

  it("carries the declared non-reproducible dependencies into the summary", async () => {
    const { receipt } = await agreeing();
    const { manifest } = await agreeing({ entropy: { mode: "local" } });
    const result = manifestHonouredBy(manifest, receipt);
    expect(result.ok).toBe(true);
    expect(result.declared.length).toBe(1);
    expect(summarizeHonour(result)).toMatch(/1 declared non-reproducible dependency/);
  });

  it("checks a real run of a real notebook through the kernel", async () => {
    const kernel = createKernel();
    const { ast } = compileRecipe(SOURCE);
    const chains = recipeChains(ast);
    await kernel.runCell(0, chains[0], {});
    await kernel.runCell(1, chains[1], {});
    const log = kernel.getRunLog();

    const manifest = await buildRunManifest({
      recipeSource: SOURCE,
      // The spelling the kernel records — `appendRunLog` serializes each chain.
      cells: chains.map((chain, index) => ({
        index,
        recipe: serializeRecipe({ chains: [chain] }),
      })),
      entropy: { mode: "none" },
      clock: { mode: "pinned", t0: "2020-01-01T00:00:00.000Z" },
    });
    const receipt = await buildRunReceipt({ recipeSource: SOURCE, cells: log });

    const result = manifestHonouredBy(manifest, receipt);
    expect(result.mismatches).toEqual([]);
    expect(result.ok).toBe(true);
  });
});

describe("the check, in every dimension the manifest pins", () => {
  /**
   * @param {object} mutate  a shallow patch applied to the receipt
   * @returns {Promise<import("../lib/toolkit/manifest.js").RunManifest extends never ? never : *>}
   */
  const departing = async (mutate) => {
    const { manifest, receipt } = await agreeing();
    return manifestHonouredBy(manifest, mutate(structuredClone(receipt)) || receipt);
  };

  it("catches a recipe that is not the one that was agreed", async () => {
    const r = await departing((rec) => {
      rec.recipeDigest = "0".repeat(64);
      return rec;
    });
    expect(r.ok).toBe(false);
    expect(r.mismatches[0]).toMatchObject({ path: "manifest", field: "recipeDigest" });
    expect(summarizeHonour(r)).toMatch(/manifest not honoured at manifest \(recipeDigest\)/);
  });

  it("catches a run against a different op registry", async () => {
    const r = await departing((rec) => {
      rec.registry = "ops-1-deadbeef";
      return rec;
    });
    expect(r.mismatches.some((m) => m.field === "registry")).toBe(true);
  });

  it("catches a receipt written to a different envelope than the one agreed", async () => {
    const r = await departing((rec) => {
      rec.v = 99;
      return rec;
    });
    expect(r.mismatches.some((m) => m.field === "receiptVersion")).toBe(true);
  });

  it("catches a cell the manifest never listed", async () => {
    const r = await departing((rec) => {
      rec.cells.push({ index: 2, recipe: "random 32 | out $x", inputs: [], outputs: [] });
      return rec;
    });
    expect(r.mismatches).toContainEqual({
      path: "manifest",
      field: "cells",
      expected: "2",
      actual: "3",
    });
  });

  it("catches an edited cell, and names the cell", async () => {
    const r = await departing((rec) => {
      rec.cells[1].recipe = "in $a | gpg.encrypt to=mallory | out $b";
      return rec;
    });
    expect(r.mismatches[0]).toMatchObject({ path: "cell 1", field: "recipe" });
    expect(r.mismatches[0].expected).toBe("in $a | out $b");
  });

  it("catches cells run out of the order the manifest fixed", async () => {
    const r = await departing((rec) => {
      rec.cells.reverse();
      return rec;
    });
    expect(r.mismatches.some((m) => m.field === "index")).toBe(true);
  });

  it("catches a different value bound to a pinned input", async () => {
    const r = await departing((rec) => {
      rec.cells[0].inputs[0].digest = "b".repeat(64);
      return rec;
    });
    expect(r.mismatches).toContainEqual({
      path: "cell 0 · input text",
      field: "digest",
      expected: "a".repeat(64),
      actual: "b".repeat(64),
    });
  });

  it("catches a pinned input the run never consumed", async () => {
    const r = await departing((rec) => {
      rec.cells[0].inputs = [];
      return rec;
    });
    expect(r.mismatches).toContainEqual({
      path: "cell 0 · input text",
      field: "missing",
      expected: "a".repeat(64),
      actual: "",
    });
  });

  it("catches a value that entered the run from outside the manifest", async () => {
    // The direction a one-way check waves through: every digest the manifest
    // pinned is present and correct, and a share was pasted in as well.
    const r = await departing((rec) => {
      rec.cells[1].inputs = [{ channel: "shares", index: 1, digest: "e".repeat(64) }];
      return rec;
    });
    expect(r.ok).toBe(false);
    expect(r.mismatches).toContainEqual({
      path: "cell 1 · input shares 1",
      field: "undeclared",
      expected: "",
      actual: "e".repeat(64),
    });
  });

  it("does not report a mismatch when pinned inputs arrive in another order", async () => {
    const { receipt } = await agreeing();
    const manifest = (
      await agreeing({
        inputs: [
          { cell: 1, channel: "shares", index: 2, digest: "f".repeat(64) },
          { cell: 0, channel: "text", digest: "a".repeat(64) },
          { cell: 1, channel: "shares", index: 1, digest: "e".repeat(64) },
        ],
      })
    ).manifest;
    receipt.cells[1].inputs = [
      { channel: "shares", index: 2, digest: "f".repeat(64) },
      { channel: "shares", index: 1, digest: "e".repeat(64) },
    ];
    expect(manifestHonouredBy(manifest, receipt).ok).toBe(true);
  });

  it("catches a receipt that predates the clock it claims to honour", async () => {
    const r = await departing((rec) => {
      rec.createdAt = "2020-01-01T00:00:00.000Z";
      rec.cells[0].startedAt = "2020-01-01T00:00:00.000Z";
      return rec;
    });
    expect(r.ok).toBe(false);
    expect(r.mismatches[0]).toMatchObject({
      path: "manifest",
      field: "clock",
      expected: "not before 2026-08-01T00:00:00.000Z",
    });
    expect(r.mismatches.some((m) => m.path === "cell 0" && m.field === "clock")).toBe(true);
  });

  it("catches a clock declared pinned and never actually pinned", async () => {
    const { receipt } = await agreeing();
    const { manifest } = await agreeing({ clock: { mode: "pinned" } });
    const r = manifestHonouredBy(manifest, receipt);
    expect(r.mismatches).toContainEqual({
      path: "manifest",
      field: "clock",
      expected: "a pinned t0",
      actual: "",
    });
  });

  it("asserts nothing about time when the clock is declared free", async () => {
    const { receipt } = await agreeing();
    const { manifest } = await agreeing({ clock: { mode: "free" } });
    receipt.createdAt = "1999-01-01T00:00:00.000Z";
    const r = manifestHonouredBy(manifest, receipt);
    expect(r.mismatches).toEqual([]);
    expect(r.declared.some((d) => /clock: free/.test(d))).toBe(true);
  });
});

describe("one canonicalization, not two", () => {
  const SRC = readFileSync(
    fileURLToPath(new URL("../lib/toolkit/manifest.js", import.meta.url)),
    "utf8"
  ).replace(/\r\n/g, "\n");
  const code = SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

  it("imports the receipt's machinery rather than restating it", () => {
    expect(code).toMatch(/import \{[\s\S]*?\} from "\.\/receipt\.js";/);
    for (const name of ["canonicalJson", "digestText", "mismatchLog", "unwrapCleartext"]) {
      expect(code, name).toMatch(new RegExp(`\\b${name}\\b`));
      expect(code, name).not.toMatch(new RegExp(`function ${name}\\b`));
    }
  });

  it("hashes nothing by hand and defines no second digest", () => {
    // A manifest whose digests were computed differently from a receipt's
    // would fail to verify an honest run, which is the worst failure this
    // pair of documents has.
    expect(code).not.toMatch(/crypto\.subtle|TextEncoder|0x811c9dc5/);
  });

  it("agrees with the receipt about what canonical JSON is", async () => {
    const { manifest } = await agreeing();
    expect(manifestToJson(manifest)).toBe(canonicalJson(manifest));
  });
});

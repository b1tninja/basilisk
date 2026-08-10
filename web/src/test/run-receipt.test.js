/**
 * Run receipts — the digest logic, the no-leak invariant, and the
 * verify-without-reveal comparison, tested as pure units.
 *
 * The two properties worth locking down are the ones a reader cannot check by
 * eye: that a receipt of a ceremony contains no share, and that comparing two
 * secrets by digest answers "same?" without either being reconstructible from
 * what the comparison returns.
 */
import { describe, expect, it } from "vitest";
import {
  RECEIPT_VERSION,
  buildRunReceipt,
  canonicalJson,
  compareReceipts,
  compareSecretsByDigest,
  constantTimeEqual,
  digestArtifact,
  digestInputs,
  digestText,
  opsRegistryVersion,
  parseReceipt,
  receiptToJson,
  summarizeComparison,
} from "../lib/toolkit/receipt.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { createKernel } from "../lib/toolkit/kernel.js";

describe("canonical JSON", () => {
  it("sorts keys so two builds of the same receipt sign identically", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalJson({ a: 2, b: 1 })).toBe(canonicalJson({ b: 1, a: 2 }));
  });

  it("keeps array order, which is meaningful for cells and outputs", () => {
    expect(canonicalJson([3, 1, 2])).toBe("[3,1,2]");
  });

  it("drops undefined rather than emitting a hole", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("refuses non-finite numbers instead of writing null", () => {
    // A receipt that silently loses a field is worse than one that fails.
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(/non-finite/);
  });
});

describe("registry version", () => {
  it("is stable across calls", () => {
    expect(opsRegistryVersion()).toBe(opsRegistryVersion());
  });

  it("names the op count, so a mismatch is readable", () => {
    expect(opsRegistryVersion()).toMatch(/^ops-\d+-[0-9a-f]{8}$/);
  });
});

describe("digesting", () => {
  it("gives an artifact its digest and length, never its content", async () => {
    const row = await digestArtifact({
      label: "Share 1",
      filename: "share-1.txt",
      role: "share",
      sensitive: true,
      shareIndex: 1,
      content: "abandon ability able about above absent absorb abstract",
    });
    expect(row.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(row.length).toBe(55);
    expect(JSON.stringify(row)).not.toContain("abandon");
    expect(row).not.toHaveProperty("content");
    expect(row).not.toHaveProperty("bytes");
  });

  it("digests each pasted share separately, so a receipt records which were used", async () => {
    const rows = await digestInputs({
      shares: { mnemonics: ["alpha beta", "gamma delta", "   "] },
      text: { value: "hello" },
    });
    const shares = rows.filter((r) => r.channel === "shares");
    expect(shares.map((r) => r.index)).toEqual([1, 2]);
    expect(shares[0].digest).not.toBe(shares[1].digest);
    expect(JSON.stringify(rows)).not.toContain("alpha");
    expect(rows.some((r) => r.channel === "text")).toBe(true);
  });

  it("agrees with a plain SHA-256 of the UTF-8 bytes", async () => {
    // Known vector: SHA-256("abc").
    expect(await digestText("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });
});

describe("receipt envelope", () => {
  const cells = [
    {
      index: 0,
      recipe: "random 32 | out $m",
      inputs: [],
      outputs: [{ label: "m", digest: "a".repeat(64), length: 32 }],
    },
  ];

  it("carries the recipe source and its digest", async () => {
    const r = await buildRunReceipt({
      label: "Ceremony",
      recipeSource: "random 32 | out $m",
      cells,
    });
    expect(r.v).toBe(RECEIPT_VERSION);
    expect(r.kind).toBe("basilisk.run-receipt");
    expect(r.recipeDigest).toBe(await digestText("random 32 | out $m"));
    expect(r.registry).toMatch(/^ops-/);
  });

  it("round-trips through canonical JSON", async () => {
    const r = await buildRunReceipt({ recipeSource: "x", cells });
    expect(parseReceipt(receiptToJson(r))).toEqual(JSON.parse(receiptToJson(r)));
  });

  it("finds the payload inside an OpenPGP cleartext signature", async () => {
    const r = await buildRunReceipt({ recipeSource: "x", cells });
    const json = receiptToJson(r);
    const signed = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      json,
      "-----BEGIN PGP SIGNATURE-----",
      "iQIzBAEBCgAdFiEE",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    // Asking a user to unwrap the armor by hand would make the signed form
    // less useful than the unsigned one.
    expect(parseReceipt(signed).recipeDigest).toBe(r.recipeDigest);
  });

  it("rejects text that is not a receipt", () => {
    expect(() => parseReceipt("hello")).toThrow(/not JSON/);
    expect(() => parseReceipt('{"kind":"something-else"}')).toThrow(/not a Basilisk/);
    expect(() => parseReceipt('{"kind":"basilisk.run-receipt","v":99}')).toThrow(
      /unsupported version/
    );
    expect(() => parseReceipt("")).toThrow(/empty/);
  });
});

describe("comparison", () => {
  const mkCells = (digest) => [
    {
      index: 0,
      recipe: "random 32 | out $m",
      inputs: [{ channel: "text", digest: "b".repeat(64) }],
      outputs: [{ label: "m", digest, length: 32 }],
    },
  ];

  it("accepts a re-run that differs only in timing", async () => {
    const a = await buildRunReceipt({
      createdAt: "2020-01-01T00:00:00.000Z",
      recipeSource: "r",
      cells: mkCells("c".repeat(64)),
    });
    const b = await buildRunReceipt({
      createdAt: "2026-07-30T12:00:00.000Z",
      recipeSource: "r",
      cells: mkCells("c".repeat(64)).map((c) => ({ ...c, durationMs: 4321 })),
    });
    const result = compareReceipts(a, b);
    expect(result.ok).toBe(true);
    expect(result.checked).toBeGreaterThan(3);
    expect(summarizeComparison(result)).toMatch(/verified/);
  });

  it("catches a changed output digest and says where", async () => {
    const a = await buildRunReceipt({ recipeSource: "r", cells: mkCells("c".repeat(64)) });
    const b = await buildRunReceipt({ recipeSource: "r", cells: mkCells("d".repeat(64)) });
    const result = compareReceipts(a, b);
    expect(result.ok).toBe(false);
    expect(result.mismatches[0].path).toBe("cell 0 · output 1");
    expect(result.mismatches[0].field).toBe("digest");
    expect(summarizeComparison(result)).toMatch(/mismatch at cell 0 · output 1/);
  });

  it("catches an edited recipe even when the digests still line up", async () => {
    const a = await buildRunReceipt({ recipeSource: "r", cells: mkCells("c".repeat(64)) });
    const b = await buildRunReceipt({
      recipeSource: "r",
      cells: mkCells("c".repeat(64)).map((c) => ({ ...c, recipe: "random 16 | out $m" })),
    });
    const result = compareReceipts(a, b);
    expect(result.ok).toBe(false);
    expect(result.mismatches.some((m) => m.field === "recipe")).toBe(true);
  });

  it("catches an extra or missing cell", async () => {
    const a = await buildRunReceipt({ recipeSource: "r", cells: mkCells("c".repeat(64)) });
    const b = await buildRunReceipt({
      recipeSource: "r",
      cells: [...mkCells("c".repeat(64)), { index: 1, recipe: "x", inputs: [], outputs: [] }],
    });
    const result = compareReceipts(a, b);
    expect(result.ok).toBe(false);
    expect(result.mismatches.some((m) => m.field === "cells")).toBe(true);
  });

  it("catches a receipt minted against a different op registry", async () => {
    const a = await buildRunReceipt({ registry: "ops-1-deadbeef", recipeSource: "r", cells: [] });
    const b = await buildRunReceipt({ registry: "ops-2-cafebabe", recipeSource: "r", cells: [] });
    expect(compareReceipts(a, b).mismatches[0].field).toBe("registry");
  });
});

describe("verify without reveal", () => {
  it("confirms two secrets match without either being in the answer", async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const recovered = new Uint8Array(secret);
    const result = await compareSecretsByDigest(secret, recovered);
    expect(result.match).toBe(true);
    // What comes back is a pair of SHA-256 digests. Neither the caller nor a
    // screenshot of the caller's screen contains the 32 bytes.
    expect(result.digestA).toMatch(/^[0-9a-f]{64}$/);
    expect(result.digestA).toBe(result.digestB);
    const hex = [...secret].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(JSON.stringify(result)).not.toContain(hex);
  });

  it("reports a mismatch when one byte differs", async () => {
    const secret = new Uint8Array(32).fill(7);
    const wrong = new Uint8Array(32).fill(7);
    wrong[31] = 8;
    const result = await compareSecretsByDigest(secret, wrong);
    expect(result.match).toBe(false);
    expect(result.digestA).not.toBe(result.digestB);
  });

  it("compares text secrets the same way", async () => {
    const a = await compareSecretsByDigest("correct horse", "correct horse");
    const b = await compareSecretsByDigest("correct horse", "correct horsf");
    expect([a.match, b.match]).toEqual([true, false]);
  });

  it("has a length-safe equality that does not early-exit on content", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
  });
});

describe("run.receipt / run.verify through the engine", () => {
  it("receipts a split without recording a single share", async () => {
    const { ast } = compileRecipe(
      `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

run.receipt "Board key ceremony" | out $receipt`
    );
    const arts = await runRecipe(ast);
    const receiptTile = arts.find((a) => a.role === "receipt");
    expect(receiptTile).toBeTruthy();
    const receipt = parseReceipt(receiptTile.content);
    expect(receipt.label).toBe("Board key ceremony");

    const shares = arts.filter((a) => a.role === "share");
    expect(shares.length).toBe(3);
    for (const s of shares) {
      expect(receiptTile.content).not.toContain(String(s.content).trim());
    }
    // It does record that three share tiles existed, and their digests.
    const shareRows = receipt.cells.flatMap((c) =>
      (c.outputs || []).filter((o) => o.role === "share")
    );
    expect(shareRows.length).toBe(3);
    expect(shareRows.every((r) => /^[0-9a-f]{64}$/.test(r.digest))).toBe(true);
  }, 30_000);

  it("verifies a receipt against the run that minted it", async () => {
    const { ast } = compileRecipe("run.receipt | run.verify | out $ok");
    const arts = await runRecipe(ast);
    expect(arts.some((a) => String(a.content).trim() === "true")).toBe(true);
  });

  it("fails loud on a tampered receipt, and soft with -q", async () => {
    const { ast: mint } = compileRecipe("run.receipt | out $r");
    const minted = (await runRecipe(mint)).find((a) => a.role === "receipt");
    const tampered = JSON.parse(minted.content);
    tampered.recipeDigest = "0".repeat(64);
    const bindings = { inputs: { text: { value: JSON.stringify(tampered) } } };

    const { ast: loud } = compileRecipe("input | run.verify | out $ok");
    await expect(runRecipe(loud, bindings)).rejects.toThrow(/mismatch/i);

    const { ast: soft } = compileRecipe("input | run.verify -q | out $ok");
    const arts = await runRecipe(soft, bindings);
    expect(arts.some((a) => String(a.content).trim() === "false")).toBe(true);
  });

  it("refuses text that is not a receipt even in soft mode", async () => {
    // Soft mode is about "the receipt does not match", not "you piped in the
    // wrong thing" — the same distinction `verify -q` draws for setup errors.
    const { ast } = compileRecipe("input | run.verify -q | out $ok");
    await expect(
      runRecipe(ast, { inputs: { text: { value: "not a receipt" } } })
    ).rejects.toThrow(/not JSON|not a Basilisk/);
  });
});

describe("kernel run log", () => {
  it("accumulates one digested entry per cell run", async () => {
    const kernel = createKernel();
    const { ast } = compileRecipe("bytes deadbeef | encode hex | out $a\n\nin $a | out $b");
    await kernel.runCell(0, ast.chains[0], {});
    await kernel.runCell(1, ast.chains[1], {});
    const log = kernel.getRunLog();
    expect(log.map((c) => c.index)).toEqual([0, 1]);
    expect(log[0].recipe).toContain("bytes");
    expect(log[0].outputs[0].digest).toMatch(/^[0-9a-f]{64}$/);
    expect(log[0].durationMs).toBeGreaterThanOrEqual(0);
  });

  it("lets a receipt in the last cell cover the whole notebook", async () => {
    const kernel = createKernel();
    const { ast } = compileRecipe(
      "bytes deadbeef | encode hex | out $a\n\nrun.receipt | out $receipt"
    );
    await kernel.runCell(0, ast.chains[0], {});
    const arts = await kernel.runCell(1, ast.chains[1], {});
    const receipt = parseReceipt(arts.find((a) => a.role === "receipt").content);
    // Cell 0 from the kernel's log, plus cell 1 from the live run.
    expect(receipt.cells.length).toBe(2);
    expect(receipt.cells[0].recipe).toContain("bytes");
  });

  it("forgets the log on Clear sensitive, because a digest is still a fact", async () => {
    const kernel = createKernel();
    const { ast } = compileRecipe("bytes deadbeef | encode hex | out $a");
    await kernel.runCell(0, ast.chains[0], {});
    expect(kernel.getRunLog().length).toBe(1);
    kernel.clearSensitive();
    expect(kernel.getRunLog()).toEqual([]);
  });
});

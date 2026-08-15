/**
 * The run's record answers "whose shares rebuilt this secret" — finding 7a.
 *
 * The reproduction this replaces, run at 36d0f26: a recovery-shaped cell —
 * shares registered exactly as `execQuorumRecv` returns them, `meta.from`
 * carrying the senders' fingerprints — recombined correctly, and afterwards
 * the gather's run-log row read `"inputs": []`, the slot metas read
 * `{ "label": "share-1", "type": "text", "sensitive": true }` with no sender
 * anywhere, and `run.receipt`'s output contained neither fingerprint. The one
 * machine that ends up with the secret was the one machine with no readable
 * record of where it came from.
 *
 * The record lives on the run now (`lib/toolkit/run.js`), written by two
 * seams in the kernel — the observed slot registry, and the engine's
 * `noteArrivals` for values consumed off a channel before any slot holds them
 * — and it reaches a person in two places: the cell's own provenance line
 * (`CellProvenance`, asserted in the browser by
 * `dealer-absent-recovery.e2e.js` step 7) and the receipt's per-cell
 * `provenance` rows, which this file pins.
 */

import { describe, expect, it, vi } from "vitest";
import { createKernel } from "../lib/toolkit/kernel.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { originStamps } from "../lib/toolkit/engine.js";
import { buildRunReceipt, compareReceipts } from "../lib/toolkit/receipt.js";
import { cellsInScope, createRun, noteOfferVerdicts } from "../lib/toolkit/run.js";
import { provenanceRows } from "../toolkit/widgets/CellProvenance.tsx";

const DEALER = "A".repeat(40);
const BYSTANDER = "B".repeat(40);

/**
 * `quorum.recv` without a room: the mock returns exactly the shape the real
 * op builds for a single message (`quorum-ops.js`), which is the one fact the
 * engine's arrival seam reads. Everything else the recovery runs — shares
 * collection, BLIP39, the Shamir recombination, the digest — is real.
 */
let nextRecv = null;
vi.mock("../lib/toolkit/quorum-ops.js", () => ({
  execQuorumRecv: async () => {
    if (!nextRecv) throw new Error("test: nothing queued for quorum.recv");
    const msg = nextRecv;
    nextRecv = null;
    return { type: "text", data: msg.text, meta: { sensitive: true, from: msg.from, ts: msg.ts } };
  },
  closeQuorumExchange: () => {},
}));

const chainOf = (text) => {
  const { ast } = compileRecipe(text);
  if (!ast) throw new Error(`did not parse: ${text}`);
  return ast.chains?.[0] || { steps: ast.steps || [] };
};

/**
 * A dealer's split, shaped like `roomCeremony`'s dealing cell, and the two
 * facts a recovery needs from it: the mnemonics and the expected digest.
 */
async function dealt() {
  const dealer = createKernel();
  await dealer.runCell(
    0,
    chainOf(
      ["random 32 | tee", "  - digest | encode hex | out $expected", "| sss.split 2/2 | blip39 | out $set"].join("\n")
    )
  );
  const set = dealer.slots.resolve("$set");
  const expected = String(dealer.slots.resolve("$expected").data);
  return { mnemonics: set.data.mnemonics, expected };
}

/** The generator's gather, verbatim in shape: one recv, one slot, recombine. */
const GATHER = [
  "quorum.recv count=1 wait=1800000 | shares with=$share-2 | blip39 -d | sss.combine | tee",
  "  - digest | encode hex | out $recovered",
  "| encode hex | out $secret",
].join("\n");

describe("a recovering machine can say whose shares rebuilt the secret", () => {
  it("records the slot's sender and the channel's sender, and the receipt carries both", async () => {
    const { mnemonics, expected } = await dealt();
    const [m1, m2] = mnemonics;

    // The recovering machine. $share-2 arrived from the dealer during the
    // deal — registered as `quorum.recv from=<dealer> | out $share-2` leaves
    // it; the other share arrives inside the gather itself, from the
    // bystander, after the dealer is gone.
    const kernel = createKernel();
    kernel.slots.register("$share-2", {
      type: "text",
      data: m2,
      meta: { sensitive: true, from: DEALER, ts: 1 },
    });
    nextRecv = { text: m1, from: BYSTANDER, ts: 2 };

    const run = createRun({
      cause: { kind: "press", press: "run-from", cell: 0 },
      scope: { from: 0, to: 1 },
    });
    await kernel.runCell(0, chainOf(GATHER), { receipt: { recipeSource: GATHER, label: "recovery" } }, undefined, run);

    // The recombination is real — the digest a third machine wrote down is
    // the digest this one recovered — so everything below is about a run
    // that actually rebuilt the secret.
    expect(String(kernel.slots.resolve("$recovered").data)).toBe(expected);

    // The cell's record: the slot read names the dealer, the in-pipeline
    // arrival names the bystander. This is the pair finding 7a says never
    // reached anything a person can read.
    const prov = kernel.getCellProvenance(0);
    expect(prov.reads).toContainEqual({ slot: "share-2", from: DEALER });
    expect(prov.received).toContainEqual({ from: BYSTANDER, step: "quorum.recv" });
    // And the writes say what the run bound, with no origin invented for
    // values made here.
    expect(prov.writes).toContainEqual({ slot: "recovered" });
    expect(prov.writes).toContainEqual({ slot: "secret" });

    // The same rows ride the run object and the run log — one recorder,
    // three readers.
    expect(run.record.cells).toHaveLength(1);
    expect(run.record.cells[0].cell).toBe(0);
    expect(run.record.cells[0].received).toContainEqual({ from: BYSTANDER, step: "quorum.recv" });
    const row = kernel.getRunLog()[0];
    expect(row.provenance.reads).toContainEqual({ slot: "share-2", from: DEALER });
    // And why the cell ran, which is the fact whose absence blocked
    // automating `sendCellResult`: "nothing records why a cell ran".
    expect(row.run).toEqual({ id: run.id, cause: { kind: "press", press: "run-from", cell: 0 } });

    // `run.receipt`, minted by a later cell of the same session, names both
    // contributors — the reproduction's receipt named neither.
    const receiptArts = await kernel.runCell(1, chainOf("run.receipt | out $receipt"), {
      receipt: { recipeSource: GATHER, label: "recovery" },
    });
    const receiptText = receiptArts.find((a) => a.content)?.content || "";
    expect(receiptText).toContain(DEALER);
    expect(receiptText).toContain(BYSTANDER);
  });

  it("keeps the record on the cell across a remap, and wipes it with the outputs", async () => {
    const { mnemonics } = await dealt();
    const kernel = createKernel();
    kernel.slots.register("$share-2", {
      type: "text",
      data: mnemonics[1],
      meta: { sensitive: true, from: DEALER, ts: 1 },
    });
    await kernel.runCell(1, chainOf("$share-2 | out $copy"));
    expect(kernel.getCellProvenance(1).reads).toContainEqual({ slot: "share-2", from: DEALER });

    // Deleting cell 0 moves the bucket with the timing it belongs to — a
    // provenance line left behind would name senders to a different cell.
    kernel.remapCells((i) => (i === 0 ? null : i - 1));
    expect(kernel.getCellProvenance(1)).toBeNull();
    expect(kernel.getCellProvenance(0).reads).toContainEqual({ slot: "share-2", from: DEALER });

    // Clearing a cell clears its record; the rows name fingerprints, which
    // is exactly what Clear sensitive exists to remove.
    kernel.clearCellOutputs(0);
    expect(kernel.getCellProvenance(0)).toBeNull();
  });

  it("clears every record with Clear sensitive", async () => {
    const { mnemonics } = await dealt();
    const kernel = createKernel();
    kernel.slots.register("$share-2", {
      type: "text",
      data: mnemonics[1],
      meta: { sensitive: true, from: DEALER, ts: 1 },
    });
    await kernel.runCell(0, chainOf("$share-2 | out $copy"));
    expect(kernel.getCellProvenance(0)).not.toBeNull();
    kernel.clearSensitive();
    expect(kernel.getCellProvenance(0)).toBeNull();
    expect(kernel.getRunLog()).toEqual([]);
  });
});

describe("an origin that no key identifies never wears a fingerprint", () => {
  it("exports a peer.recv value as a link origin, not a from", () => {
    // `peer.recv` stamps `meta.from` with the link's local *name* — there is
    // no key confirmation on a hand-carried link — and marks it `meta.link`.
    // The stamp collector turns that into `{ link }`, never `{ from }`, so
    // nothing downstream can print a link id where a fingerprint goes:
    // unverified never looks verified.
    const single = {
      type: "text",
      data: "hello",
      meta: { sensitive: true, from: "alice", ts: 1, link: "alice" },
    };
    expect(originStamps(single)).toEqual([{ link: "alice" }]);
    // Bundle parts carry `from` without their own `link`; the bundle's link
    // covers them, and the same rule holds.
    const bundle = {
      type: "bundle",
      data: {
        parts: [{ type: "text", data: "x", meta: { sensitive: true, from: "alice", ts: 1 } }],
        count: 1,
      },
      meta: { kind: "recv", count: 1, sensitive: true, link: "alice" },
    };
    expect(originStamps(bundle)).toEqual([{ link: "alice" }]);
    // And a key-confirmed sender is a fingerprint, once, however many parts
    // repeat it.
    const mesh = {
      type: "bundle",
      data: {
        parts: [
          { type: "text", data: "x", meta: { from: DEALER } },
          { type: "text", data: "y", meta: { from: DEALER } },
          { type: "text", data: "z", meta: { from: BYSTANDER } },
        ],
        count: 3,
      },
      meta: { kind: "recv", count: 3 },
    };
    expect(originStamps(mesh)).toEqual([{ from: DEALER }, { from: BYSTANDER }]);
  });
});

describe("the cell's provenance line draws what is known and nothing twice", () => {
  it("keeps the gather's two contributors and drops the receive cell's echo", () => {
    // The gather: a slot from the dealer, an arrival from the bystander —
    // two rows, both kept.
    expect(
      provenanceRows({
        reads: [{ slot: "share-2", from: DEALER }],
        writes: [{ slot: "recovered" }, { slot: "secret" }],
        received: [{ from: BYSTANDER, step: "quorum.recv" }],
      }).map((r) => `${r.slot || "recv"}:${r.from}`)
    ).toEqual([`share-2:${DEALER}`, `recv:${BYSTANDER}`]);

    // The receive cell: `quorum.recv from=X | out $share-2` both receives
    // from X and writes a slot holding X's value — one fact, one row.
    expect(
      provenanceRows({
        reads: [],
        writes: [{ slot: "share-2", from: DEALER }],
        received: [{ from: DEALER, step: "quorum.recv" }],
      })
    ).toEqual([{ key: `share-2·from:${DEALER}`, slot: "share-2", from: DEALER, link: undefined }]);
  });

  it("says nothing about a purely local run", () => {
    expect(
      provenanceRows({
        reads: [{ slot: "me" }],
        writes: [{ slot: "out" }],
        received: [],
      })
    ).toEqual([]);
    expect(provenanceRows(null)).toEqual([]);
  });

  it("keeps a link origin distinct from a fingerprint origin", () => {
    const rows = provenanceRows({
      reads: [{ slot: "msg", link: "alice" }],
      writes: [],
      received: [{ link: "alice", step: "peer.recv" }],
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].link).toBe("alice");
    expect(rows[0].from).toBeUndefined();
  });
});

describe("the run object", () => {
  it("mints distinct ids and an empty record", () => {
    const a = createRun({ cause: { kind: "press", press: "run-from", cell: 0 }, scope: { from: 0, to: 3 } });
    const b = createRun({ cause: { kind: "press", press: "ceremony-stage", stage: "split" }, scope: { from: 1, to: 1 } });
    expect(a.id).not.toBe(b.id);
    expect(a.record.declined).toEqual([]);
    expect(a.record.sent.size).toBe(0);
    expect(a.plan).toBeNull();
  });

  it("scopes the walk to the cells the run states", () => {
    const chains = [{ steps: [{}] }, { steps: [] }, { steps: [{}] }, { steps: [{}] }];
    expect(cellsInScope({ from: 0, to: 3 }, chains)).toEqual([0, 2, 3]);
    // `runFrom(i)` is `i..end`, stated: the empty cell spends its index and
    // runs nothing, exactly as the loop always treated it.
    expect(cellsInScope({ from: 2, to: 3 }, chains)).toEqual([2, 3]);
    // A ceremony stage's run is one cell.
    expect(cellsInScope({ from: 2, to: 2 }, chains)).toEqual([2]);
  });

  it("folds offer verdicts latest-per-cell, keeping earlier cells' rows", () => {
    const run = createRun({ cause: { kind: "press", press: "run-from", cell: 0 }, scope: { from: 0, to: 5 } });
    noteOfferVerdicts(run, [
      { cell: 3, peer: "B", state: "aside" },
      { cell: 1, peer: "A", state: "sent" },
    ]);
    const after = noteOfferVerdicts(run, [{ cell: 3, peer: "B", state: "sent" }]);
    expect(after).toEqual([
      { cell: 1, peer: "A", state: "sent" },
      { cell: 3, peer: "B", state: "sent" },
    ]);
    expect(run.record.offers).toEqual(after);
  });
});

describe("the receipt carries the record without judging by it", () => {
  it("copies provenance and run rows through buildRunReceipt", async () => {
    const receipt = await buildRunReceipt({
      recipeSource: "x",
      cells: [
        {
          index: 0,
          recipe: "x",
          inputs: [],
          outputs: [],
          provenance: { reads: [{ slot: "share-2", from: DEALER }], writes: [], received: [] },
          run: { id: 7, cause: { kind: "press", press: "run-from", cell: 0 } },
        },
      ],
    });
    expect(receipt.cells[0].provenance.reads[0].from).toBe(DEALER);
    expect(receipt.cells[0].run.id).toBe(7);
  });

  it("verifies a provenance-free receipt against a recorded re-run", async () => {
    // Any majority may rebuild a split and any press may be the one that ran
    // a cell — two honest runs differ in both, and a receipt minted before
    // the record existed carries neither. Comparison must not care, or every
    // old receipt would fail an honest re-verification.
    const base = { index: 0, recipe: "x", inputs: [], outputs: [] };
    const claimed = await buildRunReceipt({ recipeSource: "x", cells: [base] });
    const actual = await buildRunReceipt({
      recipeSource: "x",
      cells: [
        {
          ...base,
          provenance: { reads: [{ slot: "share-2", from: DEALER }], writes: [], received: [] },
          run: { id: 9, cause: { kind: "press", press: "run-from", cell: 0 } },
        },
      ],
    });
    const result = compareReceipts(claimed, actual);
    expect(result.ok).toBe(true);
    expect(result.mismatches).toEqual([]);
  });
});

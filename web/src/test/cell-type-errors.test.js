/**
 * Type-error banner logic (§33c) — the part that can be wrong on its own.
 *
 * The banner's rendering is not covered here (this suite runs in node, with no
 * React renderer configured). What *is* covered is the fix suggestion, because
 * that is the piece that can mislead: it reads a type out of prose and then
 * claims an op produces it.
 */
import { describe, expect, it } from "vitest";
import { expectedTypeFrom } from "../lib/toolkit/type-error-hints.js";
import { producersOf } from "../lib/toolkit/type-registry.js";
import { PRESETS, compileRecipe, parseRecipe } from "../lib/toolkit/recipe.js";
import {
  cellErrorRows,
  cellErrorsForChains,
  cellWarningsForChains,
} from "../toolkit/useNotebook";
import { warningDismissKey } from "../toolkit/CellWarnings";

describe("expectedTypeFrom", () => {
  it("reads the wanted type out of the registry's real phrasings", () => {
    expect(
      expectedTypeFrom('"sss.split" does not accept text/opaque (accepted: bytes/master/16B)')
    ).toBe("bytes");
    expect(expectedTypeFrom('"digest" expects DER bytes')).toBe("bytes");
  });

  it("defers to a fix the validator already named", () => {
    // The generic suggestion comes from the producer list in registry order,
    // so for `bytes` it proposes `aes-cbc` — a real producer and terrible
    // advice next to "add export pkcs8". Silence beats a second worse answer.
    expect(expectedTypeFrom('"digest" expects DER bytes — add export pkcs8')).toBeNull();
    expect(expectedTypeFrom("shares/raw needs blip39 -d — use blip39.decode")).toBeNull();
  });

  it("returns null rather than guessing", () => {
    // A miss costs a suggestion; a wrong hit sends the user to an op that
    // cannot help. Prefer silence.
    expect(expectedTypeFrom("something went wrong")).toBeNull();
    expect(expectedTypeFrom("")).toBeNull();
  });

  it("only names types the registry can actually produce", () => {
    for (const msg of [
      '"digest" expects DER bytes',
      '"sss.split" does not accept text (accepted: bytes/master)',
    ]) {
      const t = expectedTypeFrom(msg);
      expect(t, msg).toBeTruthy();
      // The banner only offers a fix when this list is non-empty, so a parsed
      // type that nothing produces simply yields no suggestion.
      expect(producersOf(t).length, `${t} producers`).toBeGreaterThan(0);
    }
  });
});

describe("validator errors stay parseable", () => {
  it("still carries stepIndex, which anchors the banner to a chip", () => {
    const { validation } = compileRecipe("genkey ec/p256 | digest");
    expect(validation.ok).toBe(false);
    const err = validation.errors[0];
    expect(err.stepIndex).toBe(1);
    // This particular error already names its own fix, so the banner shows the
    // message alone. Pinned because the *reason* matters: if the wording ever
    // drops the "add export pkcs8" clause, a generic hint would reappear and
    // this assertion is what surfaces that.
    expect(err.message).toMatch(/add export/);
    expect(expectedTypeFrom(err.message)).toBeNull();
  });
});

/**
 * The banner used to cry wolf. `cellErrors` validated each cell on its own,
 * which discards the slot table the cells above it build, so every shipped
 * multi-cell template opened under a wall of red — `in @kp: unknown slot` and
 * the cascade behind it — before a single run, and still after a successful
 * one. The fix validates the notebook whole and deals the errors back out.
 *
 * The failure mode to guard against is the *over*-correction: suppressing
 * unknown-slot errors outside the first cell would swap a false positive for a
 * false negative, which is worse. Both directions are pinned here.
 */
describe("cellErrorsForChains", () => {
  const chainsOf = (src) => parseRecipe(src).ast.chains || [];

  it("resolves a slot written by an earlier cell", () => {
    const chains = chainsOf(`genkey ec/p256 | out @kp

@kp | export pkcs8 | pem | out @private`);
    expect(chains).toHaveLength(2);
    expect(cellErrorsForChains(chains)).toEqual([[], []]);
  });

  it("leaves every shipped multi-cell template silent on load", () => {
    // The user-visible claim, checked against the actual shipped text rather
    // than a hand-copied excerpt of it.
    const noisy = [];
    for (const p of PRESETS) {
      const chains = chainsOf(p.recipe);
      if (chains.length < 2) continue;
      const errs = cellErrorsForChains(chains).flat();
      if (errs.length) noisy.push(`${p.id}: ${errs.map((e) => e.message).join(" · ")}`);
    }
    expect(noisy).toEqual([]);
  });

  it("still reports a slot nothing ever writes, in the same words", () => {
    const chains = chainsOf(`genkey ec/p256 | out @kp

@typo | export pkcs8 | pem | out @private`);
    const cells = cellErrorsForChains(chains);
    expect(cells[0]).toEqual([]);
    expect(cells[1][0].message).toBe(
      "in @typo: unknown slot (register it earlier with out @typo)"
    );
    // …and the cascade behind it is still reported too — the point is that the
    // complaint is true, not that it is short.
    expect(cells[1].length).toBeGreaterThan(1);
  });

  it("does not accept a slot written only *below* the cell that reads it", () => {
    // Order is the whole content of "register it earlier".
    const chains = chainsOf(`@kp | export pkcs8 | pem | out @private

genkey ec/p256 | out @kp`);
    expect(cellErrorsForChains(chains)[0][0].message).toMatch(/unknown slot/);
  });

  it("anchors each error to the offending chip in its own cell", () => {
    // stepIndex is a cell-local index into that cell's `steps` — the banner
    // does `steps[e.stepIndex]` to name the chip. A whole-notebook validation
    // numbers steps continuously, so this is where the rebasing is checked.
    const chains = chainsOf(`genkey ec/p256 | out @kp

@kp | export pkcs8 | pem | out @private

@kp | digest`);
    const cells = cellErrorsForChains(chains);
    expect(cells[0]).toEqual([]);
    expect(cells[1]).toEqual([]);
    expect(cells[2]).toHaveLength(1);
    // `digest` is step 1 of cell [2] — global index 8, and 8 would be off the
    // end of a 2-step cell.
    expect(cells[2][0].stepIndex).toBe(1);
    expect(chains[2].steps[cells[2][0].stepIndex].name).toBe("digest");
  });

  it("anchors errors raised inside a foreach body to the stem chip", () => {
    const chains = chainsOf(`random 32 | sss.split threshold=2 shares=3 | out @sh

@sh | inspect | foreach
  - digest`);
    const cells = cellErrorsForChains(chains);
    expect(cells[1]).not.toHaveLength(0);
    expect(chains[1].steps[cells[1][0].stepIndex].name).toBe("foreach");
  });

  it("returns one array per cell, empty ones included", () => {
    const chains = [{ steps: [] }, ...chainsOf("genkey ed25519 | out @k"), { steps: [] }];
    expect(cellErrorsForChains(chains)).toEqual([[], [], []]);
    expect(cellErrorsForChains([])).toEqual([]);
    expect(cellErrorsForChains([{ steps: [] }])).toEqual([[]]);
  });
});

/**
 * `validateRecipe` produced warnings from the start and nothing ever read one —
 * ten `warnings.push` sites, no consumer anywhere in `src/` outside these
 * tests. The §29f notice that `ssh.encode format=private` writes a usable
 * private key to the page was among them, including the hour someone spent
 * gating it on `passphrase=`.
 *
 * Making them visible required giving them a `stepIndex`; they used to be bare
 * strings. That is what these pin: the anchor exists, it survives the
 * whole-notebook rebasing, and it lands on the cell that earned it rather than
 * piling onto cell 1 — which is exactly what an unanchored string would have
 * done.
 */
describe("cellWarningsForChains", () => {
  const chainsOf = (src) => parseRecipe(src).ast.chains || [];
  const SSH_BARE = /emits an unencrypted private key/;

  it("surfaces the §29f unencrypted-private-key warning at all", () => {
    const cells = cellWarningsForChains(
      chainsOf("genkey ed25519 | ssh.encode format=private | out @k")
    );
    expect(cells[0].some((w) => SSH_BARE.test(w.message))).toBe(true);
  });

  it("clears it when passphrase= actually encrypts the block", () => {
    // The gate is the whole reason the message is trustworthy: it must not
    // claim "unencrypted" about a file that is encrypted.
    const cells = cellWarningsForChains(
      chainsOf("genkey ed25519 | ssh.encode format=private passphrase=@pw | out @k")
    );
    expect(cells.flat().some((w) => SSH_BARE.test(w.message))).toBe(false);
  });

  it("lands the warning on the cell that earned it, not the first one", () => {
    // The failure an unanchored string guarantees. `ssh.encode` is in cell 2.
    const chains = chainsOf(`genkey ed25519 | out @k

@k | ssh.encode format=private | out @priv`);
    const cells = cellWarningsForChains(chains);
    expect(cells[0].some((w) => SSH_BARE.test(w.message))).toBe(false);
    const hit = cells[1].find((w) => SSH_BARE.test(w.message));
    expect(hit).toBeTruthy();
    // …and on the offending chip within that cell, so the banner can name it.
    expect(chains[1].steps[hit.stepIndex].name).toBe("ssh.encode");
  });

  it("anchors the trailing-value warning to the last step", () => {
    const chains = chainsOf(`genkey ec/p256 | out @kp

@kp | export scalar`);
    const cells = cellWarningsForChains(chains);
    const hit = cells[1].find((w) => /Trailing /i.test(w.message));
    expect(hit).toBeTruthy();
    expect(chains[1].steps[hit.stepIndex].name).toBe("export");
  });

  it("stays clear of errors — a warning never blocks the run", () => {
    // `validation.ok` is errors-only, and a warning-only recipe still runs.
    const src = "genkey ed25519 | ssh.encode format=private | out @k";
    const { validation } = compileRecipe(src);
    expect(validation.ok).toBe(true);
    expect(validation.warnings.length).toBeGreaterThan(0);
    expect(cellErrorsForChains(chainsOf(src))).toEqual([[]]);
  });

  it("leaves every shipped template free of warnings it cannot act on", () => {
    // Not an assertion that presets are warning-free — several legitimately
    // warn. This pins that whatever they raise is anchored, so none of it can
    // land unplaced on cell 1 the way a bare string would have.
    for (const p of PRESETS) {
      const chains = chainsOf(p.recipe);
      cellWarningsForChains(chains).forEach((cell, ci) => {
        for (const w of cell) {
          expect(w.stepIndex, `${p.id} cell ${ci}: ${w.message}`).toBeGreaterThanOrEqual(0);
          expect(chains[ci].steps[w.stepIndex], `${p.id}: ${w.message}`).toBeTruthy();
        }
      });
    }
  });

  it("returns one array per cell, like the error side", () => {
    expect(cellWarningsForChains([])).toEqual([]);
    expect(cellWarningsForChains([{ steps: [] }])).toEqual([[]]);
  });
});

/**
 * The runtime half of the same banner.
 *
 * A cell that failed at run time used to record only *that* it failed:
 * `setCellStatus("error")`, and the reason re-thrown to the run bar, ~130px
 * above the cell and outside it. `rtc-live-diagnostics` was the worked case —
 * three empty cells under one red line. These rows now ride the compile
 * channel's component, which is what this function makes.
 */
describe("cellErrorRows", () => {
  const steps = [{ name: "rtc.state" }, { name: "out" }];

  it("passes compile errors straight through when nothing ran", () => {
    const compile = [{ message: "boom", stepIndex: 1 }];
    expect(cellErrorRows(compile, null, steps)).toBe(compile);
    expect(cellErrorRows([], undefined, steps)).toEqual([]);
  });

  it("leads with the run failure and keeps its wording byte for byte", () => {
    // `requireLinks` spends its whole message naming both ways to get a
    // connection. That sentence is the reason this row exists; it is copied,
    // never trimmed to fit.
    const message =
      "rtc.state: no live connection — open one with peer.offer / peer.answer, or a mesh with quorum.offer / quorum.join";
    const rows = cellErrorRows([{ message: "later", stepIndex: 1 }], {
      message,
      stepIndex: 0,
      stepName: "rtc.state",
    }, steps);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toEqual({ message, stepIndex: 0, when: "run" });
    expect(rows[1].when).toBeUndefined();
  });

  it("keeps the chip only while that chip is still the step that threw", () => {
    // A compile error is recomputed on every keystroke; this one is a fact
    // about a past run, and chips renumber when the cell is edited. Insert a
    // step above the failure and the anchor no longer matches by name.
    const edited = [{ name: "input" }, { name: "rtc.state" }, { name: "out" }];
    const err = { message: "no live connection", stepIndex: 0, stepName: "rtc.state" };
    expect(cellErrorRows([], err, steps)[0].stepIndex).toBe(0);
    // The message survives; only the anchor is dropped. Losing the sentence
    // would be the original defect returning through the back door.
    const moved = cellErrorRows([], err, edited)[0];
    expect(moved.stepIndex).toBe(-1);
    expect(moved.message).toBe("no live connection");
  });

  it("renders unanchored rather than guessing when there is no live chip", () => {
    for (const err of [
      { message: "x", stepIndex: -1, stepName: "rtc.state" },
      { message: "x", stepIndex: 99, stepName: "rtc.state" },
      { message: "x", stepIndex: 1, stepName: "rtc.state" },
    ]) {
      expect(cellErrorRows([], err, steps)[0].stepIndex, JSON.stringify(err)).toBe(-1);
    }
  });

  it("anchors on the index alone when the engine named no op", () => {
    // `in @nope` resolves its slot before dispatch, so it never reaches the
    // attribution point and carries no name — but it does carry an index, and
    // that index is the only word on the subject.
    const rows = cellErrorRows(
      [],
      { message: "in @nope: unknown slot", stepIndex: 0, stepName: "" },
      [{ name: "in" }]
    );
    expect(rows[0].stepIndex).toBe(0);
  });

  it("keeps the chip when the op that threw is nested inside it", () => {
    // The engine names the innermost thrower and anchors to the stem it hangs
    // off — the same rule `validateRecipe` uses for a nested complaint. A flat
    // name comparison would refuse the anchor on every foreach and tee, which
    // is most of the failures worth pointing at.
    const nested = [
      { name: "random" },
      { name: "encode" },
      { name: "tee", body: [{ name: "pem" }] },
    ];
    expect(
      cellErrorRows([], { message: "pem expects bytes", stepIndex: 2, stepName: "pem" }, nested)[0]
        .stepIndex
    ).toBe(2);
    const branched = [
      { name: "foreach", branches: [{ body: [{ name: "sss.combine" }] }] },
    ];
    expect(
      cellErrorRows([], { message: "boom", stepIndex: 0, stepName: "sss.combine" }, branched)[0]
        .stepIndex
    ).toBe(0);
  });
});

describe("warningDismissKey", () => {
  it("is per cell and per message", () => {
    const w = { message: "trailing bytes", stepIndex: 1 };
    expect(warningDismissKey(0, w)).not.toBe(warningDismissKey(1, w));
    expect(warningDismissKey(0, w)).not.toBe(
      warningDismissKey(0, { message: "other", stepIndex: 1 })
    );
  });

  it("survives renumbering, so adding a step above does not un-dismiss", () => {
    // stepIndex deliberately absent from the key: a complaint you have read and
    // accepted should not return because a chip moved.
    expect(warningDismissKey(2, { message: "same", stepIndex: 0 })).toBe(
      warningDismissKey(2, { message: "same", stepIndex: 7 })
    );
  });
});

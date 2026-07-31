/**
 * Guided key ceremony — the stage machine and the recipes behind it.
 *
 * The toolkit already has every primitive a ceremony needs (`sss.split`,
 * `blip39`, `qr`, `run.receipt`, share cards). What it did not have was an
 * order: split, *prove the shares recombine*, print, sign a receipt — with the
 * proof step done before anyone leaves the room and without the secret being
 * shown a second time.
 *
 * Two decisions are load-bearing and live here rather than in the Sheet:
 *
 * 1. **The master is never `out`.** A tee branch digests it in place, so the
 *    expected digest becomes an ordinary non-sensitive tile while the 32 bytes
 *    themselves never reach a revealable artifact. Writing `out @master` would
 *    have been the obvious way to get a value to compare against later, and it
 *    would have put the secret one click from the screen for the rest of the
 *    session.
 *
 * 2. **Verification compares digests, not values.** The recombine cell hashes
 *    what it recovered and prints the hex; the UI compares that string to the
 *    expected one. A ceremony that verified by showing the recovered secret
 *    would be asking the room to eyeball the thing it just finished protecting.
 *
 * The recipes are ordinary notebook cells — the Sheet appends them and runs
 * them through `useNotebook`, so anything done here is reproducible by hand,
 * inspectable in Source view, and shareable as recipe text.
 *
 * @module lib/toolkit/ceremony
 */

/** @typedef {"setup"|"split"|"verify"|"cards"|"receipt"} CeremonyStageId */

/**
 * @typedef {object} CeremonyStage
 * @property {CeremonyStageId} id
 * @property {string} title
 * @property {string} blurb
 * @property {boolean} runsCells  whether entering this stage executes notebook cells
 */

/** @type {readonly CeremonyStage[]} */
export const CEREMONY_STAGES = Object.freeze([
  {
    id: "setup",
    title: "Choose the quorum",
    blurb:
      "How many shares to make, and how many of them must come back together to recover the secret.",
    runsCells: false,
  },
  {
    id: "split",
    title: "Split the secret",
    blurb:
      "Draw 32 fresh random bytes and split them into verifiable shares, each encoded as a BLIP39 mnemonic with a QR. The published commitments let a holder check their share is genuine without any of the others.",
    runsCells: true,
  },
  {
    id: "verify",
    title: "Prove the shares work",
    blurb:
      "Check each share against the commitments, then recombine and compare digests with the original — before anyone leaves the room, and without showing the secret again.",
    runsCells: true,
  },
  {
    id: "cards",
    title: "Print the cards",
    blurb: "One card per share holder. This is the step that puts a secret on paper.",
    runsCells: false,
  },
  {
    id: "receipt",
    title: "Sign the receipt",
    blurb:
      "A signed record of what this ceremony did — recipe, timestamps, and digests of every output. No secrets in it.",
    runsCells: true,
  },
]);

/** @param {CeremonyStageId} id */
export function stageIndex(id) {
  return CEREMONY_STAGES.findIndex((s) => s.id === id);
}

/**
 * @param {CeremonyStageId} id
 * @returns {CeremonyStageId|null}
 */
export function nextStage(id) {
  const i = stageIndex(id);
  if (i < 0 || i >= CEREMONY_STAGES.length - 1) return null;
  return CEREMONY_STAGES[i + 1].id;
}

/**
 * @param {CeremonyStageId} id
 * @returns {CeremonyStageId|null}
 */
export function prevStage(id) {
  const i = stageIndex(id);
  if (i <= 0) return null;
  return CEREMONY_STAGES[i - 1].id;
}

/**
 * @typedef {object} CeremonyParams
 * @property {number} threshold  shares required to recover (K)
 * @property {number} shares     shares produced (N)
 * @property {string} [label]    ceremony / room name
 * @property {boolean} [qr]      emit a QR beside each mnemonic
 * @property {string} [signWith] vault fingerprint slot to sign the receipt with
 */

/**
 * Why a proposed quorum will not work, in the words the Sheet shows.
 *
 * `threshold > shares` is the one that actually happens: someone sets 3-of-5,
 * then lowers the share count and forgets. The registry's own bounds (1..16)
 * are repeated rather than imported because this validates *intent* before a
 * recipe exists, and a number typed into a stepper should be rejected at the
 * stepper.
 *
 * @param {Partial<CeremonyParams>} params
 * @returns {string[]}
 */
export function ceremonyIssues(params = {}) {
  const threshold = Number(params.threshold);
  const shares = Number(params.shares);
  /** @type {string[]} */
  const issues = [];
  if (!Number.isInteger(shares) || shares < 2 || shares > 16) {
    issues.push("Make between 2 and 16 shares.");
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > 16) {
    issues.push("The recovery threshold must be between 1 and 16.");
  }
  if (
    Number.isInteger(threshold) &&
    Number.isInteger(shares) &&
    threshold > shares
  ) {
    issues.push(
      `${threshold} shares cannot be required when only ${shares} exist — lower the threshold or make more shares.`
    );
  }
  if (threshold === 1 && shares >= 2) {
    issues.push(
      "A threshold of 1 means any single card recovers the secret on its own — that is a copy, not a quorum."
    );
  }
  return issues;
}

/**
 * The split cell.
 *
 * The tee branch is the important part: it digests the master *in place* so the
 * expected digest is available to the verify step without the master itself
 * ever being written to an `out` tile.
 *
 * @param {CeremonyParams} params
 * @returns {string}
 */
export function splitRecipe(params) {
  const k = Number(params.threshold) || 2;
  const n = Number(params.shares) || 3;
  const body = params.qr === false ? "  - out @share" : "  - out @share | qr";
  return [
    "random 32 | tee",
    "  - digest | encode hex | out @expected",
    // Verifiable rather than plain Shamir: each custodian can check the share
    // they were handed against the published commitments, at the table,
    // instead of discovering a bad one when recovery is attempted and the
    // room is long gone. `vss.commitments` is a second tee branch because the
    // commitments are *public* and travel separately from the mnemonics —
    // words carry no commitments, which is the real-world model, not a gap.
    `| vss.split threshold=${k} shares=${n} | tee`,
    "  - vss.commitments | out @commitments",
    "| blip39 | foreach",
    body,
  ].join("\n");
}

/**
 * The verification cell — recombine and hash, never reveal.
 *
 * The `shares` source runs with an empty paste panel and falls back to the
 * indexed share slots the split cell's `foreach` just registered, so the room
 * does not have to type mnemonics back in to prove they work.
 *
 * @returns {string}
 */
export function verifyRecipe() {
  // `vss.verify` before combining is the point of using VSS at all: without
  // it, recombining a corrupted set returns a *different* secret rather than
  // an error, and the digest comparison would report a mismatch without
  // saying which share was wrong. With it, the bad share is named.
  return [
    "shares | blip39.decode",
    "| vss.verify commitments=@commitments",
    "| vss.combine | digest | encode hex | out @recovered",
  ].join(" ");
}

/**
 * The receipt cell. Signed when the ceremony picked a key, plain otherwise —
 * an unsigned receipt is still a useful record, and refusing to make one
 * because no vault key is unlocked would fail the ceremony at its last step.
 *
 * @param {CeremonyParams} params
 * @returns {string}
 */
export function receiptRecipe(params = /** @type {*} */ ({})) {
  const label = String(params.label || "").trim();
  const quoted = label ? ` ${JSON.stringify(label)}` : "";
  const key = String(params.signWith || "").trim();
  if (key) {
    return `run.receipt${quoted} | gpg.sign key=@${key.replace(/^@/, "")} | out @receipt`;
  }
  return `run.receipt${quoted} | out @receipt`;
}

/**
 * Every cell the ceremony will add, in order, with the stage that owns it.
 *
 * The Sheet appends these one stage at a time rather than all at once, because
 * `runFrom(i)` runs every cell from `i` onward — a notebook pre-loaded with the
 * receipt cell would mint a receipt the moment the verify step ran.
 *
 * @param {CeremonyParams} params
 * @returns {{ stage: CeremonyStageId, recipe: string }[]}
 */
export function ceremonyCells(params) {
  return [
    { stage: "split", recipe: splitRecipe(params) },
    { stage: "verify", recipe: verifyRecipe() },
    { stage: "receipt", recipe: receiptRecipe(params) },
  ];
}

/**
 * A title for the notebook the ceremony builds.
 * @param {CeremonyParams} params
 */
export function ceremonyTitle(params) {
  const label = String(params?.label || "").trim();
  const k = Number(params?.threshold) || 2;
  const n = Number(params?.shares) || 3;
  return `${label || "Key ceremony"} — ${k}-of-${n}`;
}

/**
 * @typedef {object} VerificationResult
 * @property {"pending"|"match"|"mismatch"|"incomplete"} status
 * @property {string} message
 * @property {string} expected
 * @property {string} recovered
 */

/**
 * Compare the two digest tiles the ceremony produced.
 *
 * Takes the hex strings, not the values — by the time anything reaches here the
 * secret has already been reduced to a SHA-256 digest by the recipe, so there
 * is nothing sensitive left to mishandle.
 *
 * @param {string} expected  hex digest of the original master
 * @param {string} recovered hex digest of the recombined master
 * @returns {VerificationResult}
 */
export function verificationResult(expected, recovered) {
  const a = String(expected || "").trim().toLowerCase();
  const b = String(recovered || "").trim().toLowerCase();
  if (!a || !b) {
    return {
      status: a || b ? "incomplete" : "pending",
      message: a
        ? "Waiting for the recombined digest."
        : "Run the split step first.",
      expected: a,
      recovered: b,
    };
  }
  if (!/^[0-9a-f]{64}$/.test(a) || !/^[0-9a-f]{64}$/.test(b)) {
    return {
      status: "incomplete",
      message: "One of the digests is not a SHA-256 hex string — re-run the cells.",
      expected: a,
      recovered: b,
    };
  }
  // Length is already known equal; compare without an early exit anyway.
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0
    ? {
        status: "match",
        message:
          "The shares recombine to the original secret. Digests match; neither value was shown.",
        expected: a,
        recovered: b,
      }
    : {
        status: "mismatch",
        message:
          "The recombined secret is NOT the one that was split. Do not distribute these cards — re-run the ceremony.",
        expected: a,
        recovered: b,
      };
}

/**
 * Pull a named `out` tile's text out of a cell's outputs.
 * @param {{ label?: string, filename?: string, content?: string }[]} outputs
 * @param {string} slot  slot label without `@`
 * @returns {string}
 */
export function tileForSlot(outputs, slot) {
  const want = String(slot || "").replace(/^@/, "").toLowerCase();
  for (const a of outputs || []) {
    const label = String(a.label || "").toLowerCase();
    const file = String(a.filename || "").toLowerCase();
    if (label === want || label === `@${want}` || file === `${want}.txt`) {
      return String(a.content || "").trim();
    }
  }
  // Fall back to a looser contains-match: `out @expected` labels its tile from
  // the slot name, but the exact spelling has changed before and a ceremony
  // that silently reports "pending" because of a label tweak is worse than one
  // that matches a little loosely.
  for (const a of outputs || []) {
    if (String(a.label || "").toLowerCase().includes(want)) {
      return String(a.content || "").trim();
    }
  }
  return "";
}

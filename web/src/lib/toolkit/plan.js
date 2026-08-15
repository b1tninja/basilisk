/**
 * Run plans — who runs which cell, worked out before anything runs.
 *
 * A manifest says *what* a run will do. This says *where*. Both are answered
 * from a compiled recipe and nothing else, which is the property that makes
 * either one worth having: a plan you can only obtain by starting a run is not
 * a pre-flight, it is a post-mortem with better timing.
 *
 * ## The rule, and why it is a rule rather than a scheduler
 *
 * **A cell runs where its private input already lives.** Bob's cell needs
 * Bob's key, so it runs on Bob — not because a scheduler weighed anything, but
 * because the alternative is moving Bob's key, and moving it is the failure
 * this whole design exists to prevent. So placement is *derived from data
 * dependencies*, and the interesting output is not the assignment. It is that
 * most assignments have exactly one legal answer, and the few that do not are
 * either a question for the author or a protocol that cannot exist.
 *
 * Written as a decision procedure over one cell:
 *
 * 1. Collect the slots the cell consumes. `ParamSpec.slot` says which params
 *    can hold a `$ref` and `boundAsSlotRef` (recipe.js's, imported, not
 *    re-spelled) says which ones do. Before `d532a4c` this was a sigil sniff,
 *    and a sniff cannot see `gpg.encrypt to=cek` — so an honest version of
 *    this pass could not have been written.
 * 2. For each, find the cell that wrote it and read that cell's header. A slot
 *    written under `@alice` and not published is **alice's private value**. A
 *    slot from a `publish` cell, or from a cell with no header at all, is not
 *    private to anyone.
 * 3. Count the distinct owners of the private ones.
 *    - **0** — nothing private is read, so everyone can run it and compare
 *      digests. *Witnessed.*
 *    - **1** — exactly one machine can run it. *Forced.* No header needed, and
 *      a header that disagrees is an error rather than an override.
 *    - **2 or more** — no placement exists. This is the refusal below.
 *
 * ## The refusal that matters
 *
 * A single pipeline that needs two different owners' secrets is not a hard
 * scheduling problem. It is a protocol that requires somebody to hand over a
 * private key, and the useful thing to say about it is exactly that. It is
 * caught here, at compile time, on text — before a ceremony deals a share and
 * halts halfway with a value already out of its owner's hands.
 *
 * ## The roster, and the binding this module owns
 *
 * **A recipe names peers by fingerprint.** `@83421F2C…` — the whole of it, 40
 * characters for v4 and 64 for v6, never a part. This module's header used to
 * state the opposite rule at length: a peer was "a *label*, deliberately never
 * a fingerprint", because recipe text travels in a `#r=` link and the room is a
 * digest of the audience, so a fingerprint in shared text hands a stranger the
 * room. That reasoning was sound and the conclusion drawn from it was an
 * invented label layer — `@peer1`, `@peer2`, positions in the sorted audience —
 * which told a reader nothing about who would run a cell and moved under them
 * every time the room changed size.
 *
 * The disclosure is real and is now *stated* rather than designed around: a
 * placed notebook's link carries its audience's fingerprints, and the Share
 * sheet says so whenever the notebook names any. What was bought with it is
 * that a peer means exactly one key, everywhere, with nothing carried between
 * the two ends to make it so.
 *
 * **This is still the holder of the binding.** The roster is
 * `{ peer: fingerprint }` — the same shape `peersDigest` hashes, so the thing
 * planned against and the thing committed to are one object — and it is now
 * identity-mapped, which is what makes `peersSha` agree between two browsers
 * *by construction*. `labelForFingerprint` is the crossing and is the only
 * crossing; it is trivial now and is kept because a session speaks fingerprints
 * and a plan speaks peers, and one call at one layer is what stops a second,
 * cleverer crossing appearing somewhere else.
 *
 * `attesterLabels` stood beside it and is gone. It crossed a whole *set* of
 * fingerprints at once, and the only input its own comment named was
 * `NotebookSession.attestersOf()`, which is gone too: attestation coverage is
 * counted per attestation now, from the documents the roster carries, and that
 * wants the one-at-a-time crossing. Its `unknown` half could not fire either —
 * a roster is the room's own audience and a session's peers are that audience
 * minus self, so there was never a fingerprint here for it to fail to name.
 *
 * A recipe naming a peer the roster does not have is **refused**, and that is
 * the case a notebook written before this change lands in: `@peer1` still
 * parses, still compiles, and is refused as `unknown-peer` naming exactly what
 * is true — no key in this room answers to it. It is not a warning: a cell
 * addressed to a peer nobody answers to never runs, and a plan that says
 * otherwise is a plan that hangs. With *no* roster the plan is `bound: false`:
 * placement is still computed, in peer space, so the structural refusals bite
 * while authoring, and nothing is claimed about who is in the room.
 *
 * ## What does not change
 *
 * A recipe with no `@peer` header anywhere plans as `solo`: every cell runs
 * here, no refusals, no questions. That is today's behaviour stated as a plan
 * rather than reimplemented as one, and `run-plan-differential.test.js` holds
 * it against every preset, the whole registry sweep, and every
 * `docs/RECIPE.md` fence.
 *
 * @module lib/toolkit/plan
 */

import { cellKind } from "./manifest.js";
import { mismatchLog } from "./receipt.js";
import {
  PEER_SIGIL,
  PEER_WILDCARD,
  PUBLISH_STEP,
  SELECT_PUBLIC,
  SLOT_SIGIL,
  normalizePeerRef,
  peerKeyIdError,
  peerLooksLikeKeyId,
  slotLabelKey,
} from "./recipe-parse.js";
import {
  boundAsSlotRef,
  chainHeaderText,
  outSlotLabels,
  publishedSlots,
  recipeChains,
} from "./recipe.js";
import { getStep, stepEntropy } from "./registry.js";
import {
  artifactMetaFromType,
  formatType,
  hasKeyHalves,
  walkPipelineTypes,
} from "./types.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";
import { formatFingerprint } from "../utils.js";

/**
 * Why a cell is where it is. Every cell carries one, and it is the field that
 * makes a plan interrogable rather than merely correct.
 *
 * - `solo` — the notebook names no peers. Nothing was inferred because there
 *   was nothing to infer between.
 * - `secret-locality` — a private input pinned it. The author had no choice
 *   and neither did this pass.
 * - `header` — the author chose, and no private input contradicted them.
 * - `no-private-input` — the cell reads nothing anyone owns, so everyone runs
 *   it and the digests are the check.
 * - `rendezvous` — `@*`. Everyone, together.
 * - `empty` — the cell has no steps. There is nothing to place, and it is here
 *   because it holds the number the notebook shows for it.
 * @typedef {"empty"|"solo"|"secret-locality"|"header"|"no-private-input"|"rendezvous"} PlacementBasis
 */

/**
 * One slot a cell reads, and what is known about it before the run.
 * @typedef {object} ConsumedSlot
 * @property {string} label    slot label, no sigil
 * @property {string} via      `in`, or `step param=`
 * @property {number} from     index of the cell that wrote it, -1 if none does
 * @property {string} owner    peer label holding it privately, "" if nobody
 * @property {boolean} private nobody but `owner` has this value
 * @property {string} type     `formatType` of the slot, "" when untypeable
 * @property {string[]} slotOf the types the param declared it would accept
 */

/**
 * @typedef {object} PlannedCell
 * @property {number} index
 * @property {string} peer     "" everyone · `*` rendezvous · a peer label
 * @property {"witnessed"|"placed"|"rendezvous"} kind  `cellKind`'s reading
 * @property {boolean} declared  a header said so
 * @property {boolean} forced    the data said so, header or not
 * @property {PlacementBasis} basis
 * @property {string} why        one sentence, always present
 * @property {string[]} runsOn   resolved labels; empty means every participant
 * @property {boolean} mine      `me` runs this cell
 * @property {string[]} publishes  what leaves: one label per `out` a `publish`
 *   step stands behind, in source order, and empty when nothing leaves. There
 *   is no boolean beside it. There was, and it was exactly
 *   `publishes.length > 0` — a summary that could only ever agree with the
 *   list or contradict it, and a mutation setting it to `false` outright was
 *   caught by nothing.
 * @property {string[]} produces slot labels this cell writes
 * @property {ConsumedSlot[]} consumes
 * @property {number} [start]    header anchor, for a complaint about placement
 * @property {number} [end]
 */

/**
 * A cell this run will not perform, and why not.
 *
 * The first four fields are `mismatchLog()`'s and are produced by it — the
 * same `{path, field, expected, actual}` a receipt comparison and a manifest
 * check report in. "The plan and the recipe disagree, here" is the same idea
 * as "the run and its description disagree, here", and one idea gets one
 * spelling.
 * @typedef {object} PlanRefusal
 * @property {string} path      `cell 5`
 * @property {string} field     `peer` · `publish` · `roster` · `entropy` · `recipe`
 * @property {string} expected
 * @property {string} actual
 * @property {number} cell
 * @property {"two-owners"|"unknown-peer"|"publish-secret"|"keying-in-mirror"|"unreadable"|"uncompiled"|"scatter-count"} reason
 * @property {string} message   the sentence a person reads, naming the remedy
 * @property {number} [start]
 * @property {number} [end]
 */

/**
 * Something this pass cannot decide from the text, phrased as a question.
 *
 * Distinct from a refusal on purpose: a refusal says *this cannot run*, an ask
 * says *this pass does not know, and guessing would be worse than asking*. The
 * design expected ambiguity to come from two peers both being able to run a
 * cell; it does not, because the owner count is 0, 1 or many and the many case
 * is a refusal. It comes from vaults and from unplaced key generation, neither
 * of which is a dataflow fact.
 * @typedef {object} PlanAsk
 * @property {number} cell
 * @property {"vault-locality"|"keying-unplaced"|"publish-untyped"|"who-am-i"
 *   |"seal-outside-room"} reason
 * @property {string} question
 * @property {string[]} choices  peer labels that would answer it, when known
 * @property {number} [start]
 * @property {number} [end]
 */

/**
 * A thing `me` cannot start until somebody else finishes.
 * @typedef {object} PlanWait
 * @property {number} cell   my cell, blocked
 * @property {number} on     the cell it waits for
 * @property {string} peer   who runs `on` — `*` for a rendezvous
 * @property {string} slot   the published slot carrying the value, "" for a barrier
 * @property {"published-slot"|"rendezvous"} reason
 */

/**
 * @typedef {object} RunPlan
 * @property {boolean} ok        no refusals
 * @property {boolean} bound     a roster was supplied, so labels mean people
 * @property {"solo"|"mirrored"|"placed"} play
 * @property {string} me         this peer's label, "" when unbound or unnamed
 * @property {string[]} peers    labels the recipe names, sorted
 * @property {string[]} unknownPeers  named by the recipe, absent from the roster
 * @property {PlannedCell[]} cells
 * @property {PlanRefusal[]} refusals
 * @property {PlanAsk[]} asks
 * @property {PlanWait[]} waits
 * @property {{ solo: number, forced: number, chosen: number, witnessed: number,
 *   rendezvous: number, empty: number }} counts  every cell falls in exactly
 *   one bucket, so the six sum to `cells.length` — `empty` is the bucket that
 *   keeps that true rather than the one that hides a blank cell
 */

/**
 * Artifact roles that may leave the machine that made them.
 *
 * A closed list of what *may* publish rather than of what may not, for the
 * reason `entropy` reads `keying` when undeclared and `slot` reads `false`:
 * the cost of forgetting has to be a refusal. A role added next year is
 * unpublishable until somebody argues it is publishable, and the argument is
 * an edit here.
 *
 * `key` is absent although it sounds harmless. `artifactMetaFromType` uses it
 * for a handle *whose half is unknown* — its own comment says so — and the
 * half is the entire question. A public half arrives here tagged `public`,
 * which is the escape hatch below and the only one.
 * @type {ReadonlySet<string>}
 */
const PUBLISHABLE_ROLES = new Set([
  "text",
  "public-key",
  "ssh-public",
  "ciphertext",
  "envelope",
  "recipients",
  "sshsig",
  "token",
  "netvalue",
  "diagnostic",
  "inspect",
  "receipt",
  "qr",
]);

/**
 * Toolbox whose ops reach the vault of whoever runs them.
 *
 * Read as a toolbox rather than as a list of op names, because the toolbox is
 * the declaration and a name list is a copy of one. `recipeNeedsMainThread`
 * hand-writes four names for a different question (which thread), and that
 * list has already drifted once.
 */
const VAULT_TOOLBOX = "agent";

/**
 * The roster: peer → fingerprint, canonicalised.
 *
 * Refuses a *partial* key written as a peer with the compiler's own copy. A
 * roster is assembled from a session and a session speaks fingerprints, so this
 * is the exact place a short key id would be dropped into the peer column by a
 * caller in a hurry — and a suffix of a fingerprint names more than one key, so
 * a roster keyed by one binds nothing.
 *
 * A *whole* fingerprint is no longer refused: it is the spelling this module
 * expects on both sides.
 *
 * @param {Record<string, string>|null|undefined} roster
 * @returns {{ labels: string[], byLabel: Map<string, string>, byFpr: Map<string, string> }}
 */
export function normalizeRoster(roster) {
  /** @type {Map<string, string>} */
  const byLabel = new Map();
  /** @type {Map<string, string>} */
  const byFpr = new Map();
  for (const [rawLabel, rawFpr] of Object.entries(roster || {})) {
    const norm = normalizePeerRef(String(rawLabel ?? ""));
    if (!norm.ok) throw new Error(`roster: ${norm.error}`);
    if (norm.peer === PEER_WILDCARD) {
      throw new Error(
        `roster: \`${PEER_SIGIL}${PEER_WILDCARD}\` is every participant, not a ` +
          "participant — it cannot be bound to a fingerprint"
      );
    }
    if (peerLooksLikeKeyId(norm.peer)) {
      throw new Error(`roster: ${peerKeyIdError(norm.peer)}`);
    }
    const fpr = normalizeFingerprintInput(String(rawFpr ?? ""));
    if (!fpr) {
      throw new Error(
        `roster: \`${PEER_SIGIL}${norm.peer}\` has no fingerprint — a roster is ` +
          "the label→fingerprint binding, so a label with nothing behind it " +
          "binds nothing"
      );
    }
    byLabel.set(norm.peer, fpr);
    byFpr.set(fpr, norm.peer);
  }
  return { labels: [...byLabel.keys()].sort(), byLabel, byFpr };
}

/**
 * Which label does this fingerprint answer to?
 *
 * The direction the session needs and cannot take itself. Returns "" for a
 * fingerprint the roster does not carry, which is a fact rather than an error:
 * a peer can be in the room and absent from a recipe's cast.
 *
 * @param {Record<string, string>|null|undefined} roster
 * @param {string} fingerprint
 * @returns {string}
 */
export function labelForFingerprint(roster, fingerprint) {
  const { byFpr } = normalizeRoster(roster);
  return byFpr.get(normalizeFingerprintInput(String(fingerprint ?? ""))) || "";
}

/**
 * Every slot a cell reads, with the declaration that made it a read.
 *
 * Every read goes through a declared param — `in $x` included, because `in`'s
 * `ref` is `slot: "required"` and there is no reason for this pass to know
 * that `in` is special when the registry already says what it is. `out $x`'s
 * `name` is excluded: there `$x` is the binding occurrence, which is the same
 * exclusion `validateStepSlotParams` makes and for the same reason.
 *
 * A positional `in 2` is an index into the *run's* slot table. Nothing in a
 * recipe says which cell fills index 2, so it names no dependency here and is
 * skipped rather than guessed at.
 *
 * @param {import("./recipe.js").RecipeStep[]} steps
 * @param {(row: { label: string, via: string, slotOf: string[] }) => void} add
 */
function collectConsumed(steps, add) {
  for (const step of steps || []) {
    const spec = getStep(step.name);
    for (const p of spec?.params || []) {
      if (step.name === "out" && p.name === "name") continue;
      const raw = String(step.params?.[p.name] ?? "").trim();
      if (!raw) continue;
      if (/^\d+$/.test(raw)) continue;
      if (!boundAsSlotRef(p, step.name, raw)) continue;
      const label = slotLabelKey(raw.startsWith(SLOT_SIGIL) ? raw : `${SLOT_SIGIL}${raw}`);
      if (!label) continue;
      add({
        label,
        via: p.positional ? step.name : `${step.name} ${p.name}=`,
        slotOf: p.slotOf ? (Array.isArray(p.slotOf) ? [...p.slotOf] : [p.slotOf]) : [],
      });
    }
    collectConsumed(step.body || [], add);
    for (const br of step.branches || []) collectConsumed(br.body || [], add);
  }
}

/**
 * The chains a plan calls cells, in the order it numbers them.
 *
 * **This is the only definition of "cell index" in the placement stack, and it
 * is the notebook's own: a cell's index is its position in the chain list,
 * counting every chain including the empty ones.**
 *
 * That is not an arbitrary pick between two defensible numberings. It is the
 * one a person can see. `ToolkitShell` renders the notebook as
 * `nb.chains.map((chain, i) => …)` and labels each cell `[i]`; the kernel keys
 * outputs, statuses and its run log by the same `i`; `dealByCell` attributes
 * compile errors by it. So `Cell 1 reads $seed, which cell 0 writes on @mara`
 * names the cells the reader is looking at. A number in an error that does not
 * match the number on screen is worse than no number.
 *
 * An empty chain is therefore a **no-op cell**, not a gap: it appears here, in
 * `planRun`'s cells, in the manifest and in the gate's bookkeeping, and it
 * performs nothing. Filtering it in one of those places and not another is what
 * put "cell 2" out of step three times running.
 *
 * @param {*} compiled  a `compileRecipe` result, the AST from one, or the
 *   notebook's chain array itself
 * @returns {import("./recipe.js").RecipeChain[]}
 */
export function planChains(compiled) {
  const source = /** @type {*} */ (compiled);
  const ast = source?.ast !== undefined ? source.ast : source;
  return recipeChains(ast);
}

/**
 * What is in every labeled slot this notebook writes.
 *
 * `walkPipelineTypes`' own map, filled by the walk itself as it passes each
 * `out` — one shared map across all the chains, so a later cell reading `$kpA`
 * sees the type the earlier cell registered. A second type walk would be a
 * second answer to "what is in this slot", which is why this is exported and
 * `slotOrigins` calls it rather than keeping a private copy.
 *
 * @param {import("./recipe.js").RecipeChain[]} chains
 * @returns {Map<string, import("./types.js").RefinedType>}
 */
function typesOf(chains) {
  return typesAndEdgesOf(chains).types;
}

/**
 * `typesOf`, keeping each chain's step edges as well.
 *
 * The edges carry the one plan-time fact the slot map cannot: the refined
 * type *entering* a step. `planRun` reads a `scatter` edge's input `length` —
 * the share count `sss.split K/N` stamped and `blip39` carried — to compare
 * against the roster before anything runs. One walk, both answers, so the
 * count checked and the types placed against cannot come from two walks that
 * disagree.
 *
 * @param {import("./recipe.js").RecipeChain[]} chains
 * @returns {{ types: Map<string, import("./types.js").RefinedType>,
 *   edgesByChain: Array<Array<{ name: string, input: import("./types.js").RefinedType }>> }}
 */
function typesAndEdgesOf(chains) {
  /** @type {Map<string, import("./types.js").RefinedType>} */
  const types = new Map();
  /** @type {Array<Array<{ name: string, input: import("./types.js").RefinedType }>>} */
  const edgesByChain = [];
  for (const chain of chains) {
    try {
      edgesByChain.push(
        walkPipelineTypes(chain?.steps || [], { getStep }, types).edges
      );
    } catch (_) {
      // A chain the type walk cannot finish still has an owner for whatever it
      // writes. Placement is a question about headers and slot names, and it
      // must not become unanswerable because a type could not be resolved.
      edgesByChain.push([]);
    }
  }
  return { types, edgesByChain };
}

/**
 * What is in every slot of a compiled notebook, by label.
 *
 * The handoff's second private-value guard reads this: a slot whose type says
 * `keypair` is key material whatever the ownership analysis concluded about who
 * holds it. A label this map does not carry is one nothing could be established
 * about, and a caller checking whether a value may leave the machine must treat
 * that as "no" rather than as "unconstrained".
 *
 * @param {*} compiled  a `compileRecipe` result, or the AST from one
 * @returns {Map<string, import("./types.js").RefinedType>}
 */
export function slotTypes(compiled) {
  return typesOf(planChains(compiled));
}

/**
 * Where every slot in the notebook comes from, and whether anyone owns it.
 *
 * @param {import("./recipe.js").RecipeChain[]} chains
 * @returns {{ owners: Map<string, { cell: number, peer: string, published: boolean }>,
 *   types: Map<string, import("./types.js").RefinedType> }}
 */
function slotOrigins(chains) {
  // Types first, over the whole notebook: the walk registers each chain's `out`
  // slots as it goes, and a chain below may read them.
  const { types, edgesByChain } = typesAndEdgesOf(chains);
  /** @type {Map<string, { cell: number, peer: string, published: boolean }>} */
  const owners = new Map();
  for (let i = 0; i < chains.length; i++) {
    const steps = chains[i]?.steps || [];
    const peer = String(chains[i]?.peer || "");
    // Per slot, not per cell. `@mara publish=$commitments` publishes one of the
    // three things its cell writes; the other two stay mara's, and a reader
    // that treated the whole cell as published would place a cell needing a
    // share on somebody who does not have one.
    const published = new Set(publishedSlots(chains[i]));
    for (const label of outSlotLabels(steps)) {
      // First writer wins, matching `validateRecipe` — a duplicate `out` is
      // already an error there, so this only decides which cell a plan blames
      // in a recipe that will not compile anyway.
      if (owners.has(label)) continue;
      owners.set(label, { cell: i, peer, published: published.has(label) });
    }
  }
  return { owners, types, edgesByChain };
}

/**
 * Is this value one that may leave the machine that produced it?
 *
 * Exported because `handoff.js` asks exactly this question about a value an
 * offer would carry, and asking it a second way would be a second answer. A
 * `publish` cell and a handoff payload are the same act — a value crossing a
 * machine boundary — so the closed list above governs both, and a role added to
 * it is argued for once.
 *
 * `publicHalf` rides along for the same reason. Both callers, having heard
 * "no", immediately have to decide whether to offer `:public` as the way out,
 * and the answer is a fact about the value rather than about the caller. Asking
 * it here means the two refusals cannot come to different conclusions about the
 * same slot — which is precisely what happened while each wrote its own
 * sentence: both offered `:public` unconditionally, so a mnemonic share was
 * told to publish a public half that does not exist and cannot be projected.
 *
 * Note it is *not* derivable from `role`. `key` is the role of a `pem` blob, an
 * `openpgp-key` and a `keypair` handle alike, and `:public` compiles against
 * exactly one of the three — so the test is the type's shape, which is what
 * `hasKeyHalves` reads and what the `select` type rule enforces.
 *
 * @param {import("./types.js").RefinedType|undefined} type
 * @returns {{ known: boolean, publishable: boolean, role: string,
 *   publicHalf: boolean }}
 */
export function publishability(type) {
  if (!type || !type.base || type.base === "none") {
    return { known: false, publishable: false, role: "", publicHalf: false };
  }
  const meta = artifactMetaFromType(type);
  const role = String(meta?.role || "");
  const tags = meta?.tags || [];
  // `pem`/`der` and OpenPGP public halves land on the `key` role with a
  // `public` tag — the tag is the half, and the half is the question.
  const publishable =
    PUBLISHABLE_ROLES.has(role) || tags.includes("public") || type.which === "public";
  return { known: true, publishable, role, publicHalf: hasKeyHalves(type) };
}

/**
 * Does this cell reach the vault of whoever runs it?
 * @param {import("./recipe.js").RecipeStep[]} steps
 * @returns {string} the first such op's name, "" when none
 */
function vaultOp(steps) {
  for (const step of steps || []) {
    if (getStep(step.name)?.toolbox === VAULT_TOOLBOX) return step.name;
    const nested = vaultOp(step.body || []);
    if (nested) return nested;
    for (const br of step.branches || []) {
      const inBranch = vaultOp(br.body || []);
      if (inBranch) return inBranch;
    }
  }
  return "";
}

/**
 * Does this cell mint key material?
 * @param {import("./recipe.js").RecipeStep[]} steps
 * @returns {string} the first keying op's name, "" when none
 */
function keyingOp(steps) {
  for (const step of steps || []) {
    const spec = getStep(step.name);
    // Only a *known* step counts. `stepEntropy(null)` is `keying`, which is
    // right for a mirrored run's refusal and wrong here: an unknown step is a
    // compile error already, and asking the author to place it would be asking
    // about a cell that cannot run at all.
    if (spec && stepEntropy(spec) === "keying") return step.name;
    const nested = keyingOp(step.body || []);
    if (nested) return nested;
    for (const br of step.branches || []) {
      const inBranch = keyingOp(br.body || []);
      if (inBranch) return inBranch;
    }
  }
  return "";
}

/**
 * Every constant recipient fingerprint this cell seals to, with where it is
 * written so the ask can point at it.
 *
 * Only the *constant* spelling. `to=each` and `to=room` are derivations the
 * room supplies — `scatter` already refuses a body that names anybody else,
 * and a member the audience does not name cannot appear in one. `to=$slot` and
 * `to=<email>` are not constants either: what they resolve to is decided at
 * run time by a tray or a keyserver, and a pass that reads only the text
 * cannot say which key they will land on. Guessing at one and asking about it
 * would put a fingerprint in front of a reader that the run may never use.
 *
 * `fpr:`/`0x` prefixes are accepted alongside the bare form because
 * `gpg.encrypt to=` documents all three, and a reader who wrote the prefix
 * meant the same key as one who did not.
 *
 * @param {import("./recipe.js").RecipeStep[]} steps
 * @param {{ fpr: string, step: import("./recipe.js").RecipeStep }[]} [out]
 * @returns {{ fpr: string, step: import("./recipe.js").RecipeStep }[]}
 */
function sealedToConstants(steps, out = []) {
  for (const step of steps || []) {
    if (step?.name === "seal" || step?.name === "gpg.encrypt") {
      const raw = String(step.params?.to ?? "").trim();
      // A bare `$slot` and the two reserved words are handled above; anything
      // that normalises to a whole fingerprint is the constant spelling.
      if (raw && !raw.startsWith(SLOT_SIGIL)) {
        const fpr = normalizeFingerprintInput(raw.replace(/^(?:fpr:|0x)/i, ""));
        if (fpr.length >= 40) out.push({ fpr, step });
      }
    }
    sealedToConstants(step?.body || [], out);
    for (const br of step?.branches || []) sealedToConstants(br?.body || [], out);
  }
  return out;
}

/** @param {string[]} list */
function andList(list) {
  const l = [...list];
  if (l.length <= 1) return l.join("");
  return `${l.slice(0, -1).join(", ")} and ${l[l.length - 1]}`;
}

/**
 * Plan a run: who runs which cell, what this peer waits for, and what will not
 * run at all.
 *
 * @param {{ ast?: import("./recipe.js").RecipeAst|null,
 *   validation?: { ok?: boolean, errors?: { message: string }[] } }
 *   | import("./recipe.js").RecipeAst
 *   | import("./recipe.js").RecipeChain[]
 *   | null|undefined} compiled  a `compileRecipe` result, or the AST from one
 * @param {{ me?: string, roster?: Record<string, string>|null }} [opts]
 *   `me` is a peer label or this peer's fingerprint — either is resolved
 *   through the roster, because a session knows the second and a recipe knows
 *   the first.
 *
 *   There was a `manifest` option here, arming a whole-notebook entropy
 *   pre-flight. It is gone with the check it armed — see `manifest.js` for why
 *   that check was wrong — and nothing ever passed it.
 * @returns {RunPlan}
 */
export function planRun(compiled, opts = {}) {
  const source = /** @type {*} */ (compiled);
  const validation = source?.validation;
  const chains = planChains(source);

  const log = mismatchLog();
  /** @type {PlanRefusal[]} */
  const refusals = [];
  /**
   * Record one refusal in `mismatchLog`'s vocabulary, and keep the sentence
   * beside it. The four structural fields come from the log rather than from
   * an object literal, so there is exactly one producer of them.
   * @param {{ path: string, cell: number, start?: number, end?: number }} at
   * @param {string} field @param {string} expected @param {string} actual
   * @param {PlanRefusal["reason"]} reason @param {string} message
   */
  const refuse = (at, field, expected, actual, reason, message) => {
    log.note(at.path, field, expected, actual);
    const all = log.result().mismatches;
    refusals.push({
      ...all[all.length - 1],
      cell: at.cell,
      reason,
      message,
      ...(at.start == null ? {} : { start: at.start }),
      ...(at.end == null ? {} : { end: at.end }),
    });
  };

  /** @type {PlanAsk[]} */
  const asks = [];
  /** @type {PlanWait[]} */
  const waits = [];

  const roster = opts.roster;
  const bound = !!roster && Object.keys(roster).length > 0;
  const { byLabel, byFpr, labels: rosterLabels } = normalizeRoster(bound ? roster : {});

  // `me` arrives as whichever of the two names the caller happens to hold.
  const rawMe = String(opts.me ?? "").trim();
  let me = "";
  if (rawMe) {
    const asFpr = normalizeFingerprintInput(rawMe);
    me = (asFpr && byFpr.get(asFpr)) || (byLabel.has(rawMe) ? rawMe : "");
    if (!me && !bound) {
      const norm = normalizePeerRef(rawMe);
      if (norm.ok && norm.peer !== PEER_WILDCARD) me = norm.peer;
    }
  }

  /** @type {Set<string>} */
  const named = new Set();
  for (const c of chains) {
    const p = String(c.peer || "");
    if (p && p !== PEER_WILDCARD) named.add(p);
  }
  const peers = [...named].sort();
  const unknownPeers = bound ? peers.filter((p) => !byLabel.has(p)) : [];
  // No header anywhere is the case that must plan exactly as it always did.
  // `@*` alone is not that case: it names nobody and still says everyone
  // enters together, which is a claim a headerless notebook does not make.
  const solo = !chains.some((c) => c.peer);
  const play = solo ? "solo" : peers.length ? "placed" : "mirrored";

  /** @type {RunPlan} */
  const plan = {
    ok: true,
    bound,
    play: /** @type {*} */ (play),
    me,
    peers,
    unknownPeers,
    cells: [],
    refusals,
    asks,
    waits,
    counts: { solo: 0, forced: 0, chosen: 0, witnessed: 0, rendezvous: 0, empty: 0 },
  };

  if (validation && validation.ok === false) {
    // Planning a recipe that does not compile would be describing where cells
    // run that cannot run. Named once, against the recipe rather than a cell.
    refuse(
      { path: "recipe", cell: -1 },
      "recipe",
      "a recipe that compiles",
      String(validation.errors?.[0]?.message || "compile errors"),
      "uncompiled",
      "This recipe does not compile, so there is nothing to place — fix the " +
        `compile errors first (${validation.errors?.length || 0} of them, ` +
        `starting: ${String(validation.errors?.[0]?.message || "unknown")}).`
    );
    plan.ok = false;
    return plan;
  }

  const { owners, types, edgesByChain } = slotOrigins(chains);

  for (let i = 0; i < chains.length; i++) {
    const chain = chains[i];
    const steps = chain.steps || [];
    const declaredPeer = String(chain.peer || "");
    const anchor = {
      path: `cell ${i}`,
      cell: i,
      start: chain.headerStart ?? steps[0]?.start,
      end: chain.headerEnd ?? steps[0]?.end,
    };

    /** @type {ConsumedSlot[]} */
    const consumes = [];
    /** @type {Set<string>} */
    const seen = new Set();
    collectConsumed(steps, (row) => {
      const key = `${row.label} ${row.via}`;
      if (seen.has(key)) return;
      seen.add(key);
      const origin = owners.get(row.label);
      // A cell reading a slot it writes itself owns nothing from elsewhere.
      const fromElsewhere = origin && origin.cell !== i;
      const owner = fromElsewhere && origin.peer !== PEER_WILDCARD ? origin.peer : "";
      const type = types.get(row.label);
      consumes.push({
        label: row.label,
        via: row.via,
        from: origin ? origin.cell : -1,
        owner,
        private: !!(owner && fromElsewhere && !origin.published),
        type: type ? formatType(type) : "",
        slotOf: row.slotOf,
      });
    });

    const produces = outSlotLabels(steps);
    // What the header lets out of the machine, which is a subset of what the
    // cell writes and is often none of it.
    const publishes = publishedSlots(chain);

    const privateOwners = [...new Set(consumes.filter((c) => c.private).map((c) => c.owner))].sort();

    /** @type {PlacementBasis} */
    let basis;
    let peer = declaredPeer;
    let why = "";
    let forced = privateOwners.length === 1;

    if (!steps.length) {
      // A cell with nothing in it. Answered before every other case, because
      // "where does this run" has no answer worth giving about a blank cell and
      // the generic ones are all misleading: `solo` would say it runs here, and
      // `no-private-input` would say every participant runs it and the digests
      // are the check. It is in the plan for one reason — it holds the number
      // the notebook, the manifest and the engine all give the cells below it.
      basis = "empty";
      peer = "";
      forced = false;
      why =
        "this cell is empty — there is nothing in it to run and nothing to " +
        "place. It keeps its number so that every cell under it has the number " +
        "the notebook shows";
    } else if (solo) {
      basis = "solo";
      peer = declaredPeer;
      forced = false;
      why =
        "this notebook names no peer, so the cell runs here — the same single " +
        "runner every recipe without a `@peer` header has always had";
    } else if (declaredPeer === PEER_WILDCARD) {
      basis = "rendezvous";
      forced = false;
      why =
        `\`${PEER_SIGIL}${PEER_WILDCARD}\` is a rendezvous — every participant ` +
        "enters this cell together, and no dependency chose that";
    } else if (privateOwners.length >= 2) {
      // Placement is impossible; report it below rather than pretending.
      basis = declaredPeer ? "header" : "secret-locality";
      peer = declaredPeer || privateOwners[0];
      forced = false;
      why =
        `no placement exists — this cell reads private values held by ` +
        `${andList(privateOwners.map((p) => PEER_SIGIL + p))}`;
    } else if (privateOwners.length === 1) {
      basis = "secret-locality";
      peer = privateOwners[0];
      const pinned = consumes.filter((c) => c.private);
      why =
        `runs on \`${PEER_SIGIL}${peer}\` because it reads ` +
        `${andList(pinned.map((c) => SLOT_SIGIL + c.label))}, written by cell ` +
        `${pinned[0].from} under \`${PEER_SIGIL}${peer}\` and not published — ` +
        "the value is on that machine and moving it is the thing this refuses to do";
    } else if (declaredPeer) {
      basis = "header";
      why =
        `runs on \`${PEER_SIGIL}${declaredPeer}\` because the header says so — ` +
        "nothing this cell reads is private to anyone, so this was a choice " +
        "rather than a consequence";
    } else {
      basis = "no-private-input";
      why =
        "every value this cell reads is public or published, so every " +
        "participant runs it and the digests are the check";
    }

    // A header that contradicts the data. Not an override: the data is a fact
    // about where a value is, and a header is a sentence about where a cell
    // should run. A sentence does not move a key.
    if (
      declaredPeer &&
      declaredPeer !== PEER_WILDCARD &&
      privateOwners.length === 1 &&
      privateOwners[0] !== declaredPeer
    ) {
      const pinned = consumes.filter((c) => c.private);
      refuse(
        anchor,
        "peer",
        privateOwners[0],
        declaredPeer,
        "two-owners",
        `Cell ${i} says \`${PEER_SIGIL}${declaredPeer}\` but reads ` +
          `${andList(pinned.map((c) => `\`${SLOT_SIGIL}${c.label}\``))}, which ` +
          `\`${PEER_SIGIL}${privateOwners[0]}\` holds privately (cell ` +
          `${pinned[0].from}). Running it on \`${PEER_SIGIL}${declaredPeer}\` ` +
          `means \`${PEER_SIGIL}${privateOwners[0]}\` hands over a private ` +
          `value. Move the cell to \`${PEER_SIGIL}${privateOwners[0]}\`, or ` +
          `publish what it needs from cell ${pinned[0].from} by writing ` +
          `\`${PUBLISH_STEP}\` after the \`out ${SLOT_SIGIL}${pinned[0].label}\` ` +
          "there."
      );
      peer = privateOwners[0];
    }

    if (privateOwners.length >= 2) {
      const named2 = privateOwners.map((p) => `\`${PEER_SIGIL}${p}\``);
      const bySlot = privateOwners.map((p) => {
        const mine2 = consumes.filter((c) => c.private && c.owner === p);
        return `\`${SLOT_SIGIL}${mine2[0].label}\` is \`${PEER_SIGIL}${p}\`'s`;
      });
      refuse(
        anchor,
        "peer",
        "one owner",
        privateOwners.join(", "),
        "two-owners",
        `Cell ${i} needs ${privateOwners.length} secrets that cannot be in the ` +
          `same place: ${andList(bySlot)}. There is no machine this cell can ` +
          `run on, because running it anywhere means one of ` +
          `${andList(named2)} hands over a private key. Split the cell so each ` +
          "key stays with its owner and publish the intermediate, or use " +
          "`dkg.run` for a key the group holds jointly."
      );
    }

    // A peer the room does not contain. Checked against the roster, which is
    // the only thing that knows — the recipe cannot, and must not try.
    if (bound && peer && peer !== PEER_WILDCARD && !byLabel.has(peer)) {
      refuse(
        anchor,
        "roster",
        rosterLabels.length ? rosterLabels.join(", ") : "(an empty roster)",
        peer,
        "unknown-peer",
        `Cell ${i} runs on \`${PEER_SIGIL}${peer}\`, and no one in this room ` +
          `answers to that name — the roster binds ` +
          `${rosterLabels.length ? andList(rosterLabels.map((l) => `\`${PEER_SIGIL}${l}\``)) : "nobody"}. ` +
          "A peer label means a person only because the roster says which " +
          "fingerprint it is; rename the cell's peer, or add " +
          `\`${PEER_SIGIL}${peer}\` to the roster before running.`
      );
    }

    // `scatter to=room` deals one share per room member, share i to member i
    // in canonical audience order — so a share count the text states must
    // equal the roster's size, and the audience is known *here*, before the
    // run (`planRun` holds the roster; the engine only meets the room after
    // the split has already drawn a secret). The split's N and the room's
    // size are two independently authored numbers — `sss.split`'s
    // `serialize: "always"` keeps N in the text on purpose, so a mismatch is
    // a recipe a person can write and a refusal is the honest answer. A
    // count only the run knows (an unstamped bundle) refuses at run instead.
    if (bound) {
      const roomSize = byLabel.size;
      for (const edge of edgesByChain[i] || []) {
        if (edge?.name !== "scatter") continue;
        const shareCount =
          typeof edge.input?.length === "number" ? edge.input.length : null;
        if (shareCount == null || roomSize < 1 || shareCount === roomSize) continue;
        refuse(
          anchor,
          "scatter",
          `${roomSize} shares — one per room member`,
          `${shareCount} shares`,
          "scatter-count",
          `Cell ${i} scatters ${shareCount} share${shareCount === 1 ? "" : "s"} ` +
            `into a room of ${roomSize} member${roomSize === 1 ? "" : "s"} — ` +
            `share i goes to member i in canonical audience order, so the two ` +
            `counts must agree. The split's N and the room's size are written ` +
            `independently: change the split so N is ${roomSize}, or change ` +
            `who is in the room, before this can deal.`
        );
      }
    }

    /**
     * Sealing to a key the room does not name — an ask, never a refusal.
     *
     * It is legitimate, and that is exactly why it is asked about: an offline
     * archive key, a hardware key not present at the table, a colleague who is
     * meant to be able to open this later. None of those is a mistake, and
     * refusing them would make the product unable to express the ordinary
     * reason a ceremony has an escrow. What a reader is owed is the chance to
     * confirm it, before shares are dealt and while the answer still matters —
     * which is `publish-untyped`'s shape and why this joins it rather than the
     * refusal list.
     *
     * **Bound only.** With no roster there is no audience to compare against,
     * and solo use is the normal case rather than a suspicious one — asking
     * there would fire on every recipe anybody writes alone, which is how an
     * ask stops being read.
     *
     * `to=each` and `to=room` never reach here: those are derivations from the
     * audience and are already constrained where they are written. This covers
     * the constant-fingerprint spelling, which is the one a person types.
     */
    if (bound) {
      /** Every fingerprint the room names, whatever label it wears. */
      const inRoom = new Set(byLabel.values());
      for (const { fpr } of sealedToConstants(steps)) {
        if (inRoom.has(fpr)) continue;
        asks.push({
          cell: i,
          reason: "seal-outside-room",
          question:
            `Cell ${i} seals to ${formatFingerprint(fpr)}, and this key is not ` +
            `in the room — the roster names ${andList(
              [...byLabel.keys()].map((p) => `\`${PEER_SIGIL}${p}\``)
            )}. Confirm this is intended — this key is not in the room and will ` +
            "not be at the table when shares are dealt.",
          // Nobody can answer this by being a different peer: the question is
          // about a key outside the roster, so the roster holds no answer to
          // offer. `publish-untyped` leaves this empty for the same reason.
          choices: [],
          start: anchor.start,
          end: anchor.end,
        });
      }
    }

    // `publish` moves the named `out` artifacts into the room. What may move
    // is a question about the value, and the type walk already answered it.
    // The list is the header's own — a cell that publishes one of the three
    // things it writes is asked about one of them.
    for (const label of publishes) {
      const type = types.get(label);
      const { known, publishable, role, publicHalf } = publishability(type);
      if (!known) {
        asks.push({
          cell: i,
          reason: "publish-untyped",
          question:
            `Cell ${i} publishes \`${SLOT_SIGIL}${label}\`, and this pass ` +
            "could not work out what is in it. Confirm it is safe to send to " +
            "the room before running.",
          choices: [],
          start: anchor.start,
          end: anchor.end,
        });
        continue;
      }
      if (publishable) continue;
      // The header as the author wrote it. `publish` does not compile without a
      // peer on the cell, so this is never the empty string here.
      const header = chainHeaderText(chain);
      /**
       * What can be done about it — and only what can be done about *this*
       * value.
       *
       * The list used to open with `:public` for everything it refused. That is
       * a selector over a keypair, so a mnemonic share was told to publish a
       * public half it does not have, through a pipeline that does not compile:
       * `selector ":public" requires keypair, got text/mnemonic`. A refusal
       * naming an impossible remedy costs more than one naming none, because
       * the reader spends their trust before they spend their time. So the
       * first remedy appears only when the value has halves to project, which
       * is the question `publishability` answers with the same predicate the
       * `select` type rule enforces.
       *
       * @type {string[]}
       */
      const remedies = [];
      if (publicHalf) {
        remedies.push(
          "publish the public half instead " +
            `(\`${SLOT_SIGIL}${label} | ${SELECT_PUBLIC} | out ` +
            `${SLOT_SIGIL}pub | ${PUBLISH_STEP}\`)`
        );
      }
      // "Name only what may leave" was written as `publish=$…` for every cell
      // it was said to, which is advice a reader has to solve before they can
      // take: a cell writing one slot had nothing to put there, and a header
      // that already named slots was being told to do the thing it did. The
      // slots the cell could truthfully publish are knowable here — the rest of
      // what it writes, minus whatever this pass would refuse in turn — so they
      // are written out rather than elided, and left off entirely when there
      // are none.
      const sendable = produces.filter(
        (other) => other !== label && publishability(types.get(other)).publishable
      );
      if (sendable.length) {
        remedies.push(
          `publish only what may leave (\`out ${SLOT_SIGIL}${sendable[0]} | ` +
            `${PUBLISH_STEP}\`)`
        );
      }
      // The last one is always available, and is the reason this list is never
      // empty: a cell can always stop publishing.
      remedies.push(
        `drop \`${PUBLISH_STEP}\` from after \`out ${SLOT_SIGIL}${label}\``
      );
      const joined =
        remedies.length > 1
          ? `${remedies.slice(0, -1).join(", ")}, or ${remedies.at(-1)}.`
          : `${remedies[0]}.`;
      // Sentence case, on a list whose first word is always one of a handful of
      // ASCII verbs written above. Cheaper than keeping two spellings of every
      // remedy in step with each other.
      const offer = joined[0].toUpperCase() + joined.slice(1);

      /**
       * The part before the remedies: why this value in particular.
       *
       * A share gets its own paragraph because "send something else instead" is
       * not merely impossible for it, it is beside the point. A share is
       * addressed to one holder, and a cell headed with a peer has already
       * addressed it — what the author wants is delivery, and `publish` is
       * broadcast. Saying so is the true sentence the `:public` advice was
       * standing in the way of.
       */
      let because = "";
      if (!publicHalf && role === "share") {
        const whole = type?.base === "shares";
        because =
          (whole
            ? `\`${SLOT_SIGIL}${label}\` holds the split itself rather than one ` +
              "holder's piece of it, and a room handed every share has been " +
              "handed the secret they were split out of. "
            : "A share is one holder's piece of a K-of-N split, and `publish` " +
              "is the one thing it does not survive: it puts a copy in front of " +
              "everyone in the room at once, and a piece the whole room holds " +
              "has stopped being anyone's in particular. ") +
          `Nothing needs to leave any machine for \`${PEER_SIGIL}${declaredPeer}\` ` +
          `to have ${whole ? "them" : "it"}: the header already says whose cell ` +
          "this is, and a cell runs on its peer's own machine — so what it " +
          "writes is written there, and stays there. " +
          (whole
            ? ""
            : "That is what handing one person one share looks like here, and " +
              "`publish` is the other thing. ");
      } else if (!publicHalf) {
        // Everything else that must not travel: a projected private half, a
        // `pem` blob, an OpenPGP secret key, a symmetric key, a master. Each is
        // a value in its own right rather than one side of a pair, so there is
        // nothing inside it for `:public` to select — which is what
        // `hasKeyHalves` said, and what the compiler would have said next.
        because =
          "There is no public half of it to send in its place: `:public` " +
          `selects one out of a keypair, and \`${SLOT_SIGIL}${label}\` is not a ` +
          "keypair. ";
      }
      refuse(
        anchor,
        "publish",
        // "…this machine" until now, in a plan every peer in the room reads:
        // the cell runs on `@peer`, so "this" was one machine to the author and
        // another to everybody else. The sentence below always said "the
        // machine that made it", and `handoff.js` says it about the same fact.
        "a value that may leave the machine that made it",
        `${SLOT_SIGIL}${label} (${formatType(type)})`,
        "publish-secret",
        `Cell ${i} is \`${header}\` and publishes \`${SLOT_SIGIL}${label}\`, ` +
          `which is ${formatType(type)} — not a value that may ` +
          `leave the machine that made it. ${because}${offer}`
      );
    }

    // Two questions no dataflow fact answers.
    if (!solo && !declaredPeer && basis === "no-private-input") {
      const vault = vaultOp(steps);
      if (vault) {
        asks.push({
          cell: i,
          reason: "vault-locality",
          question:
            `Cell ${i} runs \`${vault}\`, which reaches the vault of whoever ` +
            "runs it — and a fingerprint in a recipe does not say whose vault " +
            `holds it. Which peer runs this cell? Write their fingerprint as a ` +
            `\`${PEER_SIGIL}\` header at the top of it — the assignment menu ` +
            "writes one from the room's own list.",
          choices: bound ? rosterLabels : peers,
          start: anchor.start,
          end: anchor.end,
        });
      }
      const keying = keyingOp(steps);
      if (keying) {
        asks.push({
          cell: i,
          reason: "keying-unplaced",
          question:
            `Cell ${i} draws keying randomness (\`${keying}\`) and names no ` +
            `peer, so every participant runs it and each one gets a different ` +
            `${produces.length ? `\`${SLOT_SIGIL}${produces[0]}\`` : "result"}. ` +
            "That is right for a key each peer keeps, and wrong for a key the " +
            `room is supposed to share — say which by writing ` +
            `a \`${PEER_SIGIL}\` header naming whose it is, or leave it if per-peer ` +
            "is what you meant.",
          choices: bound ? rosterLabels : peers,
          start: anchor.start,
          end: anchor.end,
        });
      }
    }

    const runsOn =
      solo || basis === "no-private-input" || basis === "rendezvous"
        ? []
        : peer
          ? [peer]
          : [];
    const kind = cellKind({ peer: basis === "rendezvous" ? PEER_WILDCARD : runsOn.length ? peer : "" });
    const mine = runsOn.length === 0 ? true : !!me && runsOn.includes(me);

    plan.cells.push({
      index: i,
      peer: basis === "rendezvous" ? PEER_WILDCARD : runsOn.length ? peer : "",
      kind,
      declared: !!declaredPeer,
      forced,
      basis,
      why,
      runsOn,
      mine,
      publishes,
      produces,
      consumes,
      ...(anchor.start == null ? {} : { start: anchor.start }),
      ...(anchor.end == null ? {} : { end: anchor.end }),
    });

    if (basis === "empty") plan.counts.empty++;
    else if (basis === "solo") plan.counts.solo++;
    else if (basis === "rendezvous") plan.counts.rendezvous++;
    else if (forced) plan.counts.forced++;
    else if (declaredPeer) plan.counts.chosen++;
    else plan.counts.witnessed++;
  }

  // What this peer waits for. A cell everyone runs is never waited on; a cell
  // that runs elsewhere and publishes into one of mine is.
  for (const cell of plan.cells) {
    if (!cell.mine) continue;
    if (cell.kind === "rendezvous") {
      waits.push({ cell: cell.index, on: cell.index, peer: PEER_WILDCARD, slot: "", reason: "rendezvous" });
      continue;
    }
    for (const slot of cell.consumes) {
      if (slot.from < 0 || slot.from === cell.index) continue;
      // A private slot never arrives, which is why the cell reading it was
      // already refused. Recording a wait for it would describe the run
      // hanging as though it were a schedule.
      if (slot.private) continue;
      const producer = plan.cells.find((c) => c.index === slot.from);
      if (!producer || producer.mine) continue;
      waits.push({
        cell: cell.index,
        on: producer.index,
        peer: producer.runsOn[0] || PEER_WILDCARD,
        slot: slot.label,
        reason: "published-slot",
      });
    }
  }


  if (bound && !me) {
    asks.push({
      cell: -1,
      reason: "who-am-i",
      question:
        "This plan does not know which peer you are, so it cannot say which " +
        "cells are yours. Name yourself with a label from the roster " +
        `(${andList(rosterLabels.map((l) => `\`${PEER_SIGIL}${l}\``))}) or with ` +
        "your fingerprint.",
      choices: rosterLabels,
    });
  }

  plan.ok = refusals.length === 0;
  return plan;
}

/**
 * A one-line human summary, for a status line or a tile — the same shape
 * `summarizeHonour` and `summarizeAttestation` return.
 * @param {RunPlan} plan
 * @returns {string}
 */
export function summarizePlan(plan) {
  if (!plan.ok) {
    const first = plan.refusals[0];
    const rest = plan.refusals.length - 1;
    return `run refused at ${first.path} (${first.field})${
      rest > 0 ? ` and ${rest} more` : ""
    }`;
  }
  if (plan.play === "solo") {
    return `${plan.cells.length} ${plan.cells.length === 1 ? "cell" : "cells"}, one runner — this notebook names no peers`;
  }
  const { forced, chosen, witnessed, rendezvous, empty } = plan.counts;
  const parts = [
    `${witnessed} witnessed`,
    `${forced} forced`,
    `${chosen} chosen`,
    ...(rendezvous ? [`${rendezvous} rendezvous`] : []),
    ...(empty ? [`${empty} blank`] : []),
  ];
  const asked = plan.asks.length ? `, ${plan.asks.length} to confirm` : "";
  return `${plan.play} run — ${parts.join(", ")}${asked}`;
}

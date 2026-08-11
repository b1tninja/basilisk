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
 * A recipe names peers. `@alice` is a *label*, deliberately never a
 * fingerprint (`630dc96`), because recipe text travels in a `#r=` link and the
 * room is a digest of the audience. A session, at the other end, knows only
 * fingerprints: `NotebookSession.attestersOf()` returns them and says in its
 * own doc comment that turning one into the other belongs to whoever holds the
 * binding `peersSha` commits to.
 *
 * **This is that holder.** The roster is `{ label: fingerprint }` — the same
 * shape `peersDigest` already hashes, so the thing planned against and the
 * thing committed to are one object. `labelForFingerprint` and
 * `attesterLabels` are the crossing, and they are the only crossing: nothing
 * here derives a label from a fingerprint by pattern, and nothing puts a
 * fingerprint where a label goes (a fingerprint-shaped roster key is refused
 * with `peerFingerprintError`, the same copy the compiler uses).
 *
 * A recipe naming a peer the roster does not have is **refused**, and that is
 * the common case rather than an edge — an author writes `@alice` and the room
 * is mara and okafor. It is not a warning: a cell addressed to a label nobody
 * answers to never runs, and a plan that says otherwise is a plan that hangs.
 * With *no* roster the plan is `bound: false`: placement is still computed, in
 * label space, so the structural refusals bite while authoring, and nothing is
 * claimed about who is in the room.
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

import { cellKind, mirroredRunRefusals } from "./manifest.js";
import { mismatchLog } from "./receipt.js";
import {
  PEER_SIGIL,
  PEER_WILDCARD,
  SLOT_SIGIL,
  normalizePeerRef,
  peerFingerprintError,
  peerLooksLikeFingerprint,
  slotLabelKey,
} from "./recipe-parse.js";
import { boundAsSlotRef, recipeChains } from "./recipe.js";
import { getStep, stepEntropy } from "./registry.js";
import { artifactMetaFromType, formatType, walkPipelineTypes } from "./types.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";

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
 * @typedef {"solo"|"secret-locality"|"header"|"no-private-input"|"rendezvous"} PlacementBasis
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
 * @property {boolean} publish
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
 * @property {"two-owners"|"unknown-peer"|"publish-secret"|"keying-in-mirror"|"unreadable"|"uncompiled"} reason
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
 * @property {"vault-locality"|"keying-unplaced"|"publish-untyped"|"who-am-i"} reason
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
 *   rendezvous: number }} counts
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
 * The roster: peer label → fingerprint, canonicalised.
 *
 * Refuses a fingerprint written as a label with the compiler's own copy. A
 * roster is assembled from a session and a session speaks fingerprints, so
 * this is the exact place a fingerprint would be dropped into the label
 * column by a caller in a hurry.
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
    if (peerLooksLikeFingerprint(norm.peer)) {
      throw new Error(`roster: ${peerFingerprintError(norm.peer)}`);
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
 * Turn `NotebookSession.attestersOf()` into the peer labels `manifestAttestedBy`
 * wants for `by`.
 *
 * The whole of the binding, in one call, at the one layer entitled to make it.
 * `unknown` is returned rather than dropped: an attestation from a fingerprint
 * the roster cannot name is a signature that was checked and a signer that was
 * not identified, and a coverage report that silently discarded it would be
 * reporting less than it knows.
 *
 * @param {Record<string, string>|null|undefined} roster
 * @param {string[]} fingerprints
 * @returns {{ labels: string[], unknown: string[] }}
 */
export function attesterLabels(roster, fingerprints) {
  const { byFpr } = normalizeRoster(roster);
  /** @type {Set<string>} */
  const labels = new Set();
  /** @type {Set<string>} */
  const unknown = new Set();
  for (const raw of fingerprints || []) {
    const fpr = normalizeFingerprintInput(String(raw ?? ""));
    if (!fpr) continue;
    const label = byFpr.get(fpr);
    if (label) labels.add(label);
    else unknown.add(fpr);
  }
  return { labels: [...labels].sort(), unknown: [...unknown].sort() };
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
 * Every slot a cell writes, at any depth — a `foreach` body's `out` is still
 * this cell's output.
 * @param {import("./recipe.js").RecipeStep[]} steps
 * @param {(label: string) => void} add
 */
function collectProduced(steps, add) {
  for (const step of steps || []) {
    if (step.name === "out") {
      const label = slotLabelKey(String(step.params?.name || ""));
      if (label) add(label);
    }
    collectProduced(step.body || [], add);
    for (const br of step.branches || []) collectProduced(br.body || [], add);
  }
}

/**
 * The chains a plan calls cells, in the order it numbers them.
 *
 * **This is the only definition of "cell index" in the placement stack.** A
 * notebook's chains and a plan's cells are not the same list: an empty chain is
 * a blank line in the editor and not a cell, so it is filtered out here and
 * every index below counts non-empty chains. `engine.js` says the same thing in
 * its own words when it lines the gate up (`filled`), and `handoff.js` names a
 * cell with a number produced by this function rather than by a second filter
 * that happens to agree today.
 *
 * @param {*} compiled  a `compileRecipe` result, or the AST from one
 * @returns {import("./recipe.js").RecipeChain[]}
 */
export function planChains(compiled) {
  const source = /** @type {*} */ (compiled);
  const ast = source?.ast !== undefined ? source.ast : source;
  return recipeChains(ast).filter((c) => c?.steps?.length);
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
  /** @type {Map<string, import("./types.js").RefinedType>} */
  const types = new Map();
  for (const chain of chains) {
    try {
      walkPipelineTypes(chain?.steps || [], { getStep }, types);
    } catch (_) {
      // A chain the type walk cannot finish still has an owner for whatever it
      // writes. Placement is a question about headers and slot names, and it
      // must not become unanswerable because a type could not be resolved.
    }
  }
  return types;
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
  const types = typesOf(chains);
  /** @type {Map<string, { cell: number, peer: string, published: boolean }>} */
  const owners = new Map();
  for (let i = 0; i < chains.length; i++) {
    const steps = chains[i]?.steps || [];
    const peer = String(chains[i]?.peer || "");
    const published = !!chains[i]?.publish;
    collectProduced(steps, (label) => {
      // First writer wins, matching `validateRecipe` — a duplicate `out` is
      // already an error there, so this only decides which cell a plan blames
      // in a recipe that will not compile anyway.
      if (!owners.has(label)) owners.set(label, { cell: i, peer, published });
    });
  }
  return { owners, types };
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
 * @param {import("./types.js").RefinedType|undefined} type
 * @returns {{ known: boolean, publishable: boolean, role: string }}
 */
export function publishability(type) {
  if (!type || !type.base || type.base === "none") {
    return { known: false, publishable: false, role: "" };
  }
  const meta = artifactMetaFromType(type);
  const role = String(meta?.role || "");
  const tags = meta?.tags || [];
  // `pem`/`der` and OpenPGP public halves land on the `key` role with a
  // `public` tag — the tag is the half, and the half is the question.
  const publishable =
    PUBLISHABLE_ROLES.has(role) || tags.includes("public") || type.which === "public";
  return { known: true, publishable, role };
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
 * @param {{ me?: string, roster?: Record<string, string>|null,
 *   manifest?: import("./manifest.js").RunManifest|null }} [opts]
 *   `me` is a peer label or this peer's fingerprint — either is resolved
 *   through the roster, because a session knows the second and a recipe knows
 *   the first. `manifest` arms the mirrored-run entropy pre-flight.
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
    counts: { solo: 0, forced: 0, chosen: 0, witnessed: 0, rendezvous: 0 },
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

  const { owners, types } = slotOrigins(chains);

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

    /** @type {string[]} */
    const produces = [];
    collectProduced(steps, (l) => {
      if (!produces.includes(l)) produces.push(l);
    });

    const privateOwners = [...new Set(consumes.filter((c) => c.private).map((c) => c.owner))].sort();

    /** @type {PlacementBasis} */
    let basis;
    let peer = declaredPeer;
    let why = "";
    let forced = privateOwners.length === 1;

    if (solo) {
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
          `publish what it needs from cell ${pinned[0].from} with ` +
          `\`${PEER_SIGIL}${privateOwners[0]} publish\`.`
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

    // `publish` moves this cell's `out` artifacts into the room. What may move
    // is a question about the value, and the type walk already answered it.
    if (chain.publish) {
      for (const label of produces) {
        const { known, publishable } = publishability(types.get(label));
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
        refuse(
          anchor,
          "publish",
          "a value that may leave this machine",
          `${SLOT_SIGIL}${label} (${formatType(types.get(label))})`,
          "publish-secret",
          `Cell ${i} is marked \`${PEER_SIGIL}${declaredPeer || "peer"} publish\` ` +
            `but \`${SLOT_SIGIL}${label}\` is ` +
            `${formatType(types.get(label))}, which is not a value that may ` +
            "leave the machine that made it. Publish the public half instead " +
            `(\`${SLOT_SIGIL}${label} | :public | out ${SLOT_SIGIL}pub\`), or ` +
            "drop `publish` from this cell."
        );
      }
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
            `holds it. Which peer runs this cell? Write \`${PEER_SIGIL}peer\` ` +
            "at the head of it.",
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
            `\`${PEER_SIGIL}peer\`, or leave it if per-peer is what you meant.`,
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
      publish: !!chain.publish,
      produces,
      consumes,
      ...(anchor.start == null ? {} : { start: anchor.start }),
      ...(anchor.end == null ? {} : { end: anchor.end }),
    });

    if (basis === "solo") plan.counts.solo++;
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

  // The entropy pre-flight. `mirroredRunRefusals` reads the manifest's declared
  // mode and every op's declared `entropy`, and answers the one question a plan
  // must not answer for itself: whether a run that agreed its randomness in
  // advance may contain an op that mints a key from it.
  if (opts.manifest) {
    const mirrored = mirroredRunRefusals(opts.manifest);
    for (const r of mirrored.refusals) {
      const cell = plan.cells.find((c) => c.index === r.cell);
      refuse(
        {
          path: `cell ${r.cell}`,
          cell: r.cell,
          start: cell?.start,
          end: cell?.end,
        },
        "entropy",
        "an op whose randomness may be seeded from a pool",
        r.step ? `${r.step} (${r.reason})` : r.reason,
        r.reason === "keying" ? "keying-in-mirror" : "unreadable",
        r.message
      );
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
  const { forced, chosen, witnessed, rendezvous } = plan.counts;
  const parts = [
    `${witnessed} witnessed`,
    `${forced} forced`,
    `${chosen} chosen`,
    ...(rendezvous ? [`${rendezvous} rendezvous`] : []),
  ];
  const asked = plan.asks.length ? `, ${plan.asks.length} to confirm` : "";
  return `${plan.play} run — ${parts.join(", ")}${asked}`;
}

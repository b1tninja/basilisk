/**
 * The handoff offer — a cell the plan placed on somebody else, turned into
 * something that peer can accept.
 *
 * `ecf3999` made a placed cell stop running here. It did not make it run
 * anywhere else: the gate reports a `SkippedCell` and the run walks on, and a
 * later cell that needed the skipped one's output stops with a sentence naming
 * the peer that holds it. This module is the other half — the document that
 * turns "not mine" into "yours, and here is what it needs".
 *
 * ## The seam, and why nothing here touches the gate
 *
 * The gate asks the slot registry **first**: a value that is already present
 * runs the cell, because a gate has nothing to say about a value it can see.
 * So acceptance delivers by registering bindings into the registry, and the
 * withheld-input check stops firing on its own with no edit to `placement.js`.
 * `run-gate.test.js` has held that seam since before this file existed — *"runs
 * the moment the value is actually here"* — and this unit is written to arrive
 * through it rather than beside it.
 *
 * ## The invariant, asserted twice at each end
 *
 * **An offer carries only public values.** Placement guarantees a cell runs
 * where its private inputs already live, so what has to travel is the public
 * output of an upstream cell; an offer that needed to carry a secret would be
 * the planner's `two-owners` refusal, caught on text at compile time. That is
 * an argument, and an argument is not a check. So the property is checked at
 * the boundary anyway, in two ways that do not share a premise:
 *
 * 1. **Ownership** — `consumes[].private`, the planner's answer to *does
 *    somebody hold this and not publish it*.
 * 2. **Kind** — `publishability()` over the slot's refined type, the same
 *    closed list of roles that decides whether a `publish` cell may send a
 *    value into the room. `plan.js` exports it so there is one list.
 *
 * The second is not decoration. A witnessed cell `genkey x25519 | out $kp`
 * carries no `@peer` header, so nothing *owns* `$kp` and guard 1 passes it — and
 * a placed cell downstream reading `$kp` would take a private key across a
 * machine boundary. Guard 2 refuses it, on the type. The two guards run at both
 * ends: the offerer will not build such an offer, and a recipient re-runs both
 * against **their own** plan and their own notebook rather than trusting the
 * document.
 *
 * Neither guard is a runtime `meta.sensitive` read. That flag is a hint an op
 * chose to leave on a value; the question here is what the recipe says the slot
 * holds, and it is answerable before anything runs.
 *
 * ## Which index a cell is named by
 *
 * There is one numbering and everything uses it: a cell's index is its position
 * in the notebook, counting every cell including the empty ones. That is what
 * the notebook shows, what `planChains` counts, what the gate admits by, what
 * `cells[].index` means in a manifest and what the run log records. `v2` of this
 * document is the bump for it — a `cell` written under `v1` counted only the
 * non-empty cells and so names a different cell in a notebook with a blank one.
 *
 * The number alone is still not trusted to select anything. `offer.cell` is only
 * honoured when all three of these agree:
 *
 * - the manifest has a cell at that **position**, and that cell's own `index`
 *   field equals the position — one numbering means these can only differ in a
 *   malformed document, and a malformed document does not get to pick a cell;
 * - the manifest's cell at that position digests to `offer.cellDigest`;
 * - the **recipient's own notebook**, serialised the way a manifest and a
 *   receipt both spell a cell, digests to the same thing.
 *
 * A wrong index does not select the wrong cell. It selects nothing.
 *
 * ## The offer names no assignee, and that is the design
 *
 * There is no `assignee` field, no peer label, no fingerprint. Who runs a cell
 * is a question the recipient's own plan already answers, and a document that
 * answered it too would be a second opinion about placement — the defect this
 * stack has paid for repeatedly. The offerer addresses the offer on the wire,
 * to one confirmed peer; the wire is transport, not a claim. Every acceptance
 * check below is made against documents the recipient holds: their plan, their
 * notebook, and a manifest they have already seen.
 *
 * That is also why an offer is **not signed**. A manifest and an attestation are
 * commitments, and a signature is what lets one be shown to a third party. An
 * offer is a delivery: it asserts nothing the recipient takes on trust, since
 * every field is checked against the recipient's own copy of the notebook and
 * the values are inputs their receipt will digest anyway. Signing it would need
 * a signing path for a document no recipe produces — and `475fd81` refused
 * exactly that temptation for the session. The sender is the peer whose pairwise
 * key opened the frame, which is the same claim the room's other documents rest
 * their identity on.
 *
 * ## Consent
 *
 * An offer **arrives pending**. Nothing in this module registers a binding,
 * starts a run, or answers a peer: `acceptHandoffOffer` returns the bindings a
 * caller would register, and registering them is the caller's act, taken because
 * a person clicked. `approval-gate.js` states the rule — *"Grants are minted
 * only by a human clicking, never by a param."* There is no path from
 * `runRecipe` to this file, and no parameter anywhere that accepts an offer.
 *
 * A **declined** offer and an **ignored** one are the same thing from the
 * offerer's side, and this unit does not pretend otherwise — see
 * `offerAwaiting`. Declining is local: the recipient registers nothing and their
 * cell does not run. The offerer's own run already stopped at the withheld-input
 * sentence the gate produced, naming the slot and the peer, and it stays stopped
 * until a result comes back — which is the next unit's business, not this one's.
 *
 * @module lib/toolkit/handoff
 */

import { base64ToBytes, bytesToBase64 } from "./encode.js";
import { manifestDigest } from "./manifest.js";
import { planChains, publishability, slotTypes } from "./plan.js";
import { PEER_SIGIL, PEER_WILDCARD, SLOT_SIGIL, slotLabelKey } from "./recipe-parse.js";
import { canonicalJson, digestText, isoTimestamp, mismatchLog } from "./receipt.js";
import { serializeRecipe } from "./recipe.js";

/**
 * Offer envelope version. Bump when the *shape* changes, or when a field keeps
 * its shape and changes which thing it names.
 *
 * Independent of `MANIFEST_VERSION`, `ATTESTATION_VERSION` and
 * `RECEIPT_VERSION` — four documents, four reasons to break, and this time two
 * of them broke for the same one: **v2 is the cell numbering**, alongside
 * `MANIFEST_VERSION` 2. `cell` counted the non-empty cells under v1 and counts
 * every cell under v2, so the same integer names a different cell of any
 * notebook with a blank one in it. The other two documents stayed where they
 * were: a receipt already numbered every cell, because the kernel it comes from
 * always did, and an attestation carries a manifest digest and nothing that
 * counts cells. Nothing in the shape
 * changed, which is exactly why the version has to say it — an unbumped v1
 * offer would have been read against the new numbering and refused as a digest
 * mismatch, which tells the reader that a cell's text is wrong when what is
 * wrong is which cell was meant.
 */
export const HANDOFF_VERSION = 2;

/** The `kind` discriminator, so no other document can be read as an offer. */
export const HANDOFF_KIND = "basilisk.cell-handoff";

/**
 * Every field an offer may carry — the whole document.
 *
 * A closed list rather than a minimum, for `attest.js`'s reason: "carries no
 * fingerprint" and "makes no claim about who runs this" are only enforceable if
 * there is nowhere to put one.
 * @type {readonly string[]}
 */
export const HANDOFF_FIELDS = Object.freeze([
  "v",
  "kind",
  "manifest",
  "cell",
  "cellDigest",
  "needs",
  "offeredAt",
]);

/** Every field one carried value may carry. @type {readonly string[]} */
export const NEED_FIELDS = Object.freeze(["label", "type", "data"]);

/**
 * The pipeline values an offer can carry.
 *
 * Deliberately short, and it is not an encoding limitation. Everything a
 * `publish` cell may send into the room is one of these: text, bytes, a number,
 * a flag. `shares`, `keypair` and an OpenPGP private key have no encoding here
 * because they must never travel, and leaving them unrepresentable is a
 * stronger statement than refusing them at the door — though `buildOfferFor`
 * refuses them at the door as well.
 * @type {ReadonlySet<string>}
 */
const CARRIABLE = new Set(["text", "bytes", "int", "bool"]);

/** A SHA-256 digest as this codebase writes one: 64 lowercase hex characters. */
const DIGEST_RE = /^[0-9a-f]{64}$/;

/**
 * @typedef {object} CarriedValue
 * @property {string} label  slot label, no sigil
 * @property {"text"|"bytes"|"int"|"bool"} type
 * @property {string|number|boolean} data  bytes are base64
 */

/**
 * @typedef {object} HandoffOffer
 * @property {number} v
 * @property {"basilisk.cell-handoff"} kind
 * @property {string} manifest    SHA-256 of the manifest's canonical JSON
 * @property {number} cell        the plan's cell index — see the module header
 * @property {string} cellDigest  digest of that cell's recipe text
 * @property {CarriedValue[]} needs  sorted by label
 * @property {string} offeredAt   ISO — the offerer's own word, witnessed by nothing
 */

/**
 * One reason an offer was not built, or not accepted.
 *
 * The first four fields are `mismatchLog()`'s and are produced by it, the same
 * `{path, field, expected, actual}` a receipt comparison, a manifest check and a
 * `PlanRefusal` report in. One idea, one spelling.
 * @typedef {object} HandoffRefusal
 * @property {string} path
 * @property {string} field
 * @property {string} expected
 * @property {string} actual
 * @property {number} cell
 * @property {"no-such-cell"|"ambiguous-index"|"cell-mismatch"|"different-notebook"
 *   |"unknown-manifest"|"not-mine"|"mine-already"|"rendezvous"|"private-value"
 *   |"untyped-value"|"uncarriable"|"absent-value"|"unasked-slot"|"incomplete"
 *   |"slot-present"} reason
 * @property {string} message
 */

/**
 * A refusal list that speaks `mismatchLog`'s vocabulary.
 * @returns {{ refuse: (at: { path: string, cell: number }, field: string,
 *   expected: *, actual: *, reason: HandoffRefusal["reason"], message: string) => void,
 *   list: HandoffRefusal[] }}
 */
function refusals() {
  const log = mismatchLog();
  /** @type {HandoffRefusal[]} */
  const list = [];
  return {
    list,
    refuse(at, field, expected, actual, reason, message) {
      log.note(at.path, field, String(expected ?? ""), String(actual ?? ""));
      const all = log.result().mismatches;
      list.push({ ...all[all.length - 1], cell: at.cell, reason, message });
    },
  };
}

/** @param {string} label */
const slot = (label) => `\`${SLOT_SIGIL}${label}\``;
/** @param {string} peer */
const who = (peer) => (peer ? `\`${PEER_SIGIL}${peer}\`` : "another peer");

/**
 * The one spelling of a cell's text.
 *
 * `serializeRecipe({ chains: [chain] })` is what `appendRunLog` records and what
 * `currentRunManifest` digests into `cells[].recipeDigest`. A second
 * normalisation here would make an honest offer and an honest manifest disagree
 * on whitespace, which is the defect `manifest.js` warns about at length.
 *
 * @param {import("./recipe.js").RecipeChain|undefined} chain
 * @returns {Promise<string>} the digest, or "" when the cell will not serialize
 */
async function cellTextDigest(chain) {
  if (!chain) return "";
  try {
    return await digestText(serializeRecipe({ chains: [chain] }));
  } catch (_) {
    return "";
  }
}

/**
 * Lift a live pipeline value into the document, or say why it cannot go.
 * @param {string} label
 * @param {import("./engine.js").PipelineValue|null|undefined} value
 * @returns {{ ok: true, need: CarriedValue } | { ok: false, why: string }}
 */
function carry(label, value) {
  if (!value) return { ok: false, why: "there is no value in that slot here" };
  const type = String(value.type || "");
  if (!CARRIABLE.has(type)) {
    return {
      ok: false,
      why:
        `a ${type || "typeless"} value has no form an offer can carry — an offer ` +
        "carries text, bytes, a number or a flag, and nothing that is key " +
        "material has an encoding here at all",
    };
  }
  if (type === "bytes") {
    const data = value.data;
    if (!(data instanceof Uint8Array)) {
      return { ok: false, why: "the slot says bytes and holds something else" };
    }
    return { ok: true, need: { label, type: "bytes", data: bytesToBase64(data) } };
  }
  if (type === "int") {
    const n = Number(value.data);
    return {
      ok: true,
      need: { label, type: "int", data: Number.isFinite(n) ? Math.trunc(n) : 0 },
    };
  }
  if (type === "bool") return { ok: true, need: { label, type: "bool", data: !!value.data } };
  return { ok: true, need: { label, type: "text", data: String(value.data ?? "") } };
}

/**
 * Turn a carried value back into a pipeline value.
 *
 * **No `meta`.** The offerer's annotations on a value — `sensitive`, a
 * fingerprint, a filename, an inspect snapshot — are things an op said about a
 * value, not the value, and every one of them is a field a peer would be
 * choosing on the recipient's behalf. A handed-over value arrives the way a
 * pasted one does, which is a form this engine already runs on.
 *
 * @param {CarriedValue} need
 * @returns {import("./engine.js").PipelineValue}
 */
function uncarry(need) {
  if (need.type === "bytes") {
    return { type: "bytes", data: base64ToBytes(String(need.data)), meta: {} };
  }
  if (need.type === "int") return { type: "int", data: Number(need.data) || 0, meta: {} };
  if (need.type === "bool") return { type: "bool", data: !!need.data, meta: {} };
  return { type: "text", data: String(need.data ?? ""), meta: {} };
}

/**
 * Canonical bytes of an offer — what travels, and what its digest covers.
 * @param {HandoffOffer} offer
 * @returns {string}
 */
export function offerToJson(offer) {
  return canonicalJson(offer);
}

/**
 * Parse an offer out of text.
 *
 * Refuses any field outside `HANDOFF_FIELDS`, and any field on a carried value
 * outside `NEED_FIELDS`. A document that grew an `assignee`, a `peer`, an `fpr`
 * or a `meta` is not a richer offer — it is a peer putting a claim where this
 * document deliberately has none, and reading it as this one would carry that
 * claim inward.
 *
 * There is no cleartext unwrapping here, unlike a manifest or an attestation:
 * an offer is not signed, so there is no wrapper and no second answer to which
 * bytes anybody meant.
 *
 * @param {string} text
 * @returns {HandoffOffer}
 */
export function parseHandoffOffer(text) {
  /** @type {*} */
  let parsed;
  try {
    parsed = JSON.parse(String(text ?? ""));
  } catch (_) {
    throw new Error("handoff: not JSON (expected a Basilisk cell handoff offer)");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("handoff: not a Basilisk cell handoff offer");
  }
  if (parsed.kind !== HANDOFF_KIND) {
    throw new Error("handoff: not a Basilisk cell handoff offer");
  }
  if (Number(parsed.v) !== HANDOFF_VERSION) {
    throw new Error(
      `handoff: unsupported version ${parsed.v} (this build writes and reads ` +
        `v${HANDOFF_VERSION})` +
        (Number(parsed.v) === 1
          ? " — v1 numbered a notebook's cells by skipping the empty ones and v2 " +
            "numbers every cell the way the notebook does, so `cell` names a " +
            "different cell in each. Nothing is accepted against the old " +
            "numbering: build the offer again from the run that is happening now."
          : "")
    );
  }
  const extra = Object.keys(parsed).filter((k) => !HANDOFF_FIELDS.includes(k));
  if (extra.length) {
    throw new Error(
      `handoff: unexpected field${extra.length === 1 ? "" : "s"} ` +
        `${extra.sort().join(", ")} — an offer names a manifest, a cell and the ` +
        "values that cell needs, and nothing else. It does not say who runs the " +
        "cell: the peer holding it decides that from their own plan."
    );
  }
  if (!DIGEST_RE.test(String(parsed.manifest ?? ""))) {
    throw new Error(
      "handoff: manifest must be a SHA-256 digest as 64 lowercase hex characters"
    );
  }
  if (!DIGEST_RE.test(String(parsed.cellDigest ?? ""))) {
    throw new Error(
      "handoff: cellDigest must be a SHA-256 digest as 64 lowercase hex characters"
    );
  }
  if (!Number.isInteger(parsed.cell) || parsed.cell < 0) {
    throw new Error(
      `handoff: cell must be a cell index, got ${JSON.stringify(parsed.cell)} — ` +
        "the index a plan gives a cell, counting every cell from 0 the way the " +
        "notebook does"
    );
  }
  if (!Array.isArray(parsed.needs)) {
    throw new Error("handoff: needs must be a list of the values the cell reads");
  }
  /** @type {Set<string>} */
  const seen = new Set();
  for (const raw of parsed.needs) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("handoff: every entry in needs is a { label, type, data }");
    }
    const over = Object.keys(raw).filter((k) => !NEED_FIELDS.includes(k));
    if (over.length) {
      throw new Error(
        `handoff: carried value ${JSON.stringify(String(raw.label ?? ""))} has ` +
          `unexpected field${over.length === 1 ? "" : "s"} ${over.sort().join(", ")} — ` +
          "a value travels as a label, a type and its data, and the annotations " +
          "an op left on it stay on the machine that made it"
      );
    }
    const label = slotLabelKey(String(raw.label ?? ""));
    if (!label) {
      throw new Error("handoff: a carried value must name the slot it fills");
    }
    if (seen.has(label)) {
      throw new Error(
        `handoff: ${slot(label)} is carried twice — one slot holds one value, and ` +
          "which of two an offer meant is not a question this can answer"
      );
    }
    seen.add(label);
    if (!CARRIABLE.has(String(raw.type ?? ""))) {
      throw new Error(
        `handoff: ${slot(label)} is offered as ${JSON.stringify(String(raw.type ?? ""))}, ` +
          `which is not a kind an offer carries (${[...CARRIABLE].sort().join(", ")})`
      );
    }
    if (raw.type === "bytes") {
      try {
        base64ToBytes(String(raw.data ?? ""));
      } catch (_) {
        throw new Error(`handoff: ${slot(label)} says bytes and is not base64`);
      }
    }
  }
  return /** @type {HandoffOffer} */ (parsed);
}

/**
 * Which slots does this cell read that the peer running it cannot produce?
 *
 * Answered entirely off the plan, from one side or the other depending on whose
 * plan it is — the same three cases either way. A slot's producer is either the
 * cell's own peer's (they will have it), or this peer's (it has to travel), or a
 * third peer's (nobody here can hand it over).
 *
 * @param {import("./plan.js").RunPlan} plan
 * @param {number} cell
 * @param {string} runner  peer label the cell runs on, "" for everyone
 * @returns {{ label: string, from: number, peer: string, private: boolean,
 *   type: string }[]}
 */
function slotsFromElsewhere(plan, cell, runner) {
  const planned = plan.cells[cell];
  /** @type {ReturnType<typeof slotsFromElsewhere>} */
  const out = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const consumed of planned?.consumes || []) {
    if (consumed.from < 0 || consumed.from === cell) continue;
    if (seen.has(consumed.label)) continue;
    const producer = plan.cells[consumed.from];
    if (!producer) continue;
    // Everyone runs a witnessed cell, so the peer running this one already has
    // whatever it wrote; so does a cell placed on that same peer.
    const runnerHasIt =
      producer.runsOn.length === 0 || (!!runner && producer.runsOn.includes(runner));
    if (runnerHasIt) continue;
    seen.add(consumed.label);
    out.push({
      label: consumed.label,
      from: consumed.from,
      peer: producer.peer || producer.runsOn[0] || "",
      private: !!consumed.private,
      type: consumed.type,
    });
  }
  return out;
}

/**
 * Both private-value guards, over one slot.
 *
 * @param {{ label: string, private: boolean, type: string }} row
 * @param {Map<string, import("./types.js").RefinedType>} types
 * @returns {{ ok: true } | { ok: false, reason: "private-value"|"untyped-value",
 *   field: string, expected: string, actual: string, message: string }}
 */
function publicEnough(row, types) {
  if (row.private) {
    return {
      ok: false,
      reason: "private-value",
      field: "private",
      expected: "a value nobody holds privately",
      actual: row.label,
      message:
        `${slot(row.label)} is held privately by whoever wrote it and was never ` +
        "published, so it must not leave that machine. An offer carrying it " +
        "would move a secret, which is the one thing placement exists to " +
        "prevent — the plan that produced this should have refused the run, and " +
        "this offer refuses it instead.",
    };
  }
  const verdict = publishability(types.get(row.label));
  if (!verdict.known) {
    return {
      ok: false,
      reason: "untyped-value",
      field: "type",
      expected: "a slot whose contents can be read from the recipe",
      actual: row.label,
      message:
        `Nothing could be established about what is in ${slot(row.label)}, and a ` +
        "value that cannot be shown to be public is treated here as though it " +
        "were not. Give the cell that writes it a form this build can type, or " +
        `publish the public half into a fresh slot and read that instead.`,
    };
  }
  if (!verdict.publishable) {
    return {
      ok: false,
      reason: "private-value",
      field: "role",
      expected: "a value that may leave the machine that made it",
      actual: `${row.label} (${row.type || verdict.role})`,
      message:
        `${slot(row.label)} is ${row.type || verdict.role}, which is not a value ` +
        "that may leave the machine that made it — the same closed list of roles " +
        "that stops a `publish` cell sending it into the room. Nothing *owns* it, " +
        "so the ownership analysis had no reason to object; what it is settles " +
        `the question instead. Publish the public half (\`${SLOT_SIGIL}${row.label}` +
        ` | :public | out ${SLOT_SIGIL}pub\`) and have the cell read that.`,
    };
  }
  return { ok: true };
}

/**
 * Build the offer for a cell this run left to somebody else.
 *
 * Takes the `SkippedCell` the gate reported, the plan it came from, the compiled
 * notebook that plan was made against, the manifest the room is running under,
 * and a way to read this peer's slots. Everything else is derived; nothing is
 * decided.
 *
 * Refuses rather than throws, so a shell can show a person why a cell cannot be
 * handed over. `offer` is `null` whenever `ok` is false — there is no partial
 * offer, because a partial offer is one that says "run this" while withholding
 * something the cell reads.
 *
 * @param {object} spec
 * @param {import("./plan.js").RunPlan} spec.plan  this peer's plan
 * @param {*} spec.compiled  the compiled notebook that plan was made against
 * @param {import("./manifest.js").RunManifest} spec.manifest  the run's manifest
 * @param {import("./placement.js").SkippedCell} spec.skipped  what the gate reported
 * @param {(label: string) => import("./engine.js").PipelineValue|null} spec.readSlot
 * @param {string|number|Date} [spec.offeredAt]
 * @returns {Promise<{ ok: boolean, offer: HandoffOffer|null,
 *   refusals: HandoffRefusal[] }>}
 */
export async function buildOfferFor(spec) {
  const { plan, compiled, manifest, skipped } = spec;
  const cell = Number(skipped?.cell);
  const at = { path: `cell ${cell}`, cell };
  const { refuse, list } = refusals();
  const stop = () => ({ ok: false, offer: /** @type {HandoffOffer|null} */ (null), refusals: list });

  const planned = plan?.cells?.[cell];
  if (!planned || planned.index !== cell) {
    refuse(
      at,
      "cell",
      `a cell this plan describes (0–${(plan?.cells?.length || 0) - 1})`,
      cell,
      "no-such-cell",
      `There is no cell ${cell} in this plan, so there is nothing to hand over. ` +
        "An offer names a cell by the index the plan gives it, counting every " +
        "cell from 0 the way the notebook does."
    );
    return stop();
  }
  // Before the `mine` check, and that order is the point: a rendezvous cell is
  // `mine` today — everybody's is also mine — so asking "is it mine" first would
  // answer a rendezvous with "nothing to hand over", which is true only by
  // accident and stops being true the moment a barrier exists.
  if (planned.kind === "rendezvous" || skipped.waitingOn === PEER_WILDCARD) {
    refuse(
      at,
      "peer",
      "a cell placed on one peer",
      PEER_WILDCARD,
      "rendezvous",
      `Cell ${cell} is a rendezvous (\`${PEER_SIGIL}${PEER_WILDCARD}\`) — every ` +
        "participant enters it together, and there is no barrier machinery in " +
        "this build to enter it with. A handoff hands one cell to one peer, so " +
        "this is refused outright rather than half-supported: half a rendezvous " +
        "is one peer running alone and believing the room ran with them."
    );
    return stop();
  }
  if (planned.mine) {
    refuse(
      at,
      "mine",
      "a cell this peer is not performing",
      "mine",
      "mine-already",
      `Cell ${cell} runs here, so there is nothing to offer anybody. A handoff ` +
        "is built from a cell the gate declined to perform, never from one this " +
        "run is about to do itself."
    );
    return stop();
  }

  const runner = planned.runsOn[0] || skipped.waitingOn || "";

  // The cell's identity, three ways, before anything is put in the document.
  const chains = planChains(compiled);
  const mineDigest = await cellTextDigest(chains[cell]);
  const declared = manifest?.cells?.[cell];
  const identity = await checkCellIdentity({ at, cell, plan, manifest, mineDigest, refuse });
  if (!identity) return stop();

  const types = slotTypes(compiled);
  /** @type {CarriedValue[]} */
  const needs = [];
  for (const row of slotsFromElsewhere(plan, cell, runner)) {
    const producer = plan.cells[row.from];
    if (!producer.mine) {
      refuse(
        at,
        "needs",
        `${row.label} from this peer`,
        `${row.label} from ${row.peer || "a third peer"}`,
        "incomplete",
        `Cell ${cell} reads ${slot(row.label)}, which cell ${row.from} writes on ` +
          `${who(row.peer)} — not here. This peer cannot hand over a value it ` +
          `does not hold, and an offer that left it out would tell ${who(runner)} ` +
          "to run a cell that stops the moment it reads that slot. The offer " +
          `${who(row.peer)} makes is theirs to make.`
      );
      continue;
    }
    const verdict = publicEnough(row, types);
    if (!verdict.ok) {
      refuse(at, verdict.field, verdict.expected, verdict.actual, verdict.reason, verdict.message);
      continue;
    }
    const value = spec.readSlot?.(row.label) || null;
    const held = carry(row.label, value);
    if (!held.ok) {
      refuse(
        at,
        "needs",
        `a value in ${row.label}`,
        held.why,
        value ? "uncarriable" : "absent-value",
        `Cell ${cell} reads ${slot(row.label)} and ${held.why}. An offer is built ` +
          "from values this run actually produced, so run the cells above it " +
          "first — and if that slot can never take a form an offer carries, the " +
          "cell reading it cannot be handed over at all."
      );
      continue;
    }
    needs.push(held.need);
  }
  if (list.length) return stop();

  needs.sort((a, b) => a.label.localeCompare(b.label));
  return {
    ok: true,
    refusals: list,
    offer: {
      v: HANDOFF_VERSION,
      kind: /** @type {"basilisk.cell-handoff"} */ (HANDOFF_KIND),
      manifest: await manifestDigest(manifest),
      cell,
      cellDigest: String(declared?.recipeDigest || mineDigest),
      needs,
      // The offerer's claim, not a fact — `attest.js`'s `claimedAt` under
      // another name, and no more evidence than that one is.
      offeredAt: isoTimestamp(spec.offeredAt),
    },
  };
}

/**
 * The three-way agreement that makes `cell` mean one thing. See the module
 * header; this is that paragraph, executable.
 *
 * @param {object} args
 * @param {{ path: string, cell: number }} args.at
 * @param {number} args.cell
 * @param {import("./plan.js").RunPlan} args.plan
 * @param {import("./manifest.js").RunManifest} args.manifest
 * @param {string} args.mineDigest  digest of this notebook's cell at that index
 * @param {ReturnType<typeof refusals>["refuse"]} args.refuse
 * @param {string} [args.offered]  the digest an offer claims, when checking one
 * @returns {Promise<boolean>}
 */
async function checkCellIdentity({ at, cell, plan, manifest, mineDigest, refuse, offered }) {
  const cells = manifest?.cells || [];
  if (cells.length !== plan.cells.length) {
    refuse(
      at,
      "cells",
      plan.cells.length,
      cells.length,
      "different-notebook",
      `This manifest describes ${cells.length} ` +
        `${cells.length === 1 ? "cell" : "cells"} and this notebook plans ` +
        `${plan.cells.length} — the two are not the same notebook, so a cell ` +
        "index means a different cell on each side and no offer written in one " +
        "can be read in the other."
    );
    return false;
  }
  const declared = cells[cell];
  if (!declared) {
    refuse(
      at,
      "cell",
      `a manifest cell at position ${cell}`,
      "",
      "no-such-cell",
      `The manifest has no cell at position ${cell}, so there is nothing for an ` +
        "offer to name."
    );
    return false;
  }
  if (Number(declared.index) !== cell) {
    refuse(
      at,
      "index",
      cell,
      declared.index,
      "ambiguous-index",
      `The manifest's cell at position ${cell} calls itself cell ` +
        `${declared.index}. A manifest numbers its cells by their position — ` +
        "every cell, blank ones included — so a document where the two disagree " +
        "was not built by this rule, and there is no way to tell which of the " +
        "two numbers an offer naming it meant. Nothing is handed over while a " +
        "cell index means two things: get the manifest from the run that is " +
        "actually happening."
    );
    return false;
  }
  const want = String(declared.recipeDigest || "");
  if (!mineDigest || mineDigest !== want) {
    refuse(
      at,
      "recipeDigest",
      want,
      mineDigest,
      "cell-mismatch",
      `The manifest's cell ${cell} is not the cell ${cell} in this notebook — ` +
        "same number, different text. Load the recipe this manifest was built " +
        "from before offering or accepting anything against it."
    );
    return false;
  }
  if (offered != null && offered !== want) {
    refuse(
      at,
      "cellDigest",
      want,
      offered,
      "cell-mismatch",
      `This offer names cell ${cell} and carries the digest of a different ` +
        "cell's text. An index alone would have selected *some* cell; the " +
        "digest is what makes a wrong index select nothing."
    );
    return false;
  }
  return true;
}

/**
 * Read an offer, decide whether it can be accepted, and say what to register.
 *
 * **This function accepts nothing.** It returns the bindings a caller *would*
 * register, and the caller registers them because a person clicked. There is no
 * parameter that skips a check and none that consents on anybody's behalf.
 *
 * Every check is made against documents the recipient holds — their plan, their
 * notebook, a manifest they have already seen — because the offer deliberately
 * carries no claim about who runs the cell. In particular an offer for a
 * manifest digest the recipient has never seen is refused rather than treated as
 * a manifest arriving late: it is either a race with a document still in flight
 * or a peer inventing a run, and the two are told apart by asking the offerer to
 * publish the manifest first, never by guessing here.
 *
 * @param {HandoffOffer} offer  already through `parseHandoffOffer`
 * @param {object} ctx
 * @param {import("./plan.js").RunPlan} ctx.plan  the recipient's own plan
 * @param {*} ctx.compiled  the recipient's own compiled notebook
 * @param {import("./manifest.js").RunManifest|null} [ctx.manifest]  the manifest
 *   the recipient holds for `offer.manifest`, or nothing if they hold none
 * @param {(label: string) => boolean} [ctx.hasSlot]  the recipient's registry
 * @returns {Promise<{ ok: boolean, cell: number, refusals: HandoffRefusal[],
 *   bindings: { label: string, value: import("./engine.js").PipelineValue }[] }>}
 */
export async function acceptHandoffOffer(offer, ctx) {
  const cell = Number(offer?.cell);
  const at = { path: `cell ${cell}`, cell };
  const { refuse, list } = refusals();
  const stop = () => ({ ok: false, cell, refusals: list, bindings: [] });
  const plan = ctx?.plan;

  if (!plan || !Array.isArray(plan.cells)) {
    throw new Error(
      "handoff: an offer is checked against the recipient's own plan, and none " +
        "was supplied — there is no reading of an offer that does not need one"
    );
  }

  // The manifest, first: without it the offer names a run this peer knows
  // nothing about, and nothing below is answerable.
  const manifest = ctx.manifest || null;
  const held = manifest ? await manifestDigest(manifest) : "";
  if (!manifest || held !== String(offer.manifest || "")) {
    refuse(
      at,
      "manifest",
      String(offer.manifest || ""),
      held,
      "unknown-manifest",
      `This offer is against a run manifest this peer has not seen` +
        `${held ? " — the manifest held here digests to something else" : ""}. ` +
        "That is either a race, with the manifest still on its way, or a peer " +
        "naming a run nobody committed to; both are answered the same way and " +
        "neither is answered by guessing. Ask for the signed manifest, check it, " +
        "and offer again against the digest it actually has."
    );
    return stop();
  }

  const planned = plan.cells[cell];
  if (!planned || planned.index !== cell) {
    refuse(
      at,
      "cell",
      `a cell this plan describes (0–${plan.cells.length - 1})`,
      cell,
      "no-such-cell",
      `This plan has no cell ${cell}, so the offer names nothing this peer could ` +
        "run."
    );
    return stop();
  }

  const chains = planChains(ctx.compiled);
  const mineDigest = await cellTextDigest(chains[cell]);
  const identified = await checkCellIdentity({
    at,
    cell,
    plan,
    manifest,
    mineDigest,
    refuse,
    offered: String(offer.cellDigest || ""),
  });
  if (!identified) return stop();

  if (planned.kind === "rendezvous") {
    refuse(
      at,
      "peer",
      "a cell placed on one peer",
      PEER_WILDCARD,
      "rendezvous",
      `Cell ${cell} is a rendezvous (\`${PEER_SIGIL}${PEER_WILDCARD}\`) in this ` +
        "notebook. Every participant enters it together and this build has no " +
        "barrier to enter it with, so accepting would mean running alone while " +
        "believing the room ran along. Refused rather than half-supported."
    );
    return stop();
  }
  if (!planned.mine) {
    refuse(
      at,
      "mine",
      "a cell this peer runs",
      planned.runsOn.join(", ") || "(everyone)",
      "not-mine",
      `Cell ${cell} is not this peer's to run: this plan says it runs on ` +
        `${planned.runsOn.map((p) => who(p)).join(" and ") || "everyone"}` +
        `${plan.me ? `, and this peer is ${who(plan.me)}` : ", and this plan does not know which peer this is"}. ` +
        "An offer does not say who runs a cell — the plan on this machine does, " +
        "and it says not you. Accepting would run somebody else's cell here on " +
        "the strength of their asking."
    );
    return stop();
  }

  // Both directions, as `checkInputs` does for pinned inputs: an offer missing
  // a slot the cell reads is one that cannot be run after accepting, and an
  // offer carrying a slot the cell does not read is a peer writing into this
  // registry through a cell that never asked.
  const runner = plan.me || planned.runsOn[0] || "";
  const wanted = slotsFromElsewhere(plan, cell, runner);
  const byLabel = new Map(wanted.map((row) => [row.label, row]));
  const offered = new Set((offer.needs || []).map((n) => slotLabelKey(String(n.label))));
  const types = slotTypes(ctx.compiled);

  for (const row of wanted) {
    if (offered.has(row.label)) continue;
    refuse(
      at,
      "needs",
      row.label,
      "",
      "incomplete",
      `Cell ${cell} reads ${slot(row.label)}, which cell ${row.from} writes on ` +
        `${who(row.peer)}, and this offer does not carry it. Accepting would ` +
        "register some of what the cell needs and leave the run to stop on the " +
        "rest, which is a worse place to stop than here."
    );
  }

  /** @type {{ label: string, value: import("./engine.js").PipelineValue }[]} */
  const bindings = [];
  for (const need of offer.needs || []) {
    const label = slotLabelKey(String(need.label));
    const row = byLabel.get(label);
    if (!row) {
      refuse(
        at,
        "needs",
        "",
        label,
        "unasked-slot",
        `This offer carries ${slot(label)}, and cell ${cell} does not read it ` +
          "from anywhere this peer cannot reach. Registering it would let a peer " +
          "put a value of their choosing into a slot of their choosing on this " +
          "machine, under cover of a cell that never asked for it."
      );
      continue;
    }
    if (ctx.hasSlot?.(label)) {
      refuse(
        at,
        "needs",
        `${label} unset`,
        `${label} already here`,
        "slot-present",
        `${slot(label)} already holds a value on this machine. Accepting would ` +
          "replace something this peer has with something a peer sent, and which " +
          "of the two is the right one is not a question an offer can answer. " +
          "Clear the slot if the offered value is the one you want."
      );
      continue;
    }
    // The same two guards the offerer ran, re-run against this peer's own plan
    // and this peer's own notebook. An offerer whose analysis was wrong, or
    // whose analysis was honest and whose notebook is not this one, does not
    // get to be the only thing standing between a private value and the wire.
    const verdict = publicEnough(row, types);
    if (!verdict.ok) {
      refuse(at, verdict.field, verdict.expected, verdict.actual, verdict.reason, verdict.message);
      continue;
    }
    bindings.push({ label, value: uncarry(need) });
  }

  if (list.length) return stop();
  bindings.sort((a, b) => a.label.localeCompare(b.label));
  return { ok: true, cell, refusals: list, bindings };
}

/**
 * What the offerer sees while an offer sits unanswered.
 *
 * **A declined offer and an ignored one are the same state here, and this says
 * so rather than inventing a third.** There is no decline message on the wire: a
 * peer who declines sends nothing and a peer who never looked sends nothing, and
 * a document saying "I declined" would be a claim the offerer could not check
 * against a peer who simply stayed quiet. What the offerer has is what the gate
 * already gave them — a run stopped at the slot this cell would have written,
 * naming the peer that holds it.
 *
 * @param {{ cell: number, peer: string, sent: number, slots?: string[] }} state
 * @returns {string}
 */
export function offerAwaiting(state) {
  const to = who(state.peer);
  const carried = (state.slots || []).length;
  return (
    `cell ${state.cell} offered to ${to}` +
    (state.sent ? "" : " — and nobody was reachable to take it") +
    (carried ? `, carrying ${carried} ${carried === 1 ? "value" : "values"}` : "") +
    ` · awaiting ${to}. Declined and unread look the same from here, and this ` +
    "run stays stopped at the cell that needed it either way."
  );
}

/**
 * A one-line human summary of an acceptance check — the shape `summarizePlan`,
 * `summarizeHonour` and `summarizeAttestation` return.
 * @param {Awaited<ReturnType<typeof acceptHandoffOffer>> |
 *   Awaited<ReturnType<typeof buildOfferFor>>} result
 * @returns {string}
 */
export function summarizeHandoff(result) {
  const list = result.refusals;
  if (!result.ok) {
    const first = list[0];
    const rest = list.length - 1;
    return `handoff refused at ${first.path} (${first.field})${
      rest > 0 ? ` and ${rest} more` : ""
    }`;
  }
  const offer = /** @type {*} */ (result).offer;
  const n = offer ? offer.needs.length : /** @type {*} */ (result).bindings.length;
  const cell = offer ? offer.cell : /** @type {*} */ (result).cell;
  return (
    `cell ${cell} ready — ${n} ${n === 1 ? "value" : "values"}, every one of them ` +
    "public, and nothing runs until somebody says so"
  );
}

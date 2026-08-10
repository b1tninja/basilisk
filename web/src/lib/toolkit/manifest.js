/**
 * Run manifests — the object a peer commits to *before* a shared notebook
 * runs, and the check that a run honoured that commitment.
 *
 * A manifest is `receipt.js`'s object pointing the other way. A receipt is an
 * observation: *here is what this run did*, as digests, written after the
 * outputs exist. A manifest is a promise: *here is what a run is going to do*,
 * agreed by everyone in the room before the Run button is live. Commit, run,
 * emit a receipt, and anyone holding both can check the second against the
 * first.
 *
 * **The machinery is `receipt.js`'s, not a copy of it.** `canonicalJson`,
 * `digestText`, `opsRegistryVersion()`, `unwrapCleartext`, `isoTimestamp` and
 * the `{path, field, expected, actual}` mismatch vocabulary are imported. A
 * second `canonicalJson` would be a second answer to "which bytes did we
 * sign", and that question must have exactly one — two implementations that
 * agree today would diverge on the first edge case either one learned about
 * alone, and the symptom would be a digest mismatch on an honest run.
 *
 * ## Pinned, declared, and the difference
 *
 * A receipt records the four things a build needs — source, inputs,
 * toolchain, outputs. A manifest carries the first three (it cannot carry
 * outputs; predicting them is not a commitment, it is a guess) and adds the
 * things that make a run *not* reproducible, so that they are visible rather
 * than silent:
 *
 * - **Pinned** — `recipeDigest`, per-cell `recipe`, `toolchain`, `inputs`.
 *   Checked against a receipt, digest for digest.
 * - **Declared** — `entropy`, `clock`, `vault`, `network`. Written down,
 *   surfaced by `manifestReproducibility`, and *not* verifiable from a receipt
 *   alone. A run that reads `hkp.get` depends on a directory's state at a
 *   moment; the manifest's job is to say so, not to pretend otherwise.
 *
 * ## What `manifestHonouredBy` proves, and what it does not
 *
 * It proves the run matches what was promised: same recipe, same cells in the
 * same order, same op registry, same receipt envelope, no runtime input that
 * was not pinned, and no timestamp earlier than a pinned clock's `t0`.
 *
 * It does **not** prove:
 *
 * - **That the computation was performed correctly.** A receipt is a claim
 *   about digests, made by whoever ran the cells. Proof of correct execution
 *   needs a zero-knowledge proof or a trusted execution environment; neither
 *   is in scope and neither is a dependency this repo will take.
 * - **That the manifest came first.** Nothing in either document is timestamped
 *   by a third party, so a manifest can be written after the fact to fit any
 *   receipt you like. Commit-before-run is established by *signing and
 *   exchanging* the manifest — the next unit's job — not by comparing it to a
 *   receipt. A pinned clock's `t0` is the one weak ordering fact available
 *   here, and it only rules out a receipt minted *before* the commitment.
 * - **That a pinned clock or a pooled entropy value was actually used.** No op
 *   reads either from a manifest today. `otp.code` has the `at=` parameter a
 *   pinned clock would flow into, and nothing flows into it. The declaration is
 *   a claim by the author, checkable only once the ops declare what they draw.
 * - **That the declared vault reach and network reads are complete.** A
 *   receipt does not echo them, and no static audit produces them yet.
 * - **Placement.** A receipt has no signer. Which peer ran a cell is
 *   attestation, and attestation needs a signature over a cell result.
 *
 * ## Whitespace is a precondition, not a bug
 *
 * `cells[].recipe` is compared as text, because that is the form a receipt
 * records. There is one right spelling and the kernel already picked it:
 * `appendRunLog` stores `serializeRecipe({ chains: [chain] })`, so a manifest's
 * cells must be built the same way or two authors who wrote the same pipeline
 * with different indentation will read as a mismatch. This module deliberately
 * does not normalise recipe text itself — a second normaliser beside
 * `serializeRecipe` is the same defect as a second `canonicalJson`.
 *
 * @module lib/toolkit/manifest
 */

import {
  RECEIPT_VERSION,
  canonicalJson,
  digestText,
  isoTimestamp,
  mismatchLog,
  opsRegistryVersion,
  unwrapCleartext,
} from "./receipt.js";
import { normalizeFingerprintInput } from "../pgp/verify-fpr.js";
import {
  PEER_WILDCARD,
  normalizePeerRef,
  peerFingerprintError,
  peerLooksLikeFingerprint,
} from "./recipe-parse.js";

/**
 * Manifest envelope version. Bump when the *shape* changes.
 *
 * Independent of `RECEIPT_VERSION`: the two documents version separately
 * because they break separately, and `toolchain.receipt` is where a manifest
 * records which receipt envelope it expects a run to produce.
 */
export const MANIFEST_VERSION = 1;

/**
 * How a run gets its randomness.
 *
 * - `none` — the run draws none. The only mode under which two runs can be
 *   compared digest for digest.
 * - `pool` — a value every participant helped choose and can recompute, hashed
 *   into `entropy.digest`. Public-safe randomness only: salts, nonces, IVs,
 *   challenges.
 * - `local` — each machine draws its own. Honest, and not reproducible.
 *
 * **The refusal this list exists for is not implemented, and this is where it
 * will land.** Shared entropy must never reach key generation — if everyone can
 * recompute the key, nobody has a private key. Enforcing that needs the
 * registry to say, per op, whether the randomness an op draws is public-safe or
 * keying, and today `registry.js` says nothing about entropy at all. Until it
 * does, `pool` is a declaration no code can honour, and
 * `manifestReproducibility` treats it as such.
 * @type {readonly string[]}
 */
export const ENTROPY_MODES = Object.freeze(["none", "pool", "local"]);

/**
 * How a run gets the time.
 *
 * - `pinned` — one agreed `t0` for the whole run, so a clock-reading op is a
 *   function of the manifest rather than of when you pressed Run.
 * - `free` — the run reads the wall clock, and is not reproducible.
 * @type {readonly string[]}
 */
export const CLOCK_MODES = Object.freeze(["pinned", "free"]);

/**
 * Domain separators for the two audience digests.
 *
 * These exist so that neither digest is the room key. `notebook/room.js`
 * derives a room from `SHA-256(rpId | fpr | fpr | …)` and truncates it; the
 * room key *is* a digest of the audience, and admission to the group where
 * signalling is broadcast is exactly "can you compute it". A manifest that
 * published the audience digest under room.js's own preimage would hand the
 * room to anyone holding the manifest — the leak that carrying `audienceSha`
 * instead of a list of fingerprints was supposed to prevent. Different
 * preimage, different digest, no admission.
 */
const PEERS_DOMAIN = "basilisk.run-manifest/peers/v1\n";
const AUDIENCE_DOMAIN = "basilisk.run-manifest/audience/v1\n";

/**
 * @typedef {object} ManifestCell
 * @property {number} index          cell position in the notebook
 * @property {string} peer           chain-header peer label, `*`, or "" for everyone
 * @property {boolean} publish       this cell's `out` artifacts are meant to leave the machine
 * @property {string} recipe         the cell's recipe text, as it will be run
 * @property {string} recipeDigest   digest of `recipe`, so one cell can be
 *   attested without holding the whole notebook
 */

/**
 * A runtime input the manifest pins. The vocabulary is `digestInputs`' —
 * `channel` and `index` are its words, not new ones.
 * @typedef {object} ManifestInput
 * @property {number} cell
 * @property {string} channel
 * @property {number} [index]
 * @property {string} digest
 * @property {number} [length]
 */

/** @typedef {{ mode: string, digest?: string }} ManifestEntropy */
/** @typedef {{ mode: string, t0?: string }} ManifestClock */
/** @typedef {{ cell: number, keyId: string, kind: string, use: string }} ManifestVaultReach */
/** @typedef {{ cell: number, host: string, path: string }} ManifestNetworkRead */

/**
 * @typedef {object} RunManifest
 * @property {number} v
 * @property {"basilisk.run-manifest"} kind
 * @property {string} title
 * @property {string} recipeSource   full notebook recipe text, as it will be run
 * @property {string} recipeDigest
 * @property {ManifestCell[]} cells
 * @property {string[]} peers        labels, sorted — never fingerprints
 * @property {string} peersSha       digest of the label→fingerprint binding
 * @property {string} audienceSha    digest of the audience, never the audience
 * @property {{ ops: string, receipt: number }} toolchain
 * @property {ManifestEntropy} entropy
 * @property {ManifestClock} clock
 * @property {ManifestVaultReach[]} vault
 * @property {ManifestNetworkRead[]} network
 * @property {ManifestInput[]} inputs
 */

/**
 * What kind of cell this is, derived from the one field that decides it.
 *
 * Stored as `peer` and read as a kind, rather than stored as both: `witnessed`
 * / `placed` / `rendezvous` is a reading of who a cell is written for, and two
 * fields that must agree are two chances to disagree.
 *
 * @param {{ peer?: string }} cell
 * @returns {"witnessed"|"placed"|"rendezvous"}
 */
export function cellKind(cell) {
  const peer = String(cell?.peer || "");
  if (!peer) return "witnessed";
  return peer === PEER_WILDCARD ? "rendezvous" : "placed";
}

/**
 * Digest the peer-label → fingerprint binding without publishing it.
 *
 * Everyone in the room can confirm they agree about who is who; a bystander
 * holding the manifest learns some labels and nothing else. The labels
 * themselves are checked against the same refusal `validateRecipe` applies to
 * a chain header — a fingerprint written where a name belongs is refused here
 * too, because a manifest travels at least as far as recipe text does.
 *
 * @param {Record<string, string>} peers  label → fingerprint
 * @returns {Promise<string>}
 */
export async function peersDigest(peers) {
  /** @type {Record<string, string>} */
  const binding = {};
  for (const [label, fpr] of Object.entries(peers || {})) {
    binding[assertPeerLabel(label)] = normalizeFingerprintInput(fpr);
  }
  // canonicalJson sorts the keys, so the digest does not depend on the order
  // the room was assembled in.
  return digestText(PEERS_DOMAIN + canonicalJson(binding));
}

/**
 * Digest the audience — the set of fingerprints, sorted and deduped, and never
 * the set itself.
 * @param {string[]} fingerprints
 * @returns {Promise<string>}
 */
export async function audienceDigest(fingerprints) {
  const set = new Set();
  for (const raw of fingerprints || []) {
    const fpr = normalizeFingerprintInput(raw);
    if (fpr) set.add(fpr);
  }
  return digestText(AUDIENCE_DOMAIN + canonicalJson([...set].sort()));
}

/**
 * @param {string} label
 * @returns {string} the canonical label
 */
function assertPeerLabel(label) {
  const norm = normalizePeerRef(String(label ?? ""));
  if (!norm.ok) throw new Error(`manifest: ${norm.error}`);
  if (peerLooksLikeFingerprint(norm.peer)) {
    throw new Error(`manifest: ${peerFingerprintError(norm.peer)}`);
  }
  return norm.peer;
}

/**
 * Assemble a manifest. Async only because of the digests.
 *
 * `cells` is given, not derived: a manifest names the cells a *notebook* will
 * run, and `recipeChains` already answers "what are this recipe's chains".
 * Calling it here would put a second reading of the recipe inside a document
 * whose whole value is that it agrees with the first one.
 *
 * @param {{
 *   title?: string,
 *   recipeSource?: string,
 *   cells?: { index?: number, peer?: string, publish?: boolean, recipe?: string }[],
 *   peers?: Record<string, string>,
 *   audience?: string[],
 *   registry?: string,
 *   entropy?: { mode?: string, digest?: string },
 *   clock?: { mode?: string, t0?: string|number|Date },
 *   vault?: ManifestVaultReach[],
 *   network?: ManifestNetworkRead[],
 *   inputs?: ManifestInput[],
 * }} spec
 * @returns {Promise<RunManifest>}
 */
export async function buildRunManifest(spec = {}) {
  const recipeSource = String(spec.recipeSource ?? "");
  const peers = spec.peers || {};
  const labels = Object.keys(peers).map(assertPeerLabel).sort();

  /** @type {ManifestCell[]} */
  const cells = [];
  const given = spec.cells || [];
  for (let i = 0; i < given.length; i++) {
    const c = given[i];
    const recipe = String(c.recipe ?? "");
    const peer = c.peer ? String(c.peer) : "";
    cells.push({
      index: Number(c.index) || 0,
      peer: peer && peer !== PEER_WILDCARD ? assertPeerLabel(peer) : peer,
      publish: !!c.publish,
      recipe,
      recipeDigest: await digestText(recipe),
    });
  }

  const entropyMode = String(spec.entropy?.mode || "local");
  /** @type {ManifestEntropy} */
  const entropy = { mode: entropyMode };
  if (spec.entropy?.digest) entropy.digest = String(spec.entropy.digest);

  const clockMode = String(spec.clock?.mode || "free");
  /** @type {ManifestClock} */
  const clock = { mode: clockMode };
  if (spec.clock?.t0 != null && spec.clock.t0 !== "") {
    clock.t0 = isoTimestamp(spec.clock.t0);
  }

  return {
    v: MANIFEST_VERSION,
    kind: "basilisk.run-manifest",
    title: String(spec.title || "Untitled notebook"),
    recipeSource,
    recipeDigest: await digestText(recipeSource),
    cells,
    peers: labels,
    peersSha: await peersDigest(peers),
    audienceSha: await audienceDigest(spec.audience || Object.values(peers)),
    toolchain: {
      ops: String(spec.registry || opsRegistryVersion()),
      receipt: RECEIPT_VERSION,
    },
    entropy,
    clock,
    vault: (spec.vault || []).map((r) => ({
      cell: Number(r.cell) || 0,
      // Not truncated to a short key id. `d8d941b` is the reason: a short id
      // two keys claim resolves to neither, and an audit trail that names an
      // ambiguous key is worse than one that names none. The cost is that a
      // vault key id is key-identifying material, so a manifest is a
      // room-internal document — do not hand one to a bystander.
      keyId: String(r.keyId ?? ""),
      kind: String(r.kind ?? ""),
      use: String(r.use ?? ""),
    })),
    network: (spec.network || []).map((r) => ({
      cell: Number(r.cell) || 0,
      host: String(r.host ?? ""),
      path: String(r.path ?? ""),
    })),
    inputs: (spec.inputs || []).map((r) => {
      /** @type {ManifestInput} */
      const row = {
        cell: Number(r.cell) || 0,
        channel: String(r.channel ?? ""),
        digest: String(r.digest ?? ""),
      };
      if (r.index != null) row.index = Number(r.index);
      if (r.length != null) row.length = Number(r.length);
      return row;
    }),
  };
}

/**
 * Canonical bytes of a manifest — what gets signed, and what its digest covers.
 * @param {RunManifest} manifest
 * @returns {string}
 */
export function manifestToJson(manifest) {
  return canonicalJson(manifest);
}

/**
 * The digest every later message references. Changing any field changes it,
 * which is the point.
 * @param {RunManifest} manifest
 * @returns {Promise<string>}
 */
export async function manifestDigest(manifest) {
  return digestText(manifestToJson(manifest));
}

/**
 * Parse a manifest out of text, tolerating an OpenPGP cleartext wrapper — a
 * manifest is meant to be signed, so the signed form must be the one you can
 * hand straight back.
 * @param {string} text
 * @returns {RunManifest}
 */
export function parseManifest(text) {
  const body = unwrapCleartext(text, "manifest");
  /** @type {*} */
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    throw new Error("manifest: not JSON (expected a Basilisk run manifest)");
  }
  if (!parsed || parsed.kind !== "basilisk.run-manifest") {
    throw new Error("manifest: not a Basilisk run manifest");
  }
  if (Number(parsed.v) !== MANIFEST_VERSION) {
    throw new Error(`manifest: unsupported version ${parsed.v}`);
  }
  return /** @type {RunManifest} */ (parsed);
}

/**
 * Can this manifest's run be checked digest for digest, and if not, why not?
 *
 * Reads only the declared fields — this answers "what did the author say",
 * never "what will the engine do". The gap between those two is the entropy
 * audit `ENTROPY_MODES` describes: until an op declares whether the randomness
 * it draws is public-safe or keying, nothing can contradict a declaration here.
 *
 * @param {RunManifest} manifest
 * @returns {{ reproducible: boolean, reasons: string[] }}
 */
export function manifestReproducibility(manifest) {
  /** @type {string[]} */
  const reasons = [];
  const entropy = manifest?.entropy || { mode: "" };
  const mode = String(entropy.mode || "");
  if (mode === "pool") {
    reasons.push(
      `entropy: pool ${short(entropy.digest)} — no op declares whether its ` +
        "randomness may be seeded, so a pool cannot be honoured by this build yet"
    );
  } else if (mode === "local") {
    reasons.push("entropy: local — each machine draws its own, so digests will differ");
  } else if (mode !== "none") {
    // Omission and nonsense both land here, and both fail closed: an
    // undeclared source of randomness is treated as an unseedable one.
    reasons.push(`entropy: "${mode}" is not a declared mode — treated as local`);
  }

  const clock = manifest?.clock || { mode: "" };
  if (String(clock.mode) !== "pinned") {
    reasons.push("clock: free — an op that reads the clock re-runs to a different digest");
  } else if (!clock.t0) {
    reasons.push("clock: pinned with no t0 — nothing was actually pinned");
  }

  for (const r of manifest?.network || []) {
    reasons.push(
      `network: cell ${r.cell} reads ${r.host}${r.path} — a directory's state at a moment`
    );
  }
  for (const r of manifest?.vault || []) {
    reasons.push(
      `vault: cell ${r.cell} reaches key ${r.keyId} to ${r.use} — the material is not in the manifest and cannot be`
    );
  }
  return { reproducible: reasons.length === 0, reasons };
}

/** @param {string} [digest] */
function short(digest) {
  const s = String(digest || "");
  return s ? `${s.slice(0, 12)}…` : "(none)";
}

/**
 * Did this run honour the manifest it was committed to?
 *
 * Reports in `compareReceipts`' vocabulary — `{path, field, expected, actual}`
 * — because "the run and its description disagree, here" is one idea and
 * deserves one spelling. `expected` is always the manifest's side; `actual` is
 * always the receipt's.
 *
 * Read the module header before trusting the answer. In particular a `true`
 * here means *the run matches what was promised*, not *the run was correct*
 * and not *the promise was made first*.
 *
 * @param {RunManifest} manifest
 * @param {import("./receipt.js").RunReceipt} receipt
 * @returns {{ ok: boolean, mismatches: import("./receipt.js").ReceiptMismatch[],
 *   checked: number, declared: string[] }}
 */
export function manifestHonouredBy(manifest, receipt) {
  const log = mismatchLog();

  log.compare("manifest", "recipeDigest", manifest?.recipeDigest, receipt?.recipeDigest);
  log.compare("manifest", "registry", manifest?.toolchain?.ops, receipt?.registry);
  log.compare("manifest", "receiptVersion", manifest?.toolchain?.receipt, receipt?.v);

  const declaredCells = manifest?.cells || [];
  const ranCells = receipt?.cells || [];
  if (declaredCells.length !== ranCells.length) {
    log.note("manifest", "cells", declaredCells.length, ranCells.length);
  }
  const n = Math.min(declaredCells.length, ranCells.length);
  for (let i = 0; i < n; i++) {
    const label = `cell ${declaredCells[i].index ?? i}`;
    log.compare(label, "index", declaredCells[i].index, ranCells[i].index);
    log.compare(label, "recipe", declaredCells[i].recipe, ranCells[i].recipe);
  }

  checkInputs(log, manifest, ranCells);
  checkClock(log, manifest, receipt, ranCells);

  return { ...log.result(), declared: manifestReproducibility(manifest).reasons };
}

/**
 * Every runtime input the run consumed must be one the manifest pinned, and
 * every input the manifest pinned must be one the run consumed.
 *
 * Both directions, because each catches a different lie. A changed digest says
 * a different value was bound to a declared channel; an *undeclared* row says a
 * value entered the computation from outside the manifest entirely, which is
 * the one a one-directional check would wave through.
 *
 * Matched on `cell`/`channel`/`index` rather than on position, so a run that
 * binds the same channels in a different order is not reported as four
 * mismatches when it has none.
 *
 * @param {ReturnType<typeof mismatchLog>} log
 * @param {RunManifest} manifest
 * @param {import("./receipt.js").ReceiptCell[]} ranCells
 */
function checkInputs(log, manifest, ranCells) {
  /** @param {number} cell @param {string} channel @param {*} index */
  const key = (cell, channel, index) =>
    `${cell} ${channel} ${index == null ? "" : index}`;
  /** @param {number} cell @param {string} channel @param {*} index */
  const path = (cell, channel, index) =>
    `cell ${cell} · input ${channel}${index == null ? "" : ` ${index}`}`;

  /** @type {Map<string, { cell: number, channel: string, index: *, digest: string }>} */
  const ran = new Map();
  for (let i = 0; i < ranCells.length; i++) {
    const cell = ranCells[i].index ?? i;
    for (const row of ranCells[i].inputs || []) {
      ran.set(key(cell, String(row.channel ?? ""), row.index), {
        cell,
        channel: String(row.channel ?? ""),
        index: row.index,
        digest: String(row.digest ?? ""),
      });
    }
  }

  const seen = new Set();
  for (const row of manifest?.inputs || []) {
    const k = key(Number(row.cell) || 0, String(row.channel ?? ""), row.index);
    seen.add(k);
    const hit = ran.get(k);
    const where = path(Number(row.cell) || 0, String(row.channel ?? ""), row.index);
    if (!hit) {
      log.note(where, "missing", row.digest, "");
      continue;
    }
    log.compare(where, "digest", row.digest, hit.digest);
  }
  for (const [k, row] of ran) {
    if (seen.has(k)) continue;
    log.note(path(row.cell, row.channel, row.index), "undeclared", "", row.digest);
  }
}

/**
 * A pinned clock is the only ordering fact these two documents carry.
 *
 * It cannot show that ops read `t0` instead of the wall clock — nothing wires
 * that yet — so what is checked is the one thing that follows from a pin
 * regardless: a run cannot have started before the commitment it claims to
 * honour. `free` asserts nothing at all, which is what "declared
 * clock-dependent" means.
 *
 * `compareReceipts` refuses to treat timestamps as evidence, and is right to:
 * two honest runs differ in `createdAt` by construction. This is not that
 * comparison. It is a bound, in one direction, against a value the manifest
 * fixed in advance.
 *
 * @param {ReturnType<typeof mismatchLog>} log
 * @param {RunManifest} manifest
 * @param {import("./receipt.js").RunReceipt} receipt
 * @param {import("./receipt.js").ReceiptCell[]} ranCells
 */
function checkClock(log, manifest, receipt, ranCells) {
  const clock = manifest?.clock || { mode: "" };
  if (String(clock.mode) !== "pinned") return;
  const t0 = Date.parse(String(clock.t0 ?? ""));
  if (!Number.isFinite(t0)) {
    log.note("manifest", "clock", "a pinned t0", String(clock.t0 ?? ""));
    return;
  }
  /** @param {string} where @param {*} stamp */
  const notBefore = (where, stamp) => {
    const s = String(stamp ?? "");
    if (!s) return;
    const t = Date.parse(s);
    log.assert(
      where,
      "clock",
      Number.isFinite(t) && t >= t0,
      `not before ${clock.t0}`,
      s
    );
  };
  notBefore("manifest", receipt?.createdAt);
  for (let i = 0; i < ranCells.length; i++) {
    notBefore(`cell ${ranCells[i].index ?? i}`, ranCells[i].startedAt);
  }
}

/**
 * A one-line human summary, for a status line or a tile.
 * @param {ReturnType<typeof manifestHonouredBy>} result
 * @returns {string}
 */
export function summarizeHonour(result) {
  const caveat = result.declared.length
    ? ` — ${result.declared.length} declared non-reproducible ${
        result.declared.length === 1 ? "dependency" : "dependencies"
      }`
    : "";
  if (result.ok) {
    return `manifest honoured — ${result.checked} facts matched${caveat}`;
  }
  const first = result.mismatches[0];
  const rest = result.mismatches.length - 1;
  return `manifest not honoured at ${first.path} (${first.field})${
    rest > 0 ? ` and ${rest} more` : ""
  }`;
}

/**
 * Run receipts — a signable, verifiable record of *what a notebook run did*,
 * carrying digests instead of values.
 *
 * The problem this exists for: a key ceremony produces shares that nobody may
 * see twice, so "did the ceremony actually do what the recipe says" cannot be
 * answered by keeping the outputs around. A receipt answers it by keeping
 * SHA-256 digests of every cell's inputs and outputs, the recipe source that
 * produced them, timestamps, and the op-registry version — and nothing else.
 * Sign it with `gpg.sign`, hand it to a witness, and a later re-run can be
 * checked against it without either party revealing a secret.
 *
 * **A receipt never contains a value.** `digestArtifact` reads `content` and
 * emits only its digest and byte length; the same holds for runtime inputs.
 * That is the invariant every other function here depends on, so if you add a
 * field, add it to `SAFE_ARTIFACT_FIELDS` deliberately, not by spreading the
 * artifact.
 *
 * Determinism note, stated plainly: a recipe with `random` / `genkey` in it
 * will not re-produce the same digests, and comparison will say so. That is
 * correct — a receipt proves *this* run happened, and only a deterministic
 * stretch of pipeline (recombine a known secret, re-derive a known key) can be
 * re-verified digest-for-digest. The ceremony flow's verification step relies
 * on exactly that deterministic stretch.
 *
 * @module lib/toolkit/receipt
 */

import { listSteps } from "./registry.js";

/**
 * Receipt envelope version. Bump when the *shape* changes, not the content.
 *
 * v2 (§38c, design_handoff_artifact_actions): artifact `role` is part of
 * `digestArtifact`, and roles are now stamped from the type projection where
 * an emit site declared none — so a keypair that digested as `secret` under v1
 * digests as `key` under v2. The run is unchanged; only its description is.
 * Without the bump, `run.verify` would report a digest mismatch on a receipt
 * that is in fact perfectly good, which is the worst possible failure for a
 * tool whose job is telling you whether to trust a run.
 */
export const RECEIPT_VERSION = 2;

/**
 * Artifact fields a receipt may carry. Everything else — above all `content`,
 * `bytes`, and `inspectSnapshot` — is deliberately dropped.
 * @type {readonly string[]}
 */
export const SAFE_ARTIFACT_FIELDS = Object.freeze([
  "label",
  "filename",
  "role",
  "stepName",
  "sensitive",
  "shareIndex",
  "length",
  "digest",
]);

const encoder = new TextEncoder();

/**
 * Deterministic JSON, in the RFC 8785 spirit: object keys sorted by code unit,
 * no insignificant whitespace, arrays in order.
 *
 * Deliberately a *subset* of JCS rather than a claim to implement it — the
 * receipt only ever holds strings, integers, booleans, null, arrays, and plain
 * objects, so the parts of JCS that are hard (float formatting, lone
 * surrogates) cannot arise here. Non-finite numbers throw rather than
 * silently becoming `null`, because a receipt that quietly loses a field is
 * worse than one that fails to build.
 *
 * @param {*} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalJson: non-finite number");
    }
    return JSON.stringify(value);
  }
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  }
  if (t === "object") {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(",")}}`;
  }
  throw new Error(`canonicalJson: unsupported ${t}`);
}

/**
 * A stable fingerprint of the op registry: every step name plus its parameter
 * names and enum values, hashed.
 *
 * Derived from `listSteps()` rather than hand-maintained, for the same reason
 * the type docs are: a hand-written version string records what someone
 * remembered to bump, and this records what the registry actually offers. If
 * an op gains a parameter between the ceremony and the audit, the receipt says
 * so.
 *
 * FNV-1a rather than SHA-256 because this must be synchronous (it is read
 * during registry-shaped code paths that are not async) and it is an integrity
 * *label*, not a security boundary — the signature over the whole receipt is
 * what makes it tamper-evident.
 *
 * @returns {string}
 */
export function opsRegistryVersion() {
  const parts = listSteps()
    .map((s) => {
      const params = (s.params || [])
        .map((p) => `${p.name}:${p.type}${p.enum ? `(${[...p.enum].sort().join("|")})` : ""}`)
        .sort()
        .join(",");
      return `${s.name}[${params}]`;
    })
    .sort()
    .join(";");
  let h = 0x811c9dc5;
  for (let i = 0; i < parts.length; i++) {
    h ^= parts.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  const count = listSteps().length;
  return `ops-${count}-${h.toString(16).padStart(8, "0")}`;
}

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<string>} lowercase hex SHA-256
 */
export async function sha256Hex(bytes) {
  const out = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let s = "";
  for (const b of out) s += b.toString(16).padStart(2, "0");
  return s;
}

/**
 * Digest a string as UTF-8.
 * @param {string} text
 * @returns {Promise<string>}
 */
export async function digestText(text) {
  return sha256Hex(encoder.encode(String(text ?? "")));
}

/**
 * Reduce an artifact tile to its receipt row — digest and shape, never body.
 * @param {{ label?: string, filename?: string, role?: string, stepName?: string,
 *   sensitive?: boolean, shareIndex?: number, content?: string }} art
 * @returns {Promise<Record<string, *>>}
 */
export async function digestArtifact(art) {
  const content = String(art?.content ?? "");
  /** @type {Record<string, *>} */
  const row = {
    label: String(art?.label ?? ""),
    filename: String(art?.filename ?? ""),
    role: art?.role ? String(art.role) : "",
    stepName: art?.stepName ? String(art.stepName) : "",
    sensitive: !!art?.sensitive,
    length: encoder.encode(content).length,
    digest: await digestText(content),
  };
  if (art?.shareIndex != null) row.shareIndex = Number(art.shareIndex);
  return row;
}

/**
 * Digest the runtime inputs a cell was given.
 *
 * Runtime inputs never appear in recipe text (that is the whole point of the
 * Inputs panel), so without this a receipt would describe only half of what
 * determined the outputs. Each entry names the channel and digests its value;
 * share mnemonics are digested individually so a receipt can record *which*
 * shares were used without recording them.
 *
 * @param {import("./engine.js").RuntimeBindings["inputs"]} inputs
 * @returns {Promise<Record<string, *>[]>}
 */
export async function digestInputs(inputs) {
  /** @type {Record<string, *>[]} */
  const rows = [];
  if (!inputs) return rows;
  const text = inputs.text?.value;
  if (text) {
    rows.push({ channel: "text", digest: await digestText(text) });
  }
  const armored = inputs.envelope?.armored;
  if (armored) {
    rows.push({ channel: "envelope", digest: await digestText(armored) });
  }
  for (const msg of inputs.gpg?.armoredMessages || []) {
    if (msg) rows.push({ channel: "gpg", digest: await digestText(msg) });
  }
  const mnemonics = inputs.shares?.mnemonics || [];
  for (let i = 0; i < mnemonics.length; i++) {
    const m = String(mnemonics[i] || "").trim();
    if (!m) continue;
    rows.push({ channel: "shares", index: i + 1, digest: await digestText(m) });
  }
  const keypair = /** @type {*} */ (inputs).keypair?.value;
  if (keypair) {
    rows.push({ channel: "keypair", digest: await digestText(keypair) });
  }
  return rows;
}

/**
 * @typedef {object} ReceiptCell
 * @property {number} index          cell position in the notebook
 * @property {string} recipe         that cell's recipe source
 * @property {string} [startedAt]    ISO timestamp
 * @property {number} [durationMs]
 * @property {Record<string, *>[]} inputs   digested runtime inputs
 * @property {Record<string, *>[]} outputs  digested artifact tiles
 */

/**
 * @typedef {object} RunReceipt
 * @property {number} v
 * @property {"basilisk.run-receipt"} kind
 * @property {string} label          ceremony / notebook label
 * @property {string} createdAt      ISO
 * @property {string} registry       opsRegistryVersion()
 * @property {string} recipeSource   full notebook recipe text
 * @property {string} recipeDigest   digest of recipeSource
 * @property {ReceiptCell[]} cells
 */

/**
 * Assemble a receipt. Pure apart from the digest of `recipeSource`.
 *
 * @param {{
 *   label?: string,
 *   createdAt?: string|number|Date,
 *   registry?: string,
 *   recipeSource?: string,
 *   cells?: ReceiptCell[],
 * }} spec
 * @returns {Promise<RunReceipt>}
 */
export async function buildRunReceipt(spec = {}) {
  const recipeSource = String(spec.recipeSource ?? "");
  const createdAt =
    spec.createdAt instanceof Date
      ? spec.createdAt.toISOString()
      : typeof spec.createdAt === "number"
        ? new Date(spec.createdAt).toISOString()
        : String(spec.createdAt || new Date().toISOString());
  return {
    v: RECEIPT_VERSION,
    kind: "basilisk.run-receipt",
    label: String(spec.label || "Untitled notebook"),
    createdAt,
    registry: String(spec.registry || opsRegistryVersion()),
    recipeSource,
    recipeDigest: await digestText(recipeSource),
    cells: (spec.cells || []).map((c) => ({
      index: Number(c.index) || 0,
      recipe: String(c.recipe ?? ""),
      startedAt: c.startedAt ? String(c.startedAt) : undefined,
      durationMs: c.durationMs != null ? Number(c.durationMs) : undefined,
      inputs: c.inputs || [],
      outputs: c.outputs || [],
    })),
  };
}

/**
 * Canonical bytes of a receipt — what gets signed, and what a verifier hashes.
 * @param {RunReceipt} receipt
 * @returns {string}
 */
export function receiptToJson(receipt) {
  return canonicalJson(receipt);
}

/**
 * Parse a receipt out of text, tolerating an OpenPGP cleartext wrapper.
 *
 * A signed receipt arrives as `-----BEGIN PGP SIGNED MESSAGE-----` with the
 * JSON in the body, and asking the user to strip that by hand before
 * verifying would make the signed form less useful than the unsigned one.
 * Signature validity is `gpg.verify`'s job — this only finds the payload.
 *
 * @param {string} text
 * @returns {RunReceipt}
 */
export function parseReceipt(text) {
  const raw = String(text ?? "").trim();
  if (!raw) throw new Error("receipt: empty");
  let body = raw;
  if (/^-----BEGIN PGP SIGNED MESSAGE-----/.test(raw)) {
    const start = raw.indexOf("\n\n");
    const sig = raw.indexOf("-----BEGIN PGP SIGNATURE-----");
    if (start < 0 || sig < 0) throw new Error("receipt: malformed cleartext signature");
    body = raw.slice(start + 2, sig).trim();
    // Cleartext signatures dash-escape lines beginning with "-".
    body = body.replace(/^- /gm, "");
  }
  /** @type {*} */
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (_) {
    throw new Error("receipt: not JSON (expected a Basilisk run receipt)");
  }
  if (!parsed || parsed.kind !== "basilisk.run-receipt") {
    throw new Error("receipt: not a Basilisk run receipt");
  }
  if (Number(parsed.v) === 1) {
    // Name the reason rather than the number. A v1 receipt is not corrupt and
    // its run was not wrong; this build simply describes artifacts
    // differently, so no honest comparison is possible.
    throw new Error(
      "receipt: this receipt predates a change in how artifact roles are recorded (v1). " +
        "Its run was not necessarily different — the description was. Re-run the recipe to get a comparable receipt."
    );
  }
  if (Number(parsed.v) !== RECEIPT_VERSION) {
    throw new Error(`receipt: unsupported version ${parsed.v}`);
  }
  return /** @type {RunReceipt} */ (parsed);
}

/**
 * @typedef {object} ReceiptMismatch
 * @property {string} path   human-readable location ("cell 1 · output 2")
 * @property {string} field
 * @property {string} expected
 * @property {string} actual
 */

/**
 * Compare a claimed receipt against one built from a re-run.
 *
 * Digests only — never values, and never timestamps. Two honest runs of the
 * same ceremony differ in `createdAt` and `durationMs` by construction, so
 * treating those as evidence would make every verification fail. What must
 * match is the recipe, the registry the ops came from, and every input and
 * output digest, in order.
 *
 * @param {RunReceipt} claimed
 * @param {RunReceipt} actual
 * @returns {{ ok: boolean, mismatches: ReceiptMismatch[], checked: number }}
 */
export function compareReceipts(claimed, actual) {
  /** @type {ReceiptMismatch[]} */
  const mismatches = [];
  let checked = 0;
  /** @param {string} path @param {string} field @param {*} a @param {*} b */
  const cmp = (path, field, a, b) => {
    checked++;
    if (String(a ?? "") !== String(b ?? "")) {
      mismatches.push({
        path,
        field,
        expected: String(a ?? ""),
        actual: String(b ?? ""),
      });
    }
  };

  cmp("receipt", "recipeDigest", claimed?.recipeDigest, actual?.recipeDigest);
  cmp("receipt", "registry", claimed?.registry, actual?.registry);

  const a = claimed?.cells || [];
  const b = actual?.cells || [];
  if (a.length !== b.length) {
    checked++;
    mismatches.push({
      path: "receipt",
      field: "cells",
      expected: String(a.length),
      actual: String(b.length),
    });
  }
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const label = `cell ${a[i].index ?? i}`;
    cmp(label, "recipe", a[i].recipe, b[i].recipe);
    const ai = a[i].inputs || [];
    const bi = b[i].inputs || [];
    if (ai.length !== bi.length) {
      checked++;
      mismatches.push({
        path: label,
        field: "inputs",
        expected: String(ai.length),
        actual: String(bi.length),
      });
    }
    for (let j = 0; j < Math.min(ai.length, bi.length); j++) {
      cmp(`${label} · input ${j + 1}`, "digest", ai[j].digest, bi[j].digest);
    }
    const ao = a[i].outputs || [];
    const bo = b[i].outputs || [];
    if (ao.length !== bo.length) {
      checked++;
      mismatches.push({
        path: label,
        field: "outputs",
        expected: String(ao.length),
        actual: String(bo.length),
      });
    }
    for (let j = 0; j < Math.min(ao.length, bo.length); j++) {
      cmp(`${label} · output ${j + 1}`, "digest", ao[j].digest, bo[j].digest);
    }
  }
  return { ok: mismatches.length === 0, mismatches, checked };
}

/**
 * A one-line human summary of a comparison, for a status line or a tile.
 * @param {ReturnType<typeof compareReceipts>} result
 * @returns {string}
 */
export function summarizeComparison(result) {
  if (result.ok) {
    return `receipt verified — ${result.checked} digests matched`;
  }
  const first = result.mismatches[0];
  const rest = result.mismatches.length - 1;
  return `receipt mismatch at ${first.path} (${first.field})${
    rest > 0 ? ` and ${rest} more` : ""
  }`;
}

/**
 * Compare two secrets *without revealing either*: digest both and compare the
 * digests.
 *
 * This is the ceremony's verification step in one function. After a split, you
 * want to know that K shares really do recombine to the original master —
 * but printing the recovered master onto the screen to eyeball it against the
 * original defeats the ceremony. Digesting both sides answers the question
 * with a boolean and leaks nothing beyond "these are/aren't the same bytes",
 * which the user already knows they are asking.
 *
 * Comparison is length-then-constant-time over the two digest strings. The
 * digests are public-safe by construction, so this is belt-and-braces rather
 * than load-bearing, but a timing-variable compare here would be an odd thing
 * to leave in a key ceremony.
 *
 * @param {Uint8Array|string} a
 * @param {Uint8Array|string} b
 * @returns {Promise<{ match: boolean, digestA: string, digestB: string }>}
 */
export async function compareSecretsByDigest(a, b) {
  const digestA = typeof a === "string" ? await digestText(a) : await sha256Hex(a);
  const digestB = typeof b === "string" ? await digestText(b) : await sha256Hex(b);
  return { match: constantTimeEqual(digestA, digestB), digestA, digestB };
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function constantTimeEqual(a, b) {
  const x = String(a);
  const y = String(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) {
    diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Verifiable secret sharing ops — `vss.split` / `vss.verify` / `vss.combine`.
 *
 * The difference from `sss.*` in one line: an `sss` share must be trusted, a
 * `vss` share can be checked. The dealer publishes commitments alongside the
 * shares, so a custodian can confirm on the spot that the share they were
 * handed belongs to the same polynomial as everyone else's — before the room
 * empties and it is too late to find out whose share was wrong.
 *
 * Shares are emitted in the **same `shares` shape `sss.split` uses**, so the
 * existing machinery composes untouched:
 *
 *     vss.split threshold=2 shares=3 | blip39 | foreach
 *       - out @share
 *
 * The commitments ride along on the share set (and are public — publishing
 * them is the point), so a set that survives a `blip39` round trip can still
 * be verified.
 *
 * Constraint worth knowing before reaching for these: the secret is one
 * scalar on P-256, so it must be ≤ 32 bytes. Arbitrary-length data still
 * belongs in `sss.split`, which shares byte-wise over GF(256) — a field where
 * verifiability is impossible, because its multiplicative group has order 255
 * and the discrete log that hides the secret is a table lookup.
 * @module lib/toolkit/vss-ops
 */

import {
  ORDER,
  combine,
  deal,
  publicKeyOf,
  scalarFromHex,
  scalarToHex,
  verify,
} from "../quorum/vss.js";

/** @param {Uint8Array} b */
function bytesToHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** @param {string} hex @returns {Uint8Array} */
function hexToBytes(hex) {
  const clean = hex.length % 2 ? `0${hex}` : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * @param {{ type: string, data: unknown, meta?: Record<string, unknown> }} value
 * @param {Record<string, unknown>} params
 */
export function execVssSplit(value, params) {
  let bytes;
  if (value?.type === "bytes") bytes = /** @type {Uint8Array} */ (value.data);
  else if (value?.type === "text") bytes = new TextEncoder().encode(String(value.data));
  else throw new Error("vss.split expects bytes or text");

  if (!bytes?.length) throw new Error("vss.split: empty secret");
  if (bytes.length > 32) {
    throw new Error(
      `vss.split: secret is ${bytes.length} bytes — it must fit in one P-256 scalar (≤ 32). Use sss.split for arbitrary-length data, or gpg.symencrypt first and share the key.`
    );
  }
  const secret = scalarFromHex(bytesToHex(bytes));
  if (secret === 0n) {
    // Would make every share equal f(id) of a polynomial with zero constant
    // term — reconstructable, but the "secret" is nothing.
    throw new Error("vss.split: secret reduces to zero mod the curve order");
  }

  const threshold = Number(params?.threshold) || 2;
  const count = Number(params?.shares) || 3;
  if (count < threshold) {
    throw new Error(`vss.split: shares ${count} is below threshold ${threshold}`);
  }
  // Ids are 1..n, matching how sss.split indexes, so a custodian's "share 2"
  // means the same thing in both schemes.
  const ids = Array.from({ length: count }, (_, i) => i + 1);
  const dealt = deal({ ids, threshold, secret });

  const raw = ids.map((id) => ({
    index: id,
    data: hexToBytes(dealt.shares[scalarToHex(BigInt(id))]),
  }));

  return {
    type: "shares",
    data: {
      encoding: "raw",
      raw,
      threshold,
      shares: count,
      flags: 0,
      envelope: null,
      enveloped: false,
      // Public by design — these are what make the shares checkable.
      commitments: dealt.commitments,
      vss: true,
    },
    meta: { sensitive: true, vss: true, publicKey: publicKeyOf(dealt.commitments) },
  };
}

/**
 * Resolve commitments from the share set, or from an explicit slot when the
 * custodian holds them separately from their share.
 * @param {any} data
 * @param {Record<string, unknown>} params
 * @param {{ resolveSlot?: (ref: string) => any }} bindings
 */
function commitmentsFor(data, params, bindings) {
  const ref = String(params?.commitments || "").trim();
  if (ref) {
    const slot = bindings?.resolveSlot?.(ref);
    if (!slot) throw new Error(`vss: unknown slot ${ref}`);
    const raw = slot.data;
    const list =
      Array.isArray(raw) ? raw : Array.isArray(raw?.commitments) ? raw.commitments : null;
    if (!list) {
      // A JSON text slot is the realistic form when commitments arrive over a
      // channel or a file rather than in the same pipeline.
      try {
        const parsed = JSON.parse(String(raw));
        if (Array.isArray(parsed)) return parsed;
        if (Array.isArray(parsed?.commitments)) return parsed.commitments;
      } catch {
        /* fall through to the error below */
      }
      throw new Error(`vss: ${ref} does not hold commitments`);
    }
    return list;
  }
  if (Array.isArray(data?.commitments)) return data.commitments;
  throw new Error(
    "vss.verify: no commitments — pipe a vss.split set, or pass commitments=@slot"
  );
}

/**
 * Verify every share against the commitments; pass the set through.
 *
 * Fail-loud and mid-pipeline on purpose: it reads as a guard, so
 * `in @shares | vss.verify | vss.combine` refuses to reconstruct from
 * shares that were tampered with, rather than returning a wrong secret.
 *
 * @param {{ type: string, data: any }} value
 * @param {Record<string, unknown>} params
 * @param {object} bindings
 */
export function execVssVerify(value, params, bindings) {
  if (value?.type !== "shares") throw new Error("vss.verify expects shares");
  const data = value.data || {};
  const raw = Array.isArray(data.raw) ? data.raw : [];
  if (!raw.length) throw new Error("vss.verify: no shares in the set");
  const commitments = commitmentsFor(data, params, bindings);

  const bad = [];
  for (const s of raw) {
    const ok = verify({
      share: bytesToHex(s.data),
      id: s.index,
      commitments,
    });
    if (!ok) bad.push(s.index);
  }
  if (bad.length) {
    const one = bad.length === 1;
    throw new Error(
      `vss.verify: share${one ? "" : "s"} ${bad.join(", ")} ${one ? "does" : "do"} not match the commitments — ${one ? "it is" : "they are"} corrupt or from a different split`
    );
  }
  return {
    ...value,
    meta: { ...(value.meta || {}), vssVerified: true, verifiedCount: raw.length },
  };
}

/**
 * Reconstruct the secret from a threshold of shares.
 * @param {{ type: string, data: any }} value
 */
export function execVssCombine(value) {
  if (value?.type !== "shares") throw new Error("vss.combine expects shares");
  const data = value.data || {};
  const raw = Array.isArray(data.raw) ? data.raw : [];
  if (!raw.length) throw new Error("vss.combine: no shares");
  const threshold = Number(data.threshold) || raw.length;
  if (raw.length < threshold) {
    throw new Error(`vss.combine: need at least ${threshold} shares, got ${raw.length}`);
  }
  const secretHex = combine(
    raw.map((s) => ({ id: s.index, share: bytesToHex(s.data) }))
  );
  return {
    type: "bytes",
    data: hexToBytes(secretHex),
    meta: { sensitive: true, type: { base: "bytes", kind: "scalar" } },
  };
}

export { ORDER };

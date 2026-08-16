/**
 * Feldman verifiable secret sharing over P-256.
 *
 * Shamir's scheme with one addition that changes what it can be used for: the
 * dealer publishes **commitments** to the polynomial's coefficients, so every
 * recipient can check their share is consistent with the same polynomial
 * everyone else got — without learning the secret, and without trusting the
 * dealer.
 *
 * That is the difference from the GF(256) sharing in `lib/slip39`, which this
 * does **not** replace and cannot be folded into:
 *
 * - `sss.split` shares are inert bytes. A custodian who receives one cannot
 *   tell a good share from a corrupted one until reconstruction fails — by
 *   which time the people are gone and nobody knows whose share was wrong.
 * - A VSS share can be verified the moment it is handed over.
 *
 * **Why not just make GF(256) verifiable?** Feldman commitments need a group
 * where the discrete logarithm is hard. GF(256)'s multiplicative group has
 * order 255, so recovering `a` from `gᵃ` is a lookup in a 255-entry table —
 * publishing commitments there would publish the secret. Verifiability
 * requires the prime-order group; the two schemes cannot be one
 * implementation.
 *
 * The cost of the prime field is that the secret must fit in one scalar
 * (< the curve order, so 32 bytes for P-256). That covers the actual use
 * case — a private scalar, a master seed — but not arbitrary-length data,
 * which is what GF(256) byte-wise sharing is still for.
 *
 * `lib/quorum/dkg.js` builds distributed key generation on top of this:
 * joint-Feldman is every participant running `deal` and summing what they
 * receive.
 * @module lib/quorum/vss
 */

import { p256 } from "@noble/curves/nist.js";

const Point = p256.Point;
/** Curve order — the field every scalar lives in. */
export const ORDER = Point.Fn.ORDER;

/* ────────────────────────────── scalars ────────────────────────────── */

/** @param {bigint} x */
export function mod(x) {
  const r = x % ORDER;
  return r < 0n ? r + ORDER : r;
}

/**
 * @param {string} hex
 * @returns {bigint}
 */
export function scalarFromHex(hex) {
  const clean = String(hex || "").replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(clean)) throw new Error("vss: not a hex scalar");
  return mod(BigInt(`0x${clean}`));
}

/** Fixed-width so a share never leaks its magnitude through its length. */
export function scalarToHex(s) {
  return mod(s).toString(16).padStart(64, "0");
}

function bytesToHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** A uniformly random nonzero scalar. */
export function randomScalar() {
  // noble's own secret-key generator: uniform in [1, n-1], no modulo bias.
  return scalarFromHex(bytesToHex(p256.utils.randomSecretKey()));
}

/** The public key a secret scalar corresponds to — for cross-checking. */
export function publicKeyForSecret(secretHex) {
  return Point.BASE.multiply(scalarFromHex(secretHex)).toHex(true);
}

/* ─────────────────────────── participant ids ─────────────────────────── */

/**
 * Share ids are the x-coordinates the polynomial is evaluated at.
 *
 * **Zero is rejected, and that is not a formality**: f(0) *is* the secret, so
 * a holder with id 0 would be handed it outright. Duplicates are rejected
 * too — two holders on the same x get identical shares, which silently
 * destroys the threshold property.
 *
 * @param {Array<number|string|bigint>} ids
 * @returns {bigint[]}
 */
export function normalizeIds(ids) {
  if (!Array.isArray(ids) || !ids.length) throw new Error("vss: no share ids");
  const out = ids.map((raw) => {
    const s =
      typeof raw === "bigint"
        ? mod(raw)
        : typeof raw === "number"
          ? mod(BigInt(Math.trunc(raw)))
          : scalarFromHex(String(raw));
    if (s === 0n) {
      throw new Error("vss: share id 0 is the secret itself — ids must be nonzero");
    }
    return s;
  });
  const seen = new Set(out.map((s) => s.toString(16)));
  if (seen.size !== out.length) throw new Error("vss: duplicate share ids");
  return out;
}

/**
 * How an id is written into a human-facing message: whole.
 *
 * It used to take the last 8 hex digits — not the first, because ids are
 * 64-char zero-padded scalars and small rehearsal ids (1, 2, 3) all begin
 * `00000000`, which would have rendered every participant identically. That
 * reasoning was right about the end and wrong about the length. A real room's
 * ids come from `idFromFingerprint`, which reduces a fingerprint mod the curve
 * order; a v4 fingerprint is 160 bits and the order is 256, so the reduction is
 * the identity and the scalar is the fingerprint with 24 zeros in front. The
 * last 8 digits of it are therefore the last 8 of somebody's *fingerprint* —
 * the 32-bit short key id, in a refusal, naming who dealt a bad share.
 *
 * These messages are read exactly when something has gone wrong, and `dkg.js`
 * is explicit that the remedy is social: a person takes this id to a room and
 * asks. A partial makes that conversation start with "which one of us is that",
 * and there is no press here to reveal the rest — a log line is not a widget.
 * The name went with the length, for the reason `approval-gate.js` renamed its
 * own: a function called `shortId` that returns the whole id is a comment
 * asserting something untrue.
 * @param {string|bigint} id
 */
export function idText(id) {
  return String(id || "");
}

/**
 * Derive a share id from an OpenPGP fingerprint, so existing identities index
 * the polynomial without a separate numbering scheme to agree on.
 * @param {string} fingerprint
 */
export function idFromFingerprint(fingerprint) {
  const hex = String(fingerprint || "").replace(/[^0-9a-f]/gi, "");
  if (!hex) throw new Error("vss: empty fingerprint");
  const s = mod(BigInt(`0x${hex}`));
  if (s === 0n) throw new Error("vss: fingerprint reduces to 0");
  return s;
}

/* ─────────────────────────────── dealing ─────────────────────────────── */

/**
 * @typedef {object} VssDeal
 * @property {string[]} commitments  compressed points, index k = coefficient k
 * @property {Record<string, string>} shares  share id (hex) → share (hex)
 * @property {bigint} secret  the constant term — the secret being shared
 */

/**
 * Split a secret into verifiable shares.
 *
 * @param {{
 *   ids: Array<number|string|bigint>,
 *   threshold: number,
 *   secret?: bigint,
 * }} opts  omit `secret` to share a fresh random one
 * @returns {VssDeal}
 */
export function deal({ ids, threshold, secret }) {
  const holders = normalizeIds(ids);
  const t = Math.trunc(Number(threshold));
  if (!Number.isFinite(t) || t < 1) throw new Error("vss: threshold must be ≥ 1");
  if (t > holders.length) {
    throw new Error(
      `vss: threshold ${t} exceeds ${holders.length} shares — the secret could never be reconstructed`
    );
  }

  // coeffs[0] is the secret; the rest are uniform noise that makes any t-1
  // shares independent of it.
  const coeffs = [secret === undefined ? randomScalar() : mod(secret)];
  for (let k = 1; k < t; k++) coeffs.push(randomScalar());

  const commitments = coeffs.map((a) => Point.BASE.multiply(a).toHex(true));

  /** @type {Record<string, string>} */
  const shares = {};
  for (const id of holders) {
    shares[scalarToHex(id)] = scalarToHex(evaluate(coeffs, id));
  }
  return { commitments, shares, secret: coeffs[0] };
}

/**
 * Horner evaluation of the polynomial at x, mod the curve order.
 * @param {bigint[]} coeffs
 * @param {bigint} x
 */
function evaluate(coeffs, x) {
  let acc = 0n;
  for (let k = coeffs.length - 1; k >= 0; k--) acc = mod(acc * x + coeffs[k]);
  return acc;
}

/* ─────────────────────────── verification ─────────────────────────── */

/**
 * Check a share against the dealer's public commitments.
 *
 * The whole security argument of VSS lives in this one equation:
 *
 *     share · G  ==  Σ_k  (id^k) · C_k
 *
 * The right-hand side is the committed polynomial evaluated "in the exponent"
 * at this share's id. Anyone can compute it from public data, so a dealer
 * cannot hand two holders shares of different polynomials without being
 * caught — with no trusted party involved.
 *
 * @param {{ share: string, id: number|string|bigint, commitments: string[] }} x
 * @returns {boolean}
 */
export function verify({ share, id, commitments }) {
  if (!Array.isArray(commitments) || !commitments.length) return false;
  let s;
  let point;
  try {
    s = scalarFromHex(share);
    point = normalizeIds([id])[0];
  } catch {
    return false;
  }
  // A zero share is not automatically wrong, but `Point.multiply(0)` throws in
  // noble, so it is handled explicitly rather than crashing verification.
  const lhs = s === 0n ? Point.ZERO : Point.BASE.multiply(s);

  let rhs = Point.ZERO;
  let power = 1n;
  for (const c of commitments) {
    let C;
    try {
      C = Point.fromHex(c);
    } catch {
      return false; // malformed commitment — a failed check, not a crash
    }
    if (power !== 0n) rhs = rhs.add(C.multiply(power));
    power = mod(power * point);
  }
  return lhs.equals(rhs);
}

/** The public key committed to by a deal — i.e. `secret · G`. */
export function publicKeyOf(commitments) {
  if (!Array.isArray(commitments) || !commitments.length) {
    throw new Error("vss: no commitments");
  }
  return Point.fromHex(commitments[0]).toHex(true);
}

/* ─────────────────────────── reconstruction ─────────────────────────── */

/**
 * Lagrange-interpolate the secret at x=0 from `threshold` shares.
 *
 * @param {Array<{ id: number|string|bigint, share: string }>} shares
 * @returns {string} the secret scalar, hex
 */
export function combine(shares) {
  if (!Array.isArray(shares) || !shares.length) throw new Error("vss: no shares");
  const pts = shares.map((s) => ({
    x: normalizeIds([s.id])[0],
    y: scalarFromHex(s.share),
  }));
  const xs = new Set(pts.map((p) => p.x.toString(16)));
  if (xs.size !== pts.length) throw new Error("vss: duplicate ids in reconstruction");

  let secret = 0n;
  for (let i = 0; i < pts.length; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < pts.length; j++) {
      if (i === j) continue;
      num = mod(num * pts[j].x);
      den = mod(den * mod(pts[j].x - pts[i].x));
    }
    const lambda = mod(num * Point.Fn.inv(den));
    secret = mod(secret + pts[i].y * lambda);
  }
  return scalarToHex(secret);
}

/** Sum commitment vectors coefficient-wise — the DKG aggregation step. */
export function addCommitments(a, b) {
  const n = Math.max(a.length, b.length);
  const out = [];
  for (let k = 0; k < n; k++) {
    const pa = a[k] ? Point.fromHex(a[k]) : Point.ZERO;
    const pb = b[k] ? Point.fromHex(b[k]) : Point.ZERO;
    out.push(pa.add(pb).toHex(true));
  }
  return out;
}

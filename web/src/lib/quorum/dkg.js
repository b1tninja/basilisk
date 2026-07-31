/**
 * Distributed key generation — Feldman VSS / joint-Feldman, over P-256.
 *
 * The point of the whole mesh (p2p-dkg DESIGN §5): *n* participants end up
 * holding shares of a private key **that never existed anywhere**. No
 * participant and no server ever assembles it. Any `threshold` of them can
 * reconstruct it later; fewer learn nothing.
 *
 * The protocol, and why each step is there:
 *
 *  1. Each participant picks a random degree-`t-1` polynomial over the curve
 *     order, whose constant term is their secret contribution, and broadcasts
 *     **commitments** to its coefficients — the coefficients multiplied by the
 *     base point. Commitments reveal nothing (discrete log) but pin the
 *     polynomial down.
 *  2. Each participant sends every other participant one **share**: their
 *     polynomial evaluated at that participant's id, delivered pairwise. The
 *     mesh gives pairwise channels for free, which is exactly why a mesh and
 *     not an SFU.
 *  3. A recipient **verifies** a share against the sender's commitments before
 *     accepting it. This is what makes it *verifiable* secret sharing rather
 *     than trust: a dealer who sends one participant an inconsistent share is
 *     caught immediately, by that participant, with no trusted party.
 *  4. Each participant sums the verified shares into their final share; the
 *     joint public key is the sum of everyone's constant-term commitments.
 *
 * ## What this does not do
 *
 * There is no complaint/resolution round. If a dealer's share fails
 * verification, `finalize` refuses and names them; the participants must
 * restart excluding that dealer. Real complaint handling (the accused
 * publishes the disputed share, everyone adjudicates) is a third round and is
 * deliberately absent rather than half-implemented.
 *
 * A rudimentary DKG is **not** a substitute for an audited threshold-signature
 * implementation. It gives you a shared key; it does not give you threshold
 * signing.
 * @module lib/quorum/dkg
 */

import { p256 } from "@noble/curves/nist.js";

const Point = p256.Point;
/** Curve order — the field every scalar lives in. */
const ORDER = Point.Fn.ORDER;

/* ────────────────────────────── scalars ────────────────────────────── */

/** @param {bigint} x */
function mod(x) {
  const r = x % ORDER;
  return r < 0n ? r + ORDER : r;
}

/**
 * @param {string} hex
 * @returns {bigint}
 */
export function scalarFromHex(hex) {
  const clean = String(hex || "").replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(clean)) throw new Error("dkg: not a hex scalar");
  return mod(BigInt(`0x${clean}`));
}

/** Fixed-width so a share never leaks its magnitude through its length. */
export function scalarToHex(s) {
  return mod(s).toString(16).padStart(64, "0");
}

/** A uniformly random nonzero scalar. */
export function randomScalar() {
  // noble's own secret-key generator: uniform in [1, n-1], no modulo bias.
  return scalarFromHex(bytesToHex(p256.utils.randomSecretKey()));
}

function bytesToHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/* ──────────────────────────── participants ──────────────────────────── */

/**
 * Participant ids are the x-coordinates the polynomial is evaluated at.
 *
 * **Zero is rejected, and that is not a formality**: f(0) *is* the secret, so
 * a participant with id 0 would be handed the dealer's contribution outright.
 * Duplicates are rejected too — two participants on the same x get identical
 * shares, which silently destroys the threshold property.
 *
 * @param {Array<number|string|bigint>} ids
 * @returns {bigint[]}
 */
export function normalizeIds(ids) {
  if (!Array.isArray(ids) || !ids.length) throw new Error("dkg: no participant ids");
  const out = ids.map((raw) => {
    const s =
      typeof raw === "bigint"
        ? mod(raw)
        : typeof raw === "number"
          ? mod(BigInt(Math.trunc(raw)))
          : scalarFromHex(String(raw));
    if (s === 0n) throw new Error("dkg: participant id 0 is the secret itself — ids must be nonzero");
    return s;
  });
  const seen = new Set(out.map((s) => s.toString(16)));
  if (seen.size !== out.length) throw new Error("dkg: duplicate participant ids");
  return out;
}

/**
 * Derive a participant id from an OpenPGP fingerprint, so the mesh's existing
 * identities index the polynomial without a separate numbering scheme to
 * agree on. Reduced mod the order; the zero case is astronomically unlikely
 * but still rejected rather than silently accepted.
 * @param {string} fingerprint
 */
export function idFromFingerprint(fingerprint) {
  const hex = String(fingerprint || "").replace(/[^0-9a-f]/gi, "");
  if (!hex) throw new Error("dkg: empty fingerprint");
  const s = mod(BigInt(`0x${hex}`));
  if (s === 0n) throw new Error("dkg: fingerprint reduces to 0");
  return s;
}

/* ─────────────────────────────── round 1 ─────────────────────────────── */

/**
 * @typedef {object} DkgRound1
 * @property {string[]} commitments  compressed points, index k = coefficient k
 * @property {Record<string, string>} shares  participant id (hex) → share (hex)
 * @property {bigint} secret  this participant's own contribution — never sent
 */

/**
 * Pick a polynomial, commit to it, and evaluate it for every participant.
 *
 * @param {{
 *   ids: Array<number|string|bigint>,
 *   threshold: number,
 *   secret?: bigint,
 * }} opts
 * @returns {DkgRound1}
 */
export function round1({ ids, threshold, secret }) {
  const parties = normalizeIds(ids);
  const t = Math.trunc(Number(threshold));
  if (!Number.isFinite(t) || t < 1) throw new Error("dkg: threshold must be ≥ 1");
  if (t > parties.length) {
    throw new Error(
      `dkg: threshold ${t} exceeds ${parties.length} participants — the key could never be reconstructed`
    );
  }

  // coeffs[0] is the secret contribution; the rest are uniform noise that
  // makes any t-1 shares independent of it.
  const coeffs = [secret === undefined ? randomScalar() : mod(secret)];
  for (let k = 1; k < t; k++) coeffs.push(randomScalar());

  const commitments = coeffs.map((a) => Point.BASE.multiply(a).toHex(true));

  /** @type {Record<string, string>} */
  const shares = {};
  for (const id of parties) {
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
 * Check a received share against the dealer's public commitments.
 *
 * The whole security argument of VSS lives in this one equation:
 *
 *     share · G  ==  Σ_k  (id^k) · C_k
 *
 * The right-hand side is the dealer's committed polynomial evaluated "in the
 * exponent" at this participant's id. It can be computed by anyone from
 * public data, so a dealer cannot hand different participants shares of
 * different polynomials without being caught.
 *
 * @param {{ share: string, id: number|string|bigint, commitments: string[] }} x
 * @returns {boolean}
 */
export function verifyShare({ share, id, commitments }) {
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
      return false; // malformed commitment — treat as a failed check, not a crash
    }
    if (power !== 0n) rhs = rhs.add(C.multiply(power));
    power = mod(power * point);
  }
  return lhs.equals(rhs);
}

/* ─────────────────────────────── finalize ─────────────────────────────── */

/**
 * @typedef {object} DkgResult
 * @property {string} share      this participant's share of the joint secret
 * @property {string} publicKey  compressed joint public key
 * @property {string[]} dealers  dealer ids whose contributions were included
 */

/**
 * Sum verified contributions into a final share and the joint public key.
 *
 * Every share is verified here as well as on arrival — finalizing is the last
 * point at which a bad contribution can be refused, and accepting one
 * silently corrupts the joint key for everyone.
 *
 * @param {{
 *   myId: number|string|bigint,
 *   contributions: Array<{ from: string, share: string, commitments: string[] }>,
 * }} x
 * @returns {DkgResult}
 */
export function finalize({ myId, contributions }) {
  const me = normalizeIds([myId])[0];
  if (!Array.isArray(contributions) || !contributions.length) {
    throw new Error("dkg: no contributions to finalize");
  }
  const seen = new Set();
  for (const c of contributions) {
    if (seen.has(c.from)) {
      throw new Error(`dkg: duplicate contribution from ${String(c.from).slice(0, 8)}…`);
    }
    seen.add(c.from);
    if (!verifyShare({ share: c.share, id: me, commitments: c.commitments })) {
      // Named, because the remedy is to restart without this dealer — there
      // is no complaint round to adjudicate it.
      throw new Error(
        `dkg: share from ${String(c.from).slice(0, 8)}… does not match their commitments — restart excluding that participant`
      );
    }
  }

  let share = 0n;
  let pub = Point.ZERO;
  for (const c of contributions) {
    share = mod(share + scalarFromHex(c.share));
    pub = pub.add(Point.fromHex(c.commitments[0]));
  }
  return {
    share: scalarToHex(share),
    publicKey: pub.toHex(true),
    dealers: contributions.map((c) => c.from),
  };
}

/* ────────────────────────── reconstruction ────────────────────────── */

/**
 * Lagrange-interpolate the joint secret at x=0 from `threshold` shares.
 *
 * Deliberately separate from everything above, and never called by the
 * protocol: assembling the secret is precisely what a DKG exists to avoid.
 * It is here for recovery (the participants deliberately choose to
 * reconstitute the key) and to let the tests prove the shares really do
 * describe the key the public commitments claim.
 *
 * @param {Array<{ id: number|string|bigint, share: string }>} shares
 * @returns {string} the secret scalar, hex
 */
export function reconstruct(shares) {
  if (!Array.isArray(shares) || !shares.length) throw new Error("dkg: no shares");
  const pts = shares.map((s) => ({
    x: normalizeIds([s.id])[0],
    y: scalarFromHex(s.share),
  }));
  const xs = new Set(pts.map((p) => p.x.toString(16)));
  if (xs.size !== pts.length) throw new Error("dkg: duplicate ids in reconstruction");

  let secret = 0n;
  for (let i = 0; i < pts.length; i++) {
    let num = 1n;
    let den = 1n;
    for (let j = 0; j < pts.length; j++) {
      if (i === j) continue;
      num = mod(num * pts[j].x);
      den = mod(den * mod(pts[j].x - pts[i].x));
    }
    const lambda = mod(num * inverse(den));
    secret = mod(secret + pts[i].y * lambda);
  }
  return scalarToHex(secret);
}

/** Modular inverse via Fermat, using the field noble already exposes. */
function inverse(a) {
  return Point.Fn.inv(mod(a));
}

/** The public key a reconstructed secret corresponds to — for cross-checking. */
export function publicKeyForSecret(secretHex) {
  return Point.BASE.multiply(scalarFromHex(secretHex)).toHex(true);
}

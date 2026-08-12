/**
 * How far ahead of *our* clock a signature may be created.
 *
 * OpenPGP verification is evaluated at an instant, and openpgp.js defaults that
 * instant to `new Date()`. A signature stamped even one second later than the
 * verifier's clock is refused outright with "Signature creation time is in the
 * future" — measured, not assumed.
 *
 * Two machines do not share a clock. Between two of them this is ordinary skew,
 * and ordinary skew is seconds; in the notebook mesh a person whose clock ran
 * slightly fast could not mesh with anybody, and the failure reached them as a
 * peer who never arrived. It surfaced first as a sub-second race in the browser
 * suite, where signer and verifier are the same machine and the two timestamps
 * land either side of one tick.
 *
 * ## Why sixty seconds
 *
 * A tolerance is a security parameter in both directions: it is exactly how far
 * a signer may *postdate* before we notice. So it is bounded, it is not
 * disabled, and the number is argued rather than picked.
 *
 * - It has to cover real skew. Two NTP-synchronised machines agree to
 *   milliseconds; two consumer machines that are not agree to seconds, and
 *   occasionally a minute.
 * - It must not become the weakest thing in the chain. The notebook relay's
 *   client access token carries `nbf` at issue and expires 300 s later, so a
 *   clock far enough out to defeat a minute is already close to failing to get a
 *   token at all — the tolerance sits well inside a limit the deployment has.
 * - What it costs is small where it is applied. Nothing in the notebook protocol
 *   treats a signature's creation time as freshness: replays are dropped by the
 *   envelope seen-set, and liveness comes from the per-peer ECDH nonces and the
 *   room id. Sixty seconds of postdating buys an attacker nothing they do not
 *   already have. Unbounded would, which is why this is a number.
 *
 * ## One number, both layers
 *
 * `notebook/crypto.js` verifies envelopes from a peer you are meshing with;
 * `pgp/sign.js` verifies a document a person pasted in. The documents differ,
 * the clock problem does not, and two spellings of one policy is how they come
 * to disagree. What differs is what each says when the tolerance is *exceeded* —
 * see `verifiedCleartextOpenPgp`, which owes an untrusted document a fuller
 * answer than a peer envelope does.
 *
 * Applied by verifying *as of* now-plus-tolerance. Every other check openpgp.js
 * makes at that instant — key expiry, signature expiry — therefore reads a
 * minute early, which is the conservative direction: it can refuse a key about
 * to expire, never accept one that has.
 *
 * @module lib/pgp/clock
 */

export const SIGNATURE_FUTURE_TOLERANCE_MS = 60 * 1000;

/**
 * The instant to verify a signature at.
 *
 * A function rather than a value: it has to be *now* plus the tolerance at the
 * moment of verification, and a module-level constant would freeze the clock at
 * import time.
 * @returns {Date}
 */
export function signatureVerificationDate() {
  return new Date(Date.now() + SIGNATURE_FUTURE_TOLERANCE_MS);
}

/**
 * "3 seconds", "2 minutes", "4 hours" — a gap in the units a person would use.
 * @param {number} ms
 * @returns {string}
 */
export function describeGap(ms) {
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 120) return `${s} second${s === 1 ? "" : "s"}`;
  const m = Math.round(s / 60);
  if (m < 120) return `${m} minute${m === 1 ? "" : "s"}`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hour${h === 1 ? "" : "s"}`;
  const d = Math.round(h / 24);
  return `${d} day${d === 1 ? "" : "s"}`;
}

/**
 * One question about a recipe's text: does it carry material that must not be
 * copied anywhere.
 *
 * It lived in `fragment.js`, which is a URL codec, and the answer was needed by
 * things that are not URLs — `workspace-store.js` before this file existed, and
 * `notebook-share.js` after it. A store and a wire document importing a fragment
 * encoder in order to ask "is this a secret" is the wrong direction, and the
 * cost of that shape is the one this codebase keeps paying: the second caller
 * writes its own copy of the rule instead, the two agree until the first case
 * only one of them learns about, and then a private key travels because the
 * newer copy had never heard of a JWK.
 *
 * So the rule is here, named for the question rather than for the destination,
 * and `fragment.js` re-exports it under the name every existing caller already
 * uses. There is one predicate. Adding a form of secret to it protects every
 * boundary at once, which is the only property that makes a heuristic like this
 * worth having.
 *
 * **A heuristic, and it says so.** It cannot see a passphrase typed as a step
 * parameter or a key pasted into a slot; what it catches is the material that
 * announces itself — private armor and a JWK with a private component. Every
 * caller is a boundary where the honest answer to "am I sure" is no, and
 * refusing on a strong hint is better than carrying on because the check was
 * not certain.
 *
 * ## What this used to refuse and no longer does
 *
 * A fingerprint written where a peer belongs was on this list, and it was the
 * only entry that was not secret material at all: a fingerprint is what a
 * keyserver hands to strangers. It was here because the *audience* it discloses
 * is what a room is derived from, and the product's answer at the time was an
 * invented positional label (`@peer1`) that disclosed nothing and meant nothing.
 * The product now writes the key itself, so this check would refuse every placed
 * notebook a person composed on purpose.
 *
 * It is not simply gone: the disclosure is real and is now *stated* rather than
 * prevented. `fingerprintPeersInText` is the same detector, and the Share
 * sheet's recipe row says what a link carries whenever it finds anything. A
 * refusal was the wrong shape for it — this predicate's other three entries are
 * things nobody could want to share, and that one was a thing somebody had
 * deliberately built.
 *
 * @module lib/toolkit/recipe-secrets
 */

/**
 * Heuristic: refuse to copy private armor / obvious secret blobs anywhere a
 * recipe's text is about to leave the machine that holds it.
 * @param {string} recipe
 * @returns {boolean}
 */
export function recipeLooksSecret(recipe) {
  const s = String(recipe || "");
  if (/BEGIN PGP PRIVATE KEY BLOCK/i.test(s)) return true;
  if (/BEGIN PRIVATE KEY/i.test(s)) return true;
  if (/"kty"\s*:\s*"[^"]+"/i.test(s) && /"d"\s*:/i.test(s)) return true;
  return false;
}

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
 * announces itself — private armor, a JWK with a private component, and a
 * fingerprint written where a peer label belongs. Every caller is a boundary
 * where the honest answer to "am I sure" is no, and refusing on a strong hint is
 * better than carrying on because the check was not certain.
 *
 * @module lib/toolkit/recipe-secrets
 */

import { textHasFingerprintPeer } from "./recipe-parse.js";

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
  // A fingerprint written where a peer is named. `validateRecipe` refuses the
  // same shape at compile, and the callers here never compile — `hashForRecipe`
  // builds a URL out of text and `buildNotebookProposal` builds a document out
  // of it — so the refusal has to be made twice or it is only made where it does
  // not matter.
  if (textHasFingerprintPeer(s)) return true;
  return false;
}

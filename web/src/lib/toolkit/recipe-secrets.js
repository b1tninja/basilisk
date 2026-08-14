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
 * **A heuristic, and it says so.** It cannot see a key pasted into a slot or a
 * password typed as a text cell; what it catches is the material that announces
 * itself — private armor and a JWK with a private component. Every caller is a
 * boundary where the honest answer to "am I sure" is no, and refusing on a
 * strong hint is better than carrying on because the check was not certain.
 *
 * ## The one entry that is not a hint
 *
 * `bindsSecretToLiteral` is exact, and it is here because the compiler cannot
 * reach these three callers. A param declared `secret` takes a `$ref` and
 * nothing else, so `sss.split … passphrase=hunter2` is a parse error and the
 * author is told while they are still typing — but **none of these boundaries
 * parse**. `hashForRecipe` takes text and builds a fragment from it; the
 * library saves text; a notebook proposal sends text. A notebook that does not
 * compile can still be copied as a link and pasted into a chat window, and
 * until this entry existed that link carried the passphrase that makes a stolen
 * share useless, beside the recipe that made the shares.
 *
 * So it asks the parser rather than reading the text a second way. A regex for
 * `passphrase=` would refuse `"a=1&key=2"` piped through `utf8` — a notebook
 * that runs — and the module doc above records what happened the last time this
 * predicate refused something somebody had built on purpose. The parser already
 * knows which params are secrets and where an argument begins; matching its own
 * refusal is the only reading that cannot disagree with the editor's.
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

import { SECRET_LITERAL_REFUSAL, parseRecipeSource } from "./recipe-parse.js";
import { STEPS } from "./registry.js";

/**
 * The `name=` of every param the registry declares `secret`, as one alternation.
 *
 * Only a gate on the parse below, never the answer: a hit here means "there is
 * something worth parsing for", and a miss means the text cannot contain the
 * form at all. Built from the registry so a new secret param is covered by
 * declaring itself, and rebuilt never — the registry is a constant.
 */
const SECRET_PARAM_NAMES = new RegExp(
  `(?:${[
    ...new Set(
      STEPS.flatMap((s) => (s.params || []).filter((p) => p.secret).map((p) => p.name))
    ),
  ].join("|")})=`,
  "i"
);

/**
 * Does this text bind a `secret` param to a literal rather than to a `$slot`?
 *
 * Asked of the parser, which is the only reader that knows where an argument
 * begins and which params are secrets. The parse is skipped entirely unless the
 * cheap alternation above matches, because `hashForRecipe` runs on every
 * keystroke while a notebook rewrites its own `#r=`.
 * @param {string} s
 * @returns {boolean}
 */
function bindsSecretToLiteral(s) {
  if (!SECRET_PARAM_NAMES.test(s)) return false;
  return parseRecipeSource(s).errors.some((e) =>
    String(e?.message || "").includes(SECRET_LITERAL_REFUSAL)
  );
}

/**
 * Refuse to copy private armor / obvious secret blobs — or a passphrase written
 * where the recipe should only name one — anywhere a recipe's text is about to
 * leave the machine that holds it.
 * @param {string} recipe
 * @returns {boolean}
 */
export function recipeLooksSecret(recipe) {
  const s = String(recipe || "");
  if (/BEGIN PGP PRIVATE KEY BLOCK/i.test(s)) return true;
  if (/BEGIN PRIVATE KEY/i.test(s)) return true;
  if (/"kty"\s*:\s*"[^"]+"/i.test(s) && /"d"\s*:/i.test(s)) return true;
  if (bindsSecretToLiteral(s)) return true;
  return false;
}

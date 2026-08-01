/**
 * Why an artifact action is unavailable (§33d, design_handoff_artifact_actions).
 *
 * These are the feature, not an afterthought: the rule that decides whether an
 * action is absent or disabled is "is it meaningful for this object" versus "is
 * it possible here, now", and only the second renders — with a sentence. A dead
 * button with no reason is worse than no button.
 *
 * Collected in one module so tests can assert them verbatim (the
 * `share-check.js` precedent — wording is the feature) and so the same
 * condition cannot acquire two different explanations in two widgets.
 *
 * Each is a sentence with a remedy where one exists. "Unavailable" is not a
 * reason; it is a restatement of the disabled attribute.
 */

export const ACTION_REASONS = Object.freeze({
  /**
   * Copy *or* Download on a masked value that can be revealed.
   *
   * It named Copy alone until Download landed in `2dda2af` and took the same
   * branch, at which point a user clicking a disabled **Download** was told
   * the value "cannot be copied" — a sentence about a button they had not
   * pressed. The fix is to name neither action rather than to split the
   * reason in two, for the reason stated at the top of this file: the same
   * condition must not acquire two explanations. Copy and Download are one
   * gate here — `artifact-actions.js` calls Download's branch "Copy's branch
   * verbatim" and a test asserts the two `available()` results are `toEqual`
   * — so two strings would be two places for one refusal to drift, and a
   * third destination would want a third.
   *
   * "Leave the notebook" is not a euphemism chosen to dodge the naming
   * problem; it is this codebase's existing name for exactly this pair.
   * `activity-log.js` records Copy and Download together as "how a secret
   * leaves the notebook", and it is the axis §34b gates on — which is why
   * `keyring.add` stays enabled while masked and these two do not.
   */
  maskedButRevealable: "Reveal this value first — a masked value cannot leave the notebook.",
  /**
   * Copy or Download on a masked value with no Reveal, because the engine
   * only marks `revealable` for values an explicit `out` / `text` / `inspect`
   * asked for. The remedy is a recipe edit, so it names the edit.
   */
  neverAskedFor:
    "This value was not asked for. Add `out @label` to the recipe to see or copy it.",
  /**
   * Download on a tile with no body at all — the `text` kind's own `empty`
   * line, said as a refusal. There is no remedy to name because nothing is
   * wrong with the recipe: the step ran and produced nothing to write, and a
   * 0-byte file that looks like a successful export is the outcome worth
   * refusing.
   */
  nothingToSave:
    "This artifact has no body to save — the step that produced it emitted nothing.",
  /** Anything vault-backed, in a browser without IndexedDB. */
  noVault: "My Keys is unavailable in this browser (no IndexedDB).",
  /**
   * Add to My Keys on a key tile with no body — the non-extractable case the
   * key kinds already name in their `empty` line. The remedy is a regenerate,
   * so it names that rather than a recipe edit that would not help.
   */
  noKeyBody:
    "This tile carries no key material to store — regenerate the key as extractable to save it.",
  /**
   * Add to My Keys on the least-specific `key` kind, whose body turned out to
   * be a public half. There is no remedy because nothing is wrong: a public
   * key needs no vault, which is what the sentence says instead of inventing
   * a step to take.
   */
  noPrivateHalf:
    "This body carries no private key — My Keys stores private keys, and a public half needs no vault.",
  /** Publish, with no route to the directory. */
  offline: "Publishing needs a connection to this site's directory.",
});

/**
 * **Not here on purpose: the keypair tile's withheld line.**
 *
 * `KeypairCard` renders "private half not shown — add `out @kp` to the recipe
 * to write both halves", and moving it into the table above was tried in the
 * polish pass and reverted — by the test three lines of contract below, which
 * was right. Everything in `ACTION_REASONS` is a *sentence*, capitalised and
 * full-stopped, because it is spoken by a control that refused: "a disabled
 * action always carries a reason". The withheld line is a caption, in the
 * lowercase-fragment register of the two that sit beside it on the same card
 * ("public + private halves", "symmetric — no public half"), and it explains
 * a tile rather than a refusal.
 *
 * They share a condition — the value was never asked for — and that is what
 * made the move tempting. They do not share a voice, and this module's job is
 * one voice for one kind of statement. The wording is pinned verbatim in
 * `artifact-kinds-table.test.js` instead, which is what it was actually
 * missing.
 */

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
  /** Copy on a masked value that *can* be revealed. */
  maskedButRevealable: "Reveal this value first — a masked value cannot be copied.",
  /**
   * Copy on a masked value with no Reveal, because the engine only marks
   * `revealable` for values an explicit `out` / `text` / `inspect` asked for.
   * The remedy is a recipe edit, so it names the edit.
   */
  neverAskedFor:
    "This value was not asked for. Add `out @label` to the recipe to see or copy it.",
  /** Anything vault-backed, in a browser without IndexedDB. */
  noVault: "My Keys is unavailable in this browser (no IndexedDB).",
  /** Publish, with no route to the directory. */
  offline: "Publishing needs a connection to this site's directory.",
});

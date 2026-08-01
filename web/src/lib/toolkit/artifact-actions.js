/**
 * The artifact action table (§33c, design_handoff_artifact_actions).
 *
 * Actions are declared once, globally, and referenced by id from a kind. That
 * is the other half of the anti-churn machinery: "Copy" must mean the same
 * thing, look the same, and gate the same way on every tile — which it cannot
 * if each tile builds its own button.
 *
 * **Services are injected, never imported.** The table below reaches no
 * clipboard, no vault, no network and no filesystem of its own, so it is
 * unit-testable with stubs and cannot acquire a hidden dependency on a
 * browser surface. Same shape of decision as `setApprovalGate` and
 * `setClipboardReadGate`.
 *
 * `available()` returns `true` or `{ disabled: <sentence> }` — never a bare
 * `false`. An action that cannot say why it is unavailable should not have
 * been declared by the kind in the first place (§33d): "is this meaningful
 * for this object" is the kind's question and is answered by omission; "is
 * this possible here, now" is this function's question and is answered with a
 * reason.
 */

import { ACTION_REASONS } from "./artifact-reasons.js";
import { sshIdentityFromJwk } from "./ssh-ops.js";
import { formatFingerprint } from "../utils.js";

/**
 * @typedef {true | { disabled: string }} Availability
 * @typedef {{ receipt: string, detail?: string }} ActionResult
 */

/** Parse an artifact's JWK body, or null when it is not one. */
function jwkOf(artifact) {
  try {
    const j = JSON.parse(String(artifact?.content ?? ""));
    return j && typeof j === "object" && j.kty ? j : null;
  } catch (_) {
    return null;
  }
}

/** The public half only — never let a private field reach a derivation. */
function publicJwk(jwk) {
  const { d, p, q, dp, dq, qi, ...pub } = jwk;
  void d;
  void p;
  void q;
  void dp;
  void dq;
  void qi;
  return pub;
}

/**
 * Copy is the one action whose *behaviour* already existed and is worth
 * preserving byte for byte — it fires the shipped `basilisk:clipboard-wrote`
 * toast and knows the artifact's own serialization rules. So the service is
 * the existing handler rather than a re-implementation; putting it in the
 * table is about making its gating uniform, not about rewriting it.
 */
export const ARTIFACT_ACTIONS = Object.freeze([
  {
    id: "copy",
    label: "Copy",
    tier: "inert",
    available: ({ artifact, masked }) => {
      if (!masked) return true;
      // §34b: disabled, never reveal-then-copy. Revealing on the user's
      // behalf is the mask bypass, however convenient.
      return {
        disabled:
          artifact.revealable && artifact.content
            ? ACTION_REASONS.maskedButRevealable
            : ACTION_REASONS.neverAskedFor,
      };
    },
    run: async ({ services }) => {
      await services.copyArtifact();
      return { receipt: "Copied" };
    },
  },
  {
    id: "key.copyFingerprint",
    label: "Copy fingerprint",
    tier: "inert",
    // Enabled while masked: a fingerprint is a public fact about the key, and
    // it does not derive from the masked material (§34b).
    available: ({ artifact }) =>
      jwkOf(artifact) || artifact.traits?.fingerprint
        ? true
        : { disabled: "This artifact carries no key to fingerprint." },
    run: async ({ artifact, services }) => {
      const jwk = jwkOf(artifact);
      if (jwk) {
        const id = await sshIdentityFromJwk(publicJwk(jwk));
        if (id) {
          await services.clipboard.write(id.fingerprint);
          return { receipt: "Fingerprint copied", detail: id.fingerprint };
        }
      }
      // OpenPGP and friends: copy what is displayed, in display format —
      // never a normalized variant the user cannot match against their own
      // records (§28a).
      const shown = formatFingerprint(String(artifact.traits?.fingerprint || ""));
      if (!shown) throw new Error("No fingerprint available for this key.");
      await services.clipboard.write(shown);
      return { receipt: "Fingerprint copied", detail: shown };
    },
  },
  {
    id: "key.copyPublicLine",
    label: "Copy public line",
    tier: "inert",
    /**
     * Declared only by kinds whose keys can have one. Where SSH has no key
     * type for the algorithm — x25519, AES, HMAC — the *kind* omits this
     * action rather than disabling it, because a disabled button would teach
     * that an SSH form exists for an x25519 key. This branch covers the
     * runtime case where the body is not a key at all.
     */
    available: ({ artifact }) =>
      jwkOf(artifact)
        ? true
        : { disabled: "This artifact carries no key to encode." },
    run: async ({ artifact, services }) => {
      const jwk = jwkOf(artifact);
      const id = await sshIdentityFromJwk(publicJwk(jwk));
      if (!id) {
        throw new Error(
          "SSH has no key type for this algorithm — generate ed25519 or ec/p256 for an SSH key."
        );
      }
      await services.clipboard.write(id.publicLine);
      return { receipt: "Public line copied", detail: id.publicLine };
    },
  },
]);

/** @param {string} id */
export function actionById(id) {
  return ARTIFACT_ACTIONS.find((a) => a.id === id) || null;
}

/**
 * Resolve a kind's declared action ids to entries, dropping ids with no
 * definition. A kind naming an action that does not exist is a table bug, and
 * `artifact-actions.test.js` fails on it — the tile must not be where that is
 * discovered, because the failure mode there is a silently missing button.
 */
export function actionsFor(kind) {
  return (kind?.actions || []).map(actionById).filter(Boolean);
}

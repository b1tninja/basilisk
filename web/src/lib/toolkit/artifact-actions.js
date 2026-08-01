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
import { shortKeyId } from "./approval-gate.js";
import { sshIdentityFromJwk } from "./ssh-ops.js";
import { sshKeySummary } from "./artifact-readouts.js";
import { formatFingerprint } from "../utils.js";
import { sanitizeFilename } from "../zip-store.js";

/**
 * @typedef {true | { disabled: string }} Availability
 * @typedef {{ receipt: string, detail?: string }} ActionResult
 *
 * @typedef {object} ConsequenceFact
 * @property {string} term
 * @property {string} detail
 * @property {string} [sub]
 * @property {boolean} [mono]
 *
 * @typedef {object} ConsequenceSpec
 *   What an outward or overwriting action must state before it runs (§34c).
 *   Built here, from data held at the moment of the click, so the sentences
 *   are asserted in one place rather than written into a widget.
 * @property {string} title
 * @property {ConsequenceFact[]} facts
 * @property {string} confirmLabel
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

/**
 * Whether a body has a private half at all.
 *
 * Exported because `keyring-service.js` gates on the same predicate before it
 * encodes: the button's disabled state and the service's refusal must agree
 * about what "private" means, and the one place they can disagree is if each
 * decides for itself. The service is still the authority — it names the form
 * it could not store — but it never contradicts this.
 *
 * @param {{ content?: string }} artifact
 */
export function hasPrivateKeyMaterial(artifact) {
  const body = String(artifact?.content ?? "").trim();
  if (!body) return false;
  // Armored: OpenPGP says "PRIVATE KEY BLOCK", OpenSSH and PKCS#8 say
  // "PRIVATE KEY". Any other armor is a public half or not a key at all.
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY/.test(body)) return true;
  if (body.startsWith("-----BEGIN")) return false;
  return !!jwkOf(artifact)?.d;
}

/**
 * Whether a body is an SSH key in one of the two wire forms.
 *
 * Cheap and shape-only, because `available()` is synchronous and the real
 * answer — the fingerprint — is a digest. The prefixes are
 * `keyring-service.js`'s, so the button and the vault recognise an OpenSSH
 * public line by the same rule.
 *
 * This is what lets Copy fingerprint work on an SSH tile at all. The action's
 * other two routes are a JWK body and `traits.fingerprint`, and an SSH line is
 * neither: the fingerprint is a digest of the wire blob, which no step
 * computed on the way past, so nothing could have stamped it. Deriving it here
 * — from `sshKeySummary`, the same function the tile's card draws from — is
 * one derivation with two consumers rather than a trait stamped at one emit
 * site and missing at the other (a dangling `ssh.encode` tip is built by the
 * synchronous `valueToArtifacts`, which cannot await a digest).
 *
 * @param {string} body
 */
function looksLikeSshKey(body) {
  const text = String(body || "").trim();
  if (text.includes("BEGIN OPENSSH PRIVATE KEY")) return true;
  return /^(ssh-|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)\S+\s+\S/.test(text);
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
 * A label, reduced to something a filesystem will take. The last resort only —
 * every artifact the engine emits already carries a `filename`.
 * @param {unknown} label
 */
function stemFromLabel(label) {
  return String(label ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[-.]+|-+$/g, "")
    .slice(0, 64);
}

/**
 * The name a Download lands under.
 *
 * **The engine's namer, not a second one.** `materializeOutArtifacts` already
 * computes a `filename` for every artifact it emits — `public.asc`,
 * `kp-private.jwk.json`, `artifact.svg`, `share-2.txt` — and that name rides
 * through `useNotebook`'s projection to the tile. Re-deriving one here from
 * role and traits would be two namers that can disagree about the same object,
 * which is the failure mode `keyring.add` avoided by sharing `agent-ops.js`'s
 * encoder rather than re-encoding.
 *
 * So the **stem is always the engine's**. What a kind may correct is the
 * *extension*, and only where the pipeline could not have known better: an
 * sshsig block is `text` on the wire, so `out` names it `${stem}.txt`, and
 * `.txt` is a lie about a body whose default handler should never be a text
 * editor. That is one namer with a declared per-kind correction, not two
 * schemes racing.
 *
 * Everything after the *first* dot is the extension, because the engine's
 * stems never contain one (`safeOutputStem`) and its extensions frequently do
 * — `jwk.json`, `bin.b64`, `inspect.txt` are each the whole extension, and
 * splitting on the last dot would shorten them.
 *
 * @param {{ filename?: string, label?: string }} artifact
 * @param {{ download?: { ext?: string } }} [kind]
 */
export function downloadNameFor(artifact, kind) {
  const engineName = sanitizeFilename(artifact?.filename, "");
  const dot = engineName.indexOf(".");
  const stem =
    (dot > 0 ? engineName.slice(0, dot) : engineName) ||
    stemFromLabel(artifact?.label) ||
    "artifact";
  const ext = kind?.download?.ext || (dot > 0 ? engineName.slice(dot + 1) : "") || "txt";
  return sanitizeFilename(`${stem}.${ext}`, "artifact.txt");
}

/**
 * The content type the blob is built with. The engine stamps one on every
 * artifact; a kind overrides it only where it also overrides the extension, so
 * the two can never describe different formats.
 *
 * @param {{ mime?: string }} artifact
 * @param {{ download?: { mime?: string } }} [kind]
 */
export function downloadMimeFor(artifact, kind) {
  return (
    kind?.download?.mime ||
    String(artifact?.mime || "").trim() ||
    "text/plain; charset=utf-8"
  );
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
    /**
     * The other half of Copy: same tier, same gate, a different destination.
     * The clipboard is where a value goes to be pasted once; a file is where it
     * goes to be kept — which is precisely why `activity-log.js` names Copy and
     * Download together as "how a secret leaves the notebook" and logs both.
     * `runAction` does that logging centrally, so nothing here has to.
     */
    id: "download",
    label: "Download",
    tier: "inert",
    available: ({ artifact, masked }) => {
      if (masked) {
        // §34b, and Copy's branch verbatim — deliberately the same two
        // sentences, because it is the same refusal. Writing a masked secret
        // to disk is the same exfiltration as copying it, and revealing on the
        // user's behalf to permit it is the same mask bypass.
        //
        // The contrast is with `keyring.add`, which stays *enabled* while
        // masked because it moves the secret into storage without ever
        // displaying it. This one displays nothing either — but it leaves, and
        // that is the axis §34b gates on.
        return {
          disabled:
            artifact.revealable && artifact.content
              ? ACTION_REASONS.maskedButRevealable
              : ACTION_REASONS.neverAskedFor,
        };
      }
      if (!String(artifact?.content ?? "")) {
        return { disabled: ACTION_REASONS.nothingToSave };
      }
      return true;
    },
    /**
     * No `confirm`. §34c's banner is for what leaves the machine or overwrites
     * something; a download is neither, and asking before every save would
     * teach that the banner is decorative — which is the one thing that would
     * make the Publish banner worthless.
     */
    run: async ({ artifact, kind, services }) => {
      const name = downloadNameFor(artifact, kind);
      await services.download({
        name,
        content: artifact.content,
        mime: downloadMimeFor(artifact, kind),
      });
      // The name is the detail worth logging: the Activity log's job is to
      // answer "what left, and where did it go" at 2am, and for a download the
      // destination is a filename in the browser's downloads.
      return { receipt: "Downloaded", detail: name };
    },
  },
  {
    id: "key.copyFingerprint",
    label: "Copy fingerprint",
    tier: "inert",
    // Enabled while masked: a fingerprint is a public fact about the key, and
    // it does not derive from the masked material (§34b).
    available: ({ artifact }) =>
      jwkOf(artifact) ||
      artifact.traits?.fingerprint ||
      looksLikeSshKey(artifact?.content)
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
      // An SSH body carries its own fingerprint — a digest of the wire blob,
      // which is public material even inside a private block, so this works on
      // a masked private-key tile exactly as §34b intends. Copied in the
      // `SHA256:…` form, unaltered: it is what `ssh-keygen -lf` prints and what
      // an `allowed_signers` line is compared against character for character.
      if (looksLikeSshKey(artifact?.content)) {
        const summary = await sshKeySummary(String(artifact.content));
        if (summary) {
          await services.clipboard.write(summary.fingerprint);
          return { receipt: "Fingerprint copied", detail: summary.fingerprint };
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
  {
    /**
     * "Add to My Keys" (§34a's local tier) — the button that closes the loop
     * on dispositions: how a key gets stored becomes a UX choice rather than a
     * line a shared recipe has to carry.
     *
     * The label says "My Keys" because that is what the app calls the vault
     * everywhere else, including in `ACTION_REASONS.noVault`; the id stays
     * `keyring.add`, and id ≠ label is already true elsewhere (`key.publish` →
     * "Publish").
     */
    id: "keyring.add",
    label: "Add to My Keys",
    tier: "local",
    /**
     * **Enabled while masked, deliberately.** Copy is disabled on a masked
     * value (§34b) because copying is how a secret leaves the notebook; this
     * is the opposite motion — it moves the secret *into* storage without ever
     * displaying it. Gating it on reveal would force a private key onto the
     * screen as the price of storing it safely, and private-key tiles are
     * masked by default, so the gate would disable the button in exactly the
     * case it exists for.
     *
     * What it does need is a body to store, and a private half in it — the
     * second is a runtime question precisely on the least-specific `key` kind,
     * which by construction does not know which half it holds (§33d).
     */
    available: ({ artifact, services }) => {
      if (!services?.vault?.add) return { disabled: ACTION_REASONS.noVault };
      if (!String(artifact?.content ?? "").trim()) {
        return { disabled: ACTION_REASONS.noKeyBody };
      }
      if (!hasPrivateKeyMaterial(artifact)) {
        return { disabled: ACTION_REASONS.noPrivateHalf };
      }
      return true;
    },
    /**
     * §34c. It writes a secret into storage that outlives the session, at a
     * protection level the user did not choose, so it says all four things
     * before it runs — built here, from data held at the moment of the click.
     *
     * The fingerprint is `sub` only when `traits` carries one, which is the
     * OpenPGP case. A JWK key's id is derived asynchronously and is already on
     * screen in the key card two lines above the banner; re-deriving it here
     * would mean a second computation that can disagree with the first, to
     * repeat something visible without scrolling — the same call `key.publish`
     * makes about the uid.
     */
    confirm: ({ artifact }) => ({
      title: "Add this key to My Keys",
      facts: [
        {
          term: "Key",
          detail: artifact.label,
          sub: formatFingerprint(String(artifact.traits?.fingerprint || "")) || undefined,
        },
        {
          term: "Where",
          detail: "My Keys, in this browser",
          sub: "storage on this device — it is not synced anywhere",
        },
        {
          term: "Protection",
          detail:
            "Device protection: no passkey, no passphrase. Anyone who can reach this browser profile can use the key without being asked for anything.",
          sub: "Enrol a passkey from My Keys afterwards, or write agent.save protection=passkey in the recipe.",
        },
        {
          term: "Reversible",
          detail:
            "Deleting the key from My Keys removes it. Nothing leaves this device, so this is not the one-way door publishing is.",
        },
      ],
      confirmLabel: "Add to My Keys",
    }),
    run: async ({ artifact, services }) => {
      /**
       * **No `onConflict`.** `agent.save` passes `"replace"` and says why: a
       * recipe that writes `agent.save protection=device` said it out loud,
       * with the fingerprint in front of it. A button click is precisely the
       * single click the vault's default refusal exists for, so a key already
       * held behind a passkey refuses here — in the vault's own sentence,
       * which `runAction` surfaces unaltered.
       */
      const saved = await services.vault.add({
        content: artifact.content,
        alg: artifact.traits?.alg,
      });
      return {
        // A re-save at *equal* protection is not refused — the guard only
        // rejects a weakening — so it succeeds and overwrites the row it
        // already had. "Added" would be a lie about what changed.
        receipt: saved.already ? "Already in My Keys" : "Added to My Keys",
        detail: `My Keys ${shortKeyId(saved.fingerprint)}`,
      };
    },
  },
  {
    /**
     * The one outward action there is (§34a). Declared on exactly one kind —
     * `openpgp-public`, which matches `role: "public-key"` — and
     * `publishArtifact` throws on any other role, so the registry and the
     * function agree in two places instead of one. `artifact-actions.test.js`
     * asserts no second kind declares it.
     */
    id: "key.publish",
    label: "Publish",
    tier: "outward",
    available: ({ services }) =>
      services?.directory?.publish
        ? true
        : // Not "declared but broken": the tile renders this action for every
          // public key, and whether a route to the directory exists is a fact
          // about the environment, which is exactly what §33d says belongs in
          // a reason string rather than in the kind's declaration.
          { disabled: ACTION_REASONS.offline },
    /**
     * Every line is data held at the moment of the click (§34c).
     *
     * The key is named by the artifact's own label and its fingerprint in
     * display format, not by a user id: `traits` carries only `fingerprint`,
     * and the uid would have to come from a second parse of the armor — which
     * the tile's own card, two lines above the banner, has already done and
     * already shows. Restating it here would mean two parses that can
     * disagree, to repeat something visible without scrolling.
     *
     * "Where" names this site and can never name a keyserver: `upstream-hkp.js`
     * is lookup-only and there is no upstream write path at all (§38b).
     */
    confirm: ({ artifact, services }) => ({
      title: "Publish this key to the directory",
      facts: [
        {
          term: "Key",
          detail: artifact.label,
          sub: formatFingerprint(String(artifact.traits?.fingerprint || "")) || undefined,
        },
        {
          term: "Where",
          detail: services?.directory?.host || "this site",
          sub: "this site's directory — not an upstream keyserver",
        },
        {
          term: "Becomes public",
          detail:
            "The key, its user IDs, and every signature on it — readable by anyone with directory access, including the email addresses in its user IDs.",
        },
        {
          term: "Permanent",
          detail:
            "A published key cannot be withdrawn. You can publish a revocation later; you cannot make this copy go away.",
        },
      ],
      confirmLabel: "Publish",
    }),
    run: async ({ services }) => {
      const result = await services.directory.publish();
      return {
        receipt: "Published",
        detail: result?.directoryUrl || result?.fingerprint || undefined,
      };
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

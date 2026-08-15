/**
 * Toolkit URL fragment codec — shareable recipes without hitting the server.
 *
 * Forms (first match wins):
 *   #encrypt | #decrypt | #symencrypt  — named messaging starters
 *     (#symencrypt = mode=passphrase + generated $pw)
 *   #keys                              — open the Keys tray; loads no notebook
 *   #t=<presetId>                      — Templates preset
 *   #j=<fpr,fpr,…>                     — a shared-session invite: the audience,
 *                                        which is the only thing both ends need
 *                                        to derive the same room
 *   #r=<compact-recipe>                — URL-friendly compact recipe
 *                                        (beautified via canonicalize on load)
 *   …&ct=<base64url>                   — optional ciphertext Inputs seed
 *                                        (binary OpenPGP; re-armored on load)
 *
 * Compact recipe form (written by hashForRecipe):
 *   - pipes without spaces: `input|gpg.encrypt`
 *   - chains joined with `~` instead of blank lines
 *   - tee/foreach bodies as one-line braces: `foreach{ - out $share }`
 *   - spaces as `+` in the fragment; `| @ = ~` left unescaped
 *
 * Private keys / passphrases must never be written here.
 * Ciphertext (`ct`) is an intentional public share payload (history-sensitive).
 */

import { armor, enums } from "openpgp";
import { dearmorToBytes } from "../packet-map.js";
// The room's own canonicalisation, not a second copy of it. Sorting and
// de-duping an audience is what *decides which room* a link means, so a link
// that ordered its fingerprints differently from `deriveRoomMaterial` would
// name a different room while looking identical.
import { canonicalAudience } from "../notebook/room.js";
import { base64ToBytes, bytesToBase64Url } from "./encode.js";
import {
  canonicalizeRecipe,
  serializeRecipe,
} from "./recipe.js";
// Imported *and* re-exported at the foot of this file: a bare re-export creates
// no local binding, and `hashForRecipe` below is one of the rule's callers.
import { fingerprintPeersInText } from "./recipe-parse.js";
import { recipeLooksSecret } from "./recipe-secrets.js";

/**
 * Re-armor binary OpenPGP message bytes via OpenPGP.js (RFC ASCII armor).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function armorMessageBytes(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  return armor(enums.armor.message, u8);
}

/** Soft cap for auto-updating location.hash (browsers vary; keep shareable). */
export const TOOLKIT_HASH_MAX_LEN = 6000;

/** Compact multi-chain separator (expanded to a blank line on load). */
export const COMPACT_CHAIN_SEP = "~";

/** @typedef {"encrypt"|"decrypt"|"symencrypt"} MessagingStarter */

/**
 * @typedef {{ ctArmored?: string }} ToolkitInputSeeds
 */

/** @type {Record<MessagingStarter, { title: string, recipe: string }>} */
export const MESSAGING_STARTERS = {
  encrypt: {
    title: "Encrypt message",
    recipe: "input | gpg.encrypt",
  },
  decrypt: {
    title: "Decrypt message",
    // Named, not bare. `gpg.decrypt` yields the plaintext, and a plaintext
    // nobody names is a trailing value the compiler warns about — the starter
    // must not hand a first-time reader a warning to read.
    recipe: "gpg.decrypt | out $plain",
  },
  symencrypt: {
    title: "Password encrypt",
    recipe: `passphrase mode=char | out $pw

input | gpg.symencrypt mode=passphrase passphrase=$pw | out $msg`,
  },
};

/**
 * A tray the fragment can ask for by name.
 *
 * One member, and it earns the shape: `/toolkit#keys` is the nav's "Keys"
 * entry, and the vault it names sits in a tray that may be collapsed. Spelled
 * as a kind rather than folded into the starters because a starter *replaces
 * the notebook* — landing on the vault must not throw away what you were
 * writing, which is the same rule `#j=` follows for the same reason.
 *
 * @typedef {"keys"} ToolkitTray
 */

/**
 * @typedef {{ kind: "starter", starter: MessagingStarter, inputs?: ToolkitInputSeeds }
 *   | { kind: "preset", id: string, inputs?: ToolkitInputSeeds }
 *   | { kind: "recipe", recipe: string, inputs?: ToolkitInputSeeds }
 *   | { kind: "join", audience: string[] }
 *   | { kind: "tray", tray: ToolkitTray }
 *   | { kind: "empty" }
 *   | { kind: "unknown", raw: string }} ToolkitHashAction
 */

/**
 * Minify recipe text for `#r=` (still parseable; beautify on load).
 * @param {string} recipe
 * @returns {string}
 */
export function compactRecipeText(recipe) {
  const raw = normalizeRecipeText(recipe);
  if (!raw) return "";
  const { ast } = canonicalizeRecipe(raw);
  if (ast) return serializeRecipe(ast, { compact: true });
  // Fallback: string minify when parse fails (still share something)
  return raw
    .replace(/\r\n/g, "\n")
    .split(/\n\s*\n+/)
    .map((chain) =>
      chain
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .join(" ")
        .replace(/\s*\|\s*/g, "|")
        .replace(/\s+/g, " ")
        .trim()
    )
    .filter(Boolean)
    .join(COMPACT_CHAIN_SEP);
}

/**
 * Expand a compact (or legacy pretty) share payload to recipe source.
 * Callers should canonicalize / beautify after load.
 * @param {string} payload
 * @returns {string}
 */
export function expandShareRecipe(payload) {
  let s = String(payload ?? "");
  if (!s) return "";
  // Compact multi-chain: `a~b` (no raw newlines). Legacy pretty keeps `\n\n`.
  if (!s.includes("\n") && s.includes(COMPACT_CHAIN_SEP)) {
    s = s.split(COMPACT_CHAIN_SEP).join("\n\n");
  }
  return s;
}

/**
 * Encode compact recipe for a fragment value (shorter than raw encodeURIComponent).
 * Leaves URL-friendly tokens (`|@=~._-` etc.); spaces → `+`.
 * @param {string} text
 */
export function encodeSharePayload(text) {
  return encodeURIComponent(String(text ?? ""))
    .replace(/%20/g, "+")
    .replace(/%7C/gi, "|")
    // `$` is the slot sigil and appears once per slot reference; left encoded
    // it costs three characters each against the 6000-char fragment budget.
    // It is a sub-delim, legal unescaped in a fragment.
    .replace(/%24/g, "$")
    .replace(/%40/g, "@")
    .replace(/%3D/gi, "=")
    .replace(/%7E/gi, "~")
    .replace(/%2D/g, "-")
    .replace(/%5F/g, "_")
    .replace(/%2E/g, ".")
    .replace(/%2F/g, "/")
    .replace(/%3A/gi, ":")
    .replace(/%5B/gi, "[")
    .replace(/%5D/gi, "]")
    .replace(/%7B/gi, "{")
    .replace(/%7D/gi, "}");
}

/**
 * Decode a `#r=` payload (handles `+` spaces and full percent-encoding).
 * @param {string} raw
 */
export function decodeSharePayload(raw) {
  const s = String(raw ?? "");
  if (!s) return "";
  try {
    return decodeURIComponent(s.replace(/\+/g, "%20"));
  } catch {
    return s.replace(/\+/g, " ");
  }
}

/**
 * Split trailing `&ct=` so recipe values may contain `=` safely.
 * @param {string} raw  hash without leading #
 * @returns {{ head: string, ct: string|null }}
 */
export function splitCtParam(raw) {
  const s = String(raw ?? "");
  const idx = s.search(/&ct=/i);
  if (idx < 0) return { head: s, ct: null };
  return { head: s.slice(0, idx), ct: s.slice(idx + 4) };
}

/**
 * Refuse private material in an Inputs seed.
 * @param {string} text
 */
export function seedLooksSecret(text) {
  return recipeLooksSecret(text);
}

/**
 * Pack armored (or raw binary-as-text) OpenPGP ciphertext for `&ct=`.
 * @param {string} armoredOrText
 * @returns {{ ct: string, ok: true } | { ok: false, reason: string }}
 */
export function encodeCiphertextSeed(armoredOrText) {
  const text = String(armoredOrText ?? "").trim();
  if (!text) {
    return { ok: false, reason: "No ciphertext to share." };
  }
  if (seedLooksSecret(text)) {
    return {
      ok: false,
      reason: "Refusing to put private key material in a share link.",
    };
  }
  try {
    const bytes = /-----BEGIN PGP/i.test(text)
      ? dearmorToBytes(text)
      : new TextEncoder().encode(text);
    if (!bytes.length) {
      return { ok: false, reason: "Ciphertext is empty after decode." };
    }
    return { ok: true, ct: bytesToBase64Url(bytes) };
  } catch (err) {
    return {
      ok: false,
      reason: err?.message || "Could not encode ciphertext for a link.",
    };
  }
}

/**
 * Decode `&ct=` to ASCII-armored PGP MESSAGE for Inputs.
 * @param {string} ctParam
 * @returns {{ armored: string, ok: true } | { ok: false, reason: string }}
 */
export function decodeCiphertextSeed(ctParam) {
  const raw = String(ctParam ?? "").trim();
  if (!raw) {
    return { ok: false, reason: "Missing ciphertext seed." };
  }
  try {
    // Legacy: someone pasted percent-encoded armor into ct=
    if (/BEGIN%20PGP|BEGIN\+PGP|BEGIN PGP/i.test(raw)) {
      const decoded = decodeSharePayload(raw);
      if (seedLooksSecret(decoded)) {
        return {
          ok: false,
          reason: "Refusing to load private key material from a link.",
        };
      }
      if (/-----BEGIN PGP MESSAGE-----/i.test(decoded)) {
        return { ok: true, armored: decoded.trim() };
      }
    }
    const bytes = base64ToBytes(raw.replace(/\s+/g, ""));
    if (!bytes.length) {
      return { ok: false, reason: "Ciphertext seed decoded empty." };
    }
    return { ok: true, armored: armorMessageBytes(bytes) };
  } catch (err) {
    return {
      ok: false,
      reason: err?.message || "Could not decode ciphertext seed.",
    };
  }
}

/**
 * Attach decoded inputs; surface decode errors on the action.
 * @param {{ kind: string } & Record<string, unknown>} action
 * @param {string|null} ctParam
 * @returns {ToolkitHashAction & { seedError?: string }}
 */
function withCtSeed(action, ctParam) {
  if (ctParam == null || ctParam === "") {
    return /** @type {ToolkitHashAction} */ (action);
  }
  const decoded = decodeCiphertextSeed(ctParam);
  if (!decoded.ok) {
    return /** @type {ToolkitHashAction & { seedError?: string }} */ ({
      ...action,
      inputs: { ctArmored: "" },
      seedError: decoded.reason,
    });
  }
  return /** @type {ToolkitHashAction} */ ({
    ...action,
    inputs: { ctArmored: decoded.armored },
  });
}

/**
 * @param {string} [hash]  with or without leading #
 * @returns {ToolkitHashAction & { seedError?: string }}
 */
export function parseToolkitHash(hash) {
  let raw = String(hash ?? "");
  if (raw.startsWith("#")) raw = raw.slice(1);
  raw = raw.trim();
  if (!raw) return { kind: "empty" };

  const { head, ct } = splitCtParam(raw);

  // Exact named starters (no query)
  const headLower = head.toLowerCase();
  if (
    headLower === "encrypt" ||
    headLower === "decrypt" ||
    headLower === "symencrypt"
  ) {
    return withCtSeed(
      {
        kind: "starter",
        starter: /** @type {MessagingStarter} */ (headLower),
      },
      ct
    );
  }

  // A tray by name, carrying no seed and no recipe. This is where "Keys" in
  // the nav points: the vault's home is the tray, and a link that opened the
  // toolkit without opening it would be a nav entry named for something the
  // page it loads does not show.
  if (headLower === "keys") {
    return { kind: "tray", tray: "keys" };
  }

  // Mini query on head: t=… or r=…
  if (head.includes("=")) {
    try {
      const params = new URLSearchParams(head);
      const t = params.get("t");
      if (t) return withCtSeed({ kind: "preset", id: t }, ct);
      // Before `r=`, because an invite carries no recipe and never should. Both
      // ends holding the same text, and proving it by digest, is what makes a
      // shared run a reproducible build rather than a screen share — and a link
      // that opened a room *and* replaced the notebook you were writing would
      // decide that for you at the moment you clicked something else.
      //
      // How a notebook reaches the other end is `notebook-share.js`: a signed
      // proposal on the session channel, which a peer with an empty notebook
      // adopts and a peer with work of their own is asked about. That is a
      // change to who may *receive* the text, not to the doctrine — the digest
      // check on every handed-over cell is exactly as it was. Before it existed
      // the doctrine had no mechanism at all: nothing in this product ever gave
      // a joiner the recipe, so every offer they were sent was refused against a
      // manifest derived from an empty notebook.
      const j = params.get("j");
      if (j) {
        const audience = joinAudienceFromParam(j);
        // A `j=` that names fewer than two keys derives no room, so it is not an
        // invite — reported as unknown rather than opening an empty one.
        if (audience.length >= 2) return { kind: "join", audience };
      }
      const r = params.get("r");
      if (r != null && r !== "") {
        return withCtSeed(
          { kind: "recipe", recipe: expandShareRecipe(r) },
          ct
        );
      }
    } catch {
      /* fall through */
    }
  }

  if (head.startsWith("t=")) {
    return withCtSeed(
      { kind: "preset", id: decodeURIComponent(head.slice(2)) },
      ct
    );
  }
  if (head.startsWith("r=")) {
    try {
      return withCtSeed(
        {
          kind: "recipe",
          recipe: expandShareRecipe(decodeSharePayload(head.slice(2))),
        },
        ct
      );
    } catch {
      return { kind: "unknown", raw };
    }
  }

  return { kind: "unknown", raw };
}

/**
 * Build `#decrypt&ct=…` for sharing a ciphertext artifact.
 * @param {string} armored
 * @returns {{ hash: string, ok: boolean, reason?: string }}
 */
export function hashForDecryptLink(armored) {
  const enc = encodeCiphertextSeed(armored);
  if (!enc.ok) {
    return { hash: "#", ok: false, reason: enc.reason };
  }
  const hash = `#decrypt&ct=${enc.ct}`;
  if (hash.length > TOOLKIT_HASH_MAX_LEN) {
    return {
      hash: "#",
      ok: false,
      reason:
        "Message too long for a link — copy the ciphertext or download instead.",
    };
  }
  return { hash, ok: true };
}

/**
 * @param {string} raw  the `j=` value, already URL-decoded by URLSearchParams
 * @returns {string[]}
 */
function joinAudienceFromParam(raw) {
  return canonicalAudience(String(raw || "").split(/[\s,]+/));
}

/**
 * Build a shared-session invite: `#j=<fpr>,<fpr>…`.
 *
 * **The audience is the whole invite.** The room id is
 * `SHA-256(hostname | sorted fingerprints)` truncated, so both ends compute it
 * from this list and it never travels; there is nothing here that admits
 * anybody, because admission is *being in the list* and holding the key it
 * names. That is why this can be pasted into a chat window in a way a room code
 * plus a token could not be.
 *
 * Nothing is refused as secret here, and that is deliberate rather than an
 * omission: a fingerprint is what a keyserver hands out to strangers, and
 * `recipeLooksSecret` refuses one only where a *recipe* writes it as a peer
 * label — a different rule about a different document.
 *
 * @param {string[]} audience
 * @returns {{ hash: string, ok: true } | { hash: "#", ok: false, reason: string }}
 */
export function hashForJoin(audience) {
  const list = canonicalAudience(audience || []);
  if (list.length < 2) {
    return {
      hash: "#",
      ok: false,
      reason:
        "An invite needs at least two fingerprints, including yours — a room is derived from the whole audience.",
    };
  }
  return { hash: `#j=${list.join(",")}`, ok: true };
}

/**
 * @param {MessagingStarter} starter
 * @returns {string}  hash including #
 */
export function hashForStarter(starter) {
  return `#${starter}`;
}

/**
 * @param {string} presetId
 * @returns {string}
 */
export function hashForPreset(presetId) {
  return `#t=${encodeURIComponent(String(presetId || ""))}`;
}

/**
 * @param {string} recipe
 * @returns {{ hash: string, ok: boolean, reason?: string }}
 */
export function hashForRecipe(recipe) {
  const text = String(recipe ?? "").trim();
  if (!text) return { hash: "#", ok: true };
  if (recipeLooksSecret(text)) {
    return {
      hash: "#",
      ok: false,
      reason: "Recipe looks like it contains secret material — use Inputs, not the URL.",
    };
  }
  const compact = compactRecipeText(text);
  if (recipeLooksSecret(compact)) {
    return {
      hash: "#",
      ok: false,
      reason: "Recipe looks like it contains secret material — use Inputs, not the URL.",
    };
  }
  const encoded = encodeSharePayload(compact);
  const hash = `#r=${encoded}`;
  if (hash.length > TOOLKIT_HASH_MAX_LEN) {
    return {
      hash: "#",
      ok: false,
      reason: "Recipe too long for URL — use Copy recipe or shorten the notebook.",
    };
  }
  return { hash, ok: true };
}

/**
 * What a `#r=` link would tell whoever opens it about who is in the room.
 *
 * **This is the sentence that had to be written when the refusal came out.**
 * `recipeLooksSecret` used to treat a fingerprint written as a peer as secret
 * material and refuse to build a link at all, so the Share sheet could claim
 * "No trust needed" about every link it ever produced. A peer is now the whole
 * fingerprint, on purpose, and the link is produced — so the claim would have
 * become false for exactly the notebooks people care most about, and false
 * quietly, at the moment of copying.
 *
 * The other half of the sheet's copy stays true and is not touched here: the
 * fragment never reaches a server. What changes is who can read it once it has
 * been passed on.
 *
 * **It says nothing when there is nothing to say.** An unplaced recipe — no
 * `@peer` header anywhere, which is most of them — discloses no audience, and a
 * warning printed over it would be prose describing a product that does not
 * exist, which is the defect this repo landed a fix for the same night
 * (`42875a2`) *because a test was enforcing the false sentence*. So the empty
 * list is the ordinary answer and the caller draws nothing for it.
 *
 * Counted from the text rather than from a compiled plan, because that is what
 * the link is built from: `hashForRecipe` takes text and never compiles, so a
 * disclosure derived from a plan could describe a notebook the link does not
 * carry. The detector is `fingerprintPeersInText`, which is the *same* regex
 * the refusal used — one reading of "does this text name keys", so the sentence
 * and the link cannot disagree.
 *
 * @param {string} recipe  the notebook text a link would carry
 * @returns {{ peers: string[], sentence: string }} `sentence` is "" when the
 *   notebook names nobody
 */
export function recipeLinkDiscloses(recipe) {
  const peers = fingerprintPeersInText(recipe || "");
  if (!peers.length) return { peers, sentence: "" };
  return {
    peers,
    sentence:
      `This notebook places cells on ${peers.length === 1 ? "1 key" : `${peers.length} keys`}, ` +
      `so the link carries ${peers.length === 1 ? "that fingerprint" : "those fingerprints"} ` +
      `— anyone who opens it learns who is in the room, and a room is derived ` +
      `from its audience. The link still reaches no server. Send it the way you ` +
      `would send the invite.`,
  };
}

/**
 * Prefer short form when notebook matches a starter or preset recipe.
 * @param {string} recipe
 * @param {{ starter?: MessagingStarter|null, presetId?: string|null, presetRecipe?: string|null }} [hint]
 * @returns {{ hash: string, ok: boolean, reason?: string }}
 */
export function hashForNotebook(recipe, hint = {}) {
  const norm = normalizeRecipeText(recipe);
  if (hint.starter && MESSAGING_STARTERS[hint.starter]) {
    if (norm === normalizeRecipeText(MESSAGING_STARTERS[hint.starter].recipe)) {
      return { hash: hashForStarter(hint.starter), ok: true };
    }
  }
  for (const [id, spec] of Object.entries(MESSAGING_STARTERS)) {
    if (norm === normalizeRecipeText(spec.recipe)) {
      return { hash: hashForStarter(/** @type {MessagingStarter} */ (id)), ok: true };
    }
  }
  if (hint.presetId && hint.presetRecipe != null) {
    if (norm === normalizeRecipeText(hint.presetRecipe)) {
      return { hash: hashForPreset(hint.presetId), ok: true };
    }
  }
  return hashForRecipe(recipe);
}

/**
 * The hash forms this product writes *for* a reader, as opposed to ones a
 * reader navigates to. `#keys` is the counter-example and the reason this
 * exists: it is a nav destination, so the address bar may replace it with
 * something better but must never blank it and leave the tray's own link
 * pointing at nothing.
 *
 * @param {string} hash  with or without leading #
 */
function isWrittenHash(hash) {
  const action = parseToolkitHash(hash);
  return (
    action.kind === "recipe" ||
    action.kind === "preset" ||
    action.kind === "starter" ||
    action.kind === "join"
  );
}

/**
 * What the address bar should say about the toolkit right now.
 *
 * The whole point is copy-and-paste: whatever is in the URL bar at any moment
 * should be the thing a reader would want to send someone, without them first
 * having to find a button. So this answers one question — *what is the
 * shareable artifact on screen* — and the caller writes it with
 * `writeToolkitHash`.
 *
 * **A live session outranks the notebook.** While a room is up, the useful
 * thing to paste into a chat is the way in; a recipe your peer can also just
 * ask you for is not. When the session ends the notebook takes the bar back.
 *
 * **The invite still carries no recipe**, exactly as `parseToolkitHash` reads
 * them: no `r=` is merged into the `j=` form and no `ct=` is carried onto it.
 * Both ends holding the same text, and proving it by digest, is what makes a
 * shared run a reproducible build rather than a screen share, and a URL that
 * quietly shipped one person's notebook with the invitation would undo that
 * without anybody choosing it. The notebook does travel now — signed, over the
 * session, as `notebook-share.js` describes — and that is why this stays true
 * rather than a reason to relax it: receiving a notebook is a thing a person
 * can see happen and answer, and a link that carried one silently is not.
 *
 * **`write: false` is not the same as clearing.** A notebook that cannot be
 * linked — secret material in it, or too long — must not leave a stale `#r=`
 * behind, because that link would claim to be the notebook on screen and be a
 * different one. But blanking a hash this writer did not put there would break
 * `#keys`. So it clears what it owns (`isWrittenHash`) and otherwise keeps its
 * hands off.
 *
 * @param {{
 *   recipe?: string,
 *   sessionLive?: boolean,
 *   audience?: string[],
 *   currentHash?: string,
 *   starter?: MessagingStarter|null,
 *   presetId?: string|null,
 *   presetRecipe?: string|null,
 * }} state
 * @returns {{ write: true, hash: string, kind: "join"|"notebook"|"clear" }
 *          | { write: false, reason: string }}
 */
export function hashForToolkitState(state = {}) {
  const current = String(state.currentHash ?? "");
  /**
   * @param {string} reason
   * @returns {{ write: true, hash: string, kind: "clear" } | { write: false, reason: string }}
   */
  const keepOrClear = (reason) =>
    isWrittenHash(current)
      ? { write: true, hash: "#", kind: "clear" }
      : { write: false, reason };

  if (state.sessionLive) {
    const join = hashForJoin(state.audience || []);
    // A live room always has an audience of at least two, so this branch is
    // reachable only while one is being assembled. The bar is left as it was
    // rather than flicking to a half-built invite somebody might copy.
    if (!join.ok) return { write: false, reason: join.reason || "No room to link yet." };
    return { write: true, hash: join.hash, kind: "join" };
  }

  const recipe = normalizeRecipeText(state.recipe || "");
  if (!recipe) return keepOrClear("Nothing in the notebook to link.");

  const result = hashForNotebook(recipe, {
    starter: state.starter ?? null,
    presetId: state.presetId ?? null,
    presetRecipe: state.presetRecipe ?? null,
  });
  if (!result.ok) return keepOrClear(result.reason || "This notebook cannot be shared in a link.");

  // Carry a ciphertext seed across the rewrite. Someone who opened
  // `#decrypt&ct=…` and then edited a step would otherwise watch the message
  // fall out of their own URL — the seed is an input, independent of the recipe
  // text, so an edit is no reason to drop it. If the pair no longer fits, the
  // recipe link wins and the ciphertext stays where it already is, in Inputs.
  const { ct } = splitCtParam(current.startsWith("#") ? current.slice(1) : current);
  if (ct) {
    const withSeed = `${result.hash}&ct=${ct}`;
    if (withSeed.length <= TOOLKIT_HASH_MAX_LEN) {
      return { write: true, hash: withSeed, kind: "notebook" };
    }
  }
  return { write: true, hash: result.hash, kind: "notebook" };
}

/**
 * @param {string} text
 */
export function normalizeRecipeText(text) {
  return String(text ?? "")
    .replace(/\r\n/g, "\n")
    .trim();
}

/**
 * Refuse to put private armor / obvious secret blobs in the hash.
 *
 * Re-exported, not defined here. The rule moved to `recipe-secrets.js` when a
 * second boundary needed it — a notebook proposal on the session wire, which is
 * not a URL and must not import a URL codec to ask whether a recipe holds a
 * private key. The name stays because every caller in this module and in
 * `workspace-store.js` already spells it this way, and because one predicate
 * with two names is still one predicate; two predicates would be the defect.
 */
export { recipeLooksSecret };

/**
 * Absolute share URL for the current page + hash.
 * @param {string} hash  including #
 * @param {{ origin?: string, path?: string }} [opts]
 */
export function toolkitShareUrl(hash, opts = {}) {
  const origin =
    opts.origin ||
    (typeof location !== "undefined" ? location.origin : "https://example.invalid");
  const path = opts.path || "/toolkit";
  const h = String(hash || "#").startsWith("#") ? String(hash || "#") : `#${hash}`;
  return `${origin}${path}${h === "#" ? "" : h}`;
}

/**
 * @param {string} hash
 * @param {{ replace?: boolean }} [opts]
 */
export function writeToolkitHash(hash, opts = {}) {
  if (typeof history === "undefined" || typeof location === "undefined") return;
  const h = String(hash || "#");
  const next = h.startsWith("#") ? h : `#${h}`;
  if (location.hash === next || (next === "#" && !location.hash)) return;
  const url = `${location.pathname}${location.search}${next === "#" ? "" : next}`;
  if (opts.replace !== false) {
    history.replaceState(null, "", url);
  } else {
    history.pushState(null, "", url);
  }
}

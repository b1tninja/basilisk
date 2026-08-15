/**
 * Recursive-descent recipe parser (PEG-style ordered choice).
 * Normative grammar: docs/RECIPE.md
 *
 * Supports multi-chain recipes (blank-line separated), `$slot` refs on `out`/`in`,
 * tee/foreach bodies, member selectors (`:public`, `[n]`), and bare `$slot` sources.
 *
 * AST steps match recipe.js RecipeStep, with:
 *   - chains[] + steps (= chains[0].steps)
 *   - tee.branches[].selector  e.g. ":private"
 *   - tee.branches[].member    canonical "private"|"public"
 *   - foreach.foreachSelector  e.g. ":items" (optional)
 *   - select steps for bare selectors: { name: "select", params: { selector } }
 *   - bare `$label` → { name: "in", params: { ref: "$label" } }
 *
 * Sigils. `$` marks a slot; `@` names a peer at the chain-header position and is
 * *not* a slot marker there. Recipes written before the swap spelled slots with
 * `@`, so `@label` is still read as a slot in the two positions where nothing
 * else can appear — after `out`/`in`, and after `param=` — and normalized to
 * `$label` in the AST, so the very next serialize writes the new spelling. Both
 * sigils are start-anchored: they mark a slot only as the first character of a
 * reference token, which is what keeps `to=alice@example.com` literal — and
 * what makes `passphrase=my$ecret` a literal the parser then refuses, because a
 * `secret` param takes a ref and nothing else.
 *
 * Chain header. A chain (a notebook cell) may open with `@peer` before its
 * first step: `@` is who, `$` is what. The header is inert grammar — it names
 * the party a cell belongs to and nothing else; what leaves that machine is a
 * `publish` step standing behind the `out` it is a claim about. The retired
 * `@peer publish` / `@peer publish=$a,$b` still read here and are rewritten
 * into those steps, so a link written before the change opens into the
 * notebook it meant.
 */

import { canonicalName, getStep } from "./registry.js";
import {
  legacyRemovalHint,
  resolveAlternateForm,
  resolveDecodeTwinVerb,
} from "./step-names.js";

/**
 * @typedef {import("./recipe.js").RecipeStep} RecipeStep
 * @typedef {import("./recipe.js").RecipeError} RecipeError
 * @typedef {import("./recipe.js").TeeBranch} TeeBranch
 */

/**
 * The clause a `secret` param's refusal opens with, and the one thing
 * `recipe-secrets.js` can ask this module about a text it must not copy.
 *
 * A `RecipeError` carries a message and a span, no kind, and giving it one
 * means editing a typedef three modules over for a single flag. So the sentence
 * itself is the contract: written once, matched once, and both ends fail
 * together if it is reworded.
 */
export const SECRET_LITERAL_REFUSAL = "a secret takes an $slot, never a literal";

/** @typedef {{ type: string, value: string, start: number, end: number }} Tok */

/**
 * A chain header, read.
 * @typedef {object} ChainHead
 * @property {string} peer
 * @property {boolean} publish
 * @property {string[]} publishSlots  labels `publish=` named, empty for a bare
 *   `publish` — which means every `out` the cell writes
 * @property {number} start
 * @property {number} end
 */

/**
 * The two selectors that are also step names.
 *
 * They project a keypair's halves — a pipeline value in, a pipeline value out
 * — which is a verb's shape, so they are spelled as verbs. Exported because
 * three modules have to agree on exactly which selectors lost their sigil:
 * the parser reads them, `serializePipeline` writes them bare, and the ops
 * drawer offers them.
 */
export const SELECT_PUBLIC = "public";
export const SELECT_PRIVATE = "private";

const SELECTOR_MEMBERS = new Set([
  "private",
  "public",
  "keys",
  "values",
  "items",
  "key",
  "value",
]);

/**
 * @param {string} raw
 * @returns {string}
 */
export function canonicalSelectorMember(raw) {
  const m = String(raw || "")
    .replace(/^[.:]/, "")
    .toLowerCase();
  // Legacy shorts accepted only via Upgrade recipe / migrator — not live parse.
  if (m === "private") return "private";
  if (m === "public") return "public";
  return m;
}

/** Slot sigil in the current grammar. */
export const SLOT_SIGIL = "$";

/** Pre-swap slot sigil, still read (and rewritten) for old share links. */
export const LEGACY_SLOT_SIGIL = "@";

/** Slot a bare `out` writes to. */
export const DEFAULT_OUT_SLOT = "$output";

/** Peer sigil — `@` names *who* a chain runs for, where `$` names *what*. */
export const PEER_SIGIL = "@";

/**
 * Rendezvous peer: every participant, entering together.
 *
 * Spelled `*` rather than `all` because `*` cannot be a label — `SLOT_LABEL_RE`
 * requires a leading letter — so the wildcard can never collide with a
 * participant who is actually called `all`.
 */
export const PEER_WILDCARD = "*";

/**
 * The step that sends a value to the room: `… | out $a | publish`.
 *
 * A verb, because anything that leaves this machine is a verb. It used to be a
 * modifier on the header — `@alice publish=$a,$b` — which put the claim about
 * *this value* two lines away from the value and made the header answer two
 * questions instead of one. `PEER_PUBLISH_KEYWORD` below is the same word in
 * the position it used to occupy, still read so that recipes already riding in
 * `#r=` links keep their meaning.
 */
export const PUBLISH_STEP = "publish";

/**
 * The retired header modifier, still read at the head of a cell.
 *
 * Deliberately the same word as the step: a reader who knew the old spelling
 * meets the new one under the same name, and a recipe carrying the old one is
 * rewritten into the new one on parse rather than refused — the same trade
 * `split 3` makes, where an input form converges on the canonical text through
 * `serializeRecipe` instead of living beside it.
 */
export const PEER_PUBLISH_KEYWORD = PUBLISH_STEP;

/**
 * What separates two names in the retired `publish=$a,$b`.
 *
 * A comma rather than a space, and that was forced rather than chosen. The
 * compact header spelling puts the header and the first step on one line —
 * `@alice publish $kpA|:public` is a real recipe that rides in a `#r=` link
 * today — so a space-separated list after `publish` would re-read that
 * existing text as *publish `$kpA`, then a pipeline that starts with a bare
 * selector*. One separator that cannot begin a step is the whole requirement,
 * and `comma/space separated` is already how this grammar spells a list of
 * values (`gpg.encrypt to=`, `age.encrypt to=`).
 */
export const PEER_PUBLISH_SEPARATOR = ",";

/**
 * `$` or the legacy `@`, at the *start* of a reference token only.
 * @param {string} ch
 * @returns {boolean}
 */
export function isSlotSigil(ch) {
  return ch === SLOT_SIGIL || ch === LEGACY_SLOT_SIGIL;
}

/**
 * A slot label, no sigil. Shared by the parser and by every caller that has to
 * build a pattern out of a label — `$` is the regex end-anchor, so a label must
 * never reach `new RegExp` unescaped.
 */
const SLOT_LABEL_RE = /^[A-Za-z][A-Za-z0-9_-]*$/;

/**
 * Escape a slot ref for interpolation into a regular expression.
 * `$` is the end-anchor and `$&`-style replacement syntax; a bare `$kp` spliced
 * into a pattern matches an empty string at end of input instead of the ref.
 * @param {string} ref
 * @returns {string}
 */
export function escapeSlotRefForRegExp(ref) {
  return String(ref ?? "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Path-shaped refs reserved for future file I/O.
 * @param {string} raw
 * @returns {boolean}
 */
export function isPathLikeRef(raw) {
  const s = String(raw || "").trim();
  if (!s) return false;
  if (/^file:/i.test(s)) return true;
  if (s.startsWith("./") || s.startsWith("../") || s.startsWith("/")) return true;
  if (s.includes("\\") || s.includes("/") && !isSlotSigil(s[0])) return true;
  if (/\.(pem|der|bin|txt|asc|key|spki|pkcs8)$/i.test(s)) return true;
  return false;
}

/**
 * Canonical slot ref for out/in: `$label` or decimal index string.
 * Labels must include `$` (bare `kp` / `key=cek` rejected — use migrateRecipe / Upgrade).
 * A legacy `@label` normalizes to `$label` and reports `legacy: true`, so the
 * caller can warn once and the AST carries only the new spelling.
 * @param {string} raw
 * @param {{ allowIndex?: boolean }} [opts]
 * @returns {{ ok: true, ref: string, legacy?: boolean } | { ok: false, error: string }}
 */
export function normalizeSlotRef(raw, opts = {}) {
  const allowIndex = opts.allowIndex !== false;
  const s = String(raw ?? "").trim();
  if (!s) return { ok: false, error: "Empty slot reference" };
  if (isPathLikeRef(s)) {
    return {
      ok: false,
      error:
        "File paths are not supported yet — use $label (e.g. out $kp / in $kp)",
    };
  }
  if (/^\d+$/.test(s)) {
    if (!allowIndex) {
      return { ok: false, error: `Slot index "${s}" is only valid on in` };
    }
    const n = Number(s);
    if (n < 1) return { ok: false, error: "Slot index must be ≥ 1" };
    return { ok: true, ref: String(n) };
  }
  if (!isSlotSigil(s[0])) {
    if (!SLOT_LABEL_RE.test(s)) {
      return { ok: false, error: `Invalid slot label "${s}"` };
    }
    return {
      ok: false,
      error: `Slot labels require $ (use $${s}, not ${s})`,
    };
  }
  const legacy = s[0] === LEGACY_SLOT_SIGIL;
  const bare = s.slice(1);
  if (!SLOT_LABEL_RE.test(bare)) {
    return { ok: false, error: `Invalid slot label "${s}"` };
  }
  return legacy
    ? { ok: true, ref: `${SLOT_SIGIL}${bare}`, legacy: true }
    : { ok: true, ref: `${SLOT_SIGIL}${bare}` };
}

/**
 * Longest peer name accepted.
 *
 * `SLOT_LABEL_RE` carries no length bound, which is right for a slot — the
 * label is local to the recipe and nothing else reads it. A peer is a *name in
 * shared text*, so an unbounded one is an unbounded string riding out in a
 * `#r=` link under a grammar that looks like it only holds short things.
 *
 * 64 is not an arbitrary generous number any more: it is the length of a v6
 * fingerprint, which is now the *canonical* spelling of a peer (see
 * `peerIsFingerprint`). So the bound is exactly "a whole fingerprint, and
 * nothing longer", and a hand-written name has all the room a name needs
 * underneath it.
 */
export const MAX_PEER_LABEL_LEN = 64;

/**
 * A whole OpenPGP fingerprint: 40 hex for v4, 64 for v6, and nothing between.
 *
 * These two lengths are the *only* hex spellings a peer may have, and the
 * exactness is the point — see `peerLooksLikeKeyId` immediately below for what
 * the lengths in between are and why they stay refused. `normalizePeerRef` does
 * not consult this: it admits every hex spelling structurally and leaves the
 * whole/partial question to the two predicates here, which is what keeps the
 * question answered once.
 */
const PEER_FINGERPRINT_SRC = "(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})";
const PEER_FINGERPRINT_RE = new RegExp(`^${PEER_FINGERPRINT_SRC}$`);

/**
 * Any hex run long enough to name a key and short enough to be one — the
 * superset the two rules split. Used only to tell "this was meant as a key"
 * from "this is a name".
 *
 * Bounded above at 64 rather than left open, and the bound is load-bearing
 * rather than tidy: `MAX_PEER_LABEL_LEN` is 64, so a 65-character string is
 * refused for its *length* and has to reach that refusal. Left open, a long
 * name that happened to be spelled out of `a`–`f` would be read as a malformed
 * key and told to write the whole fingerprint, which is advice about a key
 * nobody was holding.
 */
const PEER_HEXISH_RE = /^[0-9A-Fa-f]{16,64}$/;

/**
 * Is this peer a whole key fingerprint?
 *
 * **This used to be the shape a peer could not have, and it is now the shape a
 * peer is.** The old rule reasoned that a fingerprint in shared recipe text
 * hands over the audience, and the room is a digest of exactly that audience —
 * true then and true now. What changed is the answer to it: an invented label
 * layer (`@peer1`, numbered by position in the sorted audience) bought that
 * privacy with a name that meant nothing to a reader and that *moved under
 * them* every time the room changed size. The product now writes the key
 * itself, whole, and pays the disclosure openly — `fingerprintPeersInText`
 * exists so the Share sheet can say what a link carries instead of a refusal
 * pretending the situation cannot arise.
 *
 * It is exported because two very different callers need it and neither may
 * sniff for hex on its own: `normalizePeerRef` below, which must let a
 * fingerprint through a grammar that otherwise demands a leading letter, and
 * the surfaces that draw a peer, which render a *placard* for a key and plain
 * text for a name.
 *
 * @param {string} peer  canonical peer (no sigil)
 * @returns {boolean}
 */
export function peerIsFingerprint(peer) {
  return PEER_FINGERPRINT_RE.test(String(peer ?? ""));
}

/**
 * Is this peer a *part* of a key — a short or long key id?
 *
 * The refusal that survived the change, and the one worth being careful about:
 * "a fingerprint may now name a peer" is not "any hex may now name a peer".
 * 8, 16 and 32 hex characters are all suffixes of a fingerprint, so each of
 * them names *more than one key*; a roster keyed by fingerprint cannot bind
 * one, and a reader shown one is being asked to compare part of a value while
 * believing they compared the whole — which is the defect
 * `components/ui/fingerprint.tsx` exists to refuse, arriving through the
 * grammar instead of through a layout.
 *
 * So the hex peers now split in two rather than all being refused together:
 * whole is right, partial is wrong, and 16 is where "somebody typed a key id"
 * becomes a better reading than "somebody chose a name".
 *
 * @param {string} peer  canonical peer (no sigil)
 * @returns {boolean}
 */
export function peerLooksLikeKeyId(peer) {
  const s = String(peer ?? "");
  return PEER_HEXISH_RE.test(s) && !PEER_FINGERPRINT_RE.test(s);
}

/**
 * The refusal copy for a partial-key peer. One home, so the compile-time
 * refusal and anything that echoes it cannot drift apart.
 * @param {string} peer  canonical peer (no sigil)
 * @returns {string}
 */
export function peerKeyIdError(peer) {
  const s = String(peer ?? "");
  return (
    `\`${PEER_SIGIL}${s}\` is ${s.length} hex characters, which is part of a ` +
    `key rather than a key. A short id is a suffix of a fingerprint, so more ` +
    `than one key answers to it and no room can bind it — write the whole ` +
    `fingerprint (40 characters for v4, 64 for v6), or a name.`
  );
}

/**
 * The fingerprints a recipe's text names as peers.
 *
 * **The detector that used to power a refusal, now powering a disclosure.**
 * `recipeLooksSecret` called this shape a secret and stopped `#r=` links being
 * built from any notebook that had one; a placed notebook now legitimately
 * carries its audience's keys, so the link is built and the *Share sheet says
 * what is in it* instead. Same regex, opposite job, and it is the same regex
 * deliberately: a sentence about what a link discloses that could disagree
 * with what the link actually contains would be worse than no sentence.
 *
 * Anchored to the header position — start of text, start of a line, or after
 * the compact `~` separator — and nowhere else, exactly as the refusal was.
 * That is what keeps `hkp.get 4F2AC1…` and `gpg.encrypt to=4F2AC1…` out of
 * the count: a fingerprint is an ordinary public argument in those positions
 * and discloses nothing about who is in a room.
 *
 * @param {string} text
 * @returns {string[]} upper-case, each one once, in the order encountered
 */
export function fingerprintPeersInText(text) {
  const sigil = escapeSlotRefForRegExp(PEER_SIGIL);
  const re = new RegExp(
    `(?:^|[\\n~])[ ]*${sigil}(${PEER_FINGERPRINT_SRC})(?![0-9A-Za-z_-])`,
    "g"
  );
  /** @type {Set<string>} */
  const found = new Set();
  for (const m of String(text ?? "").matchAll(re)) found.add(m[1].toUpperCase());
  return [...found];
}

/**
 * Canonical peer ref for a chain header: a bare label, or `*` for everyone.
 *
 * Sits beside `normalizeSlotRef` — one canonicalizer per sigil — and shares
 * `SLOT_LABEL_RE` with it rather than restating the label rules, so there is
 * one label grammar and two sigils, not two grammars.
 *
 * **A whole fingerprint is a peer, and is canonicalised to upper case here.**
 * That is the one place the case can be settled: the roster is keyed by
 * `normalizeFingerprintInput`'s upper-case hex, `peersSha` digests it, and a
 * notebook that said `@aabb…` on one machine and `@AABB…` on the other would
 * derive two different manifests out of one identical intent. Settling it in
 * the canonicaliser means `serializeChain` writes one spelling and every
 * comparison downstream is against that spelling.
 *
 * A *partial* key is still structurally fine here and is returned as one: this
 * function answers "is this a peer", and `validateRecipe` answers "is this a
 * peer a room could bind" (`peerLooksLikeKeyId`). Splitting them keeps the
 * refusal somewhere it can carry a sentence instead of a token error — and
 * keeps *one* hex branch here, so the whole/partial line is drawn in exactly
 * one place rather than twice with a chance to disagree.
 * @param {string} raw  with or without the `@`
 * @returns {{ ok: true, peer: string } | { ok: false, error: string }}
 */
export function normalizePeerRef(raw) {
  const s = String(raw ?? "").trim();
  const bare = s[0] === PEER_SIGIL ? s.slice(1) : s;
  if (!bare) {
    return {
      ok: false,
      error:
        "Expected a peer after `@` — write `@<fingerprint>`, or `@*` for everyone",
    };
  }
  if (bare === PEER_WILDCARD) return { ok: true, peer: PEER_WILDCARD };
  // **One branch for every hex spelling, whole or partial, and it comes before
  // the name grammar.** `SLOT_LABEL_RE` demands a leading letter, and roughly
  // two hex strings in three begin with a digit; testing the name shape first
  // is what made the old rule accept some keys and reject others for a reason
  // nobody could see, and doing it here for whole fingerprints and there for
  // partial ones would rebuild that asymmetry inside the refusal.
  //
  // A *partial* key is admitted here on purpose, and refused by
  // `validateRecipe` (`peerLooksLikeKeyId`). Refusing it as a token would lose
  // the header — `parseChainHeader` consumes the bad token and carries on
  // reading the pipeline — so a mistyped key would leave a cell with no `@` at
  // all, and the notebook would compile as `solo` and run every cell here. The
  // semantic refusal keeps the header, anchors the complaint to it, and stops
  // the run.
  //
  // Upper case is settled here and nowhere else: the roster is keyed by
  // `normalizeFingerprintInput`'s upper-case hex, `peersSha` digests it, and a
  // notebook saying `@aabb…` on one machine and `@AABB…` on the other would be
  // one intent deriving two manifests.
  if (PEER_HEXISH_RE.test(bare)) return { ok: true, peer: bare.toUpperCase() };
  if (!SLOT_LABEL_RE.test(bare)) {
    return {
      ok: false,
      error:
        `Invalid peer "${PEER_SIGIL}${bare}" — a peer is a whole key ` +
        `fingerprint, or a letter followed by letters, digits, \`_\` or \`-\` ` +
        `(or \`@*\` for everyone)`,
    };
  }
  if (bare.length > MAX_PEER_LABEL_LEN) {
    return {
      ok: false,
      error:
        `Peer name "${PEER_SIGIL}${bare.slice(0, 12)}…" is ${bare.length} ` +
        `characters — a peer is a name, so keep it under ${MAX_PEER_LABEL_LEN}`,
    };
  }
  return { ok: true, peer: bare };
}

/**
 * Label key without its sigil (for registry maps). Null if index ref.
 * @param {string} ref
 * @returns {string|null}
 */
export function slotLabelKey(ref) {
  const s = String(ref || "");
  if (/^\d+$/.test(s)) return null;
  return isSlotSigil(s[0]) ? s.slice(1) : s;
}

/**
 * Every slot a cell writes, at any depth, in the order it writes them.
 *
 * A `tee` branch's `out` and a `foreach` body's `out` are this cell's output —
 * the fan-out is *how* a cell writes several things, not a different cell. One
 * definition, because four passes ask the question and each of them would
 * otherwise answer it slightly differently: the header validator used to look
 * only at the top-level steps and told a cell with three nested `out`s that it
 * had none.
 * @param {RecipeStep[]} steps
 * @returns {string[]}  labels, no sigil, first spelling wins
 */
export function outSlotLabels(steps) {
  /** @type {string[]} */
  const labels = [];
  const walk = (list) => {
    for (const step of list || []) {
      if (step?.name === "out") {
        const label = slotLabelKey(String(step.params?.name || ""));
        if (label && !labels.includes(label)) labels.push(label);
      }
      walk(step?.body || []);
      for (const br of step?.branches || []) walk(br?.body || []);
    }
  };
  walk(steps);
  return labels;
}

/**
 * The message every legacy-sigil warning carries.
 * @param {string} ref  canonical (`$label`) ref
 * @returns {string}
 */
export function legacySlotSigilWarning(ref) {
  const bare = slotLabelKey(ref) || "";
  return `Slots are written \`$${bare}\` now — \`@${bare}\` still loads and was rewritten. \`@\` names a peer.`;
}

/**
 * @typedef {import("./recipe.js").RecipeChain} RecipeChain
 */

/**
 * @param {string} source
 * @returns {{ ast: { chains: RecipeChain[], steps: RecipeStep[], source: string }|null, errors: RecipeError[], warnings: RecipeError[] }}
 */
export function parseRecipeSource(source) {
  const raw = String(source || "");
  const text = raw.trim();
  if (!text) {
    return {
      ast: { chains: [], steps: [], source: text },
      errors: [
        {
          message:
            "Empty recipe — start with a source step like genkey, random, or input.",
        },
      ],
      warnings: [],
    };
  }

  if (raw.includes("\t")) {
    const idx = raw.indexOf("\t");
    return {
      ast: null,
      errors: [
        {
          message: "Tabs are not allowed — use 2 spaces per indent level",
          start: idx,
          end: idx + 1,
        },
      ],
      warnings: [],
    };
  }

  // Pass 1 reads `@` as a slot only where nothing else can appear (after
  // `out`/`in`, after `param=`) and reads the chain-header `@` as a peer.
  const first = runParse(raw, text, false);
  // A chain-header `@kp` is only a slot in a recipe that is *provably* pre-swap:
  // one that spelled a slot `@` somewhere unambiguous. That is not a guess — a
  // bare `@kp` source can only resolve against an `out @kp` in the same source,
  // so every valid legacy recipe carries the evidence. Without it, `@` at the
  // head of a chain is the peer it now names.
  if (first.replayAsLegacy) return runParse(raw, text, true);
  return first;
}

/**
 * @param {string} raw
 * @param {string} text
 * @param {boolean} legacyChainHeader
 */
function runParse(raw, text, legacyChainHeader) {
  /** @type {RecipeError[]} */
  const errors = [];
  const p = new Parser(raw, errors);
  p.legacyChainHeader = legacyChainHeader;
  try {
    const chains = p.parseRecipe();
    const replayAsLegacy =
      !legacyChainHeader && p.sawReservedChainHeader && p.sawLegacySlotSigil;
    if (errors.length) {
      return { ast: null, errors, warnings: p.warnings, replayAsLegacy };
    }
    const steps = chains[0]?.steps || [];
    return {
      ast: { chains, steps, source: text },
      errors: [],
      warnings: p.warnings,
      replayAsLegacy,
    };
  } catch (err) {
    if (!errors.length) {
      errors.push({
        message: err?.message || String(err),
        start: p.pos,
        end: p.pos,
      });
    }
    return {
      ast: null,
      errors,
      warnings: p.warnings,
      replayAsLegacy:
        !legacyChainHeader && p.sawReservedChainHeader && p.sawLegacySlotSigil,
    };
  }
}

class Parser {
  /**
   * @param {string} src
   * @param {RecipeError[]} errors
   */
  constructor(src, errors) {
    this.src = src;
    this.errors = errors;
    /** @type {RecipeError[]} */
    this.warnings = [];
    this.pos = 0;
    /** Read a chain-header `@label` as a slot (legacy replay only). */
    this.legacyChainHeader = false;
    /** A `$label` was read as a slot where the position allows only a slot. */
    this.sawLegacySlotSigil = false;
    /** A chain began with `@label`, which this grammar reads as a peer. */
    this.sawReservedChainHeader = false;
    /**
     * Comments read since the last chain was closed, in the order written.
     *
     * A comment belongs to the cell it was written in — see `flush` — so this
     * is drained onto each chain rather than kept per step. It is the only
     * parser state that survives a `flush`: comments written above a cell are
     * read before the cell's first step exists.
     * @type {string[]}
     */
    this.comments = [];
    this.lineStarts = [0];
    for (let i = 0; i < src.length; i++) {
      if (src[i] === "\n") this.lineStarts.push(i + 1);
    }
  }

  /**
   * Record a legacy `@label` read, once per distinct ref.
   * @param {string} ref  canonical `$label`
   * @param {number} start
   * @param {number} end
   */
  noteLegacySlotSigil(ref, start, end) {
    this.sawLegacySlotSigil = true;
    const message = legacySlotSigilWarning(ref);
    if (this.warnings.some((w) => w.message === message)) return;
    this.warnings.push({ message, start, end });
  }

  eof() {
    return this.pos >= this.src.length;
  }

  peek() {
    return this.eof() ? "" : this.src[this.pos];
  }

  /**
   * Indent (spaces) at the start of the current line containing pos.
   * @returns {number}
   */
  lineIndentAt(pos) {
    let i = pos;
    while (i > 0 && this.src[i - 1] !== "\n") i--;
    let n = 0;
    while (i + n < this.src.length && this.src[i + n] === " ") n++;
    return n;
  }

  skipSpaces() {
    while (this.peek() === " ") this.pos++;
  }

  skipSpacesAndCommentsOnLine() {
    this.skipSpaces();
    if (this.peek() === "#") this.consumeComment();
  }

  /**
   * Read a `#` comment to end of line and keep it.
   *
   * Four places in this parser used to run this loop inline and throw the text
   * away — a full line at stem level, a trailing one after a pipeline, and one
   * inside each body form. Every character is consumed exactly once, so one
   * collector here means a comment is kept exactly once no matter which of the
   * four read it, and adding a fifth reading site cannot quietly reintroduce
   * the loss.
   *
   * The text is stored without the `#` and trimmed, because that is the form
   * `serializeChain` writes back: `#note`, `#  note` and `# note ` are one
   * comment, so a round trip converges instead of drifting a space per pass.
   * Positioned on the `#`.
   */
  consumeComment() {
    const from = this.pos + 1;
    while (!this.eof() && this.peek() !== "\n") this.pos++;
    this.comments.push(this.src.slice(from, this.pos).trim());
  }

  /**
   * @returns {RecipeChain[]}
   */
  parseRecipe() {
    /** @type {RecipeChain[]} */
    const chains = [];
    /** @type {RecipeStep[]} */
    let current = [];
    /** @type {ChainHead|null} */
    let head = null;

    const flush = () => {
      if (current.length) {
        /** @type {RecipeChain} */
        const chain = { steps: current };
        // A comment attaches to the cell, and only when the cell has one — an
        // absent field is what `Object.keys(chain)` has always shown for a
        // plain pipeline, and the manifest digests this shape.
        if (this.comments.length) chain.comments = this.comments;
        this.comments = [];
        if (head) {
          chain.peer = head.peer;
          if (head.publish) this.applyRetiredPublishHeader(chain, head);
          chain.headerStart = head.start;
          chain.headerEnd = head.end;
        }
        chains.push(chain);
        current = [];
      } else if (head) {
        // A header with nothing under it is not a cell — and it would not
        // survive a serialize round trip, since the serializer has no chain to
        // hang it on.
        this.errors.push({
          message:
            `\`${PEER_SIGIL}${head.peer}\` names the peer a cell runs for, ` +
            `but no steps follow it`,
          start: head.start,
          end: head.end,
        });
      }
      head = null;
    };

    while (!this.eof()) {
      const lineStart = this.pos;
      this.skipSpaces();

      // Blank line → chain separator (once we have content).
      if (this.peek() === "\n" || this.eof()) {
        if (this.peek() === "\n") this.pos++;
        if (current.length) flush();
        continue;
      }

      // Full-line comment — stays inside the current chain.
      if (this.peek() === "#") {
        this.consumeComment();
        if (this.peek() === "\n") this.pos++;
        continue;
      }

      // Orphan list marker at stem level.
      if (this.peek() === "-") {
        this.errors.push({
          message:
            "Unexpected indent — use `- step` under tee/foreach (or `{ … }` bodies)",
          start: this.pos,
          end: this.pos + 1,
        });
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }

      // A leading `|` continues the stem of the chain above it, so the line
      // after it is not the head of a chain.
      let atChainHead = current.length === 0;
      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
        atChainHead = false;
      }

      // `@peer` — who this cell runs for. Read only at the
      // head of a chain, and only when this pass is not replaying the recipe
      // as pre-swap text (see parseRecipeSource).
      if (atChainHead && this.peek() === PEER_SIGIL && !this.legacyChainHeader) {
        const h = this.parseChainHeader();
        if (h) {
          if (head) {
            this.errors.push({
              message:
                `This cell already runs for \`${PEER_SIGIL}${head.peer}\` — ` +
                `one peer per cell (start a new cell with a blank line)`,
              start: h.start,
              end: h.end,
            });
          } else {
            head = h;
          }
        }
        this.skipSpacesAndCommentsOnLine();
        if (this.peek() === "\n") {
          // Pretty form: the header owns the line, the steps follow below.
          this.pos++;
          continue;
        }
        if (this.eof()) continue;
        // Compact form: `@alice publish $kpA|:public`. The `@` is spent, so
        // the stage that follows is an ordinary first step.
      }

      void lineStart;
      const pipeSteps = this.parsePipeline(0);
      current.push(...pipeSteps);

      this.skipSpacesAndCommentsOnLine();
      if (this.peek() === "\n") {
        // Indent bodies may leave pos on a blank line (chain separator). That
        // newline is not stem EOL — flush before the next chain.
        const blankLine = this.isBlankLineEndingAt(this.pos);
        this.pos++;
        if (blankLine) flush();
      } else if (!this.eof()) {
        this.errors.push({
          message: `Unexpected "${this.peek()}"`,
          start: this.pos,
          end: this.pos + 1,
        });
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
      }
    }
    flush();
    // A comment written after the last cell has no cell of its own — a
    // header-only chain is an error and a comment-only one would serialize to
    // nothing, so there is nowhere to put it but the cell above. It joins that
    // cell's comments rather than being dropped: the whole point of this change
    // is that a sentence a person wrote for a reader is not silently destroyed,
    // and "moved to the top of the last cell" is a thing a reader can see.
    if (this.comments.length && chains.length) {
      const last = chains[chains.length - 1];
      last.comments = [...(last.comments || []), ...this.comments];
      this.comments = [];
    }
    return chains.length ? chains : [{ steps: [] }];
  }

  /**
   * Rewrite a retired `@peer publish` header into `publish` steps.
   *
   * The header used to carry the disclosure and the steps now do, so a recipe
   * written in the old spelling is *translated* on the way in rather than
   * refused. Those recipes are not hypothetical: a notebook travels as a `#r=`
   * fragment, and a link somebody mailed last week still has to open into the
   * notebook they meant. Translating on parse means one canonical text comes
   * out of `serializeRecipe` either way, which is the same trade `split 3`
   * makes — an input form that converges rather than a second dialect that
   * persists.
   *
   * `publish` with no list meant *every* `out` the cell writes, so that is what
   * it becomes: a `publish` after each of them, at any depth. `publish=$a,$b`
   * becomes one after each named `out`.
   *
   * A name the cell does not write is still an error, and still says what the
   * cell does write. It cannot become a step — there is no `out` to stand
   * behind — and dropping it silently would turn a typo into a cell that
   * publishes nothing while reading as though it publishes something.
   *
   * @param {RecipeChain} chain
   * @param {ChainHead} head
   */
  applyRetiredPublishHeader(chain, head) {
    const written = outSlotLabels(chain.steps || []);
    const named = head.publishSlots;
    if (!written.length) {
      this.errors.push({
        message:
          `\`${PEER_SIGIL}${head.peer} ${PEER_PUBLISH_KEYWORD}\` publishes ` +
          `this cell's \`out\` artifacts, but the cell has no \`out\` — add ` +
          `\`out ${SLOT_SIGIL}name | ${PUBLISH_STEP}\``,
        start: head.start,
        end: head.end,
      });
      return;
    }
    for (const label of named) {
      if (written.includes(label)) continue;
      this.errors.push({
        message:
          `\`${PEER_SIGIL}${head.peer} ${PEER_PUBLISH_KEYWORD}=` +
          `${SLOT_SIGIL}${label}\` publishes \`${SLOT_SIGIL}${label}\`, but ` +
          `this cell does not write it — it writes ` +
          `${written.map((l) => `\`${SLOT_SIGIL}${l}\``).join(", ")}`,
        start: head.start,
        end: head.end,
      });
    }
    const wanted = new Set(named.length ? named : written);
    const walk = (list) => {
      /** @type {RecipeStep[]} */
      const next = [];
      for (const step of list || []) {
        if (step?.body || step?.branches) {
          next.push({
            ...step,
            ...(step.body ? { body: walk(step.body) } : {}),
            ...(step.branches
              ? { branches: step.branches.map((br) => ({ ...br, body: walk(br.body) })) }
              : {}),
          });
        } else {
          next.push(step);
        }
        if (step?.name === "out") {
          const label = slotLabelKey(String(step.params?.name || ""));
          // Span-less on purpose: these steps are not in the source text, and a
          // squiggle under characters the author did not write would point at
          // the wrong thing. The next serialize gives them one.
          if (label && wanted.has(label)) next.push({ name: PUBLISH_STEP, params: {} });
        }
      }
      return next;
    };
    chain.steps = walk(chain.steps);
  }

  /**
   * `@peer`, `@peer publish` or `@peer publish=$a,$b` at the head of a chain.
   * Positioned on the `@`.
   *
   * Returns null when the token is not a peer name; the error is already
   * recorded and the whole bad token consumed, so the caller can carry on
   * reading the pipeline instead of producing a second complaint about the
   * same characters.
   * @returns {ChainHead|null}
   */
  parseChainHeader() {
    const start = this.pos;
    this.pos++; // @
    // Recorded, never counted: reaching this branch says the recipe *used* the
    // reserved position, not that it spelled its slots with `@`. This `@` must
    // never be its own evidence that the recipe is legacy, or the reservation
    // would unmake itself.
    this.sawReservedChainHeader = true;

    const tokStart = this.pos;
    while (!this.eof() && !/[\s|#]/.test(this.peek())) this.pos++;
    const norm = normalizePeerRef(this.src.slice(tokStart, this.pos));
    if (!norm.ok) {
      this.errors.push({ message: norm.error, start, end: this.pos });
      return null;
    }

    // `publish`, and only as a whole token — `@alice publishing` is a peer
    // followed by a step name the registry will not know. `=` is not a label
    // character, so `publish=$a` still reads as the whole keyword.
    let publish = false;
    /** @type {string[]} */
    let publishSlots = [];
    const afterPeer = this.pos;
    this.skipSpaces();
    const kwEnd = this.pos + PEER_PUBLISH_KEYWORD.length;
    if (
      this.src.startsWith(PEER_PUBLISH_KEYWORD, this.pos) &&
      !/[A-Za-z0-9_-]/.test(this.src[kwEnd] || "")
    ) {
      this.pos = kwEnd;
      publish = true;
      if (this.peek() === "=") {
        this.pos++;
        publishSlots = this.parsePublishSlots(start);
      }
    } else {
      this.pos = afterPeer;
    }
    const end = this.pos;

    // `@alice | genkey` reads as a peer with a stray pipe *or* as a pre-swap
    // slot at a position that is no longer one. Name both fixes, recover past
    // the `|`, and leave it at one error either way.
    this.skipSpaces();
    if (this.peek() === "|") {
      this.errors.push({
        message:
          `\`${PEER_SIGIL}${norm.peer}\` at the head of a cell names the peer ` +
          `it runs for, not a step — drop the \`|\` after it, or write the ` +
          `slot as \`${SLOT_SIGIL}${norm.peer}\``,
        start,
        end: this.pos + 1,
      });
      this.pos++;
    }
    return { peer: norm.peer, publish, publishSlots, start, end };
  }

  /**
   * The `$a,$b` after `publish=`. Positioned just past the `=`.
   *
   * Every name is refused unless it carries the `$`. That is stricter than
   * `out`/`in`, which still read a pre-swap `@label`, and deliberately so:
   * `publish=` is newer than the sigil swap, so no recipe in the wild spells a
   * name here at all. Accepting `@` would be reviving an ambiguity for text
   * that cannot exist, at the one position where `@` already means a peer.
   *
   * Errors are recorded and the rest of the list still read, so a typo in the
   * first name does not turn the second one into a stray step.
   * @param {number} headerStart  the `@`, so a complaint spans the whole header
   * @returns {string[]}  canonical labels, no sigil, first spelling wins
   */
  parsePublishSlots(headerStart) {
    /** @type {string[]} */
    const labels = [];
    for (;;) {
      const tokStart = this.pos;
      while (!this.eof() && !/[\s|#,]/.test(this.peek())) this.pos++;
      const raw = this.src.slice(tokStart, this.pos);
      const at = { start: headerStart, end: Math.max(this.pos, tokStart + 1) };
      if (!raw) {
        this.errors.push({
          message:
            `\`${PEER_PUBLISH_KEYWORD}=\` names the slots this cell sends to ` +
            `the room — write \`${PEER_PUBLISH_KEYWORD}=${SLOT_SIGIL}name\`, ` +
            `or drop the \`=\` to publish every \`out\` the cell writes`,
          ...at,
        });
      } else if (raw[0] === LEGACY_SLOT_SIGIL) {
        this.errors.push({
          message:
            `Slots after \`${PEER_PUBLISH_KEYWORD}=\` are written ` +
            `\`${SLOT_SIGIL}${raw.slice(1)}\` — \`${LEGACY_SLOT_SIGIL}\` names ` +
            `a peer at the head of a cell, which is where this is`,
          ...at,
        });
      } else {
        const norm = normalizeSlotRef(raw, { allowIndex: false });
        if (!norm.ok) this.errors.push({ message: norm.error, ...at });
        else {
          const label = slotLabelKey(norm.ref);
          // A repeated name is the same claim twice, not a second one.
          if (label && !labels.includes(label)) labels.push(label);
        }
      }
      if (this.peek() !== PEER_PUBLISH_SEPARATOR) break;
      this.pos++;
    }
    return labels;
  }

  /**
   * @param {number} parentIndent
   * @returns {RecipeStep[]}
   */
  parsePipeline(parentIndent) {
    /** @type {RecipeStep[]} */
    const stages = [];
    stages.push(this.parseStage(parentIndent));
    for (;;) {
      this.skipSpaces();
      if (this.peek() !== "|") break;
      // Don't consume `|` that starts a new stem line after indent body —
      // those are handled by the caller at indent 0.
      this.pos++;
      this.skipSpaces();
      if (this.peek() === "\n" || this.eof()) {
        this.errors.push({
          message: "Dangling `|` — expected a step after the pipe",
          start: this.pos,
          end: this.pos,
        });
        break;
      }
      stages.push(this.parseStage(parentIndent));
    }
    // `$kp | out` → out inherits $kp (same as `in $kp | out $kp`).
    for (let i = 1; i < stages.length; i++) {
      const prev = stages[i - 1];
      const cur = stages[i];
      if (cur.name !== "out") continue;
      const name = cur.params?.name;
      const isDefault =
        name === undefined || name === "" || name === DEFAULT_OUT_SLOT;
      if (!isDefault) continue;
      if (
        prev.name === "in" &&
        String(prev.params?.ref || "").startsWith(SLOT_SIGIL)
      ) {
        cur.params = { ...cur.params, name: String(prev.params.ref) };
      }
    }
    return stages;
  }

  /**
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseStage(parentIndent) {
    this.skipSpaces();
    if (this.peek() === ":") {
      return this.parseSelectorStage();
    }
    if (this.peek() === ".") {
      const start = this.pos;
      this.pos++;
      const id = this.readIdent();
      this.errors.push({
        message: id
          ? `Member selectors use :${id.toLowerCase()} (dot is for namespaced ops like gpg.encrypt)`
          : "Member selectors use :public / :private (dot is for namespaced ops like gpg.encrypt)",
        start,
        end: this.pos,
      });
      return {
        name: "select",
        params: { selector: id ? `:${id}` : ":" },
        start,
        end: this.pos,
      };
    }
    if (this.peek() === "[") {
      return this.parseIndexSelectorStage();
    }
    if (this.peek() === SLOT_SIGIL) {
      return this.parseBareSlotStage();
    }
    if (this.peek() === LEGACY_SLOT_SIGIL) {
      // Mid-pipeline, `@` has no peer reading — the chain-header position is
      // the only one that does, and `parseChainHeader` has already spent it by
      // the time any stage is parsed. So here the legacy slot read is safe,
      // and stays safe in the legacy replay pass, where the header `@` reaches
      // this branch too.
      return this.parseBareSlotStage();
    }

    // Stem literals: "…" / '…' / 0xff / decimal int / true|false.
    if (this.peek() === '"' || this.peek() === "'") {
      return this.parseLiteralStage();
    }
    if (/[0-9]/.test(this.peek())) {
      return this.parseLiteralStage();
    }
    if (/^(true|false)(?![A-Za-z0-9_.+/-])/i.test(this.src.slice(this.pos))) {
      return this.parseLiteralStage();
    }

    const nameStart = this.pos;
    const name = this.readStepName();
    if (!name) {
      this.errors.push({
        message: "Expected a step name",
        start: this.pos,
        end: this.pos,
      });
      return {
        name: "inspect",
        params: {},
        start: nameStart,
        end: this.pos,
      };
    }

    const lower = name.toLowerCase();
    if (lower === "merge" || lower === "collect") {
      this.errors.push({
        message:
          `"${name}" is not used — foreach bodies close by dedent or \`}\` (see docs/RECIPE.md)`,
        start: nameStart,
        end: this.pos,
      });
      return {
        name: lower,
        params: {},
        start: nameStart,
        end: this.pos,
      };
    }

    // `public` / `private` — the keypair halves, written as verbs.
    //
    // A sigil for something that is a step everywhere else was the whole of
    // what `:public` bought. It projects a pipeline value and hands the result
    // on, which is what every other transform does, and the type rule that
    // refuses it on anything but a keypair is unchanged and unchanged in
    // wording: `projectTypeForMember` still answers, and still says `selector
    // ":public" requires keypair`.
    //
    // The colon form still reads (`parseSelectorStage`), and both spellings
    // produce the one `select` step — so the AST has one shape and
    // `serializePipeline` writes the bare word, which is what makes the two
    // converge instead of persisting side by side.
    //
    // The *other* selectors keep their colon, and that is a distinction rather
    // than an omission. `:key` and `:value` project a member of the item a
    // `foreach :items` loop is currently holding, so a step named `value`
    // would be an error everywhere in the language except inside one mode of
    // one loop; `:items` / `:keys` / `:values` are not projections at all but
    // the loop's own mode, written where the loop is declared.
    if (lower === SELECT_PUBLIC || lower === SELECT_PRIVATE) {
      return {
        name: "select",
        params: { selector: `:${lower}` },
        start: nameStart,
        end: this.pos,
      };
    }

    // HMAC sugar → SubtleCrypto sign/verify (serialize as sign/verify).
    if (lower === "hmac") {
      return this.parseApply("sign", name, nameStart);
    }
    if (lower === "hmac.verify") {
      return this.parseApply("verify", name, nameStart);
    }

    // CyberChef encoding: `to` / `from` are normal registry steps (positional encoding).
    // Bare encrypt|decrypt sugar is migrator-only — hard-error in live parse.
    if (lower === "encrypt" || lower === "decrypt") {
      this.errors.push({
        message:
          `"${name}" was removed from live parse — use a concrete cipher (aes-gcm, …) or Upgrade recipe to migrate`,
        start: nameStart,
        end: this.pos,
      });
      return {
        name: "aes-gcm",
        params: { decode: lower === "decrypt" },
        start: nameStart,
        end: this.pos,
      };
    }

    // Encoding twins: base64.encode / base64.decode → base64 / base64 -d.
    const twinVerb = resolveDecodeTwinVerb(name, getStep);
    if (twinVerb) {
      const step = this.parseApply(twinVerb.canonical, name, nameStart);
      step.params = { ...step.params, decode: twinVerb.decode };
      return step;
    }

    const alt = resolveAlternateForm(name);
    const lookup = alt?.canonical || name;
    const canon = canonicalName(lookup);
    if (!canon) {
      const legacy = legacyRemovalHint(name);
      const jceHint =
        name.includes("/") && !legacy
          ? `Unknown JCE transform "${name}"; try aes-gcm (or AES/GCM/NoPadding)`
          : null;
      this.errors.push({
        message:
          legacy ||
          jceHint ||
          `Unknown step "${name}". See the Reference panel for available steps.`,
        start: nameStart,
        end: this.pos,
      });
      return {
        name: name.toLowerCase(),
        params: {},
        start: nameStart,
        end: this.pos,
      };
    }

    if (canon === "tee") {
      return this.parseTeeBlock(nameStart, parentIndent);
    }
    if (canon === "foreach") {
      return this.parseForeachBlock(nameStart, parentIndent);
    }

    const step = this.parseApply(canon, name, nameStart);
    if (alt?.expectedKeyBits) {
      step.params = { ...step.params, keyBits: alt.expectedKeyBits };
    }
    if (alt?.oaepHash) {
      step.params = { ...step.params, hash: alt.oaepHash };
    }
    // Bare `send` refuses; bare `quorum.send` broadcasts. The alias is
    // *narrower* than the name it resolves to, on purpose: an absent
    // recipient deciding "everyone" is an absence deciding a security
    // property, which the short verb never inherits. Checked here because
    // this is the last place the spelling the author typed still exists —
    // the AST carries only `quorum.send`, so `validateRecipe` could not
    // tell the two apart without a field invented to carry the difference.
    if (
      canon === "quorum.send" &&
      lower === "send" &&
      !String(step.params?.to ?? "").trim()
    ) {
      this.errors.push({
        message:
          "`send` names no recipient — write `send <fingerprint>` (or " +
          "`to=<fingerprint>`) so the text says who is handed the value. " +
          "To broadcast to every verified peer, write `quorum.send`, whose " +
          "empty `to=` is documented to mean that.",
        start: nameStart,
        end: this.pos,
      });
    }
    return step;
  }

  /**
   * Stem literal stage → internal `lit` (serialize writes the literal form).
   * @returns {RecipeStep}
   */
  parseLiteralStage() {
    const start = this.pos;
    if (this.peek() === '"' || this.peek() === "'") {
      const value = this.readString();
      return {
        name: "lit",
        params: { kind: "text", value },
        start,
        end: this.pos,
      };
    }
    // Bool: true / false (case-insensitive; must be a whole token).
    if (/^(true|false)(?![A-Za-z0-9_.+/-])/i.test(this.src.slice(this.pos))) {
      const word = this.src.slice(this.pos).match(/^(true|false)/i)?.[0] || "";
      this.pos += word.length;
      return {
        name: "lit",
        params: { kind: "bool", value: word.toLowerCase() === "true" },
        start,
        end: this.pos,
      };
    }
    // Hex int 0x… or decimal.
    if (
      this.peek() === "0" &&
      (this.src[this.pos + 1] === "x" || this.src[this.pos + 1] === "X")
    ) {
      this.pos += 2;
      const hexStart = this.pos;
      while (/[0-9A-Fa-f]/.test(this.peek())) this.pos++;
      if (this.pos === hexStart) {
        this.errors.push({
          message: "Expected hex digits after `0x`",
          start,
          end: this.pos,
        });
        return {
          name: "lit",
          params: { kind: "int", value: 0 },
          start,
          end: this.pos,
        };
      }
      const hex = this.src.slice(hexStart, this.pos);
      const n = Number.parseInt(hex, 16);
      return {
        name: "lit",
        params: { kind: "int", value: Number.isFinite(n) ? n : 0 },
        start,
        end: this.pos,
      };
    }
    const n = this.readNumber();
    if (n == null) {
      this.errors.push({
        message: "Expected a number literal",
        start,
        end: this.pos,
      });
      return {
        name: "lit",
        params: { kind: "int", value: 0 },
        start,
        end: this.pos,
      };
    }
    return {
      name: "lit",
      params: { kind: "int", value: n },
      start,
      end: this.pos,
    };
  }

  /**
   * Bare `$label` source — same as `in $label`.
   * @returns {RecipeStep}
   */
  parseBareSlotStage(noteLegacy = true) {
    const start = this.pos;
    const sigil = this.peek();
    this.pos++; // $ or legacy @
    const id = this.readIdent();
    if (!id) {
      this.errors.push({
        message: `Expected slot label after \`${sigil}\``,
        start,
        end: this.pos,
      });
      return {
        name: "in",
        params: { ref: sigil },
        start,
        end: this.pos,
      };
    }
    const ref = `${SLOT_SIGIL}${id}`;
    if (sigil === LEGACY_SLOT_SIGIL && noteLegacy) {
      this.noteLegacySlotSigil(ref, start, this.pos);
    }
    return {
      name: "in",
      params: { ref },
      start,
      end: this.pos,
    };
  }

  /**
   * @returns {RecipeStep}
   */
  parseSelectorStage() {
    const start = this.pos;
    this.pos++; // :
    const id = this.readIdent();
    if (!id) {
      this.errors.push({
        message: "Expected selector name after `:`",
        start,
        end: this.pos,
      });
      return { name: "select", params: { selector: ":" }, start, end: this.pos };
    }
    const sel = `:${id.toLowerCase()}`;
    const member = canonicalSelectorMember(id);
    if (!SELECTOR_MEMBERS.has(id.toLowerCase()) && !SELECTOR_MEMBERS.has(member)) {
      this.errors.push({
        message: `Unknown selector "${sel}"`,
        start,
        end: this.pos,
      });
    }
    return {
      name: "select",
      params: { selector: sel },
      start,
      end: this.pos,
    };
  }

  /**
   * @returns {RecipeStep}
   */
  parseIndexSelectorStage() {
    const start = this.pos;
    this.pos++; // [
    this.skipSpaces();
    const a = this.readNumber();
    if (a == null) {
      this.errors.push({
        message: "Expected number inside `[…]`",
        start,
        end: this.pos,
      });
      return { name: "at", params: { selector: "1" }, start, end: this.pos };
    }
    let selector = String(a);
    this.skipSpaces();
    if (this.peek() === ":") {
      this.pos++;
      this.skipSpaces();
      const b = this.readNumber();
      if (b == null) {
        this.errors.push({
          message: "Expected number after `:` in `[n:m]`",
          start: this.pos,
          end: this.pos,
        });
      } else {
        selector = `${a}:${b}`;
      }
    }
    this.skipSpaces();
    if (this.peek() === "]") this.pos++;
    else {
      this.errors.push({
        message: "Expected `]`",
        start: this.pos,
        end: this.pos,
      });
    }
    return {
      name: "at",
      params: { selector },
      start,
      end: this.pos,
    };
  }

  /**
   * A parsed `tee` carries its whole body in `branches` — one entry per `-`
   * line, in the order they were written. `step.body` stays in the AST because
   * the builder writes there (its "+ branch" affordance appends to the
   * unlabelled side chain) and every consumer already reads both, but nothing
   * in *text* can produce it any more, so `listBody` is empty here by
   * construction.
   * @param {number} start
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseTeeBlock(start, parentIndent) {
    this.skipSpaces();
    const body = this.parseBody(parentIndent, "tee");
    if (!body.branches.length) {
      this.errors.push({
        message:
          "tee requires a body — use `{ - :public | … }` or indented `-` lines (use `peek` for a side inspect)",
        start,
        end: this.pos,
      });
    }
    /** @type {RecipeStep} */
    const step = {
      name: "tee",
      params: {},
      start,
      end: this.pos,
    };
    if (body.branches.length) step.branches = body.branches;
    if (body.brace) step.bodyForm = "brace";
    return step;
  }

  /**
   * @param {number} start
   * @param {number} parentIndent
   * @returns {RecipeStep}
   */
  parseForeachBlock(start, parentIndent) {
    this.skipSpaces();
    /** @type {string|undefined} */
    let foreachSelector;
    if (this.peek() === ":") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      if (!id) {
        this.errors.push({
          message: "Expected selector after `foreach :`",
          start: selStart,
          end: this.pos,
        });
      } else {
        foreachSelector = `:${id.toLowerCase()}`;
        const m = id.toLowerCase();
        if (m !== "items" && m !== "values" && m !== "keys") {
          this.errors.push({
            message: `foreach selector must be :items, :values, or :keys (got ${foreachSelector})`,
            start: selStart,
            end: this.pos,
          });
        }
      }
      this.skipSpaces();
    } else if (this.peek() === ".") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      this.errors.push({
        message: id
          ? `foreach selectors use :${id.toLowerCase()} (not .${id})`
          : "foreach selectors use :items / :values / :keys",
        start: selStart,
        end: this.pos,
      });
      this.skipSpaces();
    }

    const body = this.parseBody(parentIndent, "foreach");
    if (!body.listBody.length && !body.branches.length) {
      // branches shouldn't appear under foreach with selectors as member —
      // allow list body only; if someone used - :key under foreach :items it's a list body with selector prefix...
      // Actually foreach body branches with selectors mean per-item projection via tee inside,
      // OR we allow - :value | out as a branch-style list item.
      // parseBody puts selector-prefix items into branches for tee; for foreach we need them as body with selector.
    }
    if (!body.listBody.length && !body.branches.length) {
      this.errors.push({
        message:
          "foreach requires a body — use indented `- out $share` or `foreach { - out $share }`",
        start,
        end: this.pos,
      });
    }

    // Under foreach, selector-prefixed branches are still list items that project the item.
    /** @type {RecipeStep[]} */
    const listBody = [...body.listBody];
    for (const br of body.branches) {
      // Represent as a synthetic tee? Better: store as steps with .selector on a wrapper.
      // Flatten: foreach body item with selector becomes a mini-pipeline starting with select.
      const selStep = {
        name: "select",
        params: { selector: br.selector || `:${br.member}` },
        start: br.start || start,
        end: br.end || this.pos,
      };
      listBody.push(selStep, ...br.body);
    }

    /** @type {RecipeStep} */
    const step = {
      name: "foreach",
      params: {},
      start,
      end: this.pos,
      body: listBody,
    };
    if (foreachSelector) step.foreachSelector = foreachSelector;
    if (body.brace) step.bodyForm = "brace";
    return step;
  }

  /**
   * A `-` line is one thing, and which thing it is depends only on the block
   * it hangs under — never on how many neighbours it has.
   *
   * Under `tee` it is **one branch**: a side pipeline over a clone of the stem,
   * or over a projection of it when the line opens with a selector. Under
   * `foreach` it is **the body**: the pipeline the loop applies to each item,
   * of which there is exactly one, so a second `-` line there is a refusal
   * rather than a second anything.
   *
   * `kind` is threaded down to `parseBranchLineInto` because that is the only
   * place the distinction is decidable, and both body forms (`{ … }` and
   * indented) route through it.
   * @param {number} parentIndent
   * @param {"tee"|"foreach"} kind
   * @returns {{ listBody: RecipeStep[], branches: TeeBranch[], brace: boolean }}
   */
  parseBody(parentIndent, kind) {
    this.skipSpaces();
    if (this.peek() === "{") {
      return this.parseBraceBody(kind);
    }
    // Indent body requires a newline next (after optional trailing spaces/comment)
    this.skipSpacesAndCommentsOnLine();
    if (this.peek() !== "\n") {
      return { listBody: [], branches: [], brace: false };
    }
    return this.parseIndentBody(parentIndent, kind);
  }

  /**
   * @param {"tee"|"foreach"} kind
   * @returns {{ listBody: RecipeStep[], branches: TeeBranch[], brace: boolean }}
   */
  parseBraceBody(kind) {
    this.pos++; // {
    /** @type {RecipeStep[]} */
    const listBody = [];
    /** @type {TeeBranch[]} */
    const branches = [];
    for (;;) {
      this.skipSpaces();
      if (this.peek() === "\n") {
        this.pos++;
        continue;
      }
      if (this.peek() === "#") {
        this.consumeComment();
        continue;
      }
      if (this.peek() === "}") {
        this.pos++;
        break;
      }
      if (this.eof()) {
        this.errors.push({
          message: "Unclosed `{` in tee/foreach body",
          start: this.pos,
          end: this.pos,
        });
        break;
      }
      // optional indent then -
      this.skipSpaces();
      if (this.peek() === "-") {
        this.parseBranchLineInto(listBody, branches, kind);
        this.skipSpacesAndCommentsOnLine();
        if (this.peek() === "\n") this.pos++;
        continue;
      }
      this.errors.push({
        message: "Expected `- branch` or `}` inside block body",
        start: this.pos,
        end: this.pos + 1,
      });
      while (!this.eof() && this.peek() !== "\n" && this.peek() !== "}") {
        this.pos++;
      }
    }
    return { listBody, branches, brace: true };
  }

  /**
   * True when `newlinePos` points at `\n` that ends an empty/whitespace-only line
   * (or a full-line comment). Used to detect chain separators left by indent bodies.
   * @param {number} newlinePos
   * @returns {boolean}
   */
  isBlankLineEndingAt(newlinePos) {
    if (this.src[newlinePos] !== "\n") return false;
    let i = newlinePos - 1;
    while (i >= 0 && this.src[i] !== "\n") i--;
    const lineStart = i + 1;
    let p = lineStart;
    while (p < newlinePos && this.src[p] === " ") p++;
    if (p >= newlinePos) return true;
    if (this.src[p] === "#") return true;
    return false;
  }

  /**
   * Indent of the next non-blank, non-comment line at or after `from`, or -1 at EOF.
   * @param {number} from
   * @returns {number}
   */
  peekNextContentIndent(from) {
    let p = from;
    while (p < this.src.length) {
      let i = 0;
      while (this.src[p + i] === " ") i++;
      const j = p + i;
      if (j >= this.src.length) return -1;
      if (this.src[j] === "\n") {
        p = j + 1;
        continue;
      }
      if (this.src[j] === "#") {
        while (p < this.src.length && this.src[p] !== "\n") p++;
        if (this.src[p] === "\n") p++;
        continue;
      }
      return i;
    }
    return -1;
  }

  /**
   * @param {number} parentIndent
   * @param {"tee"|"foreach"} kind
   * @returns {{ listBody: RecipeStep[], branches: TeeBranch[], brace: boolean }}
   */
  parseIndentBody(parentIndent, kind) {
    /** @type {RecipeStep[]} */
    const listBody = [];
    /** @type {TeeBranch[]} */
    const branches = [];
    // consume the newline that starts the body
    if (this.peek() === "\n") this.pos++;

    let bodyIndent = 0;
    while (!this.eof()) {
      const lineStart = this.pos;
      // peek indent
      let i = 0;
      while (this.src[lineStart + i] === " ") i++;
      const indent = i;

      // blank / comment
      let j = lineStart + i;
      if (j >= this.src.length || this.src[j] === "\n") {
        // Blank line after body items ends the body when the next content is
        // dedented (chain separator or stem continuation). Leave the blank so
        // parseRecipe can flush chains. Blanks between list items still skip.
        if (bodyIndent) {
          const nextIndent = this.peekNextContentIndent(
            j < this.src.length ? j + 1 : j
          );
          if (nextIndent < 0 || nextIndent <= parentIndent) {
            this.pos = lineStart;
            break;
          }
        }
        this.pos = j < this.src.length ? j + 1 : j;
        continue;
      }
      if (this.src[j] === "#") {
        this.pos = j;
        this.consumeComment();
        if (this.peek() === "\n") this.pos++;
        continue;
      }

      if (indent <= parentIndent) {
        // stem continuation (e.g. `| export`) — do not consume
        this.pos = lineStart;
        break;
      }

      if (!bodyIndent) {
        if (indent % 2 !== 0) {
          this.errors.push({
            message: "Use 2-space indent levels for nested list bodies",
            start: lineStart,
            end: lineStart + indent,
          });
        }
        bodyIndent = indent;
      }

      if (indent > bodyIndent) {
        this.errors.push({
          message: "Nested lists inside tee/foreach bodies are not supported in v1",
          start: lineStart,
          end: lineStart + indent,
        });
        this.pos = lineStart + indent;
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }
      if (indent < bodyIndent) {
        this.pos = lineStart;
        break;
      }

      this.pos = lineStart + indent;
      if (this.peek() !== "-") {
        this.errors.push({
          message: "Body lines under tee/foreach must be list items (`- step`)",
          start: this.pos,
          end: this.pos + 1,
        });
        while (!this.eof() && this.peek() !== "\n") this.pos++;
        if (this.peek() === "\n") this.pos++;
        continue;
      }
      this.parseBranchLineInto(listBody, branches, kind);
      this.skipSpacesAndCommentsOnLine();
      if (this.peek() === "\n") this.pos++;
    }
    return { listBody, branches, brace: false };
  }

  /**
   * Parse `- [selector |] pipeline` at current pos (on `-`).
   *
   * Under `tee` every line lands in `branches`, selector or not. It used to be
   * that only a line opening with a selector became a branch and the rest were
   * concatenated into one flat `listBody` — so `- digest sha-256 | out $a` and
   * `- encode hex | out $b` ran as the single pipeline
   * `digest sha-256 | out $a | encode hex | out $b`, and `$b` held the hex of
   * the digest rather than of the stem. Nothing on the page said so; the two
   * lines are two lines. The count of `-` characters is now the count of
   * branches, which is the only reading anyone ever gave it.
   *
   * A branch with no selector runs on a clone of the whole stem value, which is
   * what the old single-line `listBody` did and what the builder's
   * "+ branch — no selector" affordance has always meant.
   *
   * @param {RecipeStep[]} listBody
   * @param {TeeBranch[]} branches
   * @param {"tee"|"foreach"} kind
   */
  parseBranchLineInto(listBody, branches, kind) {
    const start = this.pos;
    this.pos++; // -
    if (this.peek() !== " " && this.peek() !== "\t") {
      // allow `-:public` without space; require space otherwise
      if (this.peek() !== ":" && this.peek() !== "[") {
        this.errors.push({
          message: "Expected space after `-` in list body",
          start: this.pos,
          end: this.pos,
        });
      }
    }
    this.skipSpaces();

    /** @type {string|null} */
    let selector = null;
    if (this.peek() === ":") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      if (!id) {
        this.errors.push({
          message: "Expected selector name after `:`",
          start: selStart,
          end: this.pos,
        });
      } else {
        selector = `:${id.toLowerCase()}`;
        const member = canonicalSelectorMember(id);
        if (
          !SELECTOR_MEMBERS.has(id.toLowerCase()) &&
          !SELECTOR_MEMBERS.has(member)
        ) {
          this.errors.push({
            message: `Unknown selector "${selector}"`,
            start: selStart,
            end: this.pos,
          });
        }
        this.skipSpaces();
        if (this.peek() === "|") {
          this.pos++;
          this.skipSpaces();
        } else {
          this.errors.push({
            message: `Expected \`|\` after selector ${selector} (e.g. \`- :private | inspect\`)`,
            start: this.pos,
            end: this.pos,
          });
        }
      }
    } else if (this.peek() === ".") {
      const selStart = this.pos;
      this.pos++;
      const id = this.readIdent();
      this.errors.push({
        message: id
          ? `Member selectors use :${id.toLowerCase()} (e.g. \`- :public | …\`)`
          : "Member selectors use :public / :private",
        start: selStart,
        end: this.pos,
      });
      this.skipSpaces();
      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
      }
    } else if (this.peek() === "[") {
      const idx = this.parseIndexSelectorStage();
      selector = `[${idx.params.selector}]`;
      this.skipSpaces();
      if (this.peek() === "|") {
        this.pos++;
        this.skipSpaces();
      }
    }

    const pipe = this.parsePipeline(this.lineIndentAt(start));
    // Stop pipeline if we hit end of line — parsePipeline may consume too much?
    // parsePipeline stops at non-pipe; good. But it could parse across newlines inside?
    // Our parseStage for blocks could nest — rejected for foreach/tee inside body via validate.

    if (kind === "foreach") {
      // `foreach` has one body and cannot have two: the loop threads each
      // item's value through the body and hands the result back, so there is
      // no second thing for a second line to be. Rather than quietly glue the
      // lines together — the same silence this pass removed from `tee` — say
      // that a body is already there and name the join that works.
      if (listBody.length || branches.length) {
        this.errors.push({
          message:
            "foreach already has its body on the line above — a loop body is one `- ` line; join the steps with `|` (`- inspect | out $share`)",
          start,
          end: this.pos,
        });
      }
      if (selector) {
        branches.push({
          member: canonicalSelectorMember(selector),
          selector,
          body: pipe,
          start,
          end: this.pos,
        });
      } else {
        listBody.push(...pipe);
      }
    } else {
      // A keypair half is a step, so a branch line that opens with one opens
      // with a step — the prefix grammar is not a second way to say it, it is
      // the same thing spelled before the `|`. Folded into the body here so
      // that `- :public | export spki` and `- public | export spki` produce
      // one AST rather than two that serialize differently; the branch then
      // runs on a clone of the stem, and its first step does the projecting,
      // which is what the engine already does for `- encode hex | out $a`.
      //
      // `[n]` and `:key` / `:value` keep the prefix for now: they are steps in
      // the stem too, so the same argument reaches them, but folding them is a
      // change to what the builder draws as a branch's identity and wants its
      // own pass rather than a ride on this one.
      const folded = selector === `:${SELECT_PUBLIC}` || selector === `:${SELECT_PRIVATE}`;
      branches.push({
        member: selector && !folded ? canonicalSelectorMember(selector) : "",
        ...(selector && !folded ? { selector } : {}),
        body: folded
          ? [
              {
                name: "select",
                params: { selector },
                start,
                end: this.pos,
              },
              ...pipe,
            ]
          : pipe,
        start,
        end: this.pos,
      });
    }

    // Reject nested block openers inside branch pipelines at parse time
    for (const s of pipe) {
      if (s.name === "foreach" || s.name === "tee") {
        this.errors.push({
          message: `Nested ${s.name} is not supported inside a list body in v1`,
          start: s.start,
          end: s.end,
        });
      }
    }
  }

  /**
   * @param {string} canon
   * @param {string} rawName
   * @param {number} start
   * @returns {RecipeStep}
   */
  parseApply(canon, rawName, start) {
    const spec = getStep(canon);
    /** @type {Record<string, string|number|boolean>} */
    const params = {};
    let positionalUsed = false;

    // Bracket form already handled; here handle at with positional etc.
    while (!this.eof()) {
      this.skipSpaces();
      const ch = this.peek();
      if (
        !ch ||
        ch === "\n" ||
        ch === "|" ||
        ch === "}" ||
        ch === "#"
      ) {
        break;
      }
      // Stop before indent-body list on same... won't happen same line

      if (ch === '"' || ch === "'") {
        const v = this.readString();
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (!pos) {
            this.errors.push({
              message: `Unexpected string (no positional parameter for ${canon})`,
              start: this.pos,
              end: this.pos,
            });
          } else {
            params[pos.name] = coerceParam(spec, pos.name, v);
            positionalUsed = true;
          }
        } else {
          this.errors.push({
            message: `Unexpected token "${v}"`,
            start: this.pos,
            end: this.pos,
          });
        }
        continue;
      }

      if (ch === "-" && /[A-Za-z]/.test(this.src[this.pos + 1] || "")) {
        const flagStart = this.pos;
        this.pos++;
        const flagName = this.readIdent();
        const flag = `-${flagName}`;
        const flagParam = (spec?.params || []).find((p) => p.flag === flag);
        if (!flagParam) {
          this.errors.push({
            message: `Unknown flag "${flag}" for ${canon}`,
            start: flagStart,
            end: this.pos,
          });
        } else {
          params[flagParam.name] = true;
        }
        continue;
      }

      // Path-like tokens reserved for future file I/O (out/in only).
      const tokStart = this.pos;
      if (
        (canon === "out" || canon === "in") &&
        (ch === "." || ch === "/" || ch === '"' || ch === "'")
      ) {
        let raw;
        if (ch === '"' || ch === "'") {
          raw = this.readString();
        } else {
          while (
            !this.eof() &&
            !/\s/.test(this.peek()) &&
            this.peek() !== "|" &&
            this.peek() !== "}" &&
            this.peek() !== "#"
          ) {
            this.pos++;
          }
          raw = this.src.slice(tokStart, this.pos);
        }
        this.errors.push({
          message:
            "File paths are not supported yet — use $label (e.g. out $kp / in $kp)",
          start: tokStart,
          end: this.pos,
        });
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (pos) {
            params[pos.name] = raw;
            positionalUsed = true;
          }
        }
        continue;
      }

      // $label slot sugar (legacy `@label` still read here — a positional
      // argument is one of the two positions where only a slot can appear).
      if (isSlotSigil(ch)) {
        this.pos++;
        const id = this.readIdent();
        const raw = id ? `${ch}${id}` : ch;
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (!pos) {
            this.errors.push({
              message: `Unexpected token "${raw}" (no positional parameter for ${canon})`,
              start: tokStart,
              end: this.pos,
            });
          } else {
            params[pos.name] = coerceParam(spec, pos.name, raw);
            positionalUsed = true;
          }
        } else {
          this.errors.push({
            message: `Unexpected token "${raw}"`,
            start: tokStart,
            end: this.pos,
          });
        }
        continue;
      }

      // ident or ident=value or number
      if (/[0-9]/.test(ch)) {
        if (!positionalUsed) {
          const pos = (spec?.params || []).find((p) => p.positional);
          if (!pos) {
            const num = this.readNumber();
            this.errors.push({
              message: `Unexpected token "${num}" (no positional parameter for ${canon})`,
              start: tokStart,
              end: this.pos,
            });
          } else if (pos.type === "string") {
            // Fingerprints / opaque hex often start with a digit — don't stop at
            // the first non-digit (e.g. `8F…` must not become `8` + junk).
            const raw = this.readNamedArgValue();
            params[pos.name] = coerceParam(spec, pos.name, raw);
            positionalUsed = true;
          } else {
            const num = this.readNumber();
            const raw = String(num);
            params[pos.name] = coerceParam(spec, pos.name, raw);
            positionalUsed = true;
          }
        } else {
          const num = this.readNumber();
          this.errors.push({
            message: `Unexpected token "${num}"`,
            start: tokStart,
            end: this.pos,
          });
        }
        continue;
      }

      if (/[A-Za-z]/.test(ch)) {
        // Peek whether this is `name=value` or a bare value (may contain `/`).
        const word = this.readIdent();
        this.skipSpaces();
        if (this.peek() === "=") {
          this.pos++;
          this.skipSpaces();
          // Named values may be base64url (can start with a digit) — don't use
          // readArgValue's number shortcut.
          const rawVal = this.readNamedArgValue();
          const known = (spec?.params || []).some((p) => p.name === word);
          if (!known) {
            this.errors.push({
              message: `Unknown parameter "${word}" for ${canon}`,
              start: tokStart,
              end: this.pos,
            });
          } else {
            params[word] = coerceParam(spec, word, rawVal);
          }
        } else {
          // Positional: allow alg ids (ec/p256) and emails (alice@example.org).
          let raw = word;
          if (/[/:@+$]/.test(this.peek())) {
            this.pos = tokStart;
            raw = this.readArgValue();
          }
          if (!positionalUsed) {
            const pos = (spec?.params || []).find((p) => p.positional);
            if (!pos) {
              this.errors.push({
                message: `Unexpected token "${raw}" (no positional parameter for ${canon})`,
                start: tokStart,
                end: this.pos,
              });
            } else {
              params[pos.name] = coerceParam(spec, pos.name, raw);
              positionalUsed = true;
            }
          } else {
            this.errors.push({
              message: `Unexpected token "${raw}"`,
              start: tokStart,
              end: this.pos,
            });
          }
        }
        continue;
      }

      this.errors.push({
        message: `Unexpected "${ch}"`,
        start: this.pos,
        end: this.pos + 1,
      });
      this.pos++;
      break;
    }

    // The verb's object (`sss.split 2/3`) is normalized *before* defaults are
    // filled, because "the author also wrote threshold=" and "the default
    // filled threshold in" must stay distinguishable — the first is a
    // contradiction to refuse, the second is the ordinary case.
    if (spec?.object) this.normalizeObjectParam(spec, params, start);

    for (const p of spec?.params || []) {
      if (params[p.name] === undefined && p.default !== undefined) {
        params[p.name] = p.default;
      }
    }
    if (String(rawName || "").toLowerCase() === "hexdump") {
      params.format = "hexdump";
    }

    // Normalize out/in slot refs to canonical $label or index.
    if (canon === "out" || canon === "in") {
      const key = canon === "out" ? "name" : "ref";
      const rawSlot = params[key];
      if (rawSlot != null && rawSlot !== "") {
        const norm = normalizeSlotRef(String(rawSlot), {
          allowIndex: canon === "in",
        });
        if (!norm.ok) {
          this.errors.push({
            message: norm.error,
            start,
            end: this.pos,
          });
        } else {
          params[key] = norm.ref;
          if (norm.legacy) this.noteLegacySlotSigil(norm.ref, start, this.pos);
        }
      } else if (canon === "out") {
        params.name = DEFAULT_OUT_SLOT;
      }
    }

    // Normalize slot refs to the canonical `$label`, by declaration.
    //
    // This replaces a blanket sweep over *every* string param, which existed
    // because `passphrase=`, `aad=`, `salt=`, `info=`, `signature=` and
    // `gpg.encrypt to=` accepted slots while declaring `type: "string"`. With
    // `ParamSpec.slot` the registry says which params take a ref, so the rule
    // can be applied where it belongs and nowhere else.
    //
    // `slot: "required"` holds nothing but a ref, so a malformed one is a parse
    // error. `slot: true` may hold a literal — an unquoted `to=@corp.example`
    // is an address, not a slot named `corp` — so a value that opens with a
    // sigil but is not a well-formed ref is left exactly as written, and the
    // validator decides.
    for (const p of spec?.params || []) {
      if (!p.slot) continue;
      if (canon === "in" && p.name === "ref") continue; // normalized above
      const rawSlot = params[p.name];
      if (rawSlot == null || rawSlot === "") continue;
      const raw = String(rawSlot);
      const optional = p.slot !== "required";
      if (optional && !isSlotSigil(raw.trim()[0])) continue;
      const norm = normalizeSlotRef(raw, { allowIndex: !!p.allowIndex });
      if (!norm.ok) {
        if (optional) continue;
        this.errors.push({
          // A secret gets its own sentence, and the generic one is why.
          // `normalizeSlotRef` answers a question about labels — "use $hunter2,
          // not hunter2" — which on a passphrase names a remedy nobody should
          // perform (the secret would become the slot's *label*, still in the
          // text) and quotes the secret back into an error string that is
          // rendered, copied and pasted into bug reports. `47e7ffa` is the
          // commit about refusals that name a remedy that cannot be performed;
          // this one names the state that is true and a remedy that can be.
          message: p.secret
            ? `${canon} ${p.name}=: ${SECRET_LITERAL_REFUSAL} — ` +
              `recipe text travels (share link, saved workspace, run manifest). ` +
              `Put the value in Inputs and name it: \`input | out $pw\`, then \`${p.name}=$pw\`.`
            : `${canon} ${p.name}=: ${norm.error}`,
          start,
          end: this.pos,
        });
        continue;
      }
      params[p.name] = norm.ref;
      if (norm.legacy) this.noteLegacySlotSigil(norm.ref, start, this.pos);
    }

    return {
      name: canon,
      params,
      start,
      end: this.pos,
    };
  }

  /**
   * Normalize a step's object token (`sss.split 2/3`) into the params it
   * spells, and delete it — the AST carries `threshold`/`shares`, never the
   * token, so the engine, the type walk and the chip editors have exactly one
   * place to read the quorum from and `serializeRecipe` (via the spec's
   * `object.spell`) writes the fraction back from the same place.
   *
   * Two input forms, per `LANGUAGE.md` principle 5 (abbreviated in, canonical
   * out):
   *
   * - `K/N` — the canonical object. Any K of N recover.
   * - `N` — majority of N: `floor(N/2)+1`. An input form only; it serializes
   *   as the fraction, so nobody reading a shared recipe needs the rule.
   *   Majority is what makes any two qualifying sets intersect — `2/4` would
   *   let two disjoint pairs each rebuild the secret independently.
   *
   * Writing the object *and* a named param it covers is refused rather than
   * arbitrated: `sss.split 2/3 shares=4` states the share count twice and the
   * two statements disagree, and picking a winner would make the text mean
   * something one of its clauses denies. Semantic refusals (`1/3` is a copy,
   * `4/3` unrecoverable, more than 16 shares) stay in `validateRecipe`, where
   * the named spelling reaches them too — the two spellings must refuse
   * identically or they are two dialects.
   *
   * @param {import("./registry.js").StepSpec} spec
   * @param {Record<string, string|number|boolean>} params
   * @param {number} start
   */
  normalizeObjectParam(spec, params, start) {
    const { param, covers } = spec.object;
    const raw = params[param];
    delete params[param];
    if (raw === undefined || raw === "") return;
    const text = String(raw).trim();
    const named = covers.filter((k) => params[k] !== undefined);
    if (named.length) {
      this.errors.push({
        message:
          `${spec.name} ${text} already states the quorum — drop ` +
          `${named.map((k) => `\`${k}=\``).join(" and ")}, the object is the whole of it`,
        start,
        end: this.pos,
      });
      return;
    }
    const frac = /^(\d+)\/(\d+)$/.exec(text);
    if (frac) {
      params[covers[0]] = Number(frac[1]);
      params[covers[1]] = Number(frac[2]);
      return;
    }
    if (/^\d+$/.test(text)) {
      const n = Number(text);
      params[covers[0]] = Math.floor(n / 2) + 1;
      params[covers[1]] = n;
      return;
    }
    this.errors.push({
      message:
        `${spec.name}: the object is the quorum — write \`2/3\` (any 2 of 3 ` +
        `recover) or \`3\` for a majority of 3, not "${text}"`,
      start,
      end: this.pos,
    });
  }

  /**
   * Unquoted argument value: ident extended with `/` (e.g. ec/p256), or a string/number.
   * @returns {string}
   */
  readArgValue() {
    if (this.peek() === '"' || this.peek() === "'") return this.readString();
    if (isSlotSigil(this.peek())) {
      const start = this.pos;
      const sigil = this.peek();
      this.pos++;
      const id = this.readIdent();
      return id ? `${sigil}${id}` : this.src.slice(start, this.pos);
    }
    if (/[0-9]/.test(this.peek())) return String(this.readNumber());
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    // Mid-token `@` / `$` / `:` so positional emails (`hkp.search
    // alice@example.org`) parse as one value. A sigil marks a slot only at the
    // start of the token — that is what keeps `my$ecret` a literal.
    while (/[A-Za-z0-9_+./:@$-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  /**
   * Value after `name=` — allows base64url (may start with a digit).
   * @returns {string}
   */
  readNamedArgValue() {
    if (this.peek() === '"' || this.peek() === "'") return this.readString();
    if (isSlotSigil(this.peek())) {
      const start = this.pos;
      const sigil = this.peek();
      this.pos++;
      const id = this.readIdent();
      return id ? `${sigil}${id}` : this.src.slice(start, this.pos);
    }
    // Unquoted values: allow `@` / `$` / `:` so `to=alice@example.org`,
    // `passphrase=my$ecret` and `to=email:…` / `to=fpr:…` parse as one token.
    // Only a *leading* sigil (handled above) means a slot.
    if (!/[A-Za-z0-9_+./-]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_+./:@$-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  readIdent() {
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  /**
   * Step head: dotted namespaces (`gpg.encrypt`), hyphen ciphers (`aes-gcm`),
   * or JCE transforms (`AES/GCM/NoPadding`). Not used for param names.
   * @returns {string}
   */
  readStepName() {
    if (!/[A-Za-z]/.test(this.peek())) return "";
    const start = this.pos;
    this.pos++;
    while (/[A-Za-z0-9_.+/-]/.test(this.peek())) this.pos++;
    return this.src.slice(start, this.pos);
  }

  readNumber() {
    if (!/[0-9]/.test(this.peek())) return null;
    const start = this.pos;
    while (/[0-9]/.test(this.peek())) this.pos++;
    return Number(this.src.slice(start, this.pos));
  }

  readString() {
    const q = this.peek();
    this.pos++;
    const start = this.pos;
    while (!this.eof() && this.peek() !== q) this.pos++;
    const v = this.src.slice(start, this.pos);
    if (this.peek() === q) this.pos++;
    return v;
  }
}

/**
 * @param {import("./registry.js").StepSpec|null|undefined} spec
 * @param {string} key
 * @param {string} raw
 * @returns {string|number|boolean}
 */
function coerceParam(spec, key, raw) {
  const p = (spec?.params || []).find((x) => x.name === key);
  if (!p) return raw;
  if (
    (spec?.name === "export" || spec?.name === "import") &&
    key === "format" &&
    String(raw).toLowerCase() === "d"
  ) {
    return "scalar";
  }
  if (p.type === "int") {
    const n = Number(raw);
    return Number.isFinite(n) ? Math.floor(n) : raw;
  }
  if (p.type === "bool") {
    return raw === "true" || raw === "1" || raw === "yes";
  }
  if (p.type === "enum" && Array.isArray(p.enum)) {
    const lower = String(raw).toLowerCase();
    const hit = p.enum.find((e) => String(e).toLowerCase() === lower);
    if (hit != null) return hit;
  }
  return raw;
}

/**
 * Toolkit recipe language — validate / serialize / presets.
 * Normative grammar: docs/RECIPE.md
 *
 *   genkey ec/p256 | out $kp
 *
 *   $kp | :public | export spki | pem | out $public
 *   $kp | export pkcs8 | pem | out $private
 *
 * Decode: encoding twins prefer `base64.encode` / `base64.decode` (also accept `-d`).
 * pem ↔ der and to ↔ from (encoding) are conjugate pairs (bare verbs, not decodeTwin).
 * Cipher twins still use `-d` (`aes-gcm -d`). Slot labels require `$` (`out $kp` / `key=$cek`);
 * bare `out kp` / `key=cek` → `migrateRecipe` / Upgrade. Bare `$kp` ≡ `in $kp` on load.
 * A pre-swap `@kp` still parses in step/param position and is rewritten to `$kp`
 * with a compile warning; `@` at the head of a chain is reserved.
 */

import {
  getStep,
  listSteps,
} from "./registry.js";
import {
  canonicalSelectorMember,
  DEFAULT_OUT_SLOT,
  parseRecipeSource,
  SLOT_SIGIL,
  slotLabelKey,
} from "./recipe-parse.js";
import { decodeTwinToken, migrateRecipe } from "./step-names.js";
import {
  formatType,
  isTerminalSink,
  resolveStepType,
  tNone,
  typeOf,
} from "./types.js";

export { migrateRecipe } from "./step-names.js";

/**
 * Retired *param values* — the `legacyRemovalHint` of the param world.
 *
 * An enum value that is dropped from a spec becomes an ordinary "invalid"
 * error, which is true but useless: it lists what is allowed and says nothing
 * about what happened or that `migrateRecipe` will do it for you. Keyed
 * `"<step> <param>=<value>"`, valued with the replacement clause.
 *
 * Kept here rather than in `registry.js` because a retired value is by
 * definition absent from the spec it used to live in.
 * @type {Record<string, string>}
 */
const RETIRED_PARAM_VALUES = {
  // Sniffed the chosen file to pick `text` or `bytes` while the compiler,
  // holding no file, declared `bytes` — so `file.read accept=.pem | base64`
  // compiled clean and threw at run time.
  "file.read as=auto": "use as=bytes, or as=text to decode as UTF-8",
};

/**
 * @param {RecipeStep} step
 * @param {string} name
 */
function hasSlotParam(step, name) {
  const v = step.params?.[name];
  return v != null && String(v).trim() !== "";
}

/**
 * Anchor a warning to the step that earned it.
 * @param {RecipeStep} step
 * @param {number} stepIndex
 * @param {string} message
 * @returns {RecipeWarning}
 */
function stepWarning(step, stepIndex, message) {
  return { message, start: step.start, end: step.end, stepIndex };
}

/**
 * Compile-time warnings for discouraged algorithms (still allowed).
 * @param {RecipeStep} step
 * @param {RecipeWarning[]} warnings
 * @param {number} stepIndex
 */
function pushDiscouragedAlgoWarnings(step, warnings, stepIndex) {
  if (
    step.name === "digest" &&
    String(step.params?.alg || "sha-256").toLowerCase() === "sha-1"
  ) {
    warnings.push(
      stepWarning(
        step,
        stepIndex,
        `digest alg=sha-1 is discouraged (collision-prone); prefer sha-256 — outputs tagged legacy/discouraged`
      )
    );
  }
  if (step.name === "rsa-pkcs1") {
    warnings.push(
      stepWarning(
        step,
        stepIndex,
        `rsa-pkcs1 (RSAES-PKCS1-v1_5) is discouraged; prefer rsa-oaep — outputs tagged legacy/discouraged`
      )
    );
  }
  if (
    step.name === "ssh.encode" &&
    String(step.params?.format || "public") === "private" &&
    // …and only when the block really will be bare. `passphrase=$slot` now
    // encrypts it (aes256-ctr + bcrypt_pbkdf), so warning regardless said
    // "emits an unencrypted private key" about a file that is encrypted —
    // and a warning that is false where it is most specific is worse than
    // none, because it teaches that the warnings are noise.
    !String(step.params?.passphrase ?? "").trim()
  ) {
    // §29f: the block has no passphrase, and vault protection does not
    // travel with an export. Warned at compile so it reads before the run,
    // not after the key is already on screen.
    warnings.push(
      stepWarning(
        step,
        stepIndex,
        `ssh.encode format=private emits an unencrypted private key — anything that can read the output can use the key. Prefer keeping it in My Keys and signing with agent.sign`
      )
    );
  }
  if (
    (step.name === "genkey" || step.name === "import") &&
    String(step.params?.alg || "").startsWith("rsa/") &&
    String(step.params?.usage || "auto") !== "encrypt" &&
    String(step.params?.padding || "pss").toLowerCase() === "pkcs1"
  ) {
    warnings.push(
      stepWarning(
        step,
        stepIndex,
        `${step.name} padding=pkcs1 (RSASSA-PKCS1-v1_5) is discouraged; prefer padding=pss — outputs tagged legacy/discouraged`
      )
    );
  }
}

/**
 * Warn when usage= is set but ignored for fixed-usage algorithms.
 * @param {RecipeStep} step
 * @param {RecipeWarning[]} warnings
 * @param {number} stepIndex
 */
function pushUsageHonestyWarnings(step, warnings, stepIndex) {
  if (step.name !== "genkey" && step.name !== "import") return;
  const usage = String(step.params?.usage || "auto");
  if (usage === "auto" || usage === "") return;
  const alg = String(step.params?.alg || "").toLowerCase();
  const fixed =
    alg === "ed25519" ||
    alg === "x25519" ||
    alg.startsWith("aes/") ||
    alg.startsWith("hmac/");
  if (fixed) {
    warnings.push(
      stepWarning(
        step,
        stepIndex,
        `${step.name} usage=${usage} is ignored for ${alg || "this algorithm"} (usage is fixed)`
      )
    );
  }
}

/**
 * True when the recipe source literally writes `which=` on this step
 * (defaults filled by the parser do not count).
 * @param {RecipeStep} step
 * @param {string} [source]
 */
function stepSourceHasWhich(step, source) {
  if (!source || step.start == null || step.end == null) return false;
  return /\bwhich\s*=/.test(source.slice(step.start, step.end));
}

/**
 * Discourage `export which=` — prefer `:public` / `:private` (openssl pkey -pubout).
 * @param {RecipeStep} step
 * @param {import("./types.js").RefinedType} current
 * @param {{ warnings: RecipeWarning[], errors: RecipeError[], source?: string, stepIndex: number }} ctx
 */
function pushExportWhichPolicy(step, current, ctx) {
  if (step.name !== "export") return;
  if (!stepSourceHasWhich(step, ctx.source)) return;
  const slice = String(ctx.source || "").slice(step.start ?? 0, step.end ?? 0);
  const m = slice.match(/\bwhich\s*=\s*([A-Za-z]+)/);
  const written = m?.[1]?.toLowerCase() || "";
  ctx.warnings.push(
    stepWarning(
      step,
      ctx.stepIndex,
      `export which= is discouraged — prefer :public / :private before export (like openssl pkey -pubout)`
    )
  );
  if (
    current.base === "key" &&
    (current.which === "public" || current.which === "private") &&
    written &&
    written !== current.which
  ) {
    ctx.errors.push({
      message: `export which=${written} conflicts with tip ${formatType(current)} — drop which= (selector already chose the half)`,
      start: step.start,
      end: step.end,
      stepIndex: ctx.stepIndex,
    });
  }
}

/**
 * Whether a WebCrypto op still needs the key/peer/wrap panels.
 * @param {RecipeStep} step
 */
export function stepNeedsKeyPanel(step) {
  switch (step.name) {
    case "aes-gcm":
    case "aes-cbc":
    case "aes-ctr":
    case "rsa-oaep":
    case "rsa-pkcs1":
    case "sign":
    case "verify":
    case "unwrap":
      return !hasSlotParam(step, "key");
    case "ecdh":
      return !(hasSlotParam(step, "private") && hasSlotParam(step, "peer"));
    case "wrap":
      return !(hasSlotParam(step, "key") && hasSlotParam(step, "target"));
    default:
      return false;
  }
}

/**
 * Whether an OpenPGP op still needs the vault / paste private-key panel.
 * When `key=$slot` is bound, only the passphrase field may still be needed.
 * @param {RecipeStep} step
 */
export function stepNeedsGpgPrivatePanel(step) {
  switch (step.name) {
    case "gpg.sign":
    case "gpg.verify":
      return !hasSlotParam(step, "key");
    case "gpg.encrypt":
      return !!step.params?.sign && !hasSlotParam(step, "key");
    case "gpg.decrypt":
      return true;
    default:
      return false;
  }
}

/**
 * OpenPGP passphrase field after `key=$slot` (S2K) or agent.save passphrase wrap.
 * @param {RecipeStep} step
 */
export function stepNeedsGpgPassphrasePanel(step) {
  if (
    (step.name === "gpg.sign" || step.name === "gpg.verify") &&
    hasSlotParam(step, "key")
  ) {
    return true;
  }
  if (step.name === "gpg.encrypt" && step.params?.sign && hasSlotParam(step, "key")) {
    return true;
  }
  if (
    step.name === "agent.save" &&
    String(step.params?.protection || "device") === "passphrase"
  ) {
    return true;
  }
  return false;
}

/**
 * Resolve a slot ref against compile-time slot type maps.
 * @param {string} ref
 * @param {Map<string, import("./types.js").RefinedType>} slotTypes
 * @param {import("./types.js").RefinedType[]} slotTypesByIndex
 * @returns {import("./types.js").RefinedType|null}
 */
function lookupSlotType(ref, slotTypes, slotTypesByIndex) {
  const r = String(ref || "");
  if (/^\d+$/.test(r)) {
    const n = Number(r);
    return slotTypesByIndex[n - 1] || null;
  }
  const key = slotLabelKey(r);
  return key ? slotTypes.get(key) || null : null;
}

/**
 * `gpg.encrypt to=` is the one param whose literal form is not a plain value:
 * an address, an `email:`/`fpr:`/`0x` prefix or a bare fingerprint is a
 * recipient, and *anything else* — sigil or not — names a slot. That reading
 * is the runtime's (`parseEncryptToToken`), so the compiler has to share it or
 * it would pass recipes the run rejects. `$` costs nothing to tell apart from
 * an address; before the sigil swap this had to ask whether the `@` was at
 * position 0, which made `to=@corp.example` — a perfectly ordinary domain-ish
 * address — read as a slot named `corp`.
 * @param {string} raw
 */
function recipientLiteralShape(raw) {
  const s = String(raw || "").trim();
  const looksEmail = /^email:/i.test(s) || s.includes("@");
  const looksFpr =
    /^(?:fpr:|0x)/i.test(s) || /^[0-9A-Fa-f]{40,}$/i.test(s.replace(/\s+/g, ""));
  return looksEmail || looksFpr;
}

/**
 * Is this bound value a slot reference rather than a literal?
 *
 * `slot: "required"` params hold nothing else. `slot: true` params are read by
 * the leading sigil, which is the whole of the old grammar — the difference is
 * that the declaration now says *which* params get read that way, instead of
 * every string param being sniffed and six of them turning out to be slots by
 * accident.
 * @param {import("./registry.js").ParamSpec} p
 * @param {string} stepName
 * @param {string} raw
 */
function boundAsSlotRef(p, stepName, raw) {
  if (!p.slot) return false;
  if (p.slot === "required") return true;
  if (stepName === "gpg.encrypt" && p.name === "to") return !recipientLiteralShape(raw);
  return raw.startsWith(SLOT_SIGIL);
}

/**
 * What a slot that fails `slotOf` was supposed to supply. Keyed on the
 * declared set so the phrasing follows the registry rather than the step name.
 * @param {import("./registry.js").IoType[]} want
 */
function supplyNoun(want) {
  const key = [...want].sort().join(",");
  if (key === "bytes,text") return "text/bytes";
  if (key === "openpgp-key,recipients,text") return "recipients";
  return "a key";
}

/**
 * Validate every declared slot param on a step: the ref resolves, and what it
 * resolves to is one of the types the declaration allows.
 *
 * Both halves are compile-time on purpose. A recipe's output type is known
 * before it runs; until `ParamSpec.slot` there was no way to say the same of
 * its inputs, because "is this a slot?" was answered by looking at the first
 * character of the value.
 * @param {RecipeStep} step
 * @param {Map<string, import("./types.js").RefinedType>} slotTypes
 * @param {import("./types.js").RefinedType[]} slotTypesByIndex
 * @param {RecipeError[]} errors
 * @param {number} stepIndex
 */
function validateStepSlotParams(
  step,
  slotTypes,
  slotTypesByIndex,
  errors,
  stepIndex
) {
  const spec = getStep(step.name);
  for (const p of spec?.params || []) {
    const rawVal = step.params?.[p.name];
    if (rawVal == null || String(rawVal).trim() === "") continue;
    const raw = String(rawVal).trim();

    if (!p.slot) {
      // The check the sigil rule could never make. `passphrase=$pw` on a param
      // that does not take a slot used to hand the cipher the four characters
      // `$pw`; `out` is excluded because there `$label` is the binding
      // occurrence, not a reference to one.
      if (step.name !== "out" && raw.startsWith(SLOT_SIGIL)) {
        errors.push({
          message: `${step.name} ${p.name}=${raw}: ${p.name}= takes a literal, not a slot`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      continue;
    }
    if (!boundAsSlotRef(p, step.name, raw)) continue;

    const ref =
      p.slot === "required" || raw.startsWith(SLOT_SIGIL) || /^\d+$/.test(raw)
        ? raw
        : `${SLOT_SIGIL}${raw}`;
    const loaded = lookupSlotType(ref, slotTypes, slotTypesByIndex);
    if (!loaded) {
      errors.push({
        message: `${step.name} ${p.name}=${raw}: unknown slot (register earlier with out ${ref})`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }
    // No `slotOf` means no claim about the type — `in $x` takes whatever was
    // registered, and saying otherwise would be a guess.
    if (!p.slotOf) continue;
    const want = Array.isArray(p.slotOf) ? p.slotOf : [p.slotOf];
    if (want.includes(loaded.base) || loaded.base === "none") continue;
    errors.push({
      message:
        p.name === "ice"
          ? `${step.name} ice=${raw}: slot type ${formatType(loaded)} is not an ICE config — use rtc.ice`
          : `${step.name} ${p.name}=${raw}: slot type ${formatType(loaded)} cannot supply ${supplyNoun(want)}`,
      start: step.start,
      end: step.end,
      stepIndex,
    });
  }
}

/**
 * Labeled tee branch (selector style: `- :private | …`).
 * @typedef {object} TeeBranch
 * @property {string} member  e.g. private | public | key | value
 * @property {string} [selector]  e.g. ":private"
 * @property {RecipeStep[]} body
 * @property {number} [start]
 * @property {number} [end]
 */

/**
 * @typedef {object} RecipeStep
 * @property {string} name  canonical name
 * @property {Record<string, string|number|boolean>} params
 * @property {number} start  char offset in source
 * @property {number} end
 * @property {RecipeStep[]} [body]  nested `-` list body for tee / foreach
 * @property {TeeBranch[]} [branches]  tee selector branches
 * @property {string} [foreachSelector]  e.g. ":items"
 * @property {"brace"|"indent"} [bodyForm]
 */

/**
 * @typedef {object} RecipeChain
 * @property {RecipeStep[]} steps
 */

/**
 * @typedef {object} RecipeAst
 * @property {RecipeChain[]} chains
 * @property {RecipeStep[]} steps  first chain (compat)
 * @property {string} source
 */

/**
 * @param {RecipeAst|RecipeChain[]|RecipeStep[]|null|undefined} astOrSteps
 * @returns {RecipeChain[]}
 */
export function recipeChains(astOrSteps) {
  if (!astOrSteps) return [];
  if (Array.isArray(astOrSteps)) {
    if (!astOrSteps.length) return [];
    if (astOrSteps[0] && Array.isArray(astOrSteps[0].steps)) {
      return /** @type {RecipeChain[]} */ (astOrSteps);
    }
    return [{ steps: /** @type {RecipeStep[]} */ (astOrSteps) }];
  }
  if (Array.isArray(astOrSteps.chains) && astOrSteps.chains.length) {
    return astOrSteps.chains;
  }
  if (Array.isArray(astOrSteps.steps)) {
    return astOrSteps.steps.length ? [{ steps: astOrSteps.steps }] : [];
  }
  return [];
}

/**
 * @typedef {object} RecipeError
 * @property {string} message
 * @property {number} [start]
 * @property {number} [end]
 * @property {number} [stepIndex]
 */

/**
 * A validator complaint that does not block the run.
 *
 * Structurally identical to `RecipeError` on purpose. Warnings used to be bare
 * strings, which was fine while nothing rendered them and fatal the moment
 * something did: the notebook validates every cell in one pass (see
 * `cellErrorsForChains`), so an unanchored string cannot be dealt back to the
 * cell that earned it — ten warnings about cell 4 would all have piled onto
 * cell 1. `stepIndex` is what makes a warning placeable, and it is the same
 * continuous top-level numbering errors already carry, so both travel the same
 * rebasing path and cannot drift apart.
 *
 * @typedef {object} RecipeWarning
 * @property {string} message
 * @property {number} [start]
 * @property {number} [end]
 * @property {number} [stepIndex]
 */

/**
 * @typedef {object} ValidationResult
 * @property {boolean} ok
 * @property {RecipeError[]} errors
 * @property {RecipeWarning[]} warnings
 * @property {number} [recipientSlots]  how many GPG recipient slots Run needs
 * @property {boolean} [foreachGpg]  gpg.encrypt is inside foreach
 * @property {("shares"|"gpg"|"text"|"envelope"|"key"|"keypair")[]} [inputNeeds]  runtime input panels required
 */

/**
 * Parse a recipe string into an AST.
 *
 * `warnings` carries the parse-time advisories — today, that a slot was spelled
 * with the pre-swap `@` and has been rewritten to `$`. They are warnings and
 * not errors on purpose: the recipe ran before and still runs, and the rewrite
 * is complete by the time the AST exists, so the very next serialize (share
 * link, Copy recipe, Workspace save) writes the new spelling and the warning
 * never comes back.
 * @param {string} source
 * @returns {{ ast: RecipeAst|null, errors: RecipeError[], warnings: RecipeWarning[] }}
 */
export function parseRecipe(source) {
  const r = parseRecipeSource(source);
  return { ...r, warnings: r.warnings || [] };
}

/**
 * Parse then re-serialize to canonical form (names, spacing, indent, enums).
 * On parse failure, returns the original source unchanged with errors.
 * @param {string} source
 * @returns {{ text: string, ast: RecipeAst|null, errors: RecipeError[], changed: boolean }}
 */
export function canonicalizeRecipe(source) {
  const raw = String(source ?? "");
  const { ast, errors } = parseRecipe(raw);
  if (!ast || errors.length) {
    return { text: raw, ast, errors, changed: false };
  }
  const text = serializeRecipe(ast);
  return {
    text,
    ast: { ...ast, source: text },
    errors: [],
    changed: text !== raw,
  };
}

/**
 * Serialize one step (no body) to recipe text.
 * @param {RecipeStep} step
 * @returns {string}
 */
export function serializeStep(step) {
  if (step.name === "lit") {
    const kind = String(step.params?.kind || "text");
    if (kind === "int") {
      const n = Number(step.params?.value);
      return Number.isFinite(n) ? String(Math.trunc(n)) : "0";
    }
    if (kind === "bool") {
      const v = step.params?.value;
      return v === true ||
        v === 1 ||
        String(v).toLowerCase() === "true" ||
        String(v) === "1"
        ? "true"
        : "false";
    }
    return JSON.stringify(String(step.params?.value ?? ""));
  }
  const spec = getStep(step.name);
  const useEncodeVerb =
    !!spec?.decodeTwin && decodeTwinToken(spec, false) === `${step.name}.encode`;
  const parts = [
    useEncodeVerb
      ? decodeTwinToken(spec, !!step.params?.decode)
      : step.name,
  ];
  for (const p of spec?.params || []) {
    const v = step.params?.[p.name];
    if (v === undefined || v === "") continue;
    // Secret params (design v2 §22a) only ever legitimately hold a `$slot`
    // ref — the UI enforces that, but the raw AST can still carry a literal
    // (e.g. hand-typed in Source view). Never let a literal leak into
    // serialized recipe text (share links, Copy recipe, Workspace saves).
    if (p.secret && !/^\$[^\s|=]+$/.test(String(v))) continue;
    if (p.flag && p.type === "bool") {
      // Encoding twins serialize direction in the verb; skip `-d`.
      if (useEncodeVerb && p.name === "decode") continue;
      if (v === true) parts.push(p.flag);
      continue;
    }
    // Omit default *named* params, and default out/text/peek names only.
    // `serialize: "always"` keeps defaults visible (e.g. gpg.symencrypt mode=master).
    if (v === p.default && p.serialize !== "always") {
      const omitName =
        p.positional &&
        p.name === "name" &&
        (step.name === "out" || step.name === "text" || step.name === "peek");
      if (omitName || !p.positional) continue;
    }
    // Positional values need the same quoting as named ones: a bare
    // `hkp.search john doe` or `bytes aGVsbG8=` does not reparse, so without
    // this the round trip silently corrupts Copy recipe, share links, and
    // Workspace saves for any value holding a space, pipe, or `=`.
    const needsQuote = /[\s|=]/.test(String(v));
    const quoted = needsQuote ? JSON.stringify(String(v)) : String(v);
    if (p.positional && parts.length === 1) {
      // …and it is not only those three characters. A *bare* positional has to
      // begin the way `recipe-parse.js`'s argument loop expects one to begin —
      // it dispatches on a letter, a digit, or a slot sigil, and nothing
      // else. (`.` and `/` are recognised, but only for `out`/`in`, where they
      // raise "File paths are not supported yet".) So `file.read accept=.pem`,
      // which is the op's own documented example, serialized bare to
      // `file.read .pem` and came back `Unexpected "."` — a round trip that
      // destroys the recipe. That is not a rare path: the chip flow
      // re-serializes on every mutation and Copy link serializes to build the
      // URL, so editing any chip nearby, or sharing the notebook, handed back
      // something that would not parse.
      parts.push(/^[A-Za-z0-9$@]/.test(String(v)) ? quoted : JSON.stringify(String(v)));
      continue;
    }
    parts.push(`${p.name}=${quoted}`);
  }
  return parts.join(" ");
}

/**
 * Serialize one pipeline of steps (no block wrappers).
 * @param {RecipeStep[]} steps
 * @param {{ compact?: boolean }} [opts]
 * @returns {string}
 */
function serializePipeline(steps, opts = {}) {
  const join = opts.compact ? "|" : " | ";
  return steps
    .map((s) => {
      if (s.name === "select" && s.params?.selector) {
        return String(s.params.selector);
      }
      if (s.name === "at" && s.params?.selector != null) {
        const sel = String(s.params.selector);
        if (/^\d+(:\d+)?$/.test(sel)) return `[${sel}]`;
      }
      return serializeStep(s);
    })
    .join(join);
}

/**
 * Serialize one chain's steps to recipe text.
 * @param {RecipeStep[]} steps
 * @param {{ compact?: boolean }} [opts]
 * @returns {string}
 */
function serializeChainSteps(steps, opts = {}) {
  const compact = opts.compact === true;
  const pipeJoin = compact ? "|" : " | ";
  /** @type {string[]} */
  const chunks = [];

  /**
   * @param {string} head
   */
  function pushStemPiece(head) {
    if (chunks.length && chunks[chunks.length - 1]?.endsWith("\n")) {
      chunks.push(compact ? `|${head}` : `| ${head}`);
    } else if (chunks.length) {
      chunks.push(`${pipeJoin}${head}`);
    } else {
      chunks.push(head);
    }
  }

  /**
   * Collect brace/indent body lines (without leading indent / trailing newline).
   * @returns {string[]}
   */
  function bodyLines(step) {
    /** @type {string[]} */
    const lines = [];
    const body = step.body || [];
    let bi = 0;
    while (bi < body.length) {
      const b = body[bi];
      if (b.name === "select" && b.params?.selector) {
        const group = [b];
        bi++;
        while (
          bi < body.length &&
          body[bi].name !== "select" &&
          !(body[bi].name === "tee" || body[bi].name === "foreach")
        ) {
          group.push(body[bi]);
          bi++;
        }
        const sel = String(b.params.selector);
        const rest = serializePipeline(group.slice(1), opts);
        lines.push(rest ? `- ${sel}${pipeJoin}${rest}` : `- ${sel}${pipeJoin}inspect`);
      } else {
        lines.push(`- ${serializePipeline([b], opts)}`);
        bi++;
      }
    }
    for (const br of step.branches || []) {
      const sel = br.selector || `:${br.member}`;
      const pipe = serializePipeline(br.body || [], opts);
      lines.push(`- ${sel}${pipeJoin}${pipe}`);
    }
    return lines;
  }

  for (const step of steps) {
    const hasListBody =
      (step.name === "tee" || step.name === "foreach") &&
      Array.isArray(step.body) &&
      step.body.length > 0;
    const hasBranches =
      step.name === "tee" &&
      Array.isArray(step.branches) &&
      step.branches.length > 0;
    const isBlock = hasListBody || hasBranches;

    let head = serializeStep(step);
    if (step.name === "foreach" && step.foreachSelector) {
      head = `foreach ${step.foreachSelector}`;
    } else if (step.name === "lit") {
      head = serializeStep(step);
    } else if (step.name === "in" && step.params?.ref) {
      const ref = String(step.params.ref);
      // Prefer bare `$label`; keep `in N` for 1-based indexes.
      head = /^\d+$/.test(ref)
        ? `in ${ref}`
        : ref.startsWith(SLOT_SIGIL)
          ? ref
          : `${SLOT_SIGIL}${ref}`;
    } else if (step.name === "select" && step.params?.selector) {
      head = String(step.params.selector);
    } else if (step.name === "at" && step.params?.selector != null) {
      const sel = String(step.params.selector);
      if (/^\d+(:\d+)?$/.test(sel)) head = `[${sel}]`;
    }

    if (!isBlock) {
      pushStemPiece(head);
      continue;
    }

    if (chunks.length) chunks.push(pipeJoin);
    const lines = bodyLines(step);
    const useBrace = compact || step.bodyForm === "brace";
    if (compact) {
      // One-line brace body: foreach{ - out $share }
      chunks.push(`${head}{ ${lines.join(" ")} }`);
    } else if (useBrace) {
      chunks.push(`${head} {\n`);
      for (const line of lines) chunks.push(`  ${line}\n`);
      chunks.push("}");
    } else {
      chunks.push(`${head}\n`);
      for (const line of lines) chunks.push(`  ${line}\n`);
    }
  }
  return chunks.join("").replace(/\n+$/, "");
}

/**
 * Serialize an AST (or steps / chains) back to recipe text.
 * Chains are joined with a blank line (or `~` when `compact`).
 * Canonical names; `$` slot sugar.
 * @param {RecipeAst|RecipeStep[]|RecipeChain[]} astOrSteps
 * @param {{ compact?: boolean }} [opts]
 * @returns {string}
 */
export function serializeRecipe(astOrSteps, opts = {}) {
  const compact = opts.compact === true;
  const chains = recipeChains(astOrSteps);
  return chains
    .map((c) => serializeChainSteps(c.steps || [], opts))
    .filter((t) => t.length)
    .join(compact ? "~" : "\n\n");
}

/**
 * Refined type after a selector projection (`:private`, `:items`, …).
 * @param {import("./types.js").RefinedType} current
 * @param {string} memberOrSelector
 * @returns {{ ok: true, type: import("./types.js").RefinedType } | { ok: false, error: string }}
 */
export function projectTypeForMember(current, memberOrSelector) {
  const sel = String(memberOrSelector || "");
  if (/^\[\d/.test(sel)) {
    // Index selectors use `at` typing.
    return {
      ok: false,
      error: `Use \`at\` / ${sel} as a stem stage, not a tee member`,
    };
  }
  const m = canonicalSelectorMember(sel);

  if (m === "private" || m === "public") {
    if (current.base !== "keypair") {
      return {
        ok: false,
        error: `selector ":${m}" requires keypair, got ${formatType(current)}`,
      };
    }
    return {
      ok: true,
      type: typeOf("key", { alg: current.alg, which: m }),
    };
  }

  if (m === "keys" || m === "values" || m === "items") {
    if (current.base !== "shares") {
      return {
        ok: false,
        error: `selector ":${m}" requires shares, got ${formatType(current)}`,
      };
    }
    if (m === "keys") {
      return { ok: true, type: typeOf("text", { kind: "opaque" }) };
    }
    if (m === "items") {
      return { ok: true, type: typeOf("item", { kind: current.kind || "mnemonic" }) };
    }
    // :values — same per-element type as foreach default
    if (current.kind === "raw") {
      return { ok: true, type: typeOf("bytes", { kind: "opaque" }) };
    }
    return { ok: true, type: typeOf("text", { kind: "mnemonic" }) };
  }

  if (m === "key" || m === "value") {
    if (current.base !== "item") {
      return {
        ok: false,
        error: `selector ":${m}" requires an item ({key,value}), got ${formatType(current)}`,
      };
    }
    if (m === "key") {
      return { ok: true, type: typeOf("text", { kind: "opaque" }) };
    }
    if (current.kind === "raw") {
      return { ok: true, type: typeOf("bytes", { kind: "opaque" }) };
    }
    return { ok: true, type: typeOf("text", { kind: "mnemonic" }) };
  }

  return { ok: false, error: `Unknown selector ":${m}"` };
}

/**
 * Validate steps inside a tee/foreach list body.
 * @param {RecipeStep[]} body
 * @param {import("./types.js").RefinedType} startType
 * @param {{
 *   errors: RecipeError[],
 *   warnings: RecipeWarning[],
 *   stepIndex: number,
 *   inForeach: boolean,
 *   source?: string,
 * }} ctx
 * @returns {{
 *   final: import("./types.js").RefinedType,
 *   encryptInBody: boolean,
 *   inputNeeds: ("shares"|"gpg"|"text"|"envelope"|"key"|"keypair")[],
 * }}
 */
function validateBodySteps(body, startType, ctx) {
  /** @type {import("./types.js").RefinedType} */
  let current = startType;
  let encryptInBody = false;
  /** @type {("shares"|"gpg"|"text"|"envelope"|"key")[]} */
  const inputNeeds = [];
  /** @type {Map<string, import("./types.js").RefinedType>|undefined} */
  const slotTypes = ctx.slotTypes;
  /** @type {import("./types.js").RefinedType[]|undefined} */
  const slotTypesByIndex = ctx.slotTypesByIndex;

  if (!body.length) {
    ctx.errors.push({
      message: "tee/foreach list body is empty — add at least one `- step`",
      stepIndex: ctx.stepIndex,
    });
    return { final: current, encryptInBody, inputNeeds };
  }

  for (const step of body) {
    const spec = getStep(step.name);
    if (!spec) {
      ctx.errors.push({
        message: `Unknown step "${step.name}"`,
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
      continue;
    }
    if (
      step.name === "foreach" ||
      step.name === "tee" ||
      step.name === "merge"
    ) {
      ctx.errors.push({
        message: `Cannot use "${step.name}" inside a nested list body`,
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
      continue;
    }
    if (step.name === "select") {
      const projected = projectTypeForMember(
        current,
        String(step.params?.selector || "")
      );
      if (!projected.ok) {
        ctx.errors.push({
          message: projected.error,
          start: step.start,
          end: step.end,
          stepIndex: ctx.stepIndex,
        });
        continue;
      }
      current = projected.type;
      continue;
    }
    if (step.body?.length) {
      ctx.errors.push({
        message: "Nested lists inside tee/foreach bodies are not supported in v1",
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
    }
    if (slotTypes && slotTypesByIndex) {
      validateStepSlotParams(
        step,
        slotTypes,
        slotTypesByIndex,
        ctx.errors,
        ctx.stepIndex
      );
    }
    if (stepNeedsKeyPanel(step) && !inputNeeds.includes("key")) {
      inputNeeds.push("key");
    }
    if (
      spec.unresolvedInputs &&
      spec.unresolvedInputs !== "key" &&
      spec.unresolvedInputs !== "gpg" &&
      !inputNeeds.includes(spec.unresolvedInputs)
    ) {
      inputNeeds.push(spec.unresolvedInputs);
    }
    if (stepNeedsGpgPrivatePanel(step) && !inputNeeds.includes("gpg")) {
      inputNeeds.push("gpg");
    } else if (
      stepNeedsGpgPassphrasePanel(step) &&
      !inputNeeds.includes("gpg") &&
      !inputNeeds.includes("gpgPass")
    ) {
      inputNeeds.push("gpgPass");
    }
    if (ctx.warnings) {
      // Body steps carry their stem's index, exactly as body *errors* do —
      // the chip that can be clicked is the `foreach`/`tee`, not a nested step
      // the chip row never draws.
      pushDiscouragedAlgoWarnings(step, ctx.warnings, ctx.stepIndex);
      pushUsageHonestyWarnings(step, ctx.warnings, ctx.stepIndex);
      pushExportWhichPolicy(step, current, ctx);
    }
    if (step.name === "gpg.encrypt" && !String(step.params?.to || "").trim()) {
      encryptInBody = true;
    }

    const resolved = resolveStepType(spec, current, step.params || {});
    if (!resolved.ok) {
      ctx.errors.push({
        message: resolved.error,
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
      continue;
    }
    current = resolved.output;
    if (
      step.name === "out" &&
      slotTypes &&
      slotTypesByIndex &&
      !ctx.inForeach
    ) {
      const ref = String(step.params?.name || DEFAULT_OUT_SLOT);
      const key = slotLabelKey(ref);
      if (key) {
        if (slotTypes.has(key)) {
          ctx.errors.push({
            message: `Duplicate out slot ${SLOT_SIGIL}${key}`,
            start: step.start,
            end: step.end,
            stepIndex: ctx.stepIndex,
          });
        } else {
          slotTypes.set(key, { ...current });
        }
      }
      slotTypesByIndex.push({ ...current });
    }
    if (ctx.inForeach && spec.kind === "sink") {
      current = typeOf("text", { kind: "mnemonic" });
    }
  }

  return { final: current, encryptInBody, inputNeeds };
}

/**
 * Validate a parsed AST against the registry (types, scopes, params).
 * @param {RecipeAst} ast
 * @returns {ValidationResult}
 */
export function validateRecipe(ast) {
  /** @type {RecipeError[]} */
  const errors = [];
  /** @type {RecipeWarning[]} */
  const warnings = [];
  const chains = recipeChains(ast);
  if (!chains.length || !chains.some((c) => c.steps?.length)) {
    return {
      ok: false,
      errors: [{ message: "Empty recipe" }],
      warnings,
      inputNeeds: [],
    };
  }

  /** @type {Map<string, import("./types.js").RefinedType>} */
  const slotTypes = new Map();
  /** @type {import("./types.js").RefinedType[]} */
  const slotTypesByIndex = []; // 0-based; recipe indexes are 1-based

  let sharesCount = 0;
  let gpgSlots = 0;
  let foreachGpg = false;
  /** @type {("shares"|"gpg"|"text"|"envelope"|"key")[]} */
  const inputNeeds = [];
  let sawInputShares = false;
  let sawInputText = false;
  let sawDecryptGpg = false;
  let globalStepIndex = 0;

  for (let ci = 0; ci < chains.length; ci++) {
    const steps = chains[ci].steps || [];
    if (!steps.length) continue;

    /** @type {import("./types.js").RefinedType} */
    let current = tNone();

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const stepIndex = globalStepIndex++;
    if (step.name === "merge" || step.name === "collect") {
      errors.push({
        message:
          `"${step.name}" is not used — foreach bodies close by dedent or \`}\` (see docs/RECIPE.md)`,
        start: step.start,
        end: step.end,
          stepIndex,
        });
      continue;
    }
    const spec = getStep(step.name);
    if (!spec) {
      errors.push({
        message: `Unknown step "${step.name}"`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }

    // Param checks
    for (const p of spec.params || []) {
      const v = step.params[p.name];
      if (v === undefined) continue;
      if (p.type === "enum" && p.enum && !p.enum.includes(String(v))) {
        const retired = RETIRED_PARAM_VALUES[`${step.name} ${p.name}=${String(v)}`];
        errors.push({
          message: retired
            ? `${step.name}: ${p.name}="${v}" was removed — ${retired} (or Upgrade recipe to migrate)`
            : `${step.name}: invalid ${p.name}="${v}" (allowed: ${p.enum.join(", ")})`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      if (p.type === "int") {
        const n = Number(v);
        if (!Number.isFinite(n)) {
          errors.push({
            message: `${step.name}: ${p.name} must be an integer`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        } else {
          if (p.min != null && n < p.min) {
            errors.push({
              message: `${step.name}: ${p.name} must be ≥ ${p.min}`,
              start: step.start,
              end: step.end,
              stepIndex,
            });
          }
          if (p.max != null && n > p.max) {
            errors.push({
              message: `${step.name}: ${p.name} must be ≤ ${p.max}`,
              start: step.start,
              end: step.end,
              stepIndex,
            });
          }
        }
      }
    }

    if (step.name === "sss.split") {
      const t = Number(step.params.threshold);
      const n = Number(step.params.shares);
      if (t > n) {
        errors.push({
          message: `sss: threshold (${t}) cannot exceed shares (${n})`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      sharesCount = n;
    }

    if (step.name === "shares") {
      if (sawInputShares) {
        errors.push({
          message: "Only one shares step is supported per pipeline",
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      sawInputShares = true;
      if (!inputNeeds.includes("shares")) inputNeeds.push("shares");
    }

    if (step.name === "input") {
      if (sawInputText) {
        errors.push({
          message: "Only one input step is supported per pipeline",
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      sawInputText = true;
      if (!inputNeeds.includes("text")) inputNeeds.push("text");
    }

    if (step.name === "gpg.decrypt") {
      if (sawDecryptGpg) {
        errors.push({
          message: "Only one decrypt step is supported per recipe",
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      sawDecryptGpg = true;
      if (!inputNeeds.includes("gpg")) inputNeeds.push("gpg");
      // Share rows for mnemonics already decrypted outside the browser
      // (Kleopatra/gpg/YubiKey — OpenPGP cards are not reachable from JS).
      if (!inputNeeds.includes("shares")) inputNeeds.push("shares");
    }

    // Spec-declared input panels (envelope / …).
    // Skip "key" — gated by stepNeedsKeyPanel (honors key=$slot).
    // Skip "gpg" — gated by stepNeedsGpgPrivatePanel / stepNeedsGpgPassphrasePanel.
    // gpg.decrypt / input / shares already handled above.
    // gpg.symdecrypt mode=passphrase does not need the envelope panel.
    const skipEnvelope =
      step.name === "gpg.symdecrypt" &&
      String(step.params?.mode || "master").toLowerCase() === "passphrase";
    if (
      step.name !== "gpg.decrypt" &&
      step.name !== "input" &&
      step.name !== "shares" &&
      !skipEnvelope &&
      spec.unresolvedInputs &&
      spec.unresolvedInputs !== "key" &&
      spec.unresolvedInputs !== "gpg" &&
      !inputNeeds.includes(spec.unresolvedInputs)
    ) {
      inputNeeds.push(spec.unresolvedInputs);
    }
    if (stepNeedsGpgPrivatePanel(step) && !inputNeeds.includes("gpg")) {
      inputNeeds.push("gpg");
    } else if (
      stepNeedsGpgPassphrasePanel(step) &&
      !inputNeeds.includes("gpg") &&
      !inputNeeds.includes("gpgPass")
    ) {
      inputNeeds.push("gpgPass");
    }

    if (step.name === "in") {
      const ref = String(step.params?.ref || "");
      /** @type {import("./types.js").RefinedType|undefined} */
      let loaded;
      if (/^\d+$/.test(ref)) {
        const n = Number(ref);
        loaded = slotTypesByIndex[n - 1];
        if (!loaded) {
          errors.push({
            message: `in ${ref}: no slot registered at index ${ref}`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
          continue;
        }
      } else {
        const key = slotLabelKey(ref);
        loaded = key ? slotTypes.get(key) : undefined;
        if (!loaded) {
          errors.push({
            message: `in ${ref}: unknown slot (register it earlier with out ${ref.startsWith(SLOT_SIGIL) ? ref : `${SLOT_SIGIL}${ref}`})`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
          continue;
        }
      }
      if (i > 0 && current.base !== "none") {
        warnings.push(
          stepWarning(
            step,
            stepIndex,
            `Source step "in" at position ${i + 1} discards prior pipeline value`
          )
        );
      }
      current = { ...loaded };
      continue;
    }

    validateStepSlotParams(step, slotTypes, slotTypesByIndex, errors, stepIndex);

    if (stepNeedsKeyPanel(step) && !inputNeeds.includes("key")) {
      inputNeeds.push("key");
    }

    pushDiscouragedAlgoWarnings(step, warnings, stepIndex);
    pushUsageHonestyWarnings(step, warnings, stepIndex);
    pushExportWhichPolicy(step, current, {
      warnings,
      errors,
      source: ast.source,
      stepIndex,
    });

    if (step.name === "foreach") {
      // `bundle` is a collection too — and `foreach` is what produces one, so
      // refusing to consume it left the type with a producer and no consumer.
      // `quorum.recv count=all` is the first source of a bundle that is not a
      // foreach result, which is what made the gap visible.
      if (current.base !== "shares" && current.base !== "bundle") {
        errors.push({
          message: `foreach requires a collection (shares or bundle) — got ${formatType(current)}. Add sss, blip39, shares, or quorum.recv count=all before foreach.`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      if (!step.body?.length) {
        errors.push({
          message:
            "foreach requires a body — use indented `- out $share` or `foreach { - out $share }`",
          start: step.start,
          end: step.end,
          stepIndex,
        });
        current = typeOf("bundle");
        continue;
      }
      const mode = String(step.foreachSelector || ":values").replace(/^[.:]/, "");
      /** @type {import("./types.js").RefinedType} */
      let itemType;
      if (mode === "items") {
        itemType = typeOf("item", { kind: current.kind || "mnemonic" });
      } else if (mode === "keys") {
        itemType = typeOf("text", { kind: "opaque" });
      } else {
        itemType =
          current.kind === "raw"
            ? typeOf("bytes", { kind: "opaque" })
            : typeOf("text", { kind: "mnemonic" });
      }
      const bodyVal = validateBodySteps(step.body, itemType, {
        errors,
        warnings,
        stepIndex,
        inForeach: true,
        slotTypes,
        slotTypesByIndex,
        source: ast.source,
      });
      if (bodyVal.encryptInBody) {
        foreachGpg = true;
        gpgSlots = Math.max(gpgSlots, sharesCount || 1);
      }
      for (const need of bodyVal.inputNeeds) {
        if (!inputNeeds.includes(need)) inputNeeds.push(need);
      }
      current = typeOf("bundle");
      continue;
    }

    if (step.name === "tee") {
      if (current.base === "none") {
        errors.push({
          message: `"tee" needs a pipeline value`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
        continue;
      }
      if (!step.body?.length && !step.branches?.length) {
        errors.push({
          message:
            "tee requires a body — use `{ - :public | … }` or indented `-` lines (use `peek` for a side inspect)",
          start: step.start,
          end: step.end,
          stepIndex,
        });
        continue;
      }
      if (step.body?.length) {
        const bodyVal = validateBodySteps(step.body, current, {
          errors,
          warnings,
          stepIndex,
          inForeach: false,
          slotTypes,
          slotTypesByIndex,
          source: ast.source,
        });
        for (const need of bodyVal.inputNeeds) {
          if (!inputNeeds.includes(need)) inputNeeds.push(need);
        }
        if (bodyVal.encryptInBody) gpgSlots = Math.max(gpgSlots, 1);
      }
      for (const br of step.branches || []) {
        const projected = projectTypeForMember(
          current,
          br.selector || br.member
        );
        if (!projected.ok) {
          errors.push({
            message: projected.error || `tee selector "${br.member}" invalid`,
            start: br.start ?? step.start,
            end: br.end ?? step.end,
            stepIndex,
          });
          continue;
        }
        const bodyVal = validateBodySteps(br.body, projected.type, {
          errors,
          warnings,
          stepIndex,
          inForeach: false,
          slotTypes,
          slotTypesByIndex,
          source: ast.source,
        });
        for (const need of bodyVal.inputNeeds) {
          if (!inputNeeds.includes(need)) inputNeeds.push(need);
        }
        if (bodyVal.encryptInBody) gpgSlots = Math.max(gpgSlots, 1);
      }
      // Stem type unchanged after tee body.
      continue;
    }

    if (step.name === "select") {
      const projected = projectTypeForMember(
        current,
        String(step.params?.selector || "")
      );
      if (!projected.ok) {
        errors.push({
          message: projected.error,
          start: step.start,
          end: step.end,
          stepIndex,
        });
        continue;
      }
      current = projected.type;
      continue;
    }

    // Collection into non-foreach / non-recover / non-blip39 / pass-through
    if (
      current.base === "shares" &&
      step.name !== "sss.combine" &&
      // The verifiable pair consumes the same share sets: `vss.verify` checks
      // them and hands them on, `vss.combine` reconstructs from them.
      step.name !== "vss.verify" &&
      step.name !== "vss.combine" &&
      step.name !== "vss.commitments" &&
      step.name !== "blip39" &&
      step.name !== "tee" &&
      step.name !== "peek" &&
      step.name !== "inspect" &&
      step.name !== "out" &&
      step.name !== "at" &&
      step.name !== "select"
    ) {
      errors.push({
        message: `Cannot pipe shares into "${step.name}" — add foreach to unpack, at N / [n] to select, blip39 to encode/decode, or sss.combine / vss.combine (on raw shares) for bytes/master.`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }

    if (spec.kind === "source") {
      if (i > 0 && current.base !== "none") {
        warnings.push(
          stepWarning(
            step,
            stepIndex,
            `Source step "${step.name}" at position ${i + 1} discards prior pipeline value`
          )
        );
      }
    }

    const resolved = resolveStepType(spec, current, step.params || {});
    if (!resolved.ok) {
      let message = resolved.error;
      if (current.base === "keypair" && /expects bytes/i.test(message)) {
        message = `"${step.name}" expects DER bytes — add export pkcs8, export scalar, or spki first.`;
      } else if (current.base === "none") {
        message = `"${step.name}" needs an input — start with genkey, random, passphrase, input, in, or decrypt.`;
      }
      errors.push({
        message,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }

    current = resolved.output;

    if (step.name === "out") {
      const ref = String(step.params?.name || DEFAULT_OUT_SLOT);
      const key = slotLabelKey(ref);
      if (key) {
        if (slotTypes.has(key)) {
          errors.push({
            message: `Duplicate out slot ${SLOT_SIGIL}${key}`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        } else {
          slotTypes.set(key, { ...current });
        }
      }
      slotTypesByIndex.push({ ...current });
    }

    // Reject sss on scalars that are not 16/32 (e.g. P-384)
    if (
      step.name === "export" &&
      (String(step.params.format || "") === "scalar" ||
        String(step.params.format || "") === "d") &&
      current.length != null &&
      current.length !== 16 &&
      current.length !== 32
    ) {
      warnings.push(
        stepWarning(
          step,
          stepIndex,
          `export scalar produced ${current.length}-byte material — sss only accepts 16/32; use gpg.symencrypt for larger scalars`
        )
      );
    }

    if (step.name === "gpg.encrypt") {
      // Explicit to=@ / to=email / to=fpr skips the Run recipient binder.
      if (!String(step.params?.to || "").trim()) {
        gpgSlots = Math.max(gpgSlots, 1);
      }
    }
  }

  const first = getStep(steps[0].name);
  // Sources, flow, and transforms with input "none" (ecdh / wrap with slot args) may start a chain.
  const firstOk =
    first &&
    (first.kind === "source" ||
      first.kind === "flow" ||
      first.input === "none");
  if (first && !firstOk) {
    errors.push({
      message: `Chain ${ci + 1} should start with a source (genkey, random, passphrase, input, in, decrypt) or an input-none op (ecdh, wrap), not "${steps[0].name}".`,
      start: steps[0].start,
      end: steps[0].end,
      stepIndex: globalStepIndex - steps.length,
    });
  }

  // Dangling typed value: engine auto-emits a result tile — prefer inspect/out.
  const last = steps[steps.length - 1];
  if (
    last &&
    current.base !== "none" &&
    current.base !== "artifact" &&
    current.base !== "bundle" &&
    !isTerminalSink(last.name) &&
    last.name !== "inspect"
  ) {
    const tip =
      current.base === "shares"
        ? "append sss.combine (→ bytes/master) or foreach, or inspect to dump"
        : "append inspect to dump, or out/text to emit a named tile";
    // Anchored to the last step rather than the chain: the locator used to be
    // the prose ("Chain 3:"), which in a notebook restates the cell you are
    // already looking at. `stepIndex` says it once, and clickably.
    warnings.push(
      stepWarning(
        last,
        globalStepIndex - 1,
        `Trailing ${formatType(current)} is unhandled — ${tip}.`
      )
    );
  }
  } // end chains

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    recipientSlots: gpgSlots,
    foreachGpg,
    inputNeeds,
  };
}

/**
 * Parse + validate convenience.
 * @param {string} source
 * @returns {{ ast: RecipeAst|null, validation: ValidationResult }}
 */
export function compileRecipe(source) {
  const { ast, errors, warnings } = parseRecipe(source);
  if (!ast || errors.length) {
    return {
      ast: null,
      validation: { ok: false, errors, warnings, inputNeeds: [] },
    };
  }
  const validation = validateRecipe(ast);
  // Parse-time advisories lead: a legacy sigil is a fact about the text the
  // caller handed in, and `validateRecipe` only ever sees the rewritten AST.
  return {
    ast,
    validation: warnings.length
      ? { ...validation, warnings: [...warnings, ...(validation.warnings || [])] }
      : validation,
  };
}

/**
 * Detect unresolved GPG recipient requirements without running.
 * @param {RecipeAst} ast
 * @returns {{ slots: number, foreach: boolean }}
 */
export function unresolvedRecipients(ast) {
  const v = validateRecipe(ast);
  return { slots: v.recipientSlots || 0, foreach: !!v.foreachGpg };
}

/**
 * Detect runtime input panels required.
 * @param {RecipeAst} ast
 * @returns {("shares"|"gpg"|"text"|"envelope")[]}
 */
export function unresolvedInputs(ast) {
  return validateRecipe(ast).inputNeeds || [];
}

/**
 * Registry completeness check for tests.
 * @returns {string[]}
 */
export function registryIssues() {
  /** @type {string[]} */
  const issues = [];
  const paramTypes = new Set(["enum", "int", "string", "bytes", "bool", "flag"]);
  for (const s of listSteps()) {
    if (!s.name) issues.push("step missing name");
    if (!s.kind) issues.push(`${s.name}: missing kind`);
    if (!s.toolbox) issues.push(`${s.name}: missing toolbox`);
    if (!s.doc) issues.push(`${s.name}: missing doc`);
    if (!s.input) issues.push(`${s.name}: missing input`);
    if (!s.output) issues.push(`${s.name}: missing output`);
    const positionals = (s.params || []).filter((p) => p.positional);
    if (positionals.length > 1) {
      issues.push(
        `${s.name}: at most one positional param (found ${positionals
          .map((p) => p.name)
          .join(", ")})`
      );
    }
    for (const p of s.params || []) {
      if (!p.name) issues.push(`${s.name}: param missing name`);
      if (!p.type) issues.push(`${s.name}.${p.name}: missing type`);
      else if (!paramTypes.has(p.type)) {
        issues.push(`${s.name}.${p.name}: invalid type "${p.type}"`);
      }
      if (p.serialize != null && p.serialize !== "always") {
        issues.push(
          `${s.name}.${p.name}: serialize must be "always" (got ${JSON.stringify(p.serialize)})`
        );
      }
      if (p.slot != null && p.slot !== true && p.slot !== "required") {
        issues.push(
          `${s.name}.${p.name}: slot must be true or "required" (got ${JSON.stringify(p.slot)})`
        );
      }
      if (p.slotOf && !p.slot) {
        issues.push(`${s.name}.${p.name}: slotOf without slot`);
      }
      if (p.allowIndex && !p.slot) {
        issues.push(`${s.name}.${p.name}: allowIndex without slot`);
      }
    }
  }
  return issues;
}

/**
 * Stable Templates menu category order (see PRESETS `group`).
 * @type {readonly string[]}
 */
export const PRESET_GROUP_ORDER = Object.freeze([
  "Keys",
  // Directly after Keys, not down among the named ecosystems: every SSH
  // template is a key task, and "make me an SSH key for GitHub" is the errand
  // people arrive with. Ordering here is by what a user reaches for — the same
  // rationale as WebRTC below — not by how deep the format sits in the stack.
  "SSH",
  "Secrets",
  "Digest & MAC",
  "Encrypt",
  // Its own shelf rather than more rows under Encrypt: half the age arc
  // (keygen, recipient) is key management, and the group is the whole
  // keygen → recipient → encrypt → decrypt story. Lowercase because the tool
  // is — `age`, not "Age".
  "age",
  "Keys wrap / agree",
  "Split & recover",
  // The key-ceremony kit: the guided flow's stages as templates, so the same
  // pipelines are reachable without the Sheet.
  "Ceremony",
  "OpenPGP",
  "Directory",
  "WebAuthn",
  // Straight after WebAuthn, for the reason the `otp` toolbox sits beside the
  // `webauthn` one: both answer "set up my second factor", and a user who
  // came looking for one is often choosing between them. Not filed under
  // Keys, because nothing here is a keypair — a TOTP secret is a shared
  // secret, and putting it among the asymmetric templates would teach the
  // wrong mental model of what an authenticator holds.
  "OTP",
  "JOSE",
  // ICE/STUN diagnostics and hand-carried signalling. Ordered before the live
  // mesh templates a user reaches for later, because when a connection fails
  // these are what tells you why.
  "WebRTC",
  "Encoding",
]);

/**
 * Ordered group names for the Templates menu (known order first, then any extras).
 * @param {typeof PRESETS} [presets]
 * @returns {string[]}
 */
export function listPresetGroups(presets = PRESETS) {
  const seen = new Set(presets.map((p) => p.group || "Pipelines"));
  const ordered = PRESET_GROUP_ORDER.filter((g) => seen.has(g));
  for (const g of seen) {
    if (!ordered.includes(g)) ordered.push(g);
  }
  return ordered;
}

/**
 * Preset recipes for the Templates menu.
 *
 * `group` clusters presets under a category. Presets sharing a `pair` value are
 * companion pipelines (forward ⇄ inverse, e.g. split/recover or encrypt/decrypt)
 * and render side by side; the one listed first appears on the left.
 */
export const PRESETS = [
  {
    id: "p256-pem",
    group: "Keys",
    title: "P-256 public + private (PEM)",
    blurb:
      "Tee the public SPKI PEM, then export PKCS#8 — mid-stem fork keeps the keypair on the stem.",
    recipe: `genkey ec/p256 | tee
  - :public | export spki | pem | out $public
| export pkcs8 | pem | out $private`,
  },
  {
    id: "p256-tee-inspect",
    group: "Keys",
    title: "P-256 with mid-pipeline peek",
    blurb: "Generate a key, peek an openssl-style dump, then export PEM (keypair still flows through).",
    recipe: "genkey ec/p256 | peek keypair | export pkcs8 | pem | out $private",
  },
  {
    id: "p256-multichain",
    group: "Keys",
    title: "P-256 via $slot reuse",
    blurb:
      "Register the live keypair with out $kp, then reuse it across blank-line chains with in $kp.",
    recipe: `genkey ec/p256 | out $kp

$kp | :public | export spki | pem | out $public
$kp | export pkcs8 | pem | out $private`,
  },
  {
    id: "ed25519-jwk",
    group: "Keys",
    title: "Ed25519 key (JWK)",
    blurb: "Signing key as JSON Web Key.",
    recipe: "genkey ed25519 | export jwk | out $jwk",
  },
  // ── SSH. The toolbox shipped with byte-exact ssh-keygen interop and no way
  // to find it from the Templates menu; these are the seven errands people
  // actually arrive with, in the order they arrive with them.
  {
    id: "ssh-github",
    group: "SSH",
    title: "An SSH key for GitHub",
    blurb:
      "The one line you paste into Settings → SSH keys — `ssh.encode` writes the same `ssh-ed25519 AAAA… comment` bytes as `ssh-keygen -t ed25519`, comment and all.",
    recipe: `genkey ed25519 | ssh.encode comment="you@host" | out $pub`,
  },
  {
    id: "ssh-key-vault",
    group: "SSH",
    title: "SSH key, saved to My Keys",
    blurb:
      "Fork the public line off the stem and let the private half go on to `agent.save` — one run gives you the text to paste and a vault key the `agent.*` ops can sign with (it writes to whoever runs it).",
    recipe: `genkey ed25519 | tee
  - ssh.encode comment="you@host" | out $pub
| agent.save | out $id`,
  },
  {
    id: "ssh-fingerprint",
    group: "SSH",
    title: "Fingerprint a public key",
    blurb:
      "Paste an authorized_keys line and read back the `SHA256:…` string byte-for-byte identical to `ssh-keygen -lf` — the one GitHub prints beside the key.",
    recipe: "input | ssh.decode | ssh.fingerprint | out $fp",
  },
  {
    id: "ssh-sign-git",
    group: "SSH",
    // No `pair` with ssh-verify-git, though they are conjugates. The stitch
    // bridges the forward's last output into the reverse's first source, and
    // for sshsig that bridge would be the *signature* — but a verifier needs
    // the message on the stem and the signature in a slot, so the stitched
    // preview would bind the wrong thing. `hmac-sign-verify` and
    // `gpg-sign-verify` are unpaired for the same reason.
    title: "Sign a file the way git does",
    blurb:
      "sshsig, the envelope `ssh-keygen -Y sign` and `git commit -S` both write — `namespace=` is inside what gets signed, so a `git` signature can never verify as a `file` one no matter how good the key is.",
    recipe: `genkey ed25519 | out $id

input | utf8 | ssh.sign key=$id namespace=git | out $sig`,
  },
  {
    id: "ssh-verify-git",
    group: "SSH",
    title: "Verify an SSH signature",
    blurb:
      "Both halves in one notebook so the check is readable: swap `$pub` and `$sig` for a signer's public line and their `BEGIN SSH SIGNATURE` block, and keep `namespace=` equal or a perfectly good signature fails.",
    recipe: `genkey ed25519 | tee
  - :public | ssh.encode | out $pub
| out $id

input | utf8 | out $msg

in $msg | ssh.sign key=$id namespace=git | out $sig

in $msg | ssh.verify key=$pub signature=$sig namespace=git | out $ok`,
  },
  {
    id: "ssh-to-pem",
    group: "SSH",
    pair: "ssh-pem",
    title: "SSH private key → PKCS#8 PEM",
    blurb:
      "The conversion chore, without `ssh-keygen -p -m PKCS8` overwriting your file: paste an openssh-key-v1 block and get PEM. `format=private` is written because it is what fixes the output type — a public line pasted here is refused by name instead of being decoded into the other thing. Passphrase-protected blocks work — put the passphrase in the Inputs panel.",
    recipe: "input | ssh.decode format=private | export pkcs8 | pem | out $pem",
  },
  {
    id: "pem-to-ssh",
    group: "SSH",
    pair: "ssh-pem",
    title: "PKCS#8 PEM → SSH public line",
    blurb:
      "The way back. `import` has to be told `alg=` because PEM armor alone does not say — change it to `ec/p256` and the emitted key type changes with it, not with anything you write on `ssh.encode`.",
    recipe: `input | der | import pkcs8 alg=ed25519 | ssh.encode comment="you@host" | out $pub`,
  },
  {
    id: "ssh-p521",
    group: "SSH",
    title: "A P-521 SSH key",
    blurb:
      "The key type comes out `ecdsa-sha2-nistp521` and there is no knob for the `sha2`: RFC 5656 fixes the name from the curve, and the curve alone picks the digest — P-256→SHA-256, P-384→SHA-384, P-521→SHA-512.",
    recipe: `genkey ec/p521 | ssh.encode comment="you@host" | out $pub`,
  },
  {
    id: "secret-b64url",
    group: "Secrets",
    title: "256-bit secret (base64url)",
    blurb: "Websafe random secret — no +/ or padding.",
    recipe: "random 32 | base64url | out $secret",
  },
  {
    id: "diceware",
    group: "Secrets",
    title: "Diceware passphrase",
    blurb: "EFF Large Wordlist, 6 words (~77 bits).",
    recipe: "passphrase 6 | out $passphrase",
  },
  {
    id: "passphrase-char",
    group: "Secrets",
    title: "Character passphrase",
    blurb: "69-char alphabet random passphrase (`passphrase mode=char`).",
    recipe: `passphrase mode=char length=20 | out $pass`,
  },
  {
    id: "digest-sha256",
    group: "Digest & MAC",
    title: "SHA-256 digest",
    blurb: "Hash 32 random bytes and show hex.",
    recipe: "random 32 | digest | encode hex | out $digest",
  },
  {
    id: "hmac-sign-verify",
    group: "Digest & MAC",
    title: "HMAC sign / verify",
    blurb:
      "HMAC-SHA-256 via recipe sugar `hmac` / `hmac.verify` (serialize as sign/verify).",
    recipe: `genkey hmac/sha256 | out $mac

input | utf8 | out $msg

in $msg | hmac key=$mac | base64url | out $tag

in $msg | hmac.verify key=$mac signature=$tag | out $ok`,
  },
  {
    id: "jwk-thumbprint",
    group: "Digest & MAC",
    title: "JWK SHA-256 digest",
    blurb:
      "Export a public JWK and SHA-256 digest the JSON text (handy fingerprint; not RFC 7638 canonical thumbprint).",
    recipe: `genkey ec/p256 | :public | export jwk | out $jwk

in $jwk | utf8 | digest | encode hex | out $thumb`,
  },
  {
    id: "verify-soft",
    group: "Digest & MAC",
    title: "Soft signature verify",
    blurb:
      "Fail-soft verify (`-q`): emits bool `true` or `false` instead of throwing. Bind signature= (or the sig panel) at run time; prefer fail-loud for auth.",
    recipe: `genkey ed25519 | :public | export jwk | out $pub

input | utf8 | verify -q key=$pub | out $result`,
  },
  {
    id: "rsa-oaep-roundtrip",
    group: "Encrypt",
    title: "RSA-OAEP encrypt / decrypt",
    blurb:
      "Generate an RSA-OAEP key, encrypt a message with rsa-oaep key=$rk, then decrypt across chains.",
    recipe: `genkey rsa/2048 usage=encrypt | out $rk

input | utf8 | rsa-oaep key=$rk | encode hex | out $ct

in $ct | decode hex | rsa-oaep -d key=$rk | utf8 | out $plain`,
  },
  {
    id: "aes-gcm-roundtrip",
    group: "Encrypt",
    title: "AES-GCM encrypt / decrypt",
    blurb:
      "Generate an AES-256 key, encrypt with `aes-gcm key=$cek`, then decrypt across chains (preferred AEAD).",
    recipe: `genkey aes/256 | out $cek

input | utf8 | aes-gcm key=$cek | encode hex | out $ct

in $ct | decode hex | aes-gcm -d key=$cek | utf8 | out $plain`,
  },
  {
    id: "pbkdf2-aes-gcm",
    group: "Encrypt",
    title: "Passphrase → PBKDF2 → AES-GCM",
    blurb:
      "Derive an AES-GCM CEK from a generated passphrase (`pbkdf2 as=aes/256`), encrypt plaintext, then decrypt. Swap `passphrase` for `input | utf8` to use your own password.",
    recipe: `passphrase mode=char length=20 | pbkdf2 32 as=aes/256 | out $cek

input | utf8 | aes-gcm key=$cek | base64url | out $ct

in $ct | base64url.decode | aes-gcm -d key=$cek | utf8 | out $plain`,
  },
  {
    id: "hkdf-as-aes-gcm",
    group: "Encrypt",
    title: "HKDF → AES key → encrypt",
    blurb:
      "Derive an AES-256 key with `hkdf as=aes/256` (deriveKey), then AES-GCM encrypt with key=$cek.",
    recipe: `random 32 | hkdf 32 as=aes/256 | out $cek

input | utf8 | aes-gcm key=$cek | base64url | out $ct`,
  },
  {
    id: "aes-cbc-roundtrip",
    group: "Encrypt",
    title: "AES-CBC encrypt / decrypt",
    blurb:
      "Unauthenticated AES-CBC interop (prefer aes-gcm for new work). Round-trip with key=$cek.",
    recipe: `genkey aes/256 | out $cek

input | utf8 | aes-cbc key=$cek | encode hex | out $ct

in $ct | decode hex | aes-cbc -d key=$cek | utf8 | out $plain`,
  },
  {
    id: "aes-ctr-roundtrip",
    group: "Encrypt",
    title: "AES-CTR encrypt / decrypt",
    blurb:
      "Unauthenticated AES-CTR interop (prefer aes-gcm for new work). Round-trip with key=$cek.",
    recipe: `genkey aes/256 | out $cek

input | utf8 | aes-ctr key=$cek | encode hex | out $ct

in $ct | decode hex | aes-ctr -d key=$cek | utf8 | out $plain`,
  },
  // ── age. Not another AEAD row above: this is a whole file format with its
  // own key strings, and the arc keygen → recipient → encrypt → decrypt is the
  // thing worth showing.
  {
    id: "age-identity",
    group: "age",
    title: "An age identity and its recipient",
    blurb:
      "`age-keygen` in two chains — the `AGE-SECRET-KEY-1…` half stays masked until you reveal it, the `age1…` half is what you hand out, and the arrow between them only points one way.",
    recipe: `age.keygen | out $id

in $id | age.recipient | out $pub`,
  },
  {
    id: "age-encrypt",
    group: "age",
    pair: "age-file",
    title: "Encrypt to an age recipient",
    blurb:
      "Real `age-encryption.org/v1`, not a lookalike — `armor=true` gives the PEM-style block, and `age -d -i key.txt` on the command line reads exactly this back.",
    recipe: `age.keygen | out $id
in $id | age.recipient | out $pub

input | utf8 | age.encrypt to=$pub armor=true | out $ct`,
  },
  {
    id: "age-decrypt",
    group: "age",
    pair: "age-file",
    title: "Decrypt an age file",
    blurb:
      "`age -d -i key.txt doc.age`, one picker each — `key=` is slot-typed precisely so the identity never lands in recipe text, which Copy link and Export would carry off. The identity file is read `as=text` and the ciphertext as bytes, because `file.read` takes its type from the recipe and not from what the picker happened to return.",
    recipe: `file.read as=text | out $id

file.read | age.decrypt key=$id | file.save`,
  },
  {
    id: "hkdf-as-aes-kw-wrap",
    group: "Keys wrap / agree",
    title: "HKDF → AES-KW → wrap CEK",
    blurb:
      "Derive an AES-KW KEK (`as=aes-kw/256`), wrap a CEK with AES-KW, then unwrap (`export raw` before hex — unwrap tip is a live key).",
    recipe: `random 32 | hkdf 32 as=aes-kw/256 | out $kek

genkey aes/256 | out $cek

wrap key=$kek target=$cek | encode hex | out $wrapped

in $wrapped | decode hex | unwrap key=$kek | export raw | encode hex | out $cek-raw`,
  },
  {
    id: "wrap-aes-gcm",
    group: "Keys wrap / agree",
    title: "Wrap CEK with AES-GCM",
    blurb:
      "SubtleCrypto wrapKey under AES-GCM (IV||wrapped packing). Prefer AES-KW for new key-wrap work. Unwrap yields a live key tip — `export raw` before hex.",
    recipe: `genkey aes/256 | out $kek
genkey aes/256 | out $cek

wrap mode=aes-gcm key=$kek target=$cek | encode hex | out $wrapped

in $wrapped | decode hex | unwrap mode=aes-gcm key=$kek | export raw | encode hex | out $cek-raw`,
  },
  {
    id: "x25519-ecdh",
    group: "Keys wrap / agree",
    title: "X25519 ECDH → AES key",
    blurb:
      "Generate two X25519 keys, ECDH deriveBits, then HKDF to an AES-GCM CEK.",
    recipe: `genkey x25519 | out $local
genkey x25519 | out $peer

ecdh private=$local peer=$peer | hkdf 32 as=aes/256 | out $cek
in $cek | export jwk | out $cek-jwk`,
  },
  {
    id: "slip39-split",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "SSS + BLIP39 split a secret",
    blurb: "Generate 32 random bytes, Shamir-split 2-of-3, encode as BLIP39 mnemonics.",
    recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`,
  },
  {
    id: "recover-shares",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "Recover secret from BLIP39 shares",
    blurb: "Paste K-of-N mnemonics, decode to raw SSS, reconstruct the 16/32-byte master as Base64.",
    recipe: "shares | blip39.decode | sss.combine | base64 | out $secret",
  },
  {
    id: "ceremony-receipt",
    group: "Ceremony",
    pair: "ceremony-audit",
    title: "Sign a run receipt",
    blurb:
      "Split a secret, then mint a receipt of the run — recipe, timestamps, and digests of every output, never the outputs — and OpenPGP-sign it with a vault key.",
    recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

run.receipt | gpg.sign | out $receipt`,
  },
  {
    id: "ceremony-verify",
    group: "Ceremony",
    pair: "ceremony-audit",
    title: "Check a receipt against a re-run",
    blurb:
      "Paste a receipt (signed or plain) and compare it to the run happening now. Digests only — the check never reveals what was split.",
    recipe: "input | run.verify | out $ok",
  },
  {
    id: "out-mid-pipeline",
    group: "Split & recover",
    pair: "slip39-scalar",
    title: "Split P-256 scalar into shares",
    blurb:
      "Tee the public PEM, then SSS + BLIP39-split the 32-byte scalar (no envelope) — preferred for P-256 keys.",
    recipe: `genkey ec/p256 | tee
  - :public | export spki | pem | out $public
| export scalar | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`,
  },
  {
    id: "rebuild-p256",
    group: "Split & recover",
    pair: "slip39-scalar",
    title: "Rebuild P-256 key from scalar shares",
    blurb: "Decode BLIP39 shares of a P-256 private scalar, recover SSS, and re-import as WebCrypto.",
    recipe:
      "shares | blip39.decode | sss.combine | import scalar alg=ec/p256 | export pkcs8 | pem | out $private",
  },
  {
    id: "quorum-gpg",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "P-256 scalar + quorum-share to GPG",
    blurb:
      "Tee the public PEM, SSS-split the 32-byte scalar 2-of-3, BLIP39-encode, encrypt each share to a different recipient.",
    recipe: `genkey ec/p256 | tee
  - :public | export spki | pem | out $public
| export scalar | sss.split threshold=2 shares=3 | blip39 | foreach
  - gpg.encrypt`,
  },
  {
    id: "decrypt-rebuild-p256",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Decrypt GPG shares → rebuild key",
    blurb:
      "Decrypt OpenPGP-wrapped shares in-browser and/or paste mnemonics already decrypted externally (e.g. Kleopatra/gpg + YubiKey), then blip39.decode | sss.combine and rebuild the P-256 PEM from the scalar.",
    recipe:
      "gpg.decrypt | blip39.decode | sss.combine | import scalar alg=ec/p256 | export pkcs8 | pem | out $private",
  },
  {
    id: "pem-envelope-split",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Split PEM via OpenPGP envelope",
    blurb:
      "Emit PKCS#8 PEM ($pem), OpenPGP-encrypt under a random 32-byte master, then SSS + BLIP39-split the master. Keep envelope.asc with the shares.",
    recipe: `genkey ec/p256 | export pkcs8 | pem | out $pem | gpg.symencrypt mode=master | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share`,
  },
  {
    id: "pem-envelope-rebuild",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Recover PEM from envelope + shares",
    blurb:
      "Decode + recover shares to the hex master, then gpg.symdecrypt the bound envelope.asc (also works with gpg --decrypt).",
    recipe: "shares | blip39.decode | sss.combine | gpg.symdecrypt mode=master | utf8 | out $pem",
  },
  {
    id: "stun-reachable",
    group: "WebRTC",
    title: "Is STUN reachable?",
    blurb:
      "One-shot NAT check. Reports your server-reflexive address, or says STUN is blocked — the first thing to run when a peer connection will not form.",
    recipe: "stun.check | out $nat",
  },
  {
    id: "ice-gather",
    group: "WebRTC",
    title: "Gather ICE candidates",
    blurb:
      "Every route ICE would try, typed: host, peer-reflexive, server-reflexive, relay. A missing relay row means no TURN is configured — informational, not a failure.",
    recipe: `rtc.ice | out $ice

rtc.gather ice=$ice timeout=5000 | out $candidates`,
  },
  {
    id: "ice-custom-stun",
    group: "WebRTC",
    title: "Gather against your own STUN server",
    blurb:
      "Same gather, pointed at a STUN server you choose instead of the built-in defaults. Compare the reflexive address with the previous template's to see whether a server is lying to you.",
    recipe: `rtc.ice stun=stun:stun.l.google.com:19302 | out $ice

rtc.gather ice=$ice | out $candidates`,
  },
  {
    id: "ice-turn-relay",
    group: "WebRTC",
    title: "Add a TURN relay",
    blurb:
      "For the case both peers are behind symmetric NAT, where no direct route exists. Replace the URL and username, and paste the credential into Inputs — `credential=` takes a slot on purpose, so the secret never rides out in shared recipe text.",
    recipe: `input | out $turncred

rtc.ice turn=turns:turn.example.net:5349 username=USER credential=$turncred | out $ice

rtc.gather ice=$ice | out $candidates`,
  },
  {
    id: "rtc-dtls-identity",
    group: "WebRTC",
    title: "DTLS certificate fingerprint",
    blurb:
      "The fingerprint a peer actually sees. An offer carries `a=fingerprint:` and the DTLS handshake must match it — which is what lets a signed invite prove who is on the far end of the channel.",
    recipe: "rtc.certificate | out $dtls",
  },
  {
    id: "sdp-hand-carried",
    group: "WebRTC",
    title: "Connect two browsers by hand",
    blurb:
      "A real connection with no PGP audience, no room and no relay — you are the signalling channel. As written both ends live in this notebook, so it connects to itself and you can watch the whole handshake; in a real exchange the `peer.answer` cell runs in the *other* browser and you carry `$offer` there and `$answer` back. `peer.wait` is the step that tells you ICE succeeded. The channel is DTLS-encrypted, but nothing proves who is on the far end — that is what `quorum.offer` is for.",
    recipe: `peer.offer a | out $offer

in $offer | peer.answer b | out $answer

in $answer | peer.accept a | out $state

peer.wait a | out $link

"hello from a" | peer.send a

peer.recv b | out $heard`,
  },
  {
    id: "sdp-to-clipboard",
    group: "WebRTC",
    title: "Offer, copied out of band",
    blurb:
      "Signalling has to start somewhere outside WebRTC. The tee copies the offer to the clipboard while the pipeline keeps it, so you can paste it into chat and still hold it here. The connection stays open under the name `a` while you do.",
    recipe: `peer.offer a | tee
  - clipboard.write
| out $offer`,
  },
  {
    id: "rtc-live-diagnostics",
    group: "WebRTC",
    title: "Diagnose a live exchange",
    blurb:
      "Needs a running `quorum.offer` / `quorum.join` in another cell — these read the exchange that is already open. State first, then the candidate-pair matrix (why ICE chose the route it did), then quality. `rtc.restart` renegotiates in place without losing the room.",
    recipe: `rtc.state | out $state

rtc.check | out $pairs

rtc.quality | out $quality`,
  },
  {
    id: "gpg-decrypt",
    group: "OpenPGP",
    title: "OpenPGP decrypt",
    blurb:
      "Decrypt armored ciphertext from the Inputs panel (`gpg.decrypt`) — same recipe as the `#decrypt` messaging starter. Bind a private key or unlock My Keys when prompted.",
    recipe: "gpg.decrypt",
  },
  {
    id: "gpg-sign-verify",
    group: "OpenPGP",
    title: "OpenPGP sign / verify",
    blurb:
      "Cleartext-sign with a vault OpenPGP private key (`gpg.sign`), then verify (`gpg.verify`). Distinct from WebCrypto `sign`/`verify`.",
    recipe: `input | utf8 | gpg.sign | out $signed

in $signed | gpg.verify | out $ok`,
  },
  {
    id: "agent-sign-verify",
    group: "OpenPGP",
    title: "Vault sign / verify",
    blurb:
      "Unlock My Keys (`agent.unlock`), sign with `gpg.sign key=$me`, verify. Edit the fingerprint before running.",
    recipe: `agent.unlock AABBCCDDEEFF00112233445566778899AABBCCDD | out $me
input | gpg.sign key=$me | out $signed

in $signed | gpg.verify key=$me | out $ok`,
  },
  {
    id: "agent-gen-save",
    group: "OpenPGP",
    title: "Generate & save to My Keys",
    blurb:
      "`gpg.genkey` then `agent.save protection=device` into the browser vault.",
    recipe: `gpg.genkey email="you@example.com" | agent.save protection=device | out $priv`,
  },
  {
    id: "agent-sign-encrypt-to",
    group: "OpenPGP",
    title: "Vault sign + encrypt to $alices",
    blurb:
      "Unlock My Keys, search recipients, sign-then-encrypt with `to=$alices` and `key=$me`.",
    recipe: `hkp.search alice@example.org | hkp.filter | out $alices
agent.unlock AABBCCDDEEFF00112233445566778899AABBCCDD | out $me

input | gpg.encrypt to=$alices -s key=$me mode=combined`,
  },
  {
    id: "encrypt-to-email-one",
    group: "OpenPGP",
    title: "Encrypt to email (policy=one)",
    blurb:
      "Deferred email in `to=` — look up with the search glyph; `policy=one` requires exactly one approved key.",
    recipe: `input | gpg.encrypt to=alice@example.org policy=one`,
  },
  {
    id: "gpg-genkey",
    group: "OpenPGP",
    title: "Generate OpenPGP key",
    blurb:
      "Curve25519 keypair (`gpg.genkey`) — private on the pipeline, public as an artifact. Edit the email before running.",
    recipe: `gpg.genkey email="you@example.com" | out $priv`,
  },
  {
    id: "gpg-inspect",
    group: "OpenPGP",
    title: "Inspect OpenPGP armor",
    blurb: "Summarize armored ciphertext / signatures without decrypting.",
    recipe: `input | gpg.inspect format=packets | out $report`,
  },
  {
    id: "hkp-fetch-pub",
    group: "Directory",
    title: "Fetch public key",
    blurb: "Pull armored public key from the keyserver (`hkp.get`). Edit the fingerprint before running.",
    recipe: `hkp.get AABBCCDDEEFF00112233445566778899AABBCCDD | out $bob`,
  },
  {
    id: "hkp-search-encrypt",
    group: "Directory",
    title: "Search → encrypt (separate)",
    blurb:
      "Directory search → filter approved/encrypt → `gpg.encrypt to=$alices` (one ciphertext per recipient).",
    recipe: `hkp.search alice@example.org | hkp.filter | out $alices

input | gpg.encrypt to=$alices`,
  },
  {
    id: "hkp-encrypt-combined",
    group: "Directory",
    title: "Group encrypt (combined)",
    blurb: "One OpenPGP message with N PKESKs (`mode=combined`).",
    recipe: `hkp.search alice@example.org | hkp.filter | out $alices

input | gpg.encrypt to=$alices mode=combined`,
  },
  {
    id: "webauthn-prf-aes-gcm",
    group: "WebAuthn",
    title: "WebAuthn PRF → HKDF → AES-GCM",
    blurb:
      "Unlock vault passkey PRF IKM (`webauthn.prf`), HKDF to an AES-GCM CEK, encrypt plaintext, then decrypt. Main-thread ceremony.",
    recipe: `webauthn.prf | hkdf 32 as=aes/256 | out $cek

input | utf8 | aes-gcm key=$cek | base64url | out $ct

in $ct | base64url.decode | aes-gcm -d key=$cek | utf8 | out $plain`,
  },
  {
    id: "webauthn-attest-mds",
    group: "WebAuthn",
    title: "Attestation → MDS",
    blurb:
      "Paste a base64 or hex attestationObject in Inputs, parse fmt/AAGUID (`webauthn.attest`), then soft FIDO MDS lookup. Soft / informational — not a CAST gate.",
    recipe: `input | webauthn.attest | out $att

in $att | webauthn.mds | out $mds`,
  },
  // ── OTP. One template carries the whole enrolment arc; the other three are
  // the three questions people arrive with about it — what is in this URI
  // somebody sent me, why does my hardware token not use a clock, and what
  // happens if I change the parameters.
  {
    id: "otp-enrol",
    group: "OTP",
    title: "Enrol an authenticator app",
    blurb:
      "The whole arc in one notebook: 20 random bytes become a Base32 secret, the secret becomes an `otpauth://` URI, the URI becomes a QR your phone can scan — and the last cell checks a code against it, which is the step that proves the enrolment worked rather than merely looking pretty.",
    recipe: `random 20 | tee
  - base32 | out $secret
| otp.uri issuer="Basilisk" account=you@example.com | tee
  - qr
| out $uri

in $secret | otp.code | out $code

in $code | otp.verify secret=$uri window=1 | out $ok`,
  },
  {
    id: "otp-read-uri",
    group: "OTP",
    title: "Read a Key URI someone sent you",
    blurb:
      "Paste an `otpauth://` string (or scan it with `qr.scan`) and take it apart field by field — the URI carries the algorithm and the digit count as well as the secret, which is why a code computed with the defaults can be right in every respect and still wrong.",
    recipe: `input | tee
  - otp.parse issuer | out $issuer
| tee
  - otp.parse account | out $account
| tee
  - otp.parse algorithm | out $algorithm
| tee
  - otp.parse digits | out $digits
| otp.code | out $code`,
  },
  {
    id: "otp-hotp-counter",
    group: "OTP",
    title: "HOTP — a counter, not a clock",
    blurb:
      "What a hardware token does: each press advances a counter, so codes do not expire, they get spent. The verify here allows a look-ahead of three, because a token in a drawer gets pressed by accident — and it looks *only* ahead, since a server counter that stepped backwards would accept a code already used.",
    recipe: `random 20 | base32 | tee
  - out $secret
| otp.uri mode=hotp counter=0 issuer="Basilisk" account=token-7 | out $uri

in $secret | otp.code mode=hotp counter=0 | out $first

in $secret | otp.code mode=hotp counter=2 | out $third

in $third | otp.verify -q secret=$secret mode=hotp counter=0 window=3 | out $resync`,
  },
  {
    id: "otp-parameters",
    group: "OTP",
    title: "The parameters are part of the secret",
    blurb:
      "One secret, three sets of parameters, three different codes — none of which verify against each other. RFC 6238 allows SHA-256 and SHA-512 and 6-to-8 digits, so a URI that omits `algorithm=` is trusting both ends to guess the same default; this is why `otp.uri` always writes them down.",
    recipe: `random 32 | base32 | tee
  - out $secret
| otp.uri algorithm=sha512 digits=8 issuer="Long Corp" account=ops@example.com | out $uri

in $secret | otp.code | out $plain6

in $secret | otp.code algorithm=sha512 digits=8 | out $long8

in $secret | otp.code algorithm=sha256 digits=7 period=60 at=1111111111 | out $odd7`,
  },
  {
    id: "jwt-decode",
    group: "JOSE",
    title: "Decode a JWT (unverified)",
    blurb:
      "Paste a token in Inputs and read its header and claims — without checking the signature, and labelled as such. The safe first move on a token you were handed; nothing leaves the page. To trust what it says, run the verify companion instead.",
    recipe: "input | jose.decode | out $claims",
  },
  {
    // Sign and verify ship as *one* preset rather than a companion pair, the
    // way `aes-gcm-roundtrip` and `hmac-sign-verify` already do. A pair's
    // inverse has to stand on its own when loaded alone, which the SSS
    // inverses manage because `shares` opens a paste panel — but a JWS
    // verification needs a key, and there is no panel that conjures one. The
    // cells are still slot-wired (`$jwtkey`, `$token`), so `slot-graph` gates
    // them per cell exactly as it would across a pair.
    id: "jwt-sign-es256",
    group: "JOSE",
    title: "Sign & verify a JWT (ES256)",
    blurb:
      'Generate a P-256 signing key, sign JSON claims from Inputs into a compact JWS, then verify it back. Try `{"sub":"alice","exp":2000000000}` — the token tile shows the claims and a live expiry clock. Verification enforces `exp`; add `expiry=ignore` to inspect an old token anyway.',
    recipe: `genkey ec/p256 usage=sign | out $jwtkey

input | jose.sign key=$jwtkey alg=es256 | out $token

$token | jose.verify key=$jwtkey | out $claims`,
  },
  {
    id: "jwe-roundtrip",
    group: "JOSE",
    title: "Encrypt & decrypt a JWE",
    blurb:
      "Wrap a payload in a compact JWE under a generated AES-256 key (`dir` means that key *is* the content key, so there is no wrapped-CEK segment), then unseal it. The protected header is the AEAD's additional data — editing `alg` or `enc` in transit breaks the tag rather than changing how it decrypts.",
    recipe: `genkey aes/256 | out $cek

input | jose.encrypt key=$cek | out $jwe

$jwe | jose.decrypt key=$cek | out $plain`,
  },
  {
    id: "base32-id",
    group: "Encoding",
    title: "Base32 encode",
    blurb: "RFC 4648 Base32 (no padding) — same codec as Quorum room ids.",
    recipe: `random 10 | base32 | out $id`,
  },
];

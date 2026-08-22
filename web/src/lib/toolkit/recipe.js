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
 * with a compile warning; `@` at the head of a chain names the peer the cell
 * runs for (`@alice`, `@*`), and `out $a | publish` says that slot may leave
 * the machine that made it.
 */

import {
  ENTROPY_KINDS,
  SECRET_BEARING_OUTPUTS,
  getStep,
  listSteps,
  moduleAliasSpellings,
} from "./registry.js";
import {
  INPUT_PANELS,
  stepInputDeclarations,
  stepInputNeeds,
  stepInputRequirements,
} from "./input-needs.js";
import {
  canonicalSelectorMember,
  DEFAULT_OUT_SLOT,
  normalizePeerRef,
  parseRecipeSource,
  peerKeyIdError,
  peerLooksLikeKeyId,
  PEER_SIGIL,
  PEER_WILDCARD,
  PUBLISH_STEP,
  SELECT_PRIVATE,
  SELECT_PUBLIC,
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
// Defined next to the parser rather than here, because the parser needs it too:
// a cell carrying the retired `@alice publish` header is rewritten into
// `publish` steps as it is read, and that rewrite has to know which slots the
// cell writes. Re-exported so the twelve modules that import it from here keep
// their import.
export { outSlotLabels } from "./recipe-parse.js";

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
      `export which= is discouraged — prefer \`public\` / \`private\` before export (like openssl pkey -pubout)`
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
 * Fold one step's declared input needs into the recipe's list.
 *
 * This replaces `stepNeedsKeyPanel` / `stepNeedsGpgPrivatePanel` /
 * `stepNeedsGpgPassphrasePanel` — three `switch`es over op names that had to be
 * hand-updated whenever an op grew a key param, and where forgetting failed
 * *open*: the panel simply never appeared and the user saw a recipe that could
 * not be run with no indication what was missing. `stream.seal` and
 * `stream.open` sat in that gap. The answer now comes from the declarations, so
 * an op that grows an `unresolvedInput` param grows a panel without any list
 * being touched.
 * The incoming type goes in because a need can be answered by the pipe. `shares`
 * collects a mnemonic piped into it, so the tray it would otherwise open is not
 * a need at all in that spelling — and a cell held back for a panel nobody has
 * to fill is a cell that cannot be run for a reason that is not true.
 * @param {RecipeStep} step
 * @param {import("./input-needs.js").InputPanel[]} inputNeeds
 * @param {import("./types.js").RefinedType|null} [incoming]
 */
function collectInputNeeds(step, inputNeeds, incoming = null) {
  for (const need of stepInputNeeds(step, undefined, incoming)) {
    if (!inputNeeds.includes(need)) inputNeeds.push(need);
  }
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
 *
 * Exported because `plan.js` has to ask the same question — "which slots does
 * this cell consume" is the input to placement inference — and a second
 * spelling of it would be a second answer. `gpg.encrypt to=` is the reason
 * that matters: a bare `to=cek` names a slot and `to=alice@example.com` names
 * a recipient, and a reading that only looked for `$` would place a cell on
 * the wrong peer by missing the dependency entirely.
 * @param {import("./registry.js").ParamSpec} p
 * @param {string} stepName
 * @param {string} raw
 */
export function boundAsSlotRef(p, stepName, raw) {
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
  // A mnemonic is text and several of them are a bundle, so the accepted set
  // reads as two unrelated types unless it is named for what it carries.
  if (key === "bundle,text") return "share mnemonics";
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
 * @param {boolean} [deferUnknown]  see `validateRecipe` — a placed cell's
 *   unknown slot is the run's question, not this document's
 */
function validateStepSlotParams(
  step,
  slotTypes,
  slotTypesByIndex,
  errors,
  stepIndex,
  deferUnknown = false
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
      // A slot this document never writes, named from a cell that carries a
      // peer header: whether the machine that runs the cell holds the value
      // is that machine's session's business — a ceremony's deal binds slots
      // that its *recovery*, a separate agreement written later, reads. The
      // compiler holds no claim about a value another notebook bound, so it
      // neither refuses nor types it; the run's own slot resolver is the
      // check (`placement.js`'s `hasSlot` seam, and the engine's refusal
      // names the slot when it is really absent).
      if (deferUnknown) continue;
      errors.push({
        message: `${step.name} ${p.name}=${raw}: unknown slot (register earlier with out ${ref})`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }
    // A pooled value binding a param on a step that makes key material.
    //
    // The **param** half of the pooled-value rule (the pipe half is
    // `checkPooledPipelineValue`). Default-deny: a param says `acceptsPooled`
    // or it does not take one, so a new op that takes a public salt declares it
    // and a new op that does not is refused without anyone remembering.
    //
    // The population that may declare it is small and principled — inputs that
    // are public *by definition*: a salt (RFC 5869 §3.1, RFC 8018 §4.1), HKDF's
    // `info` context, an AEAD's `aad`. Those ride in the clear beside what they
    // protect, so a pooled one costs nothing — and a pooled salt is the case
    // `entropy.pool` exists to serve. Refusing it would forbid the feature's
    // headline use, and a control that refuses correct use is one people learn
    // to route around.
    if (loaded.pooled && !p.acceptsPooled) {
      const spec = getStep(step.name);
      // Resolved where it can be — `hkdf` declares `bytes` and `hkdf as=aes/256`
      // makes a key — and the declared output otherwise. The probe runs from
      // `none`, so a step that needs a pipeline input cannot resolve here and
      // falls back to what it says it produces, which for `unwrap` is `key`.
      const probe = spec ? resolveStepType(spec, { base: "none" }, step.params || {}) : null;
      const outgoing = probe?.ok ? probe.output : spec ? { base: spec.output } : null;
      // Only where it would become key material. A pooled value reaching an
      // ordinary param of an ordinary step is a public number in a public
      // place, which is what it is for.
      if (producesKeyMaterial(outgoing)) {
        errors.push({
          message:
            `${step.name} ${p.name}=${raw}: this binds a pooled value where the ` +
            "step makes key material. `entropy.pool` draws randomness the whole " +
            "room can recompute, so anything keyed from it is too. A salt, an " +
            "`info` context or an AEAD's `aad` may take one — those are public " +
            "by definition — and this param is not one of them.",
          start: step.start,
          end: step.end,
          stepIndex,
        });
        continue;
      }
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
 * Does this type name key material?
 *
 * `key` and `keypair` by base, and `master` by kind — a 16/32-byte master is key
 * material whatever its base says, which is why `random 32` carries that kind.
 * Read from the *resolved* output rather than the declared one, because `hkdf`
 * declares `bytes` and `hkdf as=aes/256` produces a key: the declaration is a
 * family, the resolution is the answer.
 *
 * @param {import("./types.js").RefinedType} type
 * @returns {boolean}
 */
function producesKeyMaterial(type) {
  return type?.base === "key" || type?.base === "keypair" || type?.kind === "master";
}

/**
 * A value the whole room can recompute must not become key material.
 *
 * `entropy.pool` draws randomness every participant helped choose and every
 * participant can derive again. That is what makes a distributed run agree, and
 * exactly what must never reach a key: a private key everyone can recompute is
 * not one.
 *
 * A whole-notebook refusal was meant to cover this and could not. It read each
 * op's declared `entropy` and refused ops that *draw* keying randomness —
 * `hkdf` and `pbkdf2` draw none, they *derive* — so
 * `entropy.pool | out $salt` followed by `in $salt | hkdf as=aes/256` compiled,
 * planned and ran, handing back a "secret" the whole room shared. (That check
 * has since been retired for three separate reasons; `manifest.js` records
 * them.) The type system is where this is visible, because the pooled flag
 * rides with the value through `out` and `in`.
 *
 * This is the **pipe** half: the pooled value is the thing being turned into a
 * key, and there is no exception to make — the secret being stretched cannot be
 * public. The param half is in `validateStepSlotParams`, where whether it is
 * allowed depends on which param.
 *
 * @param {RecipeStep} step
 * @param {import("./types.js").RefinedType} incoming
 * @param {import("./types.js").RefinedType} outgoing
 * @param {RecipeError[]} errors
 * @param {number} stepIndex
 */
function checkPooledPipelineValue(step, incoming, outgoing, errors, stepIndex) {
  if (!incoming?.pooled || !producesKeyMaterial(outgoing)) return;
  errors.push({
    message:
      `\`${step.name}\` would turn a pooled value into key material. ` +
      "`entropy.pool` draws randomness every participant in the room can " +
      "recompute, so a key derived from it is one they can all derive — which " +
      "is not a key. Pool a salt or a nonce and keep the secret local.",
    start: step.start,
    end: step.end,
    stepIndex,
  });
}

/**
 * One `-` line under a `tee`: a side pipeline over a clone of the stem, or over
 * a projection of it when the line opens with a selector.
 *
 * The selector is optional, and `member` is `""` when there is none — an
 * unlabelled branch (`- encode hex | out $a`) forks the whole value. Every
 * consumer that projects must check for the empty case rather than reach for
 * `:${member}`, which would ask for a member named nothing.
 * @typedef {object} TeeBranch
 * @property {string} member  e.g. private | public | key | value; "" = no selector
 * @property {string} [selector]  e.g. ":private"; absent = no selector
 * @property {RecipeStep[]} body
 * @property {number} [start]
 * @property {number} [end]
 */

/**
 * A param value is a scalar and nothing else. The recipe text has no syntax
 * for anything richer, and a step's output type is meant to be knowable before
 * it runs, so a param that could hold an object would put that out of reach.
 *
 * @typedef {Record<string, string|number|boolean>} RecipeParams
 */

/**
 * `start` and `end` are optional because not every step comes from text. A step
 * built by clicking an op in the toolkit has no span in a source that does not
 * exist yet, and this file already reads them that way — `stepSourceHasWhich`
 * guards on `== null` and `pushExportWhichPolicy` falls back to `?? 0`. The
 * typedef required them anyway, which described neither producer honestly.
 *
 * @typedef {object} RecipeStep
 * @property {string} name  canonical name
 * @property {RecipeParams} params
 * @property {number} [start]  char offset in source, when there is a source
 * @property {number} [end]
 * @property {RecipeStep[]} [body]  nested `-` list body for tee / foreach
 * @property {TeeBranch[]} [branches]  tee selector branches
 * @property {string} [foreachSelector]  e.g. ":items"
 * @property {"brace"|"indent"} [bodyForm]
 */

/**
 * One cell: a pipeline, and optionally the party it belongs to.
 *
 * The header fields are all optional and absent on every chain written without
 * one, so a recipe with no `@peer` produces exactly the AST it always did.
 * `recipeChains()` normalises bare step arrays into `{ steps }` and simply
 * carries no peer, which is why every existing consumer keeps working.
 *
 * The header is inert, and now says one thing: `peer` is the party a cell is
 * *written for*. Nothing in the engine reads it, and a header does not make a
 * cell run anywhere — it names a peer, it does not command one.
 *
 * **What leaves the machine is no longer a header field.** It was `publish` /
 * `publishSlots`, and it is now a `publish` step standing after the `out` whose
 * value travels — see `publishedSlots`, which is the one place that question is
 * answered from. A chain object therefore carries no disclosure fields at all.
 *
 * @typedef {object} RecipeChain
 * @property {RecipeStep[]} steps
 * @property {string} [peer]  canonical peer label (no sigil), or `*` for everyone
 * @property {number} [headerStart]  char offsets — a complaint about the header
 * @property {number} [headerEnd]    must anchor to it, not to step 0's span
 * @property {string[]} [comments]  the `#` lines written in this cell, `#` and
 *   surrounding space stripped, in the order they were written. See
 *   `serializeChain` for where they go back and why the cell is the unit.
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
 * @property {import("./input-needs.js").InputPanel[]} [inputNeeds]  runtime input panels
 *   required — derived from the step and param declarations by `input-needs.js`,
 *   never detected by op name. Panels, not types: `key` and `gpg` are two entries
 *   because they open two trays, not because they are two kinds of value.
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
 * ## When an argument may be written without quotes
 *
 * The three constants below mirror `recipe-parse.js`'s own reading paths. They
 * are an allowlist because the predicate they replaced was a denylist —
 * `/[\s|=]/` — and a denylist can only ever be patched one symptom at a time.
 * It had been, twice: once for space, pipe and `=`, once for the leading
 * character. It still had no comma in it, which is how every shared session
 * serialized to a notebook that could not parse: an audience is a comma-joined
 * list and must hold at least two fingerprints to be a room at all, so the
 * comma was not an edge case, it was every case.
 *
 * The rule is asked of the position as well as the value, because the parser
 * reads the two positions differently and the narrower one is not the one you
 * would guess.
 */

/** A `$slot` reference, which must stay bare or it stops being a reference. */
const SLOT_REF = /^\$[A-Za-z][A-Za-z0-9_-]*$/;

/**
 * A value `readNamedArgValue` reads back whole: its start set is narrower than
 * its continuation set, and both are mirrored here rather than approximated.
 */
const BARE_AFTER_EQUALS = /^[A-Za-z0-9_+./-][A-Za-z0-9_+./:@$-]*$/;

/**
 * A value the *positional* path reads back whole, which is narrower still.
 *
 * The argument loop does not call `readArgValue` for a letter-leading token. It
 * calls `readIdent` — `[A-Za-z][A-Za-z0-9_-]*`, **no dot** — and only re-scans
 * the whole token when the character that stopped it is one of `/ : @ + $`.
 * So `ec/p256` survives bare (the `/` triggers the re-scan) and `a.b` does not:
 * it reads as `a` and leaves `.b` where the grammar wants a new argument.
 *
 * A digit-leading positional of string type goes through `readNamedArgValue`,
 * hence the third branch.
 *
 * Writing the three paths out is the point. One combined character class read
 * off `readArgValue` looked right and was wrong for `.`, because that function
 * is not the one this path uses.
 */
const BARE_POSITIONAL =
  /^(?:[A-Za-z][A-Za-z0-9_-]*(?:[/:@+$][A-Za-z0-9_+./:@$-]*)?|[0-9][A-Za-z0-9_+./:@$-]*)$/;

/**
 * Whether `raw` can be written without quotes in this position and read back
 * as itself.
 *
 * @param {string} raw
 * @param {boolean} positional
 * @returns {boolean}
 */
function readsBackBare(raw, positional) {
  if (raw === "") return true;
  if (SLOT_REF.test(raw)) return true;
  return positional ? BARE_POSITIONAL.test(raw) : BARE_AFTER_EQUALS.test(raw);
}

/**
 * Quote a value the parser cannot read bare.
 *
 * Not `JSON.stringify`, which was the previous spelling and emits `\"` for an
 * embedded double quote — an escape `readString` does not implement. It scans
 * to the next matching quote character and stops, so a JSON-escaped value came
 * back truncated at the first `\` and left the rest as loose tokens: the same
 * silent corruption as the unquoted comma, one layer along.
 *
 * The grammar already offers the way out — `readString` honours whichever
 * quote opened the literal — so a value containing `"` is written in `'`.
 *
 * A value containing **both** quote characters still cannot be spelled: the
 * grammar has no escape, and giving it one is a change to the language rather
 * than to how this function spells things. No op ships such a default and
 * nothing in the notebook generates one; a recipe that needs it wants
 * `readString` to learn escapes first.
 *
 * @param {string} raw
 * @returns {string}
 */
function quoteArg(raw) {
  return raw.includes('"') && !raw.includes("'") ? `'${raw}'` : JSON.stringify(raw);
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
  // The verb's object: one positional token spelling a param *pair*
  // (`sss.split 2/3`), which the one-param-one-token loop below cannot say.
  // The params it covers are skipped — the object is their spelling, and
  // writing `threshold=` beside `2/3` would be the same number twice with two
  // chances to disagree. A null spell (a half-formed AST) falls through to the
  // ordinary emission, so nothing becomes unserializable by having the hook.
  const objectToken = spec?.object ? spec.object.spell(step.params || {}) : null;
  const objectCovers =
    objectToken != null
      ? new Set([spec.object.param, ...spec.object.covers])
      : null;
  if (objectToken != null) parts.push(objectToken);
  for (const p of spec?.params || []) {
    if (objectCovers?.has(p.name)) continue;
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
    // A value that survives compiling but not the round trip is not a cosmetic
    // defect: the chip flow re-serializes on every mutation and Copy link
    // serializes to build the URL, so editing any chip nearby — or sharing the
    // notebook — hands back text that will not parse. Two spellings have
    // already been shipped broken this way, `file.read accept=.pem` and every
    // shared session's comma-joined audience, so the question is asked of the
    // grammar rather than of a list of characters known to have caused it.
    const raw = String(v);
    const bare = readsBackBare(raw, Boolean(p.positional && parts.length === 1));
    const spelled = bare ? raw : quoteArg(raw);
    if (p.positional && parts.length === 1) {
      parts.push(spelled);
      continue;
    }
    parts.push(`${p.name}=${spelled}`);
  }
  return parts.join(" ");
}

/**
 * How one step is spelled, wherever it appears.
 *
 * The sugared spellings — a bare selector, a bracket index — were written out
 * twice, once in `serializePipeline` for branch bodies and once in
 * `serializeChainSteps` for the stem, and the two lists had to be kept in step
 * by hand. They were not: teaching `serializePipeline` that `:public` is now
 * written `public` left the stem still spelling it with a colon, so the same
 * cell serialized two ways depending on which side of a `tee` it was on.
 * @param {RecipeStep} step
 * @returns {string}
 */
function stepToken(step) {
  if (step.name === "select" && step.params?.selector) {
    // The keypair halves are verbs and are written as verbs. Every other
    // selector keeps its colon — see the note in `parseStage` for why the item
    // projections and the loop's own views are not steps.
    const sel = String(step.params.selector);
    return sel === `:${SELECT_PUBLIC}` || sel === `:${SELECT_PRIVATE}`
      ? sel.slice(1)
      : sel;
  }
  if (step.name === "at" && step.params?.selector != null) {
    const sel = String(step.params.selector);
    if (/^\d+(:\d+)?$/.test(sel)) return `[${sel}]`;
  }
  return serializeStep(step);
}

/**
 * Serialize one pipeline of steps (no block wrappers).
 * @param {RecipeStep[]} steps
 * @param {{ compact?: boolean }} [opts]
 * @returns {string}
 */
function serializePipeline(steps, opts = {}) {
  const join = opts.compact ? "|" : " | ";
  return steps.map(stepToken).join(join);
}

/**
 * Serialize one chain's steps to recipe text.
 *
 * ## Compact does not re-spell a nested body
 *
 * `compact` minifies the *stem* — `|` instead of ` | ` — and stops there. It
 * used to flatten a `tee` / `foreach` body onto one line whatever the author
 * wrote, joining the items with a space (`tee{ - digest sha-256 - encode hex
 * - out $a }`), and that text does not parse: a step's argument loop runs to
 * `|`, `}`, `#` or end of line, so it swallowed the `-` that was meant to
 * begin the next item. Every notebook with a body of more than one step
 * produced a "Copy link" that handed the recipient a parse error.
 *
 * The parser cannot simply stop at a hyphen — `aes-gcm -d` is a real argument
 * — so there is no one-line separator to switch to. That leaves two honest
 * fixes, and this is the second: **keep the body's own form.** A brace body
 * stays braces, an indent body stays indented, and only a brace body whose
 * items carry no selector folds onto one line, where `|` is a separator the
 * argument loop already stops at.
 *
 * Declining to re-spell buys more than a parse. `serializeRecipe` is what a
 * manifest, a receipt, an attestation and a handoff offer all digest a cell
 * with, so a body that came back from a link wearing braces it was not written
 * with digests differently from the same cell pasted as text — two peers, one
 * notebook, `cell-mismatch`. The cost is length, and it is affordable: the
 * longest shipped preset is 316 characters of `#r=` against `TOOLKIT_HASH_MAX_LEN`
 * (6000) and the 2953-byte QR ceiling, and no compact form is longer than the
 * pretty text it came from. `recipe-roundtrip.test.js` holds both.
 *
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
   *
   * **One `-` line per branch, and one for the body.** A body line is a whole
   * pipeline, so several steps are written along one line with `|` —
   * `- export spki | pem | out $public`, never three lines. Spreading them out
   * is read back as three branches, which is what `parseBranchLineInto` now
   * makes of three lines, and three branches over a keypair are not the export
   * chain that was written.
   *
   * `serializePipeline` already spells a `select` step as its bare selector, so
   * a `foreach :items` body keeps its `- :value | out $share` shape without
   * this function grouping steps by hand.
   * @returns {string[]}
   */
  function bodyLines(step) {
    /** @type {string[]} */
    const lines = [];
    const body = step.body || [];
    if (body.length) lines.push(`- ${serializePipeline(body, opts)}`);
    for (const br of step.branches || []) {
      const sel = br.selector || (br.member ? `:${br.member}` : "");
      const pipe = serializePipeline(br.body || [], opts);
      lines.push(sel ? `- ${sel}${pipeJoin}${pipe}` : `- ${pipe}`);
    }
    return lines;
  }

  for (const step of steps) {
    const hasListBody =
      (step.name === "tee" || step.name === "foreach" || step.name === "scatter") &&
      Array.isArray(step.body) &&
      step.body.length > 0;
    const hasBranches =
      step.name === "tee" &&
      Array.isArray(step.branches) &&
      step.branches.length > 0;
    const isBlock = hasListBody || hasBranches;

    let head = stepToken(step);
    if (step.name === "foreach" && step.foreachSelector) {
      head = `foreach ${step.foreachSelector}`;
    } else if (step.name === "in" && step.params?.ref) {
      const ref = String(step.params.ref);
      // Prefer bare `$label`; keep `in N` for 1-based indexes.
      head = /^\d+$/.test(ref)
        ? `in ${ref}`
        : ref.startsWith(SLOT_SIGIL)
          ? ref
          : `${SLOT_SIGIL}${ref}`;
    }

    if (!isBlock) {
      pushStemPiece(head);
      continue;
    }

    if (chunks.length) chunks.push(pipeJoin);
    const lines = bodyLines(step);
    const useBrace = step.bodyForm === "brace";
    if (compact && useBrace && lines.length === 1) {
      // One line stays one line: `tee{ - :public|export spki }` is the same
      // single branch, and `}` is a terminator the argument loop already stops
      // at. Folding *two* lines together with `|` would be the concatenation
      // bug spelled backwards — two branches arriving at the far end of a link
      // as one — so the fold is gated on there being nothing to merge.
      chunks.push(`${head}{ ${lines[0]} }`);
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
 * Which of a cell's `out` artifacts leave the machine, in source order.
 *
 * The one answer to *what does this cell disclose*, asked by the planner, by
 * the handoff and by the notebook. It is read off the steps, because that is
 * where the claim is now written: `out $a | publish` publishes `$a`, and a cell
 * with no `publish` step publishes nothing.
 *
 * **A `publish` binds to the `out` immediately before it, and to nothing else.**
 * That is what makes the answer a lookup rather than a reconstruction. The
 * header form it replaces had to work backwards from a list of names to the
 * `out`s a cell might write at any depth, and got it wrong in both directions —
 * a name nothing answered to read as a licence, and an empty list meant *all of
 * them*, so the menu could not offer "publish none" without it silently meaning
 * "publish everything". Neither state is reachable now: the step sits on the
 * value, and the value is whichever one `out` just named.
 *
 * Deduplicated because two `publish` steps after two `out $a`s are the same
 * claim twice, not two claims.
 * @param {RecipeChain} chain
 * @returns {string[]}
 */
export function publishedSlots(chain) {
  /** @type {string[]} */
  const labels = [];
  const walk = (list) => {
    const steps = list || [];
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      if (step?.name === PUBLISH_STEP) {
        const prev = steps[i - 1];
        if (prev?.name === "out") {
          const label = slotLabelKey(String(prev.params?.name || ""));
          if (label && !labels.includes(label)) labels.push(label);
        }
      }
      walk(step?.body || []);
      for (const br of step?.branches || []) walk(br?.body || []);
    }
  };
  walk(chain?.steps || []);
  return labels;
}

/**
 * Rewrite a cell's steps so that exactly `labels` are published.
 *
 * The menu's edit, written once here rather than in the component, for the
 * reason `CellAssign` exists at all: the source view and the menu must make the
 * *same* edit or the two views of a notebook disagree about what leaves. A
 * `publish` is added after every `out` whose label is named and removed from
 * after every `out` whose label is not, at any depth — a `tee` branch's `out`
 * and a `foreach` body's `out` are this cell's output, so they are this cell's
 * disclosure too.
 *
 * A `publish` standing after something that is not an `out` is left alone. It
 * does not compile, and silently deleting the step a reader typed would answer
 * their mistake by hiding it.
 *
 * @param {RecipeStep[]} steps
 * @param {string[]} labels  slot labels, no sigil
 * @returns {RecipeStep[]}  a new list; the steps themselves are shared
 */
export function setPublishedSlots(steps, labels) {
  const want = new Set((labels || []).map((l) => slotLabelKey(String(l || ""))));
  const walk = (list) => {
    /** @type {RecipeStep[]} */
    const next = [];
    const src = list || [];
    for (let i = 0; i < src.length; i++) {
      const step = src[i];
      if (step?.name === PUBLISH_STEP && src[i - 1]?.name === "out") {
        // Re-decided below, from the `out` it belongs to.
        continue;
      }
      const rebuilt =
        step?.body || step?.branches
          ? {
              ...step,
              ...(step.body ? { body: walk(step.body) } : {}),
              ...(step.branches
                ? { branches: step.branches.map((br) => ({ ...br, body: walk(br.body) })) }
                : {}),
            }
          : step;
      next.push(rebuilt);
      if (step?.name === "out") {
        const label = slotLabelKey(String(step.params?.name || ""));
        if (label && want.has(label)) next.push({ name: PUBLISH_STEP, params: {} });
      }
    }
    return next;
  };
  return walk(steps);
}

/**
 * The header text for a chain, or "" when it has no peer to hang one on.
 *
 * Exported because a refusal that quotes a cell's header has to quote the one
 * the author wrote, and there is now exactly one thing a header can say. It
 * used to have to reassemble `publish=$a,$b` from two fields to avoid telling a
 * reader their cell was marked something it is not; the modifier is a step now,
 * so the reassembly is gone and the header is the peer.
 *
 * @param {RecipeChain} chain
 * @returns {string}
 */
export function chainHeaderText(chain) {
  const peer = chain?.peer == null ? "" : String(chain.peer);
  if (!peer.length) return "";
  return `${PEER_SIGIL}${peer}`;
}

/**
 * Serialize one chain, comments and header included.
 *
 * The header is emitted only when the chain has steps to hang it on: a
 * header-only cell does not parse, so writing one would be a round trip that
 * loses. Newline-joined in pretty form, space-joined in compact — where the
 * `~` chain separator already marks where a header may begin.
 *
 * ## A comment attaches to the cell, above everything else in it
 *
 * The cell is the unit every other part of this system already uses: it is
 * what a peer is assigned, what an offer carries, what a manifest row digests,
 * what the run log records and what the notebook draws as one box. There is no
 * smaller unit a comment could attach to and survive, because there is no line
 * model *inside* a cell to attach it to — `serializeChainSteps` collapses a
 * multi-line stem into one `|`-joined line, so a comment written between two
 * stem lines has no line left to sit above.
 *
 * So every comment in a cell — a full line, or one trailing a step line —
 * comes back as full lines at the top of that cell, in the order it was
 * written. A trailing comment is *promoted*, not dropped: `random 32 | out $a
 * # keep` serializes as two lines. That is the one visible move this makes,
 * and it buys the property that matters: parse → serialize is idempotent for
 * every body form, brace and indent alike, with no second grammar for where a
 * comment may sit.
 *
 * They go above the header rather than below it because the header is the
 * cell's first token and `@mara` reads as the subject of the sentence the
 * comment is introducing. Below it, a comment would separate the header
 * from the pipeline it heads.
 *
 * Comments are emitted in the **compact** form too. Dropping them there would
 * be cheaper in URL characters and wrong: `hashForRecipe` is how a notebook
 * travels in a link, and a cell that came back from a link without its
 * comments digests differently from the cell that was shared — the
 * `cell-mismatch` two peers refuse each other with. The newline a comment
 * forces is already handled: `serializeRecipe` switches the compact chain
 * separator to a blank line whenever any cell needs a second line, which is
 * exactly what `expandShareRecipe` reads back.
 *
 * @param {RecipeChain} chain
 * @param {{ compact?: boolean }} [opts]
 * @returns {string}
 */
function serializeChain(chain, opts = {}) {
  const body = serializeChainSteps(chain?.steps || [], opts);
  if (!body.length) return body;
  const head = chainHeaderText(chain);
  const lines = (chain?.comments || []).map((c) => {
    const text = String(c ?? "").trim();
    return text ? `# ${text}` : "#";
  });
  if (head.length) {
    lines.push(opts.compact === true ? `${head} ${body}` : `${head}\n${body}`);
  } else {
    lines.push(body);
  }
  return lines.join("\n");
}

/**
 * Serialize an AST (or steps / chains) back to recipe text.
 * Chains are joined with a blank line (or `~` when `compact`).
 * Canonical names; `$` slot sugar, `@` peer header.
 *
 * **The compact separator depends on whether any cell needed a second line.**
 * `expandShareRecipe` tells a compact payload from a legacy pretty one by
 * asking whether it contains a raw newline: no newline and a `~` means
 * `~`-separated cells, anything else is already blank-line separated. A cell
 * whose block body has more than one `-` line cannot be written on one line at
 * all (see the fold in `serializeChainSteps`, which merging two branches into
 * one is the price of), so emitting `~` alongside those newlines would hand
 * `expandShareRecipe` a payload it reads as one cell — a multi-cell notebook
 * silently collapsing into one on the far end of a link.
 *
 * Deciding it here keeps that invariant in one place and leaves
 * `expandShareRecipe` — which also reads links written before any of this —
 * untouched. The cost is `\n\n` instead of `~` per cell boundary, and only for
 * the notebooks that already gave up the one-line form.
 * @param {RecipeAst|RecipeStep[]|RecipeChain[]} astOrSteps
 * @param {{ compact?: boolean }} [opts]
 * @returns {string}
 */
export function serializeRecipe(astOrSteps, opts = {}) {
  const compact = opts.compact === true;
  const chains = recipeChains(astOrSteps);
  const parts = chains.map((c) => serializeChain(c, opts)).filter((t) => t.length);
  const sep = compact && !parts.some((t) => t.includes("\n")) ? "~" : "\n\n";
  return parts.join(sep);
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
 *   inScatter?: boolean,
 *   collectionLength?: number,
 *   source?: string,
 *   placed?: boolean,
 * }} ctx  `placed` — this body's cell carries a `@peer` header, so an unknown
 *   slot in it is deferred to the run (see `validateRecipe`'s argument)
 * @returns {{
 *   final: import("./types.js").RefinedType,
 *   encryptInBody: boolean,
 *   inputNeeds: import("./input-needs.js").InputPanel[],
 * }}
 */
function validateBodySteps(body, startType, ctx) {
  /** @type {import("./types.js").RefinedType} */
  let current = startType;
  let encryptInBody = false;
  /**
   * What a `send` in this body left behind, tracked because **the tip is what
   * stays**. After `send to=each` exactly one pair's payload remains — the
   * pair whose member is this machine, named once by the deduped canonical
   * audience — so an `out` after it binds a single value, not a per-pair
   * bundle. After `send to=<fingerprint>` every payload left, so a later
   * step has nothing to read and refuses here, where the author is.
   */
  let sentEach = false;
  let sentConstant = false;
  /** @type {import("./input-needs.js").InputPanel[]} */
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
      step.name === "scatter" ||
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
    // The pair verbs read both halves of the pair a scatter body is holding,
    // so outside one there is nothing for them to read — a tee or foreach
    // body reaches this refusal too, which is what keeps `seal` from riding
    // in on `foreach :items` (the item there is index/share, not a member).
    if ((step.name === "seal" || step.name === "send") && !ctx.inScatter) {
      ctx.errors.push({
        message: noPairHere(step.name),
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
      continue;
    }
    if (step.name === "seal" || step.name === "send") {
      const bad = pairRecipientError(step);
      if (bad) {
        ctx.errors.push({
          message: bad,
          start: step.start,
          end: step.end,
          stepIndex: ctx.stepIndex,
        });
        continue;
      }
    }
    if (sentConstant) {
      ctx.errors.push({
        message:
          `Nothing follows \`send to=<fingerprint>\` — every pair's payload ` +
          `left this machine for that one peer, so there is nothing for ` +
          `"${step.name}" to read. \`send to=each\` keeps this machine's own ` +
          `share, and a step after it reads that.`,
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
      continue;
    }
    {
      const reserved = reservedRecipientError(step, !!ctx.inScatter);
      if (reserved) {
        ctx.errors.push({
          message: reserved,
          start: step.start,
          end: step.end,
          stepIndex: ctx.stepIndex,
        });
        continue;
      }
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
        ctx.stepIndex,
        !!ctx.placed
      );
    }
    collectInputNeeds(step, inputNeeds, current);
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
      // The same silence `validateRecipe` keeps over a deferred tip: a value
      // another notebook bound is not one this document may make claims
      // about, in refusals or in types.
      if (current.deferred) continue;
      ctx.errors.push({
        message: resolved.error,
        start: step.start,
        end: step.end,
        stepIndex: ctx.stepIndex,
      });
      continue;
    }
    checkPooledPipelineValue(step, current, resolved.output, ctx.errors, ctx.stepIndex);
    current = resolved.output;
    if (step.name === "send") {
      const to = String(step.params?.to ?? "each").trim().toLowerCase();
      if (to === "each") sentEach = true;
      else sentConstant = true;
    }
    if (step.name === "out" && slotTypes && slotTypesByIndex) {
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
        } else if (ctx.inForeach && !sentEach) {
          // A foreach body's `out $x` runs once per iteration and binds `$x`
          // once, to a *bundle* of every iteration's value — the runtime's
          // exact shape, recorded here so `in $x` / `with=$x` type-check
          // against what the loop actually leaves behind. The length rides
          // along when the split's share count is in the text, same rule as
          // `at`. This used to be exempt from the slot walk entirely, which
          // left the label claimed by nothing and `in $x` refusing a slot the
          // notebook visibly writes.
          //
          // After `send to=each` the bundle rule does not apply: that
          // spelling retains exactly one pair's payload — this machine's own
          // share — so the slot holds the value itself, typed below by the
          // ordinary rule. The engine's `singleOuts` is the same decision at
          // run time, read off the same syntax.
          slotTypes.set(
            key,
            typeOf(
              "bundle",
              ctx.collectionLength != null ? { length: ctx.collectionLength } : {}
            )
          );
        } else {
          slotTypes.set(key, { ...current });
        }
      }
      slotTypesByIndex.push({ ...current });
    }
    // `seal` is a sink whose output the next step consumes (the armored
    // message pipes on), so the mnemonic-continues fiction below — which
    // exists for `gpg.encrypt mode=separate` bodies — must not overwrite it.
    if (ctx.inForeach && !ctx.inScatter && spec.kind === "sink") {
      current = typeOf("text", { kind: "mnemonic" });
    }
  }

  return { final: current, encryptInBody, inputNeeds };
}

/**
 * Check one chain's `@peer` header.
 *
 * The parser already refused everything that is not a peer, so what is left
 * here is the question the grammar cannot answer: whether a well-formed peer
 * is a thing a room could ever bind. `peerLooksLikeKeyId` is the whole of it,
 * and it is a security rule rather than a style one — 8, 16 and 32 hex
 * characters are all *suffixes* of a fingerprint, so each names more than one
 * key. A roster keyed by whole fingerprints cannot bind one, and a reader shown
 * one has compared part of a value believing they compared all of it.
 *
 * A **whole** fingerprint is no longer refused here and is the spelling the
 * product writes: see `peerIsFingerprint` for the trade that was made and
 * `fingerprintPeersInText` for where the disclosure it costs is now stated out
 * loud instead.
 *
 * Anchored to `headerStart`/`headerEnd` and to the chain's first step index,
 * so the complaint lands on the header in Source view and on the right cell in
 * the notebook.
 * @param {RecipeChain} chain
 * @param {number} firstStepIndex  global index of this chain's first step
 * @param {RecipeError[]} errors
 */
function validateChainHeader(chain, firstStepIndex, errors) {
  const steps = chain?.steps || [];
  const anchor = {
    start: chain?.headerStart ?? steps[0]?.start,
    end: chain?.headerEnd ?? steps[0]?.end,
    stepIndex: firstStepIndex,
  };
  const peer = chain?.peer;
  if (peer == null || peer === "") {
    // `publish` is a claim about a boundary, and an unassigned cell has not
    // drawn one. Anchored to the `publish` step rather than to the missing
    // header, because that is the thing the reader wrote.
    const site = firstPublishStep(steps);
    if (site) {
      errors.push({
        message:
          `\`${PUBLISH_STEP}\` sends a value to the room, so it needs a peer ` +
          `to send it from — give this cell a header (\`${PEER_SIGIL}alice\`), ` +
          `or drop \`${PUBLISH_STEP}\``,
        start: site.start,
        end: site.end,
        stepIndex: anchor.stepIndex,
      });
    }
    return;
  }
  const norm = normalizePeerRef(String(peer));
  if (!norm.ok) {
    errors.push({ message: norm.error, ...anchor });
    return;
  }
  if (peerLooksLikeKeyId(norm.peer)) {
    errors.push({ message: peerKeyIdError(norm.peer), ...anchor });
    return;
  }

  // `@*` parses, and it plans: `planRun` places a rendezvous cell on everyone
  // and records the barrier as a wait. Nothing *performs* it — no peer
  // announces arrival, and no peer waits for one.
  //
  // Refused here rather than in the planner, because the planner is not on
  // every path. `useNotebook` builds a placement only when a plan is `ok` and
  // `placed`, so a refused plan is simply dropped and the notebook runs
  // ungated — a plan-level refusal would have been routed around by the one
  // caller that matters. A compile error is the gate every run passes: the
  // editor shows it, Run is blocked, and a recipe arriving from a peer is
  // refused on the way in too.
  //
  // The cost of getting this wrong is why it is a refusal and not a warning: a
  // cell that plans as a rendezvous and then runs has this peer entering alone
  // while believing the room entered with it — exactly what `buildOfferFor`
  // refuses a rendezvous handoff to avoid, reached by pressing Run instead of
  // by handing a cell over.
  if (norm.peer === PEER_WILDCARD) {
    errors.push({
      message:
        `\`${PEER_SIGIL}${PEER_WILDCARD}\` is a rendezvous — every participant ` +
        "enters this cell together — and this build can describe one but not " +
        "perform one, so running it would have you enter alone while believing " +
        "the room entered with you. Write one cell per participant with " +
        `\`${PEER_SIGIL}\`their label, or drop the header and let everyone run ` +
        "it as an ordinary mirrored cell. Neither claims a barrier.",
      ...anchor,
    });
    return;
  }
}

/**
 * The first `publish` step in a cell, at any depth, or null.
 *
 * Only the first: every complaint this file makes about `publish` is about the
 * cell, so a cell publishing three things would otherwise say the same sentence
 * three times and anchor it three places.
 * @param {RecipeStep[]} steps
 * @returns {RecipeStep|null}
 */
function firstPublishStep(steps) {
  for (const step of steps || []) {
    if (step?.name === PUBLISH_STEP) return step;
    const nested =
      firstPublishStep(step?.body || []) ||
      (step?.branches || []).reduce(
        (found, br) => found || firstPublishStep(br?.body || []),
        null
      );
    if (nested) return nested;
  }
  return null;
}

/**
 * `publish` sends the value the `out` before it named — so there has to be one.
 *
 * The binding is positional and that is the whole of it: `out $a | publish`
 * publishes `$a`. Anything else standing before it is refused rather than
 * quietly ignored, because "publish the current value" is not a thing this
 * language can mean — a value that no `out` named has no name to travel under,
 * and `planRun` addresses a handoff by slot label.
 *
 * `encode hex | publish` is the case worth stating: the value is real, and it
 * is nameless. Refusing it here, at compile, is the difference between a reader
 * learning the rule while writing the cell and learning it when the room does
 * not receive what they meant to send.
 *
 * Walks bodies and branches, because a `tee` branch's `out` is this cell's
 * output and so is its disclosure.
 * @param {RecipeStep[]} steps
 * @param {number} stepIndex  the cell's first step, for the editor's anchor
 * @param {RecipeError[]} errors
 */
function validatePublishSteps(steps, stepIndex, errors) {
  const walk = (list) => {
    const src = list || [];
    for (let i = 0; i < src.length; i++) {
      const step = src[i];
      if (step?.name === PUBLISH_STEP) {
        const prev = src[i - 1];
        if (prev?.name !== "out") {
          errors.push({
            message:
              `\`${PUBLISH_STEP}\` sends the value the \`out\` before it named, ` +
              `and ${
                prev
                  ? `\`${prev.name}\` does not name one`
                  : "nothing comes before it here"
              } — write \`out ${SLOT_SIGIL}name | ${PUBLISH_STEP}\``,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        }
      }
      walk(step?.body || []);
      for (const br of step?.branches || []) walk(br?.body || []);
    }
  };
  walk(steps);
}

/**
 * Why a threshold of 1 is refused: one share reconstructs, so the split is a
 * copy wearing a quorum's name. One constant with two consumers — the
 * compiler's `sss.split` check below and `ceremonyIssues`' stepper check —
 * because both are refusing the same arithmetic fact and two spellings of one
 * refusal drift. It says "share" rather than the Sheet's old "card" because at
 * the moment either consumer fires nothing has been printed yet; the share is
 * the thing that exists.
 *
 * Lives here rather than in `ceremony.js` because the import must point this
 * way: `ceremony.js` → `fragment.js` → `recipe.js`, so recipe.js importing
 * ceremony.js would close the cycle.
 */
export const COPY_NOT_A_QUORUM =
  "A threshold of 1 means any single share recovers the secret on its own — that is a copy, not a quorum.";

/**
 * A pair verb met where no pair exists.
 *
 * The sentence is `LANGUAGE.md`'s own, and it names the state rather than a
 * remedy that cannot be performed: the pair is the input, and only a
 * `scatter` body holds one.
 * @param {string} name  `seal` or `send`
 * @returns {string}
 */
function noPairHere(name) {
  return (
    `\`${name} to=each\` reads the pair a scatter hands it, and there is no ` +
    `scatter here — the pair verbs live in a \`scatter to=room\` body ` +
    `(\`- ${name} to=each | …\`).`
  );
}

/**
 * `room` and `each` are reserved words in recipient position, naming
 * derivations — never people — so a step whose `to=` is a *choice* must not
 * read one as an address. Without this rule `gpg.encrypt to=each` would ride
 * to run time and fail as an email lookup for a person called "each", which
 * is a state nobody is in.
 *
 * Checked case-insensitively so `to=Each` is told about the reserved word
 * rather than being read as a fingerprint it is not.
 *
 * @param {RecipeStep} step  a `quorum.send` or `gpg.encrypt` step
 * @param {boolean} inScatter  whether a scatter body encloses it
 * @returns {string|null}
 */
function reservedRecipientError(step, inScatter) {
  if (step.name !== "quorum.send" && step.name !== "gpg.encrypt") return null;
  const raw = String(step.params?.to ?? "").trim();
  const word = raw.toLowerCase();
  const pairVerb = step.name === "gpg.encrypt" ? "seal" : "send";
  if (word === "each") {
    // Outside a body the remedy names the pair *verb*, not this step —
    // `- quorum.send to=each` would itself refuse, and a refusal must never
    // name a remedy that cannot be performed.
    if (!inScatter) return noPairHere(pairVerb);
    return (
      `\`${step.name} to=each\`: \`each\` is this pair's member, and the verb ` +
      `that reads the pair is \`${pairVerb}\` — write \`- ${pairVerb} to=each\`` +
      (pairVerb === "seal"
        ? " (it is gpg.encrypt mode=combined addressed by the pair)."
        : " (it is quorum.send addressed by the pair).")
    );
  }
  if (word === "room") {
    return (
      `\`${step.name} to=room\`: \`room\` is a reserved word in recipient ` +
      `position — it names the audience derivation \`scatter to=room\` reads. ` +
      (step.name === "quorum.send"
        ? "`quorum.send to=` takes one peer's fingerprint, and an empty `to=` already broadcasts to every verified peer."
        : "`gpg.encrypt to=` takes a `$slot`, `fpr:…`, or an email.")
    );
  }
  return null;
}

/**
 * The `to=` a pair verb carries: `each`, or one whole fingerprint.
 *
 * Anything between is refused here, at compile, with the two rules this
 * module already enforces elsewhere: a reserved word is spelled exactly, and
 * a fingerprint is never partial — a suffix names more than one key.
 * @param {RecipeStep} step  a `seal` or `send` step inside a scatter body
 * @returns {string|null}
 */
function pairRecipientError(step) {
  const raw = String(step.params?.to ?? "each").trim();
  if (raw === "each") return null;
  const word = raw.toLowerCase();
  if (word === "each") {
    return `\`${step.name} to=${raw}\`: the reserved word is written \`each\`.`;
  }
  if (word === "room") {
    return (
      `\`${step.name} to=room\`: \`room\` is the whole audience, which is ` +
      `\`scatter to=\`'s recipient — a pair verb addresses this pair's ` +
      `member. Write \`to=each\`, or one whole fingerprint to address every ` +
      `share to that key.`
    );
  }
  if (/^[0-9A-Fa-f]+$/.test(raw)) {
    if (raw.length === 40 || raw.length === 64) return null;
    return (
      `\`${step.name} to=${raw}\` is ${raw.length} hex characters, which is ` +
      `part of a key rather than a key — a suffix of a fingerprint names ` +
      `more than one key. Write the whole fingerprint (40 characters for ` +
      `v4, 64 for v6), or \`each\` for this pair's member.`
    );
  }
  return (
    `\`${step.name} to=\` takes \`each\` (this pair's member) or one whole ` +
    `fingerprint — not "${raw}".`
  );
}

/**
 * The Inputs panels a step consumes *whole*, and what to call each one.
 *
 * A panel here is a document, not a setting: whatever is in it is the one
 * message, the one paste, the one set of rows this run has, and a second step
 * reading it does not get a second one — it gets the same one again. That is
 * the property the rule below enforces, and it is why the list is these three
 * and not all seven of `INPUT_PANELS`. The key trays are the counter-example
 * and the reason a blanket rule would be wrong: two steps both reaching for
 * Inputs → OpenPGP *for a key* both want the same key, and refusing the second
 * would be a rule against using one's own key twice. `gpgPass` is the same
 * story one level down.
 *
 * Membership is asked of the *declarations*, never of a step name — see the
 * `param === null` filter at the reader below.
 * @type {Readonly<Record<string, string>>}
 */
const SOLE_INPUT_PANELS = Object.freeze({
  text: "Inputs → text",
  shares: "Inputs → shares",
  gpg: "Inputs → OpenPGP",
});

/**
 * The other way to get the value, per panel — a move the author can make in
 * the text in front of them, never "use a different machine".
 * @type {Readonly<Record<string, string>>}
 */
const SOLE_INPUT_REMEDIES = Object.freeze({
  text: "Read the first cell's value here instead — `out $x` there, `$x` here — or give the two cells different `@` headers so each reads its own machine's panel.",
  shares:
    "Bring this cell's rows in some other way — `quorum.recv … | shares`, or `shares with=$slot` — or give the two cells different `@` headers so each reads its own machine's tray.",
  gpg: "Pipe this cell's message in instead (`quorum.recv from=… | gpg.decrypt`), or give the two cells different `@` headers so each reads its own machine's panel.",
});

/**
 * Where a cell runs, as far as the text alone can say: its `@peer` header.
 *
 * `""` is the answer for a headerless cell and for `@*`, and it does not mean
 * *unknown* — it means **every machine**. Whoever opens a headerless notebook
 * runs its unheaded cells, and every participant enters a `@*` cell together,
 * so both stand on the same ground as every placed cell in the document. One
 * bucket for the two is what lets the collision test below be a comparison
 * instead of a pile of special cases.
 *
 * A fingerprint header arrives here already upper-cased by `normalizePeerRef`,
 * so `@aabb…` and `@AABB…` are one placement rather than two — the same
 * settling `peersSha` depends on.
 *
 * **This is the header and nothing else, deliberately.** `planRun` can narrow a
 * headerless cell onto one peer when a private slot it reads pins it there,
 * and that narrowing is a dataflow fact this pass does not hold. Re-deriving it
 * would put a second answer to "who runs this cell" in the compiler beside the
 * one `plan.js` computes and `placement.js` acts on, and two answers to that
 * question eventually differ — which is a key leaving a machine it was never
 * supposed to leave. So the rule is *conservative* exactly where the two could
 * disagree: a headerless cell is treated as standing everywhere, which refuses
 * some pairings the data would have permitted, and the refusal names writing
 * the header as the remedy — turning the reader's guess into the document's
 * statement, which is the thing `planRun` was going to read anyway.
 * @param {{ peer?: string }} chain
 * @returns {string}  a peer, or `""` for every machine
 */
function placementOfChain(chain) {
  const peer = String(chain?.peer || "");
  return peer === PEER_WILDCARD ? "" : peer;
}

/**
 * Do these two placements ever land on one machine?
 *
 * Equal placements do, and `""` — every machine — meets everything including
 * itself. This is the half a "group by header string" version gets wrong: it
 * would let two headerless `input` cells through, and they are the pair most
 * likely to be written.
 * @param {string} a @param {string} b
 */
function placementsMeet(a, b) {
  return !a || !b || a === b;
}

/**
 * The sentence for a panel that two cells would read on one machine.
 *
 * Every branch names the state that is actually true — which cells, which
 * machine, and *why* they meet — because "per pipeline" was wrong in both
 * directions at once: stricter than a pipeline (it was document-wide) and
 * looser than the truth (the panel is per machine, not per document).
 * @param {string} panel  a `SOLE_INPUT_PANELS` key
 * @param {number} cell   the cell being refused
 * @param {string} here   its placement
 * @param {{ cell: number, at: string }} prior  the reader already holding the panel
 * @returns {string}
 */
function panelReadTwiceError(panel, cell, here, prior) {
  const noun = SOLE_INPUT_PANELS[panel];
  const at = (/** @type {string} */ p) => `\`${PEER_SIGIL}${p}\``;
  const where =
    prior.cell === cell
      ? "this cell reads it twice"
      : !here && !prior.at
        ? `cell ${prior.cell} reads it too — neither cell names a peer, so both run on the same machine`
        : !here
          ? `cell ${prior.cell} reads it on ${at(prior.at)}, and this cell names no peer, so every machine runs it — ${at(prior.at)} among them`
          : !prior.at
            ? `cell ${prior.cell} reads it and names no peer, so every machine runs it — including ${at(here)}, where this cell runs`
            : // `prior.at` and `here` are the same string in this branch —
              // `placementsMeet` said so — and the prior cell's own placement
              // is the one read, so a future change to what "meet" means
              // cannot turn this clause into a claim about the wrong machine.
              `cell ${prior.cell} reads it on ${at(prior.at)}, which is where this cell runs too`;
  // Two readers in *one* cell cannot be told apart by a header — a `@` goes on
  // a cell, so the cross-cell remedies below would be naming a move that
  // cannot be made from where the author is standing.
  const remedy =
    prior.cell === cell
      ? "Delete one of them, or split the cell in two so each half can name its own peer — a `@` header goes on a cell, so two readers inside one are always on one machine."
      : SOLE_INPUT_REMEDIES[panel];
  return (
    `${noun} is one panel per machine, and ${where}. The second read returns ` +
    `what the first one got rather than something new. ${remedy}`
  );
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
  /** @type {import("./input-needs.js").InputPanel[]} */
  const inputNeeds = [];
  /**
   * Who is already reading each single-instance Inputs panel, and where.
   *
   * **One structure, because it is one rule.** This was three booleans —
   * `sawInputShares`, `sawInputText`, `sawDecryptGpg` — each scoped to the
   * whole document and each raising a message that said "per pipeline". That
   * copy was wrong in both directions at once: stricter than a pipeline, since
   * the flag never reset between cells, and looser than the truth, since the
   * thing there is one of is a *panel on a machine* and a document spans
   * machines. Two peers each reading their own Inputs panel is the ordinary
   * multi-peer notebook, and it would not compile.
   *
   * `46da380` fixed a third of this by narrowing which decrypts count, and said
   * in as many words that it was leaving the scope behind. Three separately
   * scoped counters is how a rule drifts into three rules, so the scope is
   * fixed here for all of them at once and there is one place left to read.
   *
   * Keyed panel → the first cell that claimed it at each placement. First
   * claim wins so the complaint always points *backwards*, at a cell the
   * reader has already scrolled past.
   * @type {Map<string, { cell: number, at: string }[]>}
   */
  const panelReaders = new Map();
  let globalStepIndex = 0;

  for (let ci = 0; ci < chains.length; ci++) {
    const steps = chains[ci].steps || [];
    if (!steps.length) continue;

    validateChainHeader(chains[ci], globalStepIndex, errors);
    validatePublishSteps(steps, globalStepIndex, errors);

    /**
     * Whether this cell carries a `@peer` header — the placed half of the
     * two-notebooks rule. A ceremony's deal binds slots that its *recovery*,
     * a separate agreement written later, reads: the recovery notebook names
     * `$share-2` and no cell in it writes one, because the deal did, on the
     * machine the cell is placed on. The compiler holds no claim about a
     * value another notebook bound, so a placed cell's unknown slot is
     * deferred to the run — `placement.js`'s `hasSlot` seam admits the cell
     * when the value is really there, and the engine's refusal names the
     * slot when it is really absent. An *unheaded* cell keeps the refusal:
     * with no peer there is no other machine the value could be on, so
     * "register earlier with out $x" is a remedy the author can perform.
     */
    const placed = !!chains[ci].peer;

    // The machine this cell's steps will be reaching for a panel on. Read once
    // per cell from the header and nowhere else — see `placementOfChain`.
    const where = placementOfChain(chains[ci]);

    // `shares` steps in *this* chain — the assembly-point rule below, which is
    // per pipeline and reset here because a pipeline is what it is about.
    let sharesStepsHere = 0;

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

    // A pair verb on the stem: the stem never holds a pair, only a `scatter`
    // body does. (`send` on a stem normally re-reads as `quorum.send` at
    // parse; this also covers a hand-built AST.)
    if (step.name === "seal" || step.name === "send") {
      errors.push({
        message: noPairHere(step.name),
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }
    {
      const reserved = reservedRecipientError(step, false);
      if (reserved) {
        errors.push({
          message: reserved,
          start: step.start,
          end: step.end,
          stepIndex,
        });
        continue;
      }
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
      // `1/3` is refused here, where the named spelling reaches it too —
      // `sss.split 1/3` and `sss.split threshold=1 shares=3` must refuse
      // identically or the object form and the named form are two dialects.
      // The sentence is `ceremonyIssues`' (one constant, two consumers),
      // because the Sheet's stepper and the compiler are refusing the same
      // arithmetic fact and two spellings of it would drift. `1/1` stays
      // legal: with one share there is no quorum being promised, only a copy
      // asked for by name.
      if (t === 1 && n >= 2) {
        errors.push({
          message: `sss: ${COPY_NOT_A_QUORUM}`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      sharesCount = n;
    }

    /**
     * One reader per single-instance panel per machine.
     *
     * `buildBindings` fills `inputs.text`, `inputs.shares` and `inputs.gpg`
     * from one textarea each, on the machine the run is happening on — so the
     * thing there is exactly one of is a panel *there*, and the enforcement
     * has to be keyed the same way or it is measuring something else. It was
     * keyed per document, which is why two peers each reading their own Inputs
     * panel refused: `@bo input | out $a` beside `@cara input | out $b` is the
     * shape of nearly every multi-peer notebook and none of them compiled.
     *
     * Two things are asked, and neither is a step name.
     *
     * *Which panel*, from the step's own declarations, through the same
     * `stepInputRequirements` walk the tray-opening shell reads — `46da380`'s
     * reason, kept and generalised: a `gpg.decrypt` fed by `quorum.recv`, or a
     * `shares` whose rows came down the pipe, reaches for no panel and so
     * stands in nobody's way. `param === null` is what keeps this about the
     * *content* panels and not the key trays that share their names: a
     * pipeline-value need is the whole document arriving, while a `key=` need
     * is "which key", and two steps wanting the same key is not a conflict.
     *
     * *Which machine*, from the cell's header, through `placementOfChain` —
     * the header alone, with a headerless or `@*` cell standing on every
     * machine at once. `placement.js` is the authority on who runs what and
     * this must not become a rival to it.
     */
    for (const need of stepInputRequirements(step, spec, current)) {
      if (need.param !== null || !need.panel) continue;
      if (!SOLE_INPUT_PANELS[need.panel]) continue;
      const held = panelReaders.get(need.panel) || [];
      const prior = held.find((r) => placementsMeet(r.at, where));
      if (prior) {
        errors.push({
          message: panelReadTwiceError(need.panel, ci, where, prior),
          start: step.start,
          end: step.end,
          stepIndex,
        });
      } else {
        held.push({ cell: ci, at: where });
        panelReaders.set(need.panel, held);
      }
    }

    /**
     * One place per pipeline where a share set is assembled.
     *
     * A *different* rule from the panel one above, kept apart from it on
     * purpose although the two used to be one document-wide boolean — and the
     * fusion is what made the old copy unfixable. The panel rule is about a
     * scarce resource on a machine; this one is about a reader being able to
     * answer "what went into this set?" by looking at one step. `a0c34cf`
     * named the two-cell workaround as the other road to the hybrid and closed
     * it; `635fd58` then opened the *spelled* road, `tray=merge`, and left this
     * closed so there would be exactly one spelling.
     *
     * So this counts `shares` steps and does not ask about panels: a set
     * assembled from the pipe is still a set, and a second assembly still
     * splits the answer in two. It is per chain because a pipeline is what a
     * set belongs to — which is what the old message said and what nothing
     * enforced, since the flag it read never reset between cells.
     */
    if (step.name === "shares") {
      if (sharesStepsHere) {
        errors.push({
          message:
            "A pipeline assembles its share set in one place, and this one " +
            "already has a `shares` above — a second collector splits the " +
            "answer to \"what went into this set?\" across two steps. Fold the " +
            "extra rows into the first one instead: `with=$slot` for a share " +
            "another cell bound, `tray=merge` for mnemonics typed into " +
            "Inputs → shares.",
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      sharesStepsHere++;
    }

    // Every panel this step needs, read off its declarations — the step's own
    // `unresolvedInputs` for the value that arrives through the pipe, and its
    // `unresolvedInput` params for the ones a `$slot` could have supplied.
    collectInputNeeds(step, inputNeeds, current);

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
          if (placed) {
            // The `in` half of the deferral `placed` argues above: whether
            // the machine this cell is placed on holds `$x` is that
            // machine's session's business, so the read is neither refused
            // nor typed. `deferred` marks the tip as a value this document
            // knows nothing about — the walk below suppresses every claim
            // it would otherwise make about it, and the flag rides `out`
            // into the slot map so a later read stays as unclaimed as this
            // one. (A numeric `in N` still refuses either way: an index is
            // a position in *this* document's out order, and another
            // notebook's order is not a thing this one can count into.)
            current = { ...tNone(), deferred: true };
            continue;
          }
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

    validateStepSlotParams(step, slotTypes, slotTypesByIndex, errors, stepIndex, placed);

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
      if (current.base !== "shares" && current.base !== "bundle" && !current.deferred) {
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
        // The collection's stated count (`sss.split 2/3` stamps length: 3 and
        // `blip39` carries it) — a body `out`'s bundle slot is that many parts.
        collectionLength:
          typeof current.length === "number" ? current.length : undefined,
        slotTypes,
        slotTypesByIndex,
        source: ast.source,
        placed,
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

    if (step.name === "scatter") {
      // The same collection rule as `foreach` — scatter is that loop with a
      // second list, and the second list is the room's.
      if (current.base !== "shares" && current.base !== "bundle" && !current.deferred) {
        errors.push({
          message: `scatter requires a collection (shares or bundle) — got ${formatType(current)}. Add sss.split, blip39, shares, or quorum.recv count=all before scatter.`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      // The second list is derived, never named. A fingerprint here would
      // *choose* the pairing, and the pairing must never be chosen —
      // `peersSha` commits to the room as a set, so a chosen order is the
      // divergence nothing downstream can see. The constant-recipient want is
      // real and has its spelling: on the body's verb, where it addresses
      // every pair the same way instead of reordering them.
      const to = String(step.params?.to ?? "room").trim();
      if (to !== "room") {
        errors.push({
          message:
            `\`scatter to=\` names a derivation, not a choice — the only ` +
            `recipient is \`room\`, the audience in canonical order` +
            (to.toLowerCase() === "room"
              ? ` (written \`room\`, exactly).`
              : `. A fingerprint here would choose the pairing, which must ` +
                `stay derived; to address every share to one key, put the ` +
                `constant on the body's verb: \`- seal to=<fingerprint>\`.`),
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      if (!step.body?.length) {
        errors.push({
          message:
            "scatter requires a body — one indented `- seal to=each | …` line, run once per (share, member) pair",
          start: step.start,
          end: step.end,
          stepIndex,
        });
        current = typeOf("bundle");
        continue;
      }
      // The body holds the pair: `:key` is the member (text), `:value` the
      // share — `foreach :items`'s own vocabulary, which is why the item type
      // is reused rather than a new base invented for one body form.
      const pairType = typeOf("item", { kind: current.kind || "mnemonic" });
      const bodyVal = validateBodySteps(step.body, pairType, {
        errors,
        warnings,
        stepIndex,
        inForeach: true,
        inScatter: true,
        // A body `out`'s bundle slot is one part per pair, and the pair count
        // is the share count when the text states it.
        collectionLength:
          typeof current.length === "number" ? current.length : undefined,
        slotTypes,
        slotTypesByIndex,
        source: ast.source,
        placed,
      });
      if (bodyVal.encryptInBody) {
        foreachGpg = true;
        gpgSlots = Math.max(gpgSlots, sharesCount || 1);
      }
      for (const need of bodyVal.inputNeeds) {
        if (!inputNeeds.includes(need)) inputNeeds.push(need);
      }
      // A bundle of per-pair tips, fixed by the step name — and its count is
      // the collection's, so the length refinement rides through when the
      // text states it.
      current = typeOf(
        "bundle",
        typeof current.length === "number" ? { length: current.length } : {}
      );
      continue;
    }

    if (step.name === "tee") {
      if (current.base === "none" && !current.deferred) {
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
        // No selector means no projection: the branch sees the stem's own type.
        // Typing it any other way would make `- encode hex | out $a` refuse
        // under a `tee` while the identical line passes on the stem.
        const sel = br.selector || (br.member ? String(br.member) : "");
        const projected = sel
          ? projectTypeForMember(current, sel)
          : { ok: /** @type {const} */ (true), type: current };
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
      // Reads nothing out of the set; it says the slot the `out` before it
      // named may leave. Whether a *split* may leave is a real question and a
      // different one, answered by `publishability` in the planner with the
      // sentence about what a room handed every share has been handed.
      step.name !== PUBLISH_STEP &&
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
      // A source that declares `collects` and accepts what is on the pipe does
      // not discard it — it folds it in, which is the whole reason `collects`
      // exists. Warning anyway would have told the reader of the documented
      // `quorum.recv count=2 | shares` idiom that their shares were being
      // thrown away, which is the opposite of what that step does. A type the
      // step does *not* collect needs no warning either: `resolveStepType`
      // refuses it outright a few lines below, and an error already saying the
      // value "would be thrown away" does not want a warning agreeing with it.
      const folds =
        Array.isArray(spec.collects) && spec.collects.includes(current.base);
      if (i > 0 && current.base !== "none" && !folds) {
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
      // A deferred tip is a value another notebook bound: a refusal here
      // would be a claim about a value the compiler never saw, made in words
      // that describe the wrong state ("needs an input" about a slot the run
      // will hold). No claim is made either way — the step is walked past
      // with the tip still unclaimed, and the run's own type checks are the
      // ones entitled to speak.
      if (current.deferred) continue;
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

    checkPooledPipelineValue(step, current, resolved.output, errors, stepIndex);
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
 *
 * `steps` is a parameter for `stepInputRequirements`' reason: a check that can
 * only be asked about ops the registry already contains cannot demonstrate that
 * it would catch a *new* one, which is the whole property it exists for. The
 * shipped call passes nothing and gets the real registry.
 * @param {import("./registry.js").StepSpec[]} [steps]
 * @returns {string[]}
 */
export function registryIssues(steps = listSteps()) {
  /** @type {string[]} */
  const issues = [];
  const paramTypes = new Set(["enum", "int", "string", "bytes", "bool", "flag"]);
  for (const s of steps) {
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
    // Entropy, in two halves. Anything declared has to name a real kind; and a
    // step whose output can carry a secret has to declare *something*.
    //
    // Only that population, because omission already fails closed — `stepEntropy`
    // reads an absent field as `keying`, so forgetting can never make a step
    // seedable. What forgetting can do is leave the step silently refused by
    // every mirrored run with nobody having decided that. Both facts this
    // check reads are static: the output type and the declaration are both
    // known before anything runs.
    if (s.entropy != null && !ENTROPY_KINDS.includes(s.entropy)) {
      issues.push(
        `${s.name}: entropy must be one of ${ENTROPY_KINDS.join(", ")} (got ${JSON.stringify(s.entropy)})`
      );
    } else if (s.entropy == null && SECRET_BEARING_OUTPUTS.includes(s.output)) {
      issues.push(
        `${s.name}: output ${s.output} can carry a secret, so entropy must be declared — ` +
          `"none" if it draws no randomness, "public" if what it draws is published ` +
          `alongside the output (an IV, a nonce, a challenge) and safe for every peer ` +
          `to recompute, "keying" if the randomness becomes or protects key material. ` +
          `Run it twice on the same input before deciding; leaving the field off is ` +
          `read as "keying" and the step is refused by any mirrored run.`
      );
    }
    // `collects` is a claim about a source's *pipeline* input, so a transform
    // declaring it would be saying something the field cannot mean — a
    // transform's accepted input is `input`/`overloads` and is already checked.
    if (s.collects) {
      if (s.kind !== "source") {
        issues.push(
          `${s.name}: collects is for sources — a ${s.kind} declares its pipeline input with input/overloads`
        );
      }
      if (!Array.isArray(s.collects) || !s.collects.length) {
        issues.push(`${s.name}: collects must be a non-empty list of io types`);
      } else if (s.collects.includes(/** @type {*} */ ("none"))) {
        // `none` is what "nothing was piped in" already is, and it is always
        // allowed — listing it would read as a fourth accepted value.
        issues.push(`${s.name}: collects must not list "none" — an empty pipe is always accepted`);
      }
    }
    for (const d of stepInputDeclarations(s.unresolvedInputs)) {
      if (!INPUT_PANELS.includes(d.panel)) {
        issues.push(
          `${s.name}: unresolvedInputs panel must be one of ${INPUT_PANELS.join(", ")} (got ${JSON.stringify(d.panel)})`
        );
      }
      for (const name of Object.keys(d.when || {})) {
        if (!(s.params || []).some((p) => p.name === name)) {
          issues.push(`${s.name}: unresolvedInputs when.${name} names no param`);
        }
      }
      // A guard on a type the step never sees can never lift the panel, which
      // is the silent half of a wrong declaration: the tray simply stays.
      if (d.whenInput && !d.whenInput.includes(/** @type {*} */ ("none"))) {
        issues.push(
          `${s.name}: unresolvedInputs whenInput must include "none" — a step with nothing piped in has only the tray left`
        );
      }
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
      // A panel stands in for a value a `$ref` would otherwise carry, so the
      // param has to accept one; and the panel is rendered from `slotOf`, so
      // there has to be one to render.
      if (p.unresolvedInput && !p.slot) {
        issues.push(`${s.name}.${p.name}: unresolvedInput without slot`);
      }
      if (p.unresolvedInput && !p.slotOf) {
        issues.push(`${s.name}.${p.name}: unresolvedInput without slotOf`);
      }
      if (p.requiredWith && !(s.params || []).some((q) => q.name === p.requiredWith)) {
        issues.push(
          `${s.name}.${p.name}: requiredWith "${p.requiredWith}" names no param`
        );
      }
    }
  }
  // A module alias whose spelling a real step already holds. The expansion
  // yields rather than shadows — an alias is a second way to reach an op and
  // never a way to take one over — and yielding in silence is what would make
  // this worth catching: `docs/RECIPE.md` would go on promising a spelling the
  // parser resolves somewhere else entirely.
  //
  // Outside the `steps` loop because it is a fact about the registry as a
  // whole rather than about one spec — but asked of the same `steps`, so a
  // caller can hand it a registry that *does* collide and see the check fire.
  for (const { alias, canonical, shadowed } of moduleAliasSpellings(steps)) {
    if (!shadowed) continue;
    issues.push(
      `module alias "${alias}" was not registered for ${canonical} — that ` +
        `spelling is already taken, so the alias silently names something else. ` +
        `Rename the colliding step or drop the module alias.`
    );
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
 *
 * `group` is the only field read, and it is read with a fallback — so this
 * takes anything that names one. `typeof PRESETS` demanded the whole inferred
 * literal union, which the Templates menu's own rows do not satisfy.
 * @param {readonly { group?: string }[]} [presets]
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
 * The company a notebook needs before it can do anything.
 *
 * `solo` is a machine standing alone — which is what the overwhelming majority
 * of this gallery is, and why the field is omitted there rather than typed out
 * seventy times. `room` is a live `quorum.offer`/`quorum.join` exchange with
 * somebody else meshed into it.
 *
 * There is deliberately **no `peer` value**, and the absence is the finding
 * rather than an oversight. A `peer.*`-shaped tier would have exactly zero
 * members: `peer.offer`/`peer.answer`/`peer.accept`/`peer.wait` are the
 * *managed hand-carried* layer, and `sdp-hand-carried` — the template that uses
 * all of them — runs both ends in one notebook on purpose ("both ends live in
 * this notebook, so it connects to itself"). `rtc.ice`, `rtc.gather` and
 * `rtc.certificate` likewise run alone; `rtc.gather`'s own doc says "run it
 * standalone to see why a later connection failed". A category with no members
 * is a label that can only ever be applied wrongly, so it is not offered.
 *
 * @typedef {"solo"|"room"} Company
 */

/**
 * What company this recipe's own text requires — derived, never taken on trust.
 *
 * Two things put a notebook in a room, and both are read structurally rather
 * than by matching op names against a prefix:
 *
 * 1. **A `@peer` header.** A placed cell runs on somebody else's machine, so
 *    the notebook needs that somebody.
 * 2. **A step whose registry entry declares `company`.** That is where the
 *    knowledge lives, because the op's own doc string is where it was already
 *    written down — and because a prefix rule gets it wrong in this registry:
 *    `rtc.check` needs the exchange and `rtc.gather` explicitly does not.
 *
 * Bodies and `tee` branches are walked, because `scatter to=room` keeps its
 * only interesting step (`send to=each`) inside one.
 *
 * @param {string|{ chains?: *[], steps?: *[] }} astOrSource
 * @returns {Company}
 */
export function recipeCompany(astOrSource) {
  const ast =
    typeof astOrSource === "string"
      ? parseRecipe(astOrSource).ast
      : astOrSource;
  if (!ast) return "solo";
  for (const chain of recipeChains(ast)) {
    if (String(chain?.peer || "").trim()) return "room";
    if (stepsWantCompany(chain?.steps)) return "room";
  }
  return "solo";
}

/**
 * Whether any step here — or in any body or branch below it — declares that it
 * reads a live exchange.
 * @param {*[]} [steps]
 * @returns {boolean}
 */
function stepsWantCompany(steps) {
  for (const step of steps || []) {
    if (getStep(step?.name)?.company === "room") return true;
    if (stepsWantCompany(step?.body)) return true;
    for (const br of step?.branches || []) {
      if (stepsWantCompany(br?.body)) return true;
    }
  }
  return false;
}

/**
 * Preset recipes for the Templates menu.
 *
 * `group` clusters presets under a category. Presets sharing a `pair` value are
 * companion pipelines (forward ⇄ inverse, e.g. split/recover or encrypt/decrypt)
 * and render side by side; the one listed first appears on the left.
 *
 * `company` declares what the recipe needs before it can run, and is **checked
 * against the recipe's own steps** by `preset-company.test.js` rather than
 * believed. That check is the whole value of the field: three templates in this
 * list were named for rooms they never entered for as long as nothing compared
 * the name to the pipeline. Absent means `solo`, so a room template that forgets
 * to declare fails the same comparison as one that declares the wrong thing.
 *
 * Every entry here is recipe *text* that compiles — that is what the sweeps in
 * `recipe-roundtrip`, `run-plan-differential` and `recipe.test.js` assert over
 * this array. The gallery shows more than this: see `ROOM_TEMPLATES`.
 */
export const PRESETS = [
  {
    id: "p256-pem",
    group: "Keys",
    title: "P-256 public + private (PEM)",
    blurb:
      "Tee the public SPKI PEM, then export PKCS#8 — mid-stem fork keeps the keypair on the stem.",
    recipe: `genkey ec/p256 | tee
  - public | export spki | pem | out $public
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

$kp | public | export spki | pem | out $public
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
  - public | ssh.encode | out $pub
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
    recipe: `genkey ec/p256 | public | export jwk | out $jwk

in $jwk | utf8 | digest | encode hex | out $thumb`,
  },
  {
    id: "verify-soft",
    group: "Digest & MAC",
    title: "Soft signature verify",
    blurb:
      "Fail-soft verify (`-q`): emits bool `true` or `false` instead of throwing. Bind signature= (or the sig panel) at run time; prefer fail-loud for auth.",
    recipe: `genkey ed25519 | public | export jwk | out $pub

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
    title: "Split a secret onto cards, on this machine",
    blurb:
      "The dealt split for a room that is not online: this machine draws the secret, sees all three mnemonics, and you write them onto cards. The tee is what makes that survivable — a SHA-256 of the master goes to $expected while the master itself reaches no slot, so a recovery years later can be checked without the secret being shown again. When the holders are in a live room instead, deal it over the wire from “Deal a split across a room” — that one never leaves a share behind.",
    recipe: `random 32 | tee
  - digest sha-256 | encode hex | out $expected
| sss.split 2/3 | blip39 | foreach
  - out $share`,
  },
  {
    id: "recover-shares",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "Recover secret from BLIP39 shares",
    blurb:
      "Paste K-of-N mnemonics, decode to raw SSS, reconstruct the 16/32-byte master as Base64. The digest branch is the half that tells you it worked: recombining a corrupted or mismatched set returns a *different* secret rather than an error, so $recovered is what you compare against the $expected the split kept.",
    recipe: `shares | blip39.decode | sss.combine | tee
  - digest sha-256 | encode hex | out $recovered
| base64 | out $secret`,
  },
  {
    id: "ceremony-receipt",
    group: "Ceremony",
    pair: "ceremony-audit",
    title: "Sign a receipt for a solo split",
    blurb:
      "A run to have a receipt of, and then the receipt: one machine splits a secret onto cards — nobody else is involved and no room is opened — and `run.receipt` mints the record of what it did, recipe and timestamps and digests of every output, never the outputs. Sign it with a vault key and it says who vouched for the run as well as what ran.",
    recipe: `random 32 | tee
  - digest sha-256 | encode hex | out $expected
| sss.split 2/3 | blip39 | foreach
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
  - public | export spki | pem | out $public
| export scalar | sss.split 2/3 | blip39 | foreach
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
    // The id keeps its spelling, and it is now the only place the word
    // "quorum" survives on this template. Retiring it would break the `#t=`
    // links people hold, and `useNotebook` answers an unknown preset id by
    // doing nothing at all — so a renamed id is a link that silently opens
    // whatever notebook was already there. The title and blurb are what a
    // reader sees, and those say what the recipe does.
    id: "quorum-gpg",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Split a P-256 key, one share encrypted per holder",
    blurb:
      "The out-of-band way to hand shares out: tee the public PEM, split the 32-byte scalar 2-of-3, and encrypt each mnemonic to a different key, so each armored message can be mailed to its holder. No `quorum.*` op runs and no room is opened — the transport is you. Nothing is kept: the foreach body has no `out`, so the shares leave as ciphertext and this machine ends holding none of them.",
    recipe: `genkey ec/p256 | tee
  - public | export spki | pem | out $public
| export scalar | sss.split 2/3 | blip39 | foreach
  - gpg.encrypt`,
  },
  {
    id: "decrypt-rebuild-p256",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Decrypt GPG shares → rebuild key",
    blurb:
      "Decrypt every OpenPGP-wrapped share in the panel (`count=all`), collect the plaintexts with `shares`, then blip39.decode | sss.combine and rebuild the P-256 PEM from the scalar. Mnemonics already decrypted externally (Kleopatra/gpg + YubiKey) go in Inputs → shares, which `shares` reads on its own.",
    recipe:
      "gpg.decrypt count=all | shares | blip39.decode | sss.combine | import scalar alg=ec/p256 | export pkcs8 | pem | out $private",
  },
  {
    id: "pem-envelope-split",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Split PEM via OpenPGP envelope",
    blurb:
      "Emit PKCS#8 PEM ($pem), OpenPGP-encrypt under a random 32-byte master, then SSS + BLIP39-split the master. Keep envelope.asc with the shares.",
    recipe: `genkey ec/p256 | export pkcs8 | pem | out $pem | gpg.symencrypt mode=master | sss.split 2/3 | blip39 | foreach
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
    // The one shipped template that cannot run on a machine standing alone,
    // and the one that is still honest as text: it names nobody. `rtc.state`,
    // `rtc.check` and `rtc.quality` read whatever exchange is open, so there is
    // no roster to bake in and nothing here goes stale when the room changes.
    // That is why it loads into the notebook like any other template and only
    // wears the badge — see `ROOM_TEMPLATES` for the entries that cannot.
    company: "room",
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
      "Decrypt armored ciphertext from the Inputs panel and name the plaintext — same recipe as the `#decrypt` messaging starter. Bind a private key or unlock My Keys when prompted.",
    recipe: "gpg.decrypt | out $plain",
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

/**
 * The shared notebooks — shown in the gallery, generated rather than pasted.
 *
 * ## Why they are in the gallery at all
 *
 * Because until they were, nothing in the Templates menu said the shared
 * notebook exists. Seventy templates, all of them solo, and the two notebooks
 * this product spent four commits building were reachable only by opening a
 * sheet nobody had a reason to open. A person browsing templates for "split a
 * key between us" found the card path and concluded that was the answer.
 *
 * ## Why they carry no recipe
 *
 * Because a room notebook names people, and this file cannot know them. The
 * deal is one cell per holder, each headed `@<whole fingerprint>`, with the
 * receive slots numbered by `canonicalAudience` — none of it writable before
 * the audience exists. The obvious escape, a template full of `@peer1`
 * placeholders resolved later, does not work and the reason is recorded in
 * `ROOM_CEREMONY_PLACEHOLDERS`: `@` is not legal in a param value, so
 * `quorum.recv from=@holder1` does not parse, and a notebook of placeholders
 * would draw a compile error at the reader while it waited to be filled in.
 *
 * So choosing one of these opens the picker that already exists — the deal's in
 * `SessionStart`, the recovery's in `RoomRecovery` — and the notebook falls out
 * of the roster. **One road to a shared notebook**, which is also why nothing
 * here duplicates the generators' copy: the picker prints
 * `roomCeremonySummary` beside the recipe it is about to write.
 *
 * `company` is declared here too, and checked the same way as a preset's — by
 * deriving it from what the generator this entry opens actually writes. A
 * declaration verified against a sample of the real output is the only kind
 * worth having on an entry that has no text of its own.
 *
 * @typedef {object} GalleryEntry
 * @property {string} id
 * @property {string} [group]
 * @property {string} title
 * @property {string} [blurb]
 * @property {string} [recipe]  absent exactly on the generated entries
 * @property {string} [pair]
 * @property {Company} [company]  absent means `solo`
 * @property {"ceremony"|"recovery"} [opens]  the picker a generated entry opens
 */

/** @type {readonly GalleryEntry[]} */
export const ROOM_TEMPLATES = Object.freeze([
  {
    id: "room-deal",
    group: "Ceremony",
    title: "Deal a split across a room",
    blurb:
      "The shared version of the split below: the secret is drawn on one machine and each share goes straight from the split onto the wire to the person it belongs to, so no machine is left holding the set. It is written for the people you pick — one cell each, addressed by whole fingerprint — which is why there is no text to load here. Choosing this opens the room list, and the notebook is generated from it.",
    company: "room",
    opens: "ceremony",
  },
  {
    id: "room-recover",
    group: "Ceremony",
    title: "Put a dealt secret back together",
    blurb:
      "The other agreement, written when the day comes rather than at the deal: who is contributing is the one question, and the threshold, the count and the set id are read off your own share's header. Also the road in for a custodian holding nothing but words on paper, which needs no room and no vault at all.",
    company: "room",
    opens: "recovery",
  },
]);

/**
 * Everything the Templates menu shows, in menu order.
 *
 * The room entries lead their category rather than trailing it: a reader who
 * opens "Ceremony" looking for a way to split a key between people should meet
 * the one that deals over the wire before the one that leaves every mnemonic on
 * their own screen.
 *
 * Kept separate from `PRESETS` rather than merged into it, because `PRESETS`
 * carries a promise the room entries cannot keep — every member is recipe text
 * that compiles, which is what four sweeps assert over it. Teaching those
 * sweeps to skip the recipe-less members would have weakened each of them
 * against a preset that lost its recipe by accident.
 * @type {readonly GalleryEntry[]}
 */
export const GALLERY_ENTRIES = Object.freeze([...ROOM_TEMPLATES, ...PRESETS]);

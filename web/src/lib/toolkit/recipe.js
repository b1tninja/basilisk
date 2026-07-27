/**
 * Toolkit recipe language — validate / serialize / presets.
 * Normative grammar: docs/RECIPE.md
 *
 *   genkey ec/p256 | out @kp
 *
 *   in @kp | .public | export spki | pem | out @public
 *   in @kp | export pkcs8 | pem | out @private
 *
 * Decode flags (shell-style): base64 -d | hex -d | pem -d → params.decode = true
 * Slot sugar: bare `out kp` / `in kp` canonicalize to `@kp`; `from` → `in`.
 */

import {
  getStep,
  listSteps,
} from "./registry.js";
import {
  canonicalSelectorMember,
  parseRecipeSource,
  slotLabelKey,
} from "./recipe-parse.js";
import { migrateRecipe } from "./step-names.js";
import {
  formatType,
  isTerminalSink,
  resolveStepType,
  tNone,
  typeOf,
} from "./types.js";

export { migrateRecipe } from "./step-names.js";

/**
 * @param {RecipeStep} step
 * @param {string} name
 */
function hasSlotParam(step, name) {
  const v = step.params?.[name];
  return v != null && String(v).trim() !== "";
}

/**
 * Compile-time warnings for discouraged algorithms (still allowed).
 * @param {RecipeStep} step
 * @param {string[]} warnings
 */
function pushDiscouragedAlgoWarnings(step, warnings) {
  if (
    step.name === "digest" &&
    String(step.params?.alg || "sha-256").toLowerCase() === "sha-1"
  ) {
    warnings.push(
      `digest alg=sha-1 is discouraged (collision-prone); prefer sha-256 — outputs tagged legacy/discouraged`
    );
  }
  if (step.name === "rsa-pkcs1") {
    warnings.push(
      `rsa-pkcs1 (RSAES-PKCS1-v1_5) is discouraged; prefer rsa-oaep — outputs tagged legacy/discouraged`
    );
  }
  if (
    (step.name === "genkey" || step.name === "import") &&
    String(step.params?.alg || "").startsWith("rsa/") &&
    String(step.params?.usage || "auto") !== "encrypt" &&
    String(step.params?.padding || "pss").toLowerCase() === "pkcs1"
  ) {
    warnings.push(
      `${step.name} padding=pkcs1 (RSASSA-PKCS1-v1_5) is discouraged; prefer padding=pss — outputs tagged legacy/discouraged`
    );
  }
}

/**
 * Warn when usage= is set but ignored for fixed-usage algorithms.
 * @param {RecipeStep} step
 * @param {string[]} warnings
 */
function pushUsageHonestyWarnings(step, warnings) {
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
      `${step.name} usage=${usage} is ignored for ${alg || "this algorithm"} (usage is fixed)`
    );
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
 * When `key=@slot` is bound, only the passphrase field may still be needed.
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
 * OpenPGP passphrase field after `key=@slot` (S2K) or agent.save passphrase wrap.
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
 * Validate slot-typed params on a step (existence + coarse type).
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
    if (p.type !== "slot") continue;
    const ref = step.params?.[p.name];
    if (ref == null || String(ref).trim() === "") continue;
    const loaded = lookupSlotType(String(ref), slotTypes, slotTypesByIndex);
    if (!loaded) {
      errors.push({
        message: `${step.name} ${p.name}=${ref}: unknown slot (register earlier with out ${String(ref).startsWith("@") || /^\d+$/.test(String(ref)) ? ref : `@${ref}`})`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }
    const base = loaded.base;
    let okBase =
      base === "keypair" ||
      base === "bytes" ||
      base === "text" ||
      base === "key";
    if (
      step.name === "gpg.sign" ||
      step.name === "gpg.verify" ||
      (step.name === "gpg.encrypt" && p.name === "key") ||
      step.name === "agent.save"
    ) {
      okBase = okBase || base === "openpgp-key";
    }
    if (step.name === "recipients.merge" && p.name === "with") {
      okBase =
        base === "recipients" ||
        base === "openpgp-key" ||
        base === "text";
    }
    if (!okBase) {
      errors.push({
        message: `${step.name} ${p.name}=${ref}: slot type ${formatType(loaded)} cannot supply a key`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
    }
  }

  // gpg.encrypt to=@slot — string param that may reference a slot
  if (step.name === "gpg.encrypt") {
    const toRaw = String(step.params?.to || "").trim();
    if (toRaw) {
      const looksEmail =
        (/^email:/i.test(toRaw) || (toRaw.includes("@") && !toRaw.startsWith("@")));
      const looksFpr =
        /^(?:fpr:|0x)/i.test(toRaw) ||
        /^[0-9A-Fa-f]{40,}$/i.test(toRaw.replace(/\s+/g, ""));
      if (!looksEmail && !looksFpr) {
        const ref = toRaw.startsWith("@") ? toRaw : `@${toRaw}`;
        const loaded = lookupSlotType(ref, slotTypes, slotTypesByIndex);
        if (!loaded) {
          errors.push({
            message: `${step.name} to=${toRaw}: unknown slot (register earlier with out ${ref})`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        } else if (
          loaded.base !== "recipients" &&
          loaded.base !== "openpgp-key" &&
          loaded.base !== "text"
        ) {
          errors.push({
            message: `${step.name} to=${toRaw}: slot type ${formatType(loaded)} cannot supply recipients`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        }
      }
    }
  }
}

/**
 * Labeled tee branch (selector style: `- .private | …`).
 * @typedef {object} TeeBranch
 * @property {string} member  e.g. private | public | key | value
 * @property {string} [selector]  e.g. ".private"
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
 * @property {string} [foreachSelector]  e.g. ".items"
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
 * @typedef {object} ValidationResult
 * @property {boolean} ok
 * @property {RecipeError[]} errors
 * @property {string[]} warnings
 * @property {number} [recipientSlots]  how many GPG recipient slots Run needs
 * @property {boolean} [foreachGpg]  gpg.encrypt is inside foreach
 * @property {("shares"|"gpg"|"text"|"envelope"|"key")[]} [inputNeeds]  runtime input panels required
 */

/**
 * Parse a recipe string into an AST.
 * @param {string} source
 * @returns {{ ast: RecipeAst|null, errors: RecipeError[] }}
 */
export function parseRecipe(source) {
  return parseRecipeSource(source);
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
  const spec = getStep(step.name);
  const parts = [step.name];
  for (const p of spec?.params || []) {
    const v = step.params?.[p.name];
    if (v === undefined || v === "") continue;
    if (p.flag && p.type === "bool") {
      if (v === true) parts.push(p.flag);
      continue;
    }
    // Omit default *named* params, and default out/text/peek names only.
    if (v === p.default) {
      const omitName =
        p.positional &&
        p.name === "name" &&
        (step.name === "out" || step.name === "text" || step.name === "peek");
      if (omitName || !p.positional) continue;
    }
    if (p.positional && parts.length === 1) {
      parts.push(String(v));
      continue;
    }
    const needsQuote = /[\s|=]/.test(String(v));
    parts.push(
      `${p.name}=${needsQuote ? JSON.stringify(String(v)) : String(v)}`
    );
  }
  return parts.join(" ");
}

/**
 * Serialize one pipeline of steps (no block wrappers).
 * @param {RecipeStep[]} steps
 * @returns {string}
 */
function serializePipeline(steps) {
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
    .join(" | ");
}

/**
 * Serialize one chain's steps to recipe text.
 * @param {RecipeStep[]} steps
 * @returns {string}
 */
function serializeChainSteps(steps) {
  /** @type {string[]} */
  const chunks = [];

  /**
   * @param {string} head
   */
  function pushStemPiece(head) {
    if (chunks.length && chunks[chunks.length - 1]?.endsWith("\n")) {
      chunks.push(`| ${head}`);
    } else if (chunks.length) {
      chunks.push(` | ${head}`);
    } else {
      chunks.push(head);
    }
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

    if (chunks.length) chunks.push(" | ");
    const useBrace = step.bodyForm === "brace";
    chunks.push(useBrace ? `${head} {\n` : `${head}\n`);

    // Body may contain select+follow steps from `- .value | out` flatten — regroup.
    {
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
          const rest = serializePipeline(group.slice(1));
          chunks.push(
            rest ? `  - ${sel} | ${rest}\n` : `  - ${sel} | inspect\n`
          );
        } else {
          chunks.push(`  - ${serializePipeline([b])}\n`);
          bi++;
        }
      }
    }
    for (const br of step.branches || []) {
      const sel = br.selector || `.${br.member}`;
      const pipe = serializePipeline(br.body || []);
      chunks.push(`  - ${sel} | ${pipe}\n`);
    }
    if (useBrace) chunks.push("}");
  }
  return chunks.join("").replace(/\n+$/, "");
}

/**
 * Serialize an AST (or steps / chains) back to recipe text.
 * Chains are joined with a blank line. Canonical names; `@` slot sugar.
 * @param {RecipeAst|RecipeStep[]|RecipeChain[]} astOrSteps
 * @returns {string}
 */
export function serializeRecipe(astOrSteps) {
  const chains = recipeChains(astOrSteps);
  return chains
    .map((c) => serializeChainSteps(c.steps || []))
    .filter((t) => t.length)
    .join("\n\n");
}

/**
 * Refined type after a selector projection (`.private`, `.items`, …).
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
        error: `selector ".${m}" requires keypair, got ${formatType(current)}`,
      };
    }
    if (m === "private") {
      return {
        ok: true,
        type: typeOf("keypair", { ...current, which: "private" }),
      };
    }
    return {
      ok: true,
      type: typeOf("keypair", {
        alg: current.alg,
        which: "public",
      }),
    };
  }

  if (m === "keys" || m === "values" || m === "items") {
    if (current.base !== "shares") {
      return {
        ok: false,
        error: `selector ".${m}" requires shares, got ${formatType(current)}`,
      };
    }
    if (m === "keys") {
      return { ok: true, type: typeOf("text", { kind: "opaque" }) };
    }
    if (m === "items") {
      return { ok: true, type: typeOf("item", { kind: current.kind || "mnemonic" }) };
    }
    // .values — same per-element type as foreach default
    if (current.kind === "raw") {
      return { ok: true, type: typeOf("bytes", { kind: "opaque" }) };
    }
    return { ok: true, type: typeOf("text", { kind: "mnemonic" }) };
  }

  if (m === "key" || m === "value") {
    if (current.base !== "item") {
      return {
        ok: false,
        error: `selector ".${m}" requires an item ({key,value}), got ${formatType(current)}`,
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

  return { ok: false, error: `Unknown selector ".${m}"` };
}

/**
 * Validate steps inside a tee/foreach list body.
 * @param {RecipeStep[]} body
 * @param {import("./types.js").RefinedType} startType
 * @param {{
 *   errors: RecipeError[],
 *   warnings: string[],
 *   stepIndex: number,
 *   inForeach: boolean,
 * }} ctx
 * @returns {{
 *   final: import("./types.js").RefinedType,
 *   encryptInBody: boolean,
 *   inputNeeds: ("shares"|"gpg"|"text"|"envelope"|"key")[],
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
      pushDiscouragedAlgoWarnings(step, ctx.warnings);
      pushUsageHonestyWarnings(step, ctx.warnings);
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
      const ref = String(step.params?.name || "@output");
      const key = slotLabelKey(ref);
      if (key) {
        if (slotTypes.has(key)) {
          ctx.errors.push({
            message: `Duplicate out slot @${key}`,
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
  /** @type {string[]} */
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
        errors.push({
          message: `${step.name}: invalid ${p.name}="${v}" (allowed: ${p.enum.join(", ")})`,
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
    // Skip "key" — gated by stepNeedsKeyPanel (honors key=@slot).
    // Skip "gpg" — gated by stepNeedsGpgPrivatePanel / stepNeedsGpgPassphrasePanel.
    // gpg.decrypt / input / shares already handled above.
    if (
      step.name !== "gpg.decrypt" &&
      step.name !== "input" &&
      step.name !== "shares" &&
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
            message: `in ${ref}: unknown slot (register it earlier with out ${ref.startsWith("@") ? ref : `@${ref}`})`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
          continue;
        }
      }
      if (i > 0 && current.base !== "none") {
        warnings.push(
          `Source step "in" in chain ${ci + 1} discards prior pipeline value`
        );
      }
      current = { ...loaded };
      continue;
    }

    if (step.name === "gpg.symdecrypt") {
      if (!inputNeeds.includes("envelope")) inputNeeds.push("envelope");
    }

    validateStepSlotParams(step, slotTypes, slotTypesByIndex, errors, stepIndex);

    if (stepNeedsKeyPanel(step) && !inputNeeds.includes("key")) {
      inputNeeds.push("key");
    }

    pushDiscouragedAlgoWarnings(step, warnings);
    pushUsageHonestyWarnings(step, warnings);

    // verify signature=@slot: forward-ref check like other slot params
    if (step.name === "verify") {
      const sig = String(step.params?.signature || "").trim();
      if (sig.startsWith("@")) {
        const loaded = lookupSlotType(sig, slotTypes, slotTypesByIndex);
        if (!loaded) {
          errors.push({
            message: `verify signature=${sig}: unknown slot (register earlier with out ${sig})`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        } else if (
          loaded.base !== "bytes" &&
          loaded.base !== "text" &&
          loaded.base !== "none"
        ) {
          errors.push({
            message: `verify signature=${sig}: slot type ${formatType(loaded)} cannot supply a signature`,
            start: step.start,
            end: step.end,
            stepIndex,
          });
        }
      }
    }

    if (step.name === "foreach") {
      if (current.base !== "shares") {
        errors.push({
          message: `foreach requires a collection (shares) — got ${formatType(current)}. Add sss, blip39, or shares before foreach.`,
          start: step.start,
          end: step.end,
          stepIndex,
        });
      }
      if (!step.body?.length) {
        errors.push({
          message:
            "foreach requires a body — use indented `- out @share` or `foreach { - out @share }`",
          start: step.start,
          end: step.end,
          stepIndex,
        });
        current = typeOf("bundle");
        continue;
      }
      const mode = String(step.foreachSelector || ".values").replace(/^\./, "");
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
            "tee requires a body — use `{ - .public | … }` or indented `-` lines (use `peek` for a side inspect)",
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
      step.name !== "blip39" &&
      step.name !== "tee" &&
      step.name !== "peek" &&
      step.name !== "inspect" &&
      step.name !== "out" &&
      step.name !== "at" &&
      step.name !== "select"
    ) {
      errors.push({
        message: `Cannot pipe shares into "${step.name}" — add foreach to unpack, at N / [n] to select, blip39 to encode/decode, or sss.combine (on raw shares) for bytes/master.`,
        start: step.start,
        end: step.end,
        stepIndex,
      });
      continue;
    }

    if (spec.kind === "source") {
      if (i > 0 && current.base !== "none") {
        warnings.push(
          `Source step "${step.name}" at position ${i + 1} discards prior pipeline value`
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
      const ref = String(step.params?.name || "@output");
      const key = slotLabelKey(ref);
      if (key) {
        if (slotTypes.has(key)) {
          errors.push({
            message: `Duplicate out slot @${key}`,
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
        `export scalar produced ${current.length}-byte material — sss only accepts 16/32; use gpg.symencrypt for larger scalars`
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
    warnings.push(
      `Chain ${ci + 1}: trailing ${formatType(current)} is unhandled — ${tip}.`
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
  const { ast, errors } = parseRecipe(source);
  if (!ast || errors.length) {
    return {
      ast: null,
      validation: { ok: false, errors, warnings: [], inputNeeds: [] },
    };
  }
  return { ast, validation: validateRecipe(ast) };
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
  for (const s of listSteps()) {
    if (!s.name) issues.push("step missing name");
    if (!s.kind) issues.push(`${s.name}: missing kind`);
    if (!s.toolbox) issues.push(`${s.name}: missing toolbox`);
    if (!s.doc) issues.push(`${s.name}: missing doc`);
    if (!s.input) issues.push(`${s.name}: missing input`);
    if (!s.output) issues.push(`${s.name}: missing output`);
    for (const p of s.params || []) {
      if (!p.name) issues.push(`${s.name}: param missing name`);
      if (!p.type) issues.push(`${s.name}.${p.name}: missing type`);
    }
  }
  return issues;
}

/**
 * Preset recipes for the gallery.
 *
 * `group` clusters presets under a heading. Presets sharing a `pair` value are
 * companion pipelines (forward ⇄ inverse, e.g. split/recover or encrypt/decrypt)
 * and render side by side; the one listed first appears on the left.
 */
export const PRESETS = [
  {
    id: "p256-pem",
    group: "Generate keys",
    title: "P-256 public + private (PEM)",
    blurb:
      "Tee the public SPKI PEM, then export PKCS#8 — mid-stem fork keeps the keypair on the stem.",
    recipe: `genkey ec/p256 | tee
  - .public | export spki | pem | out @public
| export pkcs8 | pem | out @private`,
  },
  {
    id: "p256-tee-inspect",
    group: "Generate keys",
    title: "P-256 with mid-pipeline peek",
    blurb: "Generate a key, peek an openssl-style dump, then export PEM (keypair still flows through).",
    recipe: "genkey ec/p256 | peek keypair | export pkcs8 | pem | out @private",
  },
  {
    id: "p256-multichain",
    group: "Generate keys",
    title: "P-256 via @slot reuse",
    blurb:
      "Register the live keypair with out @kp, then reuse it across blank-line chains with in @kp.",
    recipe: `genkey ec/p256 | out @kp

in @kp | .public | export spki | pem | out @public
in @kp | export pkcs8 | pem | out @private`,
  },
  {
    id: "ed25519-jwk",
    group: "Generate keys",
    title: "Ed25519 key (JWK)",
    blurb: "Signing key as JSON Web Key.",
    recipe: "genkey ed25519 | export jwk | out @jwk",
  },
  {
    id: "secret-b64url",
    group: "Secrets & passphrases",
    title: "256-bit secret (base64url)",
    blurb: "Websafe random secret — no +/ or padding.",
    recipe: "random 32 | base64url | out @secret",
  },
  {
    id: "diceware",
    group: "Secrets & passphrases",
    title: "Diceware passphrase",
    blurb: "EFF Large Wordlist, 6 words (~77 bits).",
    recipe: "passphrase 6 | out @passphrase",
  },
  {
    id: "digest-sha256",
    group: "WebCrypto",
    title: "SHA-256 digest",
    blurb: "Hash 32 random bytes and show hex.",
    recipe: "random 32 | digest | hex | out @digest",
  },
  {
    id: "rsa-oaep-roundtrip",
    group: "WebCrypto",
    title: "RSA-OAEP encrypt / decrypt",
    blurb:
      "Generate an RSA-OAEP key, encrypt a message with rsa-oaep key=@rk, then decrypt across chains.",
    recipe: `genkey rsa/2048 usage=encrypt | out @rk

input | utf8 | rsa-oaep key=@rk | hex | out @ct

in @ct | hex -d | rsa-oaep -d key=@rk | utf8 | out @plain`,
  },
  {
    id: "hkdf-as-aes-gcm",
    group: "WebCrypto",
    title: "HKDF → AES key → encrypt",
    blurb:
      "Derive an AES-256 key with `hkdf as=aes/256` (deriveKey), then AES-GCM encrypt with key=@cek.",
    recipe: `random 32 | hkdf 32 as=aes/256 | out @cek

input | utf8 | aes-gcm key=@cek | base64url | out @ct`,
  },
  {
    id: "hkdf-as-aes-kw-wrap",
    group: "WebCrypto",
    title: "HKDF → AES-KW → wrap CEK",
    blurb:
      "Derive an AES-KW KEK (`as=aes-kw/256`), wrap a CEK with AES-KW, then unwrap.",
    recipe: `random 32 | hkdf 32 as=aes-kw/256 | out @kek

genkey aes/256 | out @cek

wrap key=@kek target=@cek | hex | out @wrapped

in @wrapped | hex -d | unwrap key=@kek | hex | out @cek-raw`,
  },
  {
    id: "wrap-aes-gcm",
    group: "WebCrypto",
    title: "Wrap CEK with AES-GCM",
    blurb:
      "SubtleCrypto wrapKey under AES-GCM (IV||wrapped packing). Prefer AES-KW for new key-wrap work.",
    recipe: `genkey aes/256 | out @kek
genkey aes/256 | out @cek

wrap mode=aes-gcm key=@kek target=@cek | hex | out @wrapped

in @wrapped | hex -d | unwrap mode=aes-gcm key=@kek | hex | out @cek-raw`,
  },
  {
    id: "x25519-ecdh",
    group: "WebCrypto",
    title: "X25519 ECDH → AES key",
    blurb:
      "Generate two X25519 keys, ECDH deriveBits, then HKDF to an AES-GCM CEK.",
    recipe: `genkey x25519 | out @local
genkey x25519 | out @peer

ecdh private=@local peer=@peer | hkdf 32 as=aes/256 | out @cek
in @cek | export jwk | out @cek-jwk`,
  },
  {
    id: "hmac-sign-verify",
    group: "WebCrypto",
    title: "HMAC sign / verify",
    blurb:
      "HMAC-SHA-256 via recipe sugar `hmac` / `hmac.verify` (serialize as sign/verify).",
    recipe: `genkey hmac/sha256 | out @mac

input | utf8 | out @msg

in @msg | hmac key=@mac | base64url | out @tag

in @msg | hmac.verify key=@mac signature=@tag | out @ok`,
  },
  {
    id: "jwk-thumbprint",
    group: "WebCrypto",
    title: "JWK SHA-256 digest",
    blurb:
      "Export a public JWK and SHA-256 digest the JSON text (handy fingerprint; not RFC 7638 canonical thumbprint).",
    recipe: `genkey ec/p256 | .public | export jwk | out @jwk

in @jwk | utf8 | digest | hex | out @thumb`,
  },
  {
    id: "aes-cbc-roundtrip",
    group: "WebCrypto",
    title: "AES-CBC encrypt / decrypt",
    blurb:
      "Unauthenticated AES-CBC interop (prefer aes-gcm for new work). Round-trip with key=@cek.",
    recipe: `genkey aes/256 | out @cek

input | utf8 | aes-cbc key=@cek | hex | out @ct

in @ct | hex -d | aes-cbc -d key=@cek | utf8 | out @plain`,
  },
  {
    id: "aes-ctr-roundtrip",
    group: "WebCrypto",
    title: "AES-CTR encrypt / decrypt",
    blurb:
      "Unauthenticated AES-CTR interop (prefer aes-gcm for new work). Round-trip with key=@cek.",
    recipe: `genkey aes/256 | out @cek

input | utf8 | aes-ctr key=@cek | hex | out @ct

in @ct | hex -d | aes-ctr -d key=@cek | utf8 | out @plain`,
  },
  {
    id: "verify-soft",
    group: "WebCrypto",
    title: "Soft signature verify",
    blurb:
      "Fail-soft verify (`-q`): emits text `verified` or `invalid` instead of throwing. Bind signature= (or the sig panel) at run time; prefer fail-loud for auth.",
    recipe: `genkey ed25519 | .public | export jwk | out @pub

input | utf8 | verify -q key=@pub | out @result`,
  },
  {
    id: "slip39-split",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "SSS + BLIP39 split a secret",
    blurb: "Generate 32 random bytes, Shamir-split 2-of-3, encode as BLIP39 mnemonics.",
    recipe: `random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  },
  {
    id: "recover-shares",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "Recover secret from BLIP39 shares",
    blurb: "Paste K-of-N mnemonics, decode to raw SSS, reconstruct the 16/32-byte master as Base64.",
    recipe: "shares | blip39 -d | sss.combine | base64 | out @secret",
  },
  {
    id: "out-mid-pipeline",
    group: "Split & recover",
    pair: "slip39-scalar",
    title: "Split P-256 scalar into shares",
    blurb:
      "Tee the public PEM, then SSS + BLIP39-split the 32-byte scalar (no envelope) — preferred for P-256 keys.",
    recipe: `genkey ec/p256 | tee
  - .public | export spki | pem | out @public
| export scalar | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  },
  {
    id: "rebuild-p256",
    group: "Split & recover",
    pair: "slip39-scalar",
    title: "Rebuild P-256 key from scalar shares",
    blurb: "Decode BLIP39 shares of a P-256 private scalar, recover SSS, and re-import as WebCrypto.",
    recipe:
      "shares | blip39 -d | sss.combine | import scalar alg=ec/p256 | export pkcs8 | pem | out @private",
  },
  {
    id: "quorum-gpg",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "P-256 scalar + quorum-share to GPG",
    blurb:
      "Tee the public PEM, SSS-split the 32-byte scalar 2-of-3, BLIP39-encode, encrypt each share to a different recipient.",
    recipe: `genkey ec/p256 | tee
  - .public | export spki | pem | out @public
| export scalar | sss.split threshold=2 shares=3 | blip39 | foreach
  - gpg.encrypt`,
  },
  {
    id: "decrypt-rebuild-p256",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Decrypt GPG shares → rebuild key",
    blurb:
      "Decrypt OpenPGP-wrapped shares in-browser and/or paste mnemonics already decrypted externally (e.g. Kleopatra/gpg + YubiKey), then blip39 -d | sss.combine and rebuild the P-256 PEM from the scalar.",
    recipe:
      "gpg.decrypt | blip39 -d | sss.combine | import scalar alg=ec/p256 | export pkcs8 | pem | out @private",
  },
  {
    id: "pem-envelope-split",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Split PEM via OpenPGP envelope",
    blurb:
      "Emit PKCS#8 PEM (@pem), OpenPGP-encrypt under a random 32-byte master, then SSS + BLIP39-split the master. Keep envelope.asc with the shares.",
    recipe: `genkey ec/p256 | export pkcs8 | pem | out @pem | gpg.symencrypt | sss.split threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  },
  {
    id: "pem-envelope-rebuild",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Recover PEM from envelope + shares",
    blurb:
      "Decode + recover shares to the hex master, then gpg.symdecrypt the bound envelope.asc (also works with gpg --decrypt).",
    recipe: "shares | blip39 -d | sss.combine | gpg.symdecrypt | utf8 | out @pem",
  },
  {
    id: "gpg-sign-verify",
    group: "OpenPGP",
    title: "OpenPGP sign / verify",
    blurb:
      "Cleartext-sign with a vault OpenPGP private key (`gpg.sign`), then verify (`gpg.verify`). Distinct from WebCrypto `sign`/`verify`.",
    recipe: `input | utf8 | gpg.sign | out @signed

in @signed | gpg.verify | out @ok`,
  },
  {
    id: "agent-sign-verify",
    group: "OpenPGP",
    title: "Vault sign / verify",
    blurb:
      "Unlock My Keys (`agent.unlock`), sign with `gpg.sign key=@me`, verify. Edit the fingerprint before running.",
    recipe: `agent.unlock AABBCCDDEEFF00112233445566778899AABBCCDD | out @me
input | gpg.sign key=@me | out @signed

in @signed | gpg.verify key=@me | out @ok`,
  },
  {
    id: "agent-gen-save",
    group: "OpenPGP",
    title: "Generate & save to My Keys",
    blurb:
      "`gpg.genkey` then `agent.save protection=device` into the browser vault.",
    recipe: `gpg.genkey email="you@example.com" | agent.save protection=device | out @priv`,
  },
  {
    id: "hkp-fetch-pub",
    group: "OpenPGP",
    title: "Fetch public key",
    blurb: "Pull armored public key from the keyserver (`hkp.get`). Edit the fingerprint before running.",
    recipe: `hkp.get AABBCCDDEEFF00112233445566778899AABBCCDD | out @bob`,
  },
  {
    id: "hkp-search-encrypt",
    group: "OpenPGP",
    title: "Search → encrypt (separate)",
    blurb:
      "Directory search → filter approved/encrypt → `gpg.encrypt to=@alices` (one ciphertext per recipient).",
    recipe: `hkp.search alice@example.org | hkp.filter | out @alices

input | gpg.encrypt to=@alices`,
  },
  {
    id: "hkp-encrypt-combined",
    group: "OpenPGP",
    title: "Group encrypt (combined)",
    blurb: "One OpenPGP message with N PKESKs (`mode=combined`).",
    recipe: `hkp.search alice@example.org | hkp.filter | out @alices

input | gpg.encrypt to=@alices mode=combined`,
  },
  {
    id: "agent-sign-encrypt-to",
    group: "OpenPGP",
    title: "Vault sign + encrypt to @alices",
    blurb:
      "Unlock My Keys, search recipients, sign-then-encrypt with `to=@alices` and `key=@me`.",
    recipe: `hkp.search alice@example.org | hkp.filter | out @alices
agent.unlock AABBCCDDEEFF00112233445566778899AABBCCDD | out @me

input | gpg.encrypt to=@alices -s key=@me mode=combined`,
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
    recipe: `gpg.genkey email="you@example.com" | out @priv`,
  },
  {
    id: "gpg-inspect",
    group: "OpenPGP",
    title: "Inspect OpenPGP armor",
    blurb: "Summarize armored ciphertext / signatures without decrypting.",
    recipe: `input | gpg.inspect format=packets | out @report`,
  },
  {
    id: "passphrase-char",
    group: "Basics",
    title: "Character passphrase",
    blurb: "69-char alphabet random passphrase (`passphrase mode=char`).",
    recipe: `passphrase mode=char length=20 | out @pass`,
  },
  {
    id: "base32-id",
    group: "Basics",
    title: "Base32 encode",
    blurb: "RFC 4648 Base32 (no padding) — same codec as Quorum room ids.",
    recipe: `random 10 | base32 | out @id`,
  },
];

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
import {
  formatType,
  isTerminalSink,
  resolveStepType,
  tNone,
  typeOf,
} from "./types.js";

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
 * @property {boolean} [foreachGpg]  encrypt gpg is inside foreach
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
    if (
      (step.name === "sign" ||
        step.name === "verify" ||
        step.name === "aesgcm" ||
        step.name === "ecdh" ||
        step.name === "wrap" ||
        step.name === "unwrap") &&
      !inputNeeds.includes("key")
    ) {
      inputNeeds.push("key");
    }
    if (step.name === "encrypt") encryptInBody = true;

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

    if (step.name === "sss") {
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

    if (step.name === "decrypt") {
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

    if (step.name === "symdecrypt") {
      if (!inputNeeds.includes("envelope")) inputNeeds.push("envelope");
    }

    if (
      (step.name === "sign" ||
        step.name === "verify" ||
        step.name === "aesgcm" ||
        step.name === "ecdh" ||
        step.name === "wrap" ||
        step.name === "unwrap") &&
      !inputNeeds.includes("key")
    ) {
      inputNeeds.push("key");
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
      step.name !== "recover" &&
      step.name !== "blip39" &&
      step.name !== "tee" &&
      step.name !== "peek" &&
      step.name !== "inspect" &&
      step.name !== "out" &&
      step.name !== "at" &&
      step.name !== "select"
    ) {
      errors.push({
        message: `Cannot pipe shares into "${step.name}" — add foreach to unpack, at N / [n] to select, blip39 to encode/decode, or recover (on raw shares) for bytes/master.`,
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
        `export scalar produced ${current.length}-byte material — sss only accepts 16/32; use symencrypt for larger scalars`
      );
    }

    if (step.name === "encrypt") {
      gpgSlots = Math.max(gpgSlots, 1);
    }
  }

  const first = getStep(steps[0].name);
  if (first && first.kind !== "source" && first.kind !== "flow") {
    errors.push({
      message: `Chain ${ci + 1} should start with a source (genkey, random, passphrase, input, in, decrypt), not "${steps[0].name}".`,
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
        ? "append recover (→ bytes/master) or foreach, or inspect to dump"
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
    id: "slip39-split",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "SSS + BLIP39 split a secret",
    blurb: "Generate 32 random bytes, Shamir-split 2-of-3, encode as BLIP39 mnemonics.",
    recipe: `random 32 | sss threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  },
  {
    id: "recover-shares",
    group: "Split & recover",
    pair: "slip39-secret",
    title: "Recover secret from BLIP39 shares",
    blurb: "Paste K-of-N mnemonics, decode to raw SSS, reconstruct the 16/32-byte master as Base64.",
    recipe: "shares | blip39 -d | recover | base64 | out @secret",
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
| export scalar | sss threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  },
  {
    id: "rebuild-p256",
    group: "Split & recover",
    pair: "slip39-scalar",
    title: "Rebuild P-256 key from scalar shares",
    blurb: "Decode BLIP39 shares of a P-256 private scalar, recover SSS, and re-import as WebCrypto.",
    recipe:
      "shares | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem | out @private",
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
| export scalar | sss threshold=2 shares=3 | blip39 | foreach
  - encrypt gpg`,
  },
  {
    id: "decrypt-rebuild-p256",
    group: "Split & recover",
    pair: "quorum-gpg",
    title: "Decrypt GPG shares → rebuild key",
    blurb:
      "Decrypt OpenPGP-wrapped shares in-browser and/or paste mnemonics already decrypted externally (e.g. Kleopatra/gpg + YubiKey), then blip39 -d | recover and rebuild the P-256 PEM from the scalar.",
    recipe:
      "decrypt gpg | blip39 -d | recover | import scalar alg=ec/p256 | export pkcs8 | pem | out @private",
  },
  {
    id: "pem-envelope-split",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Split PEM via OpenPGP envelope",
    blurb:
      "Emit PKCS#8 PEM (@pem), OpenPGP-encrypt under a random 32-byte master, then SSS + BLIP39-split the master. Keep envelope.asc with the shares.",
    recipe: `genkey ec/p256 | export pkcs8 | pem | out @pem | symencrypt | sss threshold=2 shares=3 | blip39 | foreach
  - out @share`,
  },
  {
    id: "pem-envelope-rebuild",
    group: "Split & recover",
    pair: "slip39-pem-envelope",
    title: "Recover PEM from envelope + shares",
    blurb:
      "Decode + recover shares to the hex master, then symdecrypt the bound envelope.asc (also works with gpg --decrypt).",
    recipe: "shares | blip39 -d | recover | symdecrypt | utf8 | out @pem",
  },
];

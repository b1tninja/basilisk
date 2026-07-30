/**
 * Tip-aware next-step ranking and SuggestRail toolbox model.
 * Shared by legacy `#suggest-next` and the React ToolkitShell rail.
 */

import {
  TOOLBOX_META,
  getStep,
  listSteps,
  stepsAccepting,
} from "./registry.js";
import {
  formatType,
  isTerminalSink,
  resolveStepType,
  tNone,
  walkPipelineTypes,
} from "./types.js";
import { projectTypeForMember } from "./recipe.js";

/** @typedef {import("./types.js").RefinedType} RefinedType */
/** @typedef {import("./registry.js").StepSpec} StepSpec */
/** @typedef {import("./recipe.js").RecipeStep} RecipeStep */

const KIND_ORDER = { source: 0, transform: 1, sink: 2, flow: 3 };

/**
 * Preferred next-step order for the current pipeline tip type.
 * Unknown names sort after these, by kind then name.
 * @param {RefinedType} from
 * @returns {string[]}
 */
export function preferredNextOrder(from) {
  if (!from || from.base === "none") {
    return [
      "genkey",
      "random",
      "shares",
      "input",
      "gpg.decrypt",
      "passphrase",
      "agent.list",
      "agent.unlock",
      "hkp.search",
      "hkp.get",
      "ecdh",
      "wrap",
    ];
  }
  if (from.base === "recipients") {
    return ["out", "hkp.filter", "recipients.merge", "inspect", "text", "tee", "peek"];
  }
  if (from.base === "openpgp-key") {
    if (from.which === "private") {
      return [
        "out",
        "agent.save",
        "gpg.inspect",
        "inspect",
        "tee",
        "peek",
        "text",
      ];
    }
    return ["out", "inspect", "tee", "peek", "text", "gpg.inspect"];
  }
  if (from.base === "shares") {
    if (from.kind === "raw") {
      return [
        "blip39",
        "sss.combine",
        "foreach",
        "at",
        "inspect",
        "out",
        "gpg.encrypt",
        "tee",
        "text",
        "qr",
      ];
    }
    return [
      "blip39",
      "foreach",
      "at",
      "inspect",
      "out",
      "gpg.encrypt",
      "tee",
      "text",
      "qr",
    ];
  }
  if (from.base === "keypair") {
    return ["export", "tee", "out", "peek", "inspect", "text", "gpg.encrypt"];
  }
  if (from.base === "key") {
    return ["export", "inspect", "tee", "out", "text"];
  }
  if (from.base === "bytes" && from.kind === "der") {
    return [
      "as",
      "import",
      "pem",
      "to",
      "base64",
      "base64url",
      "inspect",
      "out",
      "tee",
      "text",
      "gpg.encrypt",
    ];
  }
  if (from.base === "text" && (from.kind === "pem" || from.encoding === "pem")) {
    return [
      "der",
      "as",
      "out",
      "inspect",
      "text",
      "tee",
      "import",
      "from",
      "base64",
      "utf8",
      "gpg.encrypt",
    ];
  }
  if (from.base === "text" && from.encoding === "hex") {
    return [
      "from",
      "out",
      "inspect",
      "text",
      "tee",
      "base64",
      "utf8",
      "gpg.encrypt",
    ];
  }
  if (from.base === "bytes" && from.kind === "scalar") {
    return [
      "import",
      "sss.split",
      "to",
      "base64",
      "base64url",
      "inspect",
      "out",
      "tee",
      "text",
      "gpg.encrypt",
    ];
  }
  if (from.base === "bytes" && from.kind === "master") {
    return [
      "sss.split",
      "gpg.symdecrypt",
      "digest",
      "hkdf",
      "aes-gcm",
      "to",
      "base64",
      "base64url",
      "inspect",
      "out",
      "tee",
      "text",
      "gpg.encrypt",
    ];
  }
  if (from.base === "bytes") {
    return [
      "as",
      "digest",
      "sign",
      "aes-gcm",
      "hkdf",
      "pbkdf2",
      "gpg.symencrypt",
      "sss.split",
      "to",
      "base64",
      "base64url",
      "utf8",
      "pem",
      "import",
      "inspect",
      "out",
      "tee",
      "text",
      "gpg.encrypt",
      "qr",
    ];
  }
  if (from.base === "text") {
    return [
      "digest",
      "sign",
      "gpg.sign",
      "aes-gcm",
      "pbkdf2",
      "pem",
      "base64",
      "from",
      "utf8",
      "gpg.encrypt",
      "qr",
      "out",
      "text",
      "inspect",
      "tee",
      "gpg.symencrypt",
      "import",
    ];
  }
  return ["inspect", "out", "tee", "text", "gpg.encrypt", "ecdh", "wrap"];
}

/**
 * The closed projector-selector table (RECIPE.md "Projectors"). Ghost chips
 * read from this list and nothing else — it is a property of the grammar, not
 * a registry field to author. Index selectors (`[n]` / `[n:m]`) are stem
 * stages (`at`), not members, and iteration views (`:items`/`:keys`/`:values`)
 * are `foreach`'s own modifier — neither belongs here.
 */
export const PROJECTOR_SELECTORS = Object.freeze([
  ":public",
  ":private",
  ":key",
  ":value",
]);

/**
 * Selector ghosts that actually project the given tip — the "+ branch"
 * affordances for a `tee` on that tip. Fit-checked exactly like any op:
 * `keypair` offers `:public`/`:private`, `item` offers `:key`/`:value`,
 * anything else offers none (a plain no-selector branch is always available —
 * the EBNF makes the selector optional).
 * @param {RefinedType} tip
 * @returns {string[]}
 */
export function selectorGhostsFor(tip) {
  if (!tip || tip.base === "none") return [];
  return PROJECTOR_SELECTORS.filter((sel) => projectTypeForMember(tip, sel).ok);
}

/**
 * Compatible next steps for the builder suggest drawer, ranked for the tip type.
 * @param {RefinedType} from
 * @param {{ hasForeach?: boolean, terminal?: boolean, nested?: boolean }} [opts]
 * @returns {StepSpec[]}
 */
export function suggestedNextSteps(from, opts = {}) {
  const terminal = !!opts.terminal;
  const nested = !!opts.nested;
  let list = stepsAccepting(from).filter((s) => {
    // Nested tee/foreach is rejected by the parser (RECIPE.md, v1), so inside
    // a branch or body they are absent — not dimmed, absent, the same as any
    // op with zero possible fits. `tee` is kind "transform", so match names.
    if (nested && (s.name === "tee" || s.name === "foreach")) return false;
    if (s.kind === "flow") return s.name === "foreach";
    return true;
  });
  if (terminal) {
    list = list.filter((s) =>
      ["inspect", "tee", "peek", "out", "text"].includes(s.name)
    );
  }
  const preferred = preferredNextOrder(from);
  const kindOrder = (k) => KIND_ORDER[k] ?? 9;
  return list.slice().sort((a, b) => {
    const ia = preferred.indexOf(a.name);
    const ib = preferred.indexOf(b.name);
    const ra = ia === -1 ? 500 + kindOrder(a.kind) : ia;
    const rb = ib === -1 ? 500 + kindOrder(b.kind) : ib;
    return ra - rb || a.name.localeCompare(b.name);
  });
}

/**
 * Tip type after walking earlier cells + this cell's stem pipeline.
 * @param {Array<{ steps?: RecipeStep[] }>} chains
 * @param {number} cellIndex
 * @returns {{ tip: RefinedType, steps: RecipeStep[], terminal: boolean, hasForeach: boolean }}
 */
export function cellPipelineTip(chains, cellIndex) {
  /** @type {Map<string, RefinedType>} */
  const slots = new Map();
  for (let i = 0; i < cellIndex; i++) {
    walkPipelineTypes(chains[i]?.steps || [], { getStep }, slots);
  }
  const steps = chains[cellIndex]?.steps || [];
  const tip = walkPipelineTypes(steps, { getStep }, slots).final;
  const last = steps[steps.length - 1];
  const terminal = !!(last && (isTerminalSink(last.name) || last.name === "inspect"));
  return {
    tip,
    steps,
    terminal,
    hasForeach: steps.some((s) => s.name === "foreach"),
  };
}

/**
 * Type flowing into a `tee`/`foreach` nest slot at `stemIndex` — the value
 * just *before* that step runs, not the cell's overall final tip. A `tee`
 * branch (or `foreach` body) starts from a clone of that value, so this is
 * the caret fit each nested position should actually use (design v2 §21d).
 * Real-registry scope note: this repo's only nestable ops are `tee`/`foreach`
 * (free-form branches/body), not the mockup's fixed-slot `signAndEncrypt`
 * example — same principle (nest fit ≠ cell fit), applied to the ops that
 * actually exist here.
 * @param {Array<{ steps?: RecipeStep[] }>} chains
 * @param {number} cellIndex
 * @param {number} stemIndex
 * @returns {RefinedType}
 */
export function nestedTipFor(chains, cellIndex, stemIndex) {
  /** @type {Map<string, RefinedType>} */
  const slots = new Map();
  for (let i = 0; i < cellIndex; i++) {
    walkPipelineTypes(chains[i]?.steps || [], { getStep }, slots);
  }
  const steps = chains[cellIndex]?.steps || [];
  const { edges } = walkPipelineTypes(steps, { getStep }, slots);
  return edges[stemIndex]?.input || tNone();
}

/**
 * @param {RefinedType} tip
 * @param {{ terminal?: boolean, hasForeach?: boolean, nested?: boolean }} [opts]
 * @returns {{ next: StepSpec[], tipFit: Set<string> }}
 */
export function tipFitFor(tip, opts = {}) {
  const nested = !!opts.nested;
  const next = suggestedNextSteps(tip, opts);
  const tipFit = new Set(next.map((s) => s.name));
  for (const s of stepsAccepting(tip)) {
    if (nested && (s.name === "tee" || s.name === "foreach")) continue;
    tipFit.add(s.name);
  }
  return { next, tipFit };
}

/**
 * Group listSteps by toolbox for suggest rail catalogs.
 * @returns {Map<string, StepSpec[]>}
 */
export function suggestByToolboxMap() {
  /** @type {Map<string, StepSpec[]>} */
  const byToolbox = new Map();
  for (const s of listSteps()) {
    if (s.kitOnly) continue;
    if (s.kind === "flow" && s.name !== "foreach" && s.name !== "tee") continue;
    const tb = s.toolbox || "io";
    const list = byToolbox.get(tb) || [];
    list.push(s);
    byToolbox.set(tb, list);
  }
  return byToolbox;
}

/**
 * Toolbox squares + pull-out chips for SuggestRail.
 * @param {{
 *   next: StepSpec[],
 *   tip: RefinedType,
 *   tipFit: Set<string>,
 *   activeToolbox?: string | null,
 *   primaryCount?: number,
 *   stepBlocked?: (name: string) => boolean,
 * }} args
 */
export function buildSuggestRailModel({
  next,
  tip,
  tipFit,
  activeToolbox = null,
  primaryCount = 3,
  stepBlocked = () => false,
}) {
  const byToolbox = suggestByToolboxMap();
  /** @type {Map<string, { spec: StepSpec, index: number }[]>} */
  const nextByTb = new Map();
  next.forEach((s, index) => {
    const tb = s.toolbox || "io";
    const list = nextByTb.get(tb) || [];
    list.push({ spec: s, index });
    nextByTb.set(tb, list);
  });

  const keys = Object.keys(TOOLBOX_META).sort(
    (a, b) => (TOOLBOX_META[a]?.order ?? 9) - (TOOLBOX_META[b]?.order ?? 9)
  );

  const toolboxes = keys.map((tb) => {
    const meta = TOOLBOX_META[tb] || { label: tb, glyph: "gear", badge: tb };
    const catalog = byToolbox.get(tb) || [];
    const picks = nextByTb.get(tb) || [];
    const fit = picks.length > 0 || catalog.some((s) => tipFit.has(s.name));
    const tipNote = picks.length
      ? ` — ${picks.length} quick pick${picks.length === 1 ? "" : "s"}`
      : fit
        ? " — tip fits; browse in Toolkit"
        : catalog.length
          ? " — no quick picks for tip"
          : " — empty";
    return {
      id: tb,
      label: meta.label || tb,
      badge: meta.badge || meta.label || tb,
      glyph: meta.glyph || "gear",
      count: picks.length || undefined,
      fit: picks.length > 0,
      muted: !fit,
      enabled: catalog.length > 0,
      title: `${meta.label || tb}${tipNote}`,
    };
  });

  const openTb =
    activeToolbox && keys.includes(activeToolbox) ? activeToolbox : null;

  const pulloutChips = openTb
    ? (nextByTb.get(openTb) || []).map(({ spec, index }) => {
        const decode =
          spec.name === "blip39" && tip.base === "shares" && tip.kind === "mnemonic";
        const params = decode ? { decode: true } : {};
        const resolved = resolveStepType(spec, tip, params);
        const outLabel =
          resolved.ok && resolved.output.base !== "none"
            ? formatType(resolved.output)
            : spec.output || "";
        return {
          op: spec,
          decode,
          label: spec.label || spec.name,
          hint: outLabel || undefined,
          primary: index < primaryCount,
          blocked: stepBlocked(spec.name),
        };
      })
    : [];

  return { toolboxes, activeToolbox: openTb, pulloutChips, byToolbox };
}

/**
 * Flat tip-aware verb tiles (nest rails / compact item mode).
 * Compatible steps are enabled + fit; others in `catalog` are dimmed/disabled.
 * @param {StepSpec[]} next ranked compatible steps
 * @param {StepSpec[]} [catalog] broader set to show disabled (defaults to next only)
 * @param {Set<string>} tipFit
 */
export function suggestRailItems(next, catalog, tipFit) {
  const list = catalog?.length ? catalog : next;
  const seen = new Set();
  /** @type {{ op: StepSpec, label?: string, fit?: boolean, dim?: boolean, disabled?: boolean, title?: string }[]} */
  const items = [];
  for (const op of list) {
    if (seen.has(op.name)) continue;
    seen.add(op.name);
    const fit = tipFit.has(op.name);
    items.push({
      op,
      label: op.label || op.name,
      fit,
      dim: !fit,
      disabled: !fit,
      title: fit
        ? `${op.label || op.name} — fits tip`
        : `${op.label || op.name} — does not accept current tip type`,
    });
  }
  // Prefer fit first for scanning
  items.sort((a, b) => Number(b.fit) - Number(a.fit) || a.op.name.localeCompare(b.op.name));
  return items;
}

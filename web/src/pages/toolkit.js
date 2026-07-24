/**
 * Crypto Toolkit page — presets-first pipeline builder + recipe language.
 * Separate from /encrypt novice UX.
 */

import { Auth } from "../lib/auth.js";
import {
  CryptoModuleError,
  assertCryptoReady,
  formatCryptoVerifiedMessage,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { mountRecipientBinder } from "../lib/recipient-picker.js";
import {
  splitArmoredMessages,
  stripArmoredMessages,
} from "../lib/pgp/armor.js";
import { validateShareMnemonic } from "../lib/slip39/blip39.js";
import { base64ToBytes, hexToBytes } from "../lib/toolkit/encode.js";
import {
  PRESETS,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
  unresolvedInputs,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import { getStep, listSteps, stepsAccepting, TOOLBOX_META } from "../lib/toolkit/registry.js";
import {
  artifactIsTextualForEncrypt,
  formatType,
  isTerminalSink,
  resolveStepType,
  walkPipelineTypes,
} from "../lib/toolkit/types.js";
import {
  PROFILE_AUTO,
  PROFILE_COMPATIBLE,
  PROFILE_MODERN,
} from "../lib/pgp/encrypt.js";
import { formatProfileSpec } from "../lib/pgp/encrypt-intent.js";
import {
  copyTextTransient,
  escapeHtml,
  formatFingerprint,
  showError,
} from "../lib/utils.js";
import {
  buildZipStore,
  sanitizeFilename,
  uniquifyFilenames,
} from "../lib/zip-store.js";
import {
  getPasskeyPrf,
  listKeys as vaultListKeys,
  unlockKey as vaultUnlockKey,
} from "../lib/vault.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/toolkit");

const errorEl = document.getElementById("error");
const app = document.getElementById("toolkit-app");

let cryptoReady = false;
/** @type {import("../lib/toolkit/recipe.js").RecipeStep[]} */
let steps = [];
/** Display title for the current pipeline (from preset or user edit). */
let recipeTitle = "";
let referenceOpen = false;
/** @type {import("../lib/toolkit/engine.js").ToolkitArtifact[]} */
let artifacts = [];
/** @type {import("../lib/recipient-picker.js").Recipient[]} */
let boundRecipients = [];
/** @type {ReturnType<typeof mountRecipientBinder>|null} */
let binder = null;
/** @type {import("../lib/vault.js").VaultKeyMeta[]} */
let vaultKeys = [];
/** @type {("shares"|"gpg"|"text"|"envelope"|"key")[]} */
let currentInputNeeds = [];
/** Per-share mnemonic rows for the modular inputs UI (survives panel re-renders). */
/** @type {string[]} */
let shareRows = [""];
/** Envelope base64 retained across re-renders. */
let envelopeDraft = "";
/** Share passphrase retained across re-renders. */
let sharePassDraft = "";
/** Free-form input text retained across re-renders. */
let inputTextDraft = "";
/** WebCrypto JWK drafts for key-bound ops. */
let keyJwkDraft = "";
let peerJwkDraft = "";
let wrapJwkDraft = "";
let signatureDraft = "";
/** Ops drawer search query. */
let opsFilter = "";
/** Collapsed category keys in the ops drawer. */
/** @type {Set<string>} */
let opsCollapsed = new Set();
/** Whether the collapsed "Cryptographic parameters" section is expanded. */
let cryptoPanelOpen = false;
/** @type {"auto"|"compatible"|"modern"|"custom"} */
let toolkitEncryptPreset = "auto";
/** @type {import("../lib/pgp/types.js").EncryptProfile} */
let toolkitEncryptProfile = { ...PROFILE_AUTO };
let toolkitHideRecipients = false;

/** Steps that emit OpenPGP ciphertext and honor the encrypt profile. */
const PGP_PROFILE_STEPS = new Set(["symencrypt", "encrypt", "gpg"]);

/**
 * @param {"auto"|"compatible"|"modern"|"custom"} value
 * @param {{ render?: boolean }} [opts]
 */
function applyToolkitEncryptPreset(value, opts = {}) {
  if (value === "compatible") {
    toolkitEncryptPreset = "compatible";
    toolkitEncryptProfile = { ...PROFILE_COMPATIBLE };
  } else if (value === "modern") {
    toolkitEncryptPreset = "modern";
    toolkitEncryptProfile = { ...PROFILE_MODERN };
  } else if (value === "auto") {
    toolkitEncryptPreset = "auto";
    toolkitEncryptProfile = { ...PROFILE_AUTO };
  } else {
    toolkitEncryptPreset = "custom";
  }
  if (opts.render !== false) {
    renderBuilder();
    renderCryptoPanel();
  }
}

function toolkitPgpModeHint() {
  if (toolkitEncryptPreset === "compatible") {
    return `Compatible: ${formatProfileSpec(PROFILE_COMPATIBLE)} — no WASM (iterated S2K).`;
  }
  if (toolkitEncryptPreset === "modern") {
    return `Modern: ${formatProfileSpec(PROFILE_MODERN)} — Argon2 uses WASM.`;
  }
  if (toolkitEncryptPreset === "custom") {
    return `Custom: ${formatProfileSpec(toolkitEncryptProfile)}.`;
  }
  return `Auto: prefers ${formatProfileSpec(PROFILE_MODERN)}; falls back to compatible for legacy recipient keys. Password envelopes (symencrypt) always follow the selected profile.`;
}

/**
 * Segmented Modern / Compatible / Auto control (shared by recipe bar + blocks).
 * @param {string} radioName  unique name= for this radio group
 * @param {{ compact?: boolean }} [opts]
 */
function renderPgpModeToggle(radioName, opts = {}) {
  const modes = [
    { value: "auto", label: "Auto" },
    { value: "modern", label: "Modern" },
    { value: "compatible", label: "Compatible" },
  ];
  const active =
    toolkitEncryptPreset === "custom" ? "" : toolkitEncryptPreset;
  return `
    <div class="pgp-mode ${opts.compact ? "pgp-mode-compact" : ""}">
      <fieldset class="pgp-mode-toggle">
        <legend class="pgp-mode-legend">OpenPGP mode</legend>
        <div class="pgp-mode-options" role="presentation">
          ${modes
            .map(
              (m) => `<label class="pgp-mode-option${active === m.value ? " is-active" : ""}">
            <input type="radio" name="${escapeHtml(radioName)}" value="${m.value}"
              ${active === m.value ? "checked" : ""}>
            <span>${m.label}</span>
          </label>`
            )
            .join("")}
          ${
            toolkitEncryptPreset === "custom"
              ? `<span class="pgp-mode-custom" title="${escapeHtml(formatProfileSpec(toolkitEncryptProfile))}">Custom</span>`
              : ""
          }
        </div>
      </fieldset>
      ${opts.compact ? "" : `<p class="muted fs-xs pgp-mode-hint mb-0">${escapeHtml(toolkitPgpModeHint())}</p>`}
    </div>`;
}

/** @param {ParentNode} root */
function wirePgpModeToggles(root) {
  root.querySelectorAll(".pgp-mode-toggle input[type=radio]").forEach((el) => {
    el.addEventListener("change", () => {
      if (!(el instanceof HTMLInputElement) || !el.checked) return;
      applyToolkitEncryptPreset(
        /** @type {"auto"|"compatible"|"modern"} */ (el.value)
      );
    });
  });
}

function pipelineUsesOpenPgpEncrypt() {
  return steps.some((s) => PGP_PROFILE_STEPS.has(s.name));
}

const IDLE_CLEAR_MS = 5 * 60 * 1000;
let idleTimer = null;

/** Worker for the in-flight run, so a secure-destroy can terminate it. */
/** @type {Worker|null} */
let activeWorker = null;

const STEP_MIME = "application/x-basilisk-step";
const REORDER_MIME = "application/x-basilisk-reorder";

const KIND_META = {
  source: { label: "Sources", order: 0 },
  transform: { label: "Transforms", order: 1 },
  sink: { label: "Outputs", order: 2 },
  flow: { label: "Flow control", order: 3 },
};

/**
 * @param {string|undefined|null} toolbox
 * @returns {string}
 */
function toolboxBadgeHtml(toolbox) {
  const tb = toolbox || "io";
  const meta = TOOLBOX_META[tb] || { badge: tb, label: tb };
  return `<span class="toolbox-badge toolbox-${escapeHtml(tb)}" title="${escapeHtml(meta.label)}">${escapeHtml(meta.badge)}</span>`;
}

/**
 * Display name for a step (optional UI label, else recipe name).
 * @param {{ name: string, label?: string }|null|undefined} spec
 * @returns {string}
 */
function stepDisplayName(spec) {
  if (!spec) return "";
  return spec.label || spec.name;
}

app.innerHTML = `
  <div class="app-toolbar">
    <details class="toolbar-menu" id="preset-gallery">
      <summary class="btn btn-ghost btn-compact toolkit-presets-summary">Templates <span aria-hidden="true">▾</span></summary>
      <div class="toolbar-popover">
        <p class="muted m-0-b-md fs-sm">One-click pipelines. Drop more operations in afterward.</p>
        <div class="preset-grid" id="preset-grid"></div>
      </div>
    </details>
    <span id="crypto-status" class="app-status" role="status">Verifying crypto module…</span>
    <span class="app-toolbar-note muted fs-xs">Advanced tool — everyday messaging belongs on <a class="text-link" href="/encrypt">Encrypt</a>.</span>
    <button type="button" class="btn btn-ghost btn-compact" id="toggle-reference" title="Full step docs">Docs</button>
    <button type="button" class="btn btn-ghost btn-compact text-error" id="destroy-btn"
      title="Zeroize all in-memory secrets, inputs, and outputs (best-effort)">Destroy</button>
  </div>

  <div class="chef-workspace" id="chef-workspace">
    <aside class="chef-ops chef-pane" aria-label="Operations">
      <button type="button" class="pane-rail" data-collapse="ops" title="Expand Operations panel">
        <span>Operations</span>
      </button>
      <div class="pane-head">
        <p class="pane-title">Operations</p>
        <button type="button" class="btn btn-ghost btn-compact pane-collapse" data-collapse="ops"
          aria-label="Collapse Operations panel" title="Collapse panel">‹</button>
      </div>
      <div class="pane-body">
        <input type="search" id="ops-filter" class="text-input" placeholder="Search operations…" autocomplete="off">
        <p class="muted fs-xs mt-xs mb-sm" id="ops-hint">Drag onto the pipeline, or click to append.</p>
        <div id="ops-drawer" class="ops-drawer"></div>
      </div>
    </aside>

    <div class="pane-splitter" data-resize="ops" role="separator" aria-orientation="vertical"
      aria-label="Resize Operations panel" title="Drag to resize · double-click to reset"></div>

    <section class="chef-recipe chef-pane" aria-label="Pipeline">
      <div class="pane-head">
        <p class="pane-title">Pipeline</p>
        <div class="pane-actions">
          <button type="button" class="btn btn-ghost btn-compact" id="clear-recipe-btn">Clear</button>
          <button type="button" class="btn btn-compact" id="run-btn" disabled>Execute</button>
        </div>
      </div>
      <div class="pane-body">
        <label class="recipe-heading">
          <span class="sr-only">Recipe title</span>
          <input type="text" id="recipe-title" class="recipe-title-input" maxlength="120"
            placeholder="Untitled recipe" autocomplete="off" spellcheck="false">
        </label>
        <p class="muted fs-sm mb-md">Drop operations here. Reorder by dragging cards. Recipients are chosen at run time — never stored in the pipeline text.</p>
        <div id="pgp-mode-host" class="pgp-mode-host hidden"></div>
        <div id="builder-steps" class="builder-steps"></div>
        <div id="suggest-next" class="suggest-next" hidden></div>
        <details class="recipe-text-details mt-md">
          <summary class="muted fs-sm">Pipeline source (text)</summary>
          <textarea id="recipe-text" class="compose-message mt-sm" rows="3" spellcheck="false"
            placeholder="genkey ec/p256 | export pkcs8 | pem"></textarea>
          <p id="recipe-errors" class="status-row err hidden mt-sm"></p>
          <p id="recipe-warnings" class="muted mt-xs fs-sm"></p>
        </details>
        <div id="crypto-params-host"></div>
        <div id="inputs-host"></div>
        <div id="recipient-bind-host"></div>
        <p id="run-status" class="status-row hidden mt-sm"></p>
      </div>
    </section>

    <div class="pane-splitter" data-resize="run" role="separator" aria-orientation="vertical"
      aria-label="Resize Output panel" title="Drag to resize · double-click to reset"></div>

    <section class="chef-run chef-pane" aria-label="Output">
      <button type="button" class="pane-rail" data-collapse="run" title="Expand Output panel">
        <span>Output</span>
      </button>
      <div class="pane-head">
        <p class="pane-title">Output</p>
        <button type="button" class="btn btn-ghost btn-compact pane-collapse" data-collapse="run"
          aria-label="Collapse Output panel" title="Collapse panel">›</button>
      </div>
      <div class="pane-body">
        <p id="output-empty" class="muted fs-sm">Execute a pipeline to see results here.</p>
        <div id="results-panel" class="hidden"></div>
      </div>
    </section>
  </div>

  <div id="reference-panel" class="reference-drawer hidden">
    <div class="pane-head">
      <p class="pane-title">Step reference</p>
      <button type="button" class="btn btn-ghost btn-compact" id="close-reference" aria-label="Close reference">✕</button>
    </div>
    <div class="pane-body" id="reference-body"></div>
  </div>
`;

/* ===== Workspace layout: resizable + collapsible panes (desktop) ===== */

const LAYOUT_KEY = "basilisk.toolkit.layout";
const PANE_LIMITS = {
  ops: { min: 180, max: 520, def: 280 },
  run: { min: 260, max: 720, def: 380 },
};

function loadLayout() {
  try {
    return JSON.parse(localStorage.getItem(LAYOUT_KEY) || "{}") || {};
  } catch (_) {
    return {};
  }
}

/** @param {Record<string, number|boolean|null>} patch */
function saveLayout(patch) {
  try {
    const next = { ...loadLayout(), ...patch };
    for (const k of Object.keys(next)) {
      if (next[k] == null) delete next[k];
    }
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(next));
  } catch (_) {
    /* private mode etc. — layout just won't persist */
  }
}

function initWorkspaceLayout() {
  const ws = document.getElementById("chef-workspace");
  if (!ws) return;

  const layout = loadLayout();
  for (const side of /** @type {("ops"|"run")[]} */ (["ops", "run"])) {
    const w = Number(layout[`${side}W`]);
    if (Number.isFinite(w) && w >= PANE_LIMITS[side].min) {
      ws.style.setProperty(`--${side}-w`, `${w}px`);
    }
    ws.classList.toggle(`${side}-collapsed`, !!layout[`${side}Collapsed`]);
  }

  // Collapse buttons and expand rails share the data-collapse attribute.
  ws.querySelectorAll("[data-collapse]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const side = btn.getAttribute("data-collapse");
      if (side !== "ops" && side !== "run") return;
      const collapsed = ws.classList.toggle(`${side}-collapsed`);
      saveLayout({ [`${side}Collapsed`]: collapsed || null });
    });
  });

  ws.querySelectorAll(".pane-splitter").forEach((split) => {
    const side = split.getAttribute("data-resize");
    if ((side !== "ops" && side !== "run") || !(split instanceof HTMLElement)) return;
    const limits = PANE_LIMITS[side];

    split.addEventListener("dblclick", () => {
      ws.style.removeProperty(`--${side}-w`);
      saveLayout({ [`${side}W`]: null });
    });

    split.addEventListener("pointerdown", (e) => {
      if (ws.classList.contains(`${side}-collapsed`)) return;
      e.preventDefault();
      split.setPointerCapture(e.pointerId);
      split.classList.add("dragging");
      let width = NaN;

      const onMove = (ev) => {
        const rect = ws.getBoundingClientRect();
        width =
          side === "ops" ? ev.clientX - rect.left : rect.right - ev.clientX;
        width = Math.round(Math.max(limits.min, Math.min(limits.max, width)));
        ws.style.setProperty(`--${side}-w`, `${width}px`);
      };
      const onUp = () => {
        split.classList.remove("dragging");
        split.removeEventListener("pointermove", onMove);
        if (Number.isFinite(width)) saveLayout({ [`${side}W`]: width });
      };
      split.addEventListener("pointermove", onMove);
      split.addEventListener("pointerup", onUp, { once: true });
      split.addEventListener("pointercancel", onUp, { once: true });
    });
  });
}

initWorkspaceLayout();

function touchActivity() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    // Idle auto-scrub: wipe secrets, inputs and outputs but keep the pipeline
    // definition (it is not secret) so the user can re-run after stepping away.
    secureDestroy({ quiet: true });
  }, IDLE_CLEAR_MS);
}

/**
 * Best-effort secure destroy of in-memory sensitive material.
 *
 * DO NOT weaken this without reading `src/lib/memory-safety.js` (canonical
 * policy + W3C/MDN cites). Browser JS cannot mlock or force UA CryptoKey
 * zeroization (https://www.w3.org/TR/webcrypto/#security-developers). We do
 * the portable best-effort stack:
 *   - terminate the crypto worker so its heap (decrypted private keys,
 *     plaintext, pipeline buffers) is discarded wholesale;
 *   - overwrite owned Uint8Array secrets with inlined fill(0) at each use site
 *     (no shared zeroBuffer — see memory-safety.js; strings cannot be wiped);
 *   - drop every reference to secret-bearing objects so they become collectable;
 *   - clear input/output DOM fields so revealed secrets leave the layout.
 * The pipeline definition itself is not a secret and is preserved (use Clear
 * to reset it).
 *
 * @param {{ quiet?: boolean }} [opts]
 */
function secureDestroy(opts = {}) {
  // 1. Kill any in-flight worker — its heap holds the most sensitive material.
  if (activeWorker) {
    try {
      activeWorker.terminate();
    } catch (_) {
      /* ignore */
    }
    activeWorker = null;
  }

  // 2. Drop references to secret-bearing module state.
  artifacts = [];
  boundRecipients = [];
  if (binder) {
    binder.destroy();
    binder = null;
  }
  shareRows = [""];
  envelopeDraft = "";
  sharePassDraft = "";
  inputTextDraft = "";

  // 3. Clear sensitive DOM fields (pasted keys, passphrases, shares, ciphertext).
  for (const id of [
    "input-text",
    "input-envelope",
    "input-share-pass",
    "input-ciphertext",
    "input-privkey",
    "input-key-pass",
  ]) {
    const el = document.getElementById(id);
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      el.value = "";
    }
  }
  document.querySelectorAll(".share-mnemonic").forEach((el) => {
    if (el instanceof HTMLTextAreaElement) el.value = "";
  });

  // 4. Re-render: rebuilds inputs empty and replaces the output pane (revealed
  //    secrets in the DOM are dropped with the old markup).
  renderResults();
  validateAndBind();

  // 5. Idle timer no longer needed until next activity.
  clearTimeout(idleTimer);

  if (!opts.quiet) {
    const status = document.getElementById("run-status");
    if (status) {
      status.className = "status-row ok";
      status.textContent =
        "Destroyed — in-memory secrets, inputs and outputs cleared (best-effort).";
      status.classList.remove("hidden");
    }
  }
}

function setRecipeFromSteps() {
  const ta = document.getElementById("recipe-text");
  if (ta instanceof HTMLTextAreaElement) {
    ta.value = serializeRecipe(steps);
  }
  validateAndBind();
  renderBuilder();
  renderSuggestDrawer();
  renderCryptoPanel();
  renderOpsDrawer();
}

/**
 * @param {import("../lib/toolkit/registry.js").StepSpec} spec
 * @returns {Record<string, string|number|boolean>}
 */
function defaultParams(spec) {
  /** @type {Record<string, string|number|boolean>} */
  const params = {};
  for (const p of spec.params || []) {
    if (p.default !== undefined) params[p.name] = p.default;
  }
  return params;
}

/**
 * @param {string} name
 * @param {number} [index]
 * @param {Record<string, string|number|boolean>} [paramOverrides]
 */
function addStepAt(name, index, paramOverrides) {
  const spec = getStep(name);
  if (!spec) return;
  const step = {
    name: spec.name,
    params: { ...defaultParams(spec), ...(paramOverrides || {}) },
    start: 0,
    end: 0,
  };
  const at =
    index == null || Number.isNaN(index)
      ? steps.length
      : Math.max(0, Math.min(steps.length, index));
  steps.splice(at, 0, step);
  setRecipeFromSteps();
}

/**
 * Refined output type after walking the builder pipeline (for suggesting ops).
 * @returns {import("../lib/toolkit/types.js").RefinedType}
 */
function currentPipelineOutput() {
  return walkPipelineTypes(steps, { getStep }).final;
}

/**
 * Per-step refined type edges for the builder.
 * @returns {ReturnType<typeof walkPipelineTypes>["edges"]}
 */
function builderTypeEdges() {
  return walkPipelineTypes(steps, { getStep }).edges;
}

/**
 * Sync fanout/export `which` when format locks the key half.
 * @param {import("../lib/toolkit/recipe.js").RecipeStep} step
 */
function syncWhichWithFormat(step) {
  if (step.name !== "fanout" && step.name !== "export") return;
  const format = String(step.params.format || "");
  if (format === "spki") step.params.which = "public";
  else if (format === "pkcs8" || format === "scalar" || format === "d") {
    step.params.which = "private";
  }
}

/**
 * Whether a param should be shown/locked for the current step params.
 * @param {string} stepName
 * @param {{ name: string }} param
 * @param {Record<string, *>} params
 * @returns {{ show: boolean, locked?: boolean, forced?: string }}
 */
function paramVisibility(stepName, param, params) {
  if (param.name !== "which") return { show: true };
  const format = String(params.format || "");
  if (stepName === "fanout" || stepName === "export") {
    if (format === "spki") {
      return { show: true, locked: true, forced: "public" };
    }
    if (format === "pkcs8" || format === "scalar" || format === "d") {
      return { show: true, locked: true, forced: "private" };
    }
  }
  return { show: true };
}

/**
 * @param {string} text
 * @param {{ title?: string }} [opts]
 */
function loadRecipeText(text, opts = {}) {
  const { ast, errors } = parseRecipe(text);
  const errEl = document.getElementById("recipe-errors");
  if (errors.length || !ast) {
    if (errEl) {
      errEl.textContent = errors.map((e) => e.message).join(" · ");
      errEl.classList.remove("hidden");
    }
    return;
  }
  steps = ast.steps.map((s) => ({
    name: s.name,
    params: { ...s.params },
    start: s.start,
    end: s.end,
  }));
  if (opts.title != null) setRecipeTitle(opts.title);
  if (errEl) errEl.classList.add("hidden");
  validateAndBind();
  renderBuilder();
  renderSuggestDrawer();
  renderCryptoPanel();
  renderOpsDrawer();
}

/** @param {string} title */
function setRecipeTitle(title) {
  recipeTitle = String(title || "").trim();
  const el = document.getElementById("recipe-title");
  if (el instanceof HTMLInputElement && el.value !== recipeTitle) {
    el.value = recipeTitle;
  }
}

function validateAndBind() {
  const { ast, validation } = compileRecipe(serializeRecipe(steps));
  const errEl = document.getElementById("recipe-errors");
  const warnEl = document.getElementById("recipe-warnings");
  const runBtn = document.getElementById("run-btn");

  if (!validation.ok) {
    if (errEl) {
      errEl.textContent = validation.errors.map((e) => e.message).join(" · ");
      errEl.classList.remove("hidden");
    }
    if (runBtn) runBtn.disabled = true;
  } else {
    if (errEl) errEl.classList.add("hidden");
    if (runBtn) runBtn.disabled = !cryptoReady;
  }
  if (warnEl) {
    warnEl.textContent = (validation.warnings || []).join(" · ");
  }

  // Runtime inputs (shares / GPG ciphertext)
  currentInputNeeds = validation.inputNeeds || (ast ? unresolvedInputs(ast) : []);
  renderInputsPanel(currentInputNeeds);

  // Recipient binder
  const host = document.getElementById("recipient-bind-host");
  if (!host) return;
  const slots = validation.recipientSlots || 0;
  if (binder) {
    binder.destroy();
    binder = null;
  }
  boundRecipients = [];
  if (slots > 0 && ast) {
    const info = unresolvedRecipients(ast);
    binder = mountRecipientBinder(host, {
      slots: info.slots || slots,
      foreach: info.foreach,
      onChange: (recs) => {
        boundRecipients = recs;
      },
    });
  } else {
    host.innerHTML = "";
  }
}

/**
 * @param {string} mnemonic
 * @returns {string}
 */
function shareChecksumBadge(mnemonic) {
  const trimmed = String(mnemonic || "").trim();
  if (!trimmed) {
    return `<span class="share-badge share-badge-empty">empty</span>`;
  }
  const v = validateShareMnemonic(trimmed);
  if (v.ok) {
    return `<span class="share-badge share-badge-ok" title="RS1024 checksum valid">valid</span>`;
  }
  return `<span class="share-badge share-badge-bad" title="${escapeHtml(
    v.error || "invalid"
  )}">invalid</span>`;
}

/**
 * Split pasted text into mnemonic lines (blank-line or newline separated).
 * @param {string} text
 * @returns {string[]}
 */
function splitSharePaste(text) {
  const raw = String(text || "").trim();
  if (!raw) return [];
  // Prefer blank-line separated blocks (full mnemonics), else one line each.
  if (/\n\s*\n/.test(raw)) {
    return raw
      .split(/\n\s*\n/)
      .map((b) => b.replace(/\s+/g, " ").trim())
      .filter(Boolean);
  }
  return raw
    .split(/\n+/)
    .map((l) => l.trim())
    .filter(Boolean);
}

/**
 * @param {("shares"|"gpg"|"text"|"envelope"|"key")[]} needs
 */
function renderInputsPanel(needs) {
  const host = document.getElementById("inputs-host");
  if (!host) return;
  if (!needs.length) {
    host.innerHTML = "";
    return;
  }
  if (!shareRows.length) shareRows = [""];

  const title = needs.includes("shares")
    ? "Share mnemonics"
    : needs.includes("gpg")
      ? "Decrypt"
      : needs.includes("key")
        ? "WebCrypto key"
        : needs.includes("envelope")
          ? "Envelope"
          : "Input";
  /** @type {string[]} */
  const parts = [`<p class="card-title">${title}</p>`];
  if (needs.includes("shares")) {
    parts.push(
      `<p class="muted fs-sm mb-sm">Runtime binding for the <code>shares</code> source → type <code>shares/mnemonic</code>. Pipe into <code>blip39 -d</code> then <code>recover</code> to get <code>bytes/master</code>.</p>`
    );
  }
  if (needs.includes("key")) {
    parts.push(`
      <p class="muted fs-sm mb-sm">Bound WebCrypto key for <code>sign</code> / <code>verify</code> / <code>aesgcm</code> / <code>ecdh</code> / <code>wrap</code>. Paste a JWK from <code>genkey | export jwk</code>. Recipe tokens stay unique — OpenPGP <code>encrypt</code> is a different toolbox.</p>
      <label class="field-label" for="input-wc-jwk">Key JWK</label>
      <textarea id="input-wc-jwk" class="compose-message" rows="4" spellcheck="false"
        placeholder='{"kty":"EC","crv":"P-256",…} or oct AES/HMAC'>${escapeHtml(keyJwkDraft)}</textarea>
      <label class="field-label mt-sm" for="input-wc-peer">Peer public JWK (ecdh)</label>
      <textarea id="input-wc-peer" class="compose-message" rows="3" spellcheck="false"
        placeholder="Peer public JWK for ecdh">${escapeHtml(peerJwkDraft)}</textarea>
      <label class="field-label mt-sm" for="input-wc-wrap">Key-to-wrap JWK (wrap)</label>
      <textarea id="input-wc-wrap" class="compose-message" rows="3" spellcheck="false"
        placeholder="oct JWK to wrap">${escapeHtml(wrapJwkDraft)}</textarea>
      <label class="field-label mt-sm" for="input-wc-sig">Signature base64url (verify)</label>
      <input type="text" id="input-wc-sig" class="text-input" spellcheck="false"
        value="${escapeHtml(signatureDraft)}" placeholder="base64url signature">
    `);
  }
  if (needs.includes("text")) {
    parts.push(`
      <div class="btn-row wrap mb-xs">
        <label class="field-label m-0" for="input-text">Input text</label>
        <button type="button" class="btn btn-ghost btn-compact" id="load-input-text-btn">Load from file…</button>
        <input type="file" id="load-input-text-file" class="hidden" multiple accept="*/*">
      </div>
      <textarea id="input-text" class="compose-message" rows="6" spellcheck="false"
        placeholder="Paste text here, or load it from a file — it feeds the input step at run time and is never stored in the pipeline.">${escapeHtml(inputTextDraft)}</textarea>
    `);
  }
  if (needs.includes("shares")) {
    const rowsHtml = shareRows
      .map(
        (m, i) => `
      <div class="share-row" data-share-idx="${i}">
        <div class="share-row-head">
          <span class="field-label m-0">Share ${i + 1}</span>
          ${shareChecksumBadge(m)}
          <button type="button" class="btn btn-ghost btn-compact text-error" data-remove-share="${i}"
            ${shareRows.length <= 1 ? "disabled" : ""} aria-label="Remove share">Remove</button>
        </div>
        <textarea class="compose-message share-mnemonic" data-share-input="${i}" rows="2"
          spellcheck="false" placeholder="Paste one mnemonic share (or several lines — they will split into rows)">${escapeHtml(m)}</textarea>
      </div>`
      )
      .join("");
    parts.push(`
      <div class="share-inputs">
        <div class="btn-row wrap mb-sm">
          <span class="field-label m-0">BLIP39 share mnemonics</span>
          <button type="button" class="btn btn-ghost btn-compact" id="add-share-btn">+ Add share</button>
          <button type="button" class="btn btn-ghost btn-compact" id="load-shares-btn">Load from file…</button>
          <input type="file" id="load-shares-file" class="hidden" multiple accept=".txt,text/plain,*/*">
        </div>
        <p class="muted fs-sm mb-sm">${
          needs.includes("gpg")
            ? "Use these rows for mnemonics already decrypted outside the browser (Kleopatra/gpg/YubiKey). Mix with OpenPGP ciphertext below — the pipeline merges both before blip39 -d | recover."
            : "One share per row. Paste multiple lines into a row to auto-split. K-of-N required to recover. Direct 16/32-byte splits need no envelope."
        }</p>
        <div id="share-rows">${rowsHtml}</div>
        <label class="field-label mt-md" for="input-share-pass">Share passphrase (optional)</label>
        <input type="password" id="input-share-pass" class="text-input" autocomplete="off" value="${escapeHtml(sharePassDraft)}">
      </div>
    `);
  }
  if (needs.includes("envelope")) {
    parts.push(`
      <div class="envelope-inputs mt-md">
        <div class="btn-row wrap mb-xs">
          <label class="field-label m-0" for="input-envelope">OpenPGP envelope (armored)</label>
          <button type="button" class="btn btn-ghost btn-compact" id="load-envelope-btn">Load envelope.asc…</button>
          <input type="file" id="load-envelope-file" class="hidden" accept=".asc,.pgp,.txt,*/*">
        </div>
        <textarea id="input-envelope" class="compose-message" rows="6" spellcheck="false"
          placeholder="-----BEGIN PGP MESSAGE-----&#10;…&#10;-----END PGP MESSAGE-----&#10;Required for symdecrypt (PEM / large-payload path). Not used for direct scalar splits.">${escapeHtml(envelopeDraft)}</textarea>
        <p class="muted fs-sm mt-xs">This is the OpenPGP symmetric ciphertext from <code>symencrypt</code> — distinct from BLIP39 share mnemonics. External recovery: <code>blip39 -d | recover</code> → hex master → <code>gpg --decrypt envelope.asc</code>.</p>
      </div>
    `);
  }
  if (needs.includes("gpg")) {
    const vaultOpts = vaultKeys.length
      ? vaultKeys
          .map(
            (k) =>
              `<option value="${escapeHtml(k.fingerprint)}">${escapeHtml(
                formatFingerprint(k.fingerprint)
              )} · ${escapeHtml(k.protection)}${
                k.email ? ` · ${escapeHtml(k.email)}` : ""
              }</option>`
          )
          .join("")
      : "";
    parts.push(`
      <div class="btn-row wrap mt-md mb-xs">
        <label class="field-label m-0" for="input-ciphertext">OpenPGP ciphertext</label>
        <button type="button" class="btn btn-ghost btn-compact" id="load-ciphertext-btn">Load from file…</button>
        <input type="file" id="load-ciphertext-file" class="hidden" multiple accept=".asc,.pgp,.txt,*/*">
      </div>
      <textarea id="input-ciphertext" class="compose-message" rows="8" spellcheck="false"
        placeholder="Paste -----BEGIN PGP MESSAGE----- blocks (and/or already-decrypted mnemonics). Smartcard/YubiKey OpenPGP keys cannot be used in the browser — decrypt those externally and paste mnemonics in the share rows above."></textarea>
      <label class="field-label mt-md" for="input-vault-key">Vault private key (only for ciphertext you can decrypt here)</label>
      <select id="input-vault-key" class="text-input">
        <option value="">— paste key below / not needed if all shares are plaintext —</option>
        ${vaultOpts}
      </select>
      <label class="field-label mt-md" for="input-privkey">Armored private key (optional if using vault)</label>
      <textarea id="input-privkey" class="compose-message" rows="4" spellcheck="false"
        placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"></textarea>
      <label class="field-label mt-md" for="input-key-pass">Key passphrase</label>
      <input type="password" id="input-key-pass" class="text-input" autocomplete="off"
        placeholder="If the OpenPGP key is locked">
      <p class="muted mt-xs fs-sm">Software/vault keys unlock only for this run. OpenPGP smartcards are not accessible from the browser — leave the key blank and paste externally decrypted mnemonics above.</p>
    `);
  }
  host.innerHTML = parts.join("\n");
  wireInputsPanel(host, needs);
}

/**
 * @param {HTMLElement} host
 * @param {("shares"|"gpg"|"text"|"envelope")[]} needs
 */
function wireInputsPanel(host, needs) {
  if (needs.includes("text")) {
    const textEl = host.querySelector("#input-text");
    textEl?.addEventListener("input", () => {
      if (textEl instanceof HTMLTextAreaElement) inputTextDraft = textEl.value;
    });

    wireFileButton(host, "#load-input-text-btn", "#load-input-text-file", async (files) => {
      /** @type {string[]} */
      const chunks = [];
      for (const f of files) chunks.push(await f.text());
      const joined = chunks.join("\n").replace(/\n+$/, "");
      if (!joined) return;
      inputTextDraft = inputTextDraft.trim()
        ? `${inputTextDraft.replace(/\n+$/, "")}\n${joined}`
        : joined;
      if (textEl instanceof HTMLTextAreaElement) textEl.value = inputTextDraft;
    });
  }

  if (needs.includes("shares")) {
    host.querySelector("#add-share-btn")?.addEventListener("click", () => {
      shareRows.push("");
      renderInputsPanel(currentInputNeeds);
    });

    host.querySelectorAll("[data-remove-share]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.getAttribute("data-remove-share"));
        if (shareRows.length <= 1) return;
        shareRows.splice(i, 1);
        renderInputsPanel(currentInputNeeds);
      });
    });

    host.querySelectorAll("[data-share-input]").forEach((el) => {
      el.addEventListener("input", () => {
        const i = Number(el.getAttribute("data-share-input"));
        if (!(el instanceof HTMLTextAreaElement) || i < 0) return;
        const parts = splitSharePaste(el.value);
        if (parts.length > 1) {
          shareRows.splice(i, 1, ...parts);
          renderInputsPanel(currentInputNeeds);
          return;
        }
        shareRows[i] = el.value;
        const row = el.closest(".share-row");
        const badge = row?.querySelector(".share-badge");
        if (badge) {
          badge.outerHTML = shareChecksumBadge(el.value);
        }
      });
    });

    const passEl = host.querySelector("#input-share-pass");
    passEl?.addEventListener("input", () => {
      if (passEl instanceof HTMLInputElement) sharePassDraft = passEl.value;
    });

    wireFileButton(host, "#load-shares-btn", "#load-shares-file", async (files) => {
      /** @type {string[]} */
      const loaded = [];
      for (const f of files) {
        const text = await f.text();
        loaded.push(...splitSharePaste(text));
      }
      if (!loaded.length) return;
      const nonempty = shareRows.filter((s) => s.trim());
      shareRows = nonempty.length ? [...nonempty, ...loaded] : loaded;
      renderInputsPanel(currentInputNeeds);
    });
  }

  if (needs.includes("envelope")) {
    const envEl = host.querySelector("#input-envelope");
    envEl?.addEventListener("input", () => {
      if (envEl instanceof HTMLTextAreaElement) envelopeDraft = envEl.value;
    });
    wireFileButton(host, "#load-envelope-btn", "#load-envelope-file", async (files) => {
      const f = files[0];
      if (!f) return;
      envelopeDraft = await readEnvelopeAscFile(f);
      renderInputsPanel(currentInputNeeds);
    });
  }

  if (needs.includes("gpg")) {
    wireFileButton(host, "#load-ciphertext-btn", "#load-ciphertext-file", async (files) => {
      const ctEl = host.querySelector("#input-ciphertext");
      if (!(ctEl instanceof HTMLTextAreaElement)) return;
      /** @type {string[]} */
      const chunks = [];
      for (const f of files) chunks.push(await f.text());
      const joined = chunks.join("\n\n").trim();
      ctEl.value = ctEl.value.trim()
        ? `${ctEl.value.trim()}\n\n${joined}`
        : joined;
    });
  }

  if (needs.includes("key")) {
    const jwkEl = host.querySelector("#input-wc-jwk");
    jwkEl?.addEventListener("input", () => {
      if (jwkEl instanceof HTMLTextAreaElement) keyJwkDraft = jwkEl.value;
    });
    const peerEl = host.querySelector("#input-wc-peer");
    peerEl?.addEventListener("input", () => {
      if (peerEl instanceof HTMLTextAreaElement) peerJwkDraft = peerEl.value;
    });
    const wrapEl = host.querySelector("#input-wc-wrap");
    wrapEl?.addEventListener("input", () => {
      if (wrapEl instanceof HTMLTextAreaElement) wrapJwkDraft = wrapEl.value;
    });
    const sigEl = host.querySelector("#input-wc-sig");
    sigEl?.addEventListener("input", () => {
      if (sigEl instanceof HTMLInputElement) signatureDraft = sigEl.value;
    });
  }
}

/**
 * @param {ParentNode} host
 * @param {string} btnSel
 * @param {string} inputSel
 * @param {(files: File[]) => void | Promise<void>} onFiles
 */
function wireFileButton(host, btnSel, inputSel, onFiles) {
  const btn = host.querySelector(btnSel);
  const input = host.querySelector(inputSel);
  if (!(btn instanceof HTMLElement) || !(input instanceof HTMLInputElement)) {
    return;
  }
  btn.addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const files = [...(input.files || [])];
    input.value = "";
    if (!files.length) return;
    try {
      await onFiles(files);
    } catch (err) {
      showError(errorEl, err?.message || "Failed to read file");
    }
  });
}

/**
 * Read an OpenPGP armored envelope (.asc) as text.
 * @param {File} file
 * @returns {Promise<string>}
 */
async function readEnvelopeAscFile(file) {
  return (await file.text()).trim();
}

async function refreshVaultKeys() {
  try {
    vaultKeys = await vaultListKeys();
  } catch (_) {
    vaultKeys = [];
  }
}

/**
 * Collect runtime input bindings from the Inputs panel.
 * Unlocks a vault key ephemerally when selected.
 * @returns {Promise<{ inputs: import("../lib/toolkit/engine.js").RuntimeBindings["inputs"], privateKeyArmored: string, passphrase: string }>}
 */
async function collectRuntimeInputs() {
  /** @type {import("../lib/toolkit/engine.js").RuntimeBindings["inputs"]} */
  const inputs = {};
  let privateKeyArmored = "";
  let passphrase = "";

  if (currentInputNeeds.includes("text")) {
    // Sync from live DOM in case the last keystroke wasn't flushed to the draft.
    const textEl = document.getElementById("input-text");
    if (textEl instanceof HTMLTextAreaElement) inputTextDraft = textEl.value;
    inputs.text = { value: inputTextDraft };
  }

  if (currentInputNeeds.includes("key")) {
    const jwkEl = document.getElementById("input-wc-jwk");
    const peerEl = document.getElementById("input-wc-peer");
    const wrapEl = document.getElementById("input-wc-wrap");
    const sigEl = document.getElementById("input-wc-sig");
    if (jwkEl instanceof HTMLTextAreaElement) keyJwkDraft = jwkEl.value;
    if (peerEl instanceof HTMLTextAreaElement) peerJwkDraft = peerEl.value;
    if (wrapEl instanceof HTMLTextAreaElement) wrapJwkDraft = wrapEl.value;
    if (sigEl instanceof HTMLInputElement) signatureDraft = sigEl.value;
    inputs.key = {
      jwkText: keyJwkDraft.trim(),
      peerJwkText: peerJwkDraft.trim(),
      wrapJwkText: wrapJwkDraft.trim(),
      signatureB64url: signatureDraft.trim(),
    };
  }

  if (currentInputNeeds.includes("shares")) {
    // Sync from live DOM in case last keystroke wasn't flushed to shareRows.
    document.querySelectorAll("[data-share-input]").forEach((el) => {
      const i = Number(el.getAttribute("data-share-input"));
      if (el instanceof HTMLTextAreaElement && i >= 0) shareRows[i] = el.value;
    });
    const passEl = document.getElementById("input-share-pass");
    if (passEl instanceof HTMLInputElement) sharePassDraft = passEl.value;
    const mnemonics = shareRows.map((m) => m.trim()).filter(Boolean);
    inputs.shares = {
      mnemonics,
      passphrase: sharePassDraft,
    };
  }

  if (currentInputNeeds.includes("envelope")) {
    const envEl = document.getElementById("input-envelope");
    if (envEl instanceof HTMLTextAreaElement) envelopeDraft = envEl.value;
    const armored = envelopeDraft.trim();
    if (armored) {
      inputs.envelope = { armored };
      if (inputs.shares) inputs.shares.envelopeArmored = armored;
    }
  }

  if (currentInputNeeds.includes("gpg")) {
    const ctEl = document.getElementById("input-ciphertext");
    const vaultEl = document.getElementById("input-vault-key");
    const privEl = document.getElementById("input-privkey");
    const passEl = document.getElementById("input-key-pass");
    const armored =
      ctEl instanceof HTMLTextAreaElement ? ctEl.value.trim() : "";
    const messages = splitArmoredMessages(armored);
    // Mnemonics interleaved with ciphertext (or a ciphertext-box-only paste).
    const remainder = stripArmoredMessages(armored);
    /** @type {string[]} */
    const plainFromCt = [];
    for (const part of remainder.split(/\n\s*\n+/)) {
      const normalized = part.replace(/\s+/g, " ").trim();
      if (normalized && validateShareMnemonic(normalized).ok) {
        plainFromCt.push(normalized);
      }
    }
    if (!messages.length && !plainFromCt.length && armored) {
      // Single blob without armor markers — try as one message/mnemonic
      messages.push(armored);
    }
    passphrase = passEl instanceof HTMLInputElement ? passEl.value : "";
    const pasted =
      privEl instanceof HTMLTextAreaElement ? privEl.value.trim() : "";
    const vaultFpr =
      vaultEl instanceof HTMLSelectElement ? vaultEl.value : "";

    if (pasted) {
      privateKeyArmored = pasted;
    } else if (vaultFpr) {
      const meta = vaultKeys.find((k) => k.fingerprint === vaultFpr);
      /** @type {{ passphrase?: string, prfIkm?: Uint8Array }} */
      const opts = {};
      try {
        if (meta?.protection === "passkey") {
          opts.prfIkm = await getPasskeyPrf();
        }
        privateKeyArmored = await vaultUnlockKey(vaultFpr, opts);
      } finally {
        // PRF-derived input keying material is a real Uint8Array — zeroize it
        // as soon as the KEK has been derived (best-effort per FIPS 140-3).
        try {
          opts.prfIkm?.fill?.(0);
        } catch (_) {
          /* wipe */
        }
      }
    }

    inputs.gpg = {
      armoredMessages: [...messages, ...plainFromCt],
      privateKeyArmored,
      passphrase,
      envelopeArmored: inputs.envelope?.armored || "",
    };
    // Merge ciphertext-box mnemonics + share rows for decrypt hybrid path
    if (plainFromCt.length) {
      inputs.shares = inputs.shares || { mnemonics: [] };
      inputs.shares.mnemonics = [
        ...(inputs.shares.mnemonics || []),
        ...plainFromCt,
      ];
    }
  }

  return { inputs, privateKeyArmored, passphrase };
}

function renderPresets() {
  const grid = document.getElementById("preset-grid");
  if (!grid) return;

  /** @param {typeof PRESETS[number]} p */
  const card = (p) => `
    <button type="button" class="preset-card" data-preset="${escapeHtml(p.id)}">
      <strong>${escapeHtml(p.title)}</strong>
      <span class="muted">${escapeHtml(p.blurb)}</span>
      <code class="preset-recipe">${escapeHtml(p.recipe)}</code>
    </button>`;

  /** @type {Map<string, typeof PRESETS>} */
  const groups = new Map();
  for (const p of PRESETS) {
    const g = p.group || "Pipelines";
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(p);
  }

  let html = "";
  for (const [name, presets] of groups) {
    let items = "";
    for (let i = 0; i < presets.length; i++) {
      const p = presets[i];
      const next = presets[i + 1];
      if (p.pair && next?.pair === p.pair) {
        // Companion pipelines (forward ⇄ inverse) render as one linked row.
        items += `
          <div class="preset-pair">
            ${card(p)}
            <span class="preset-pair-link" aria-hidden="true" title="Companion pipelines">⇄</span>
            ${card(next)}
          </div>`;
        i++;
      } else {
        items += card(p);
      }
    }
    html += `
      <p class="preset-group-title">${escapeHtml(name)}</p>
      <div class="preset-grid-items">${items}</div>`;
  }
  grid.innerHTML = html;
  grid.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-preset");
      const preset = PRESETS.find((p) => p.id === id);
      if (!preset) return;
      loadRecipeText(preset.recipe, { title: preset.title });
      document.getElementById("preset-gallery")?.removeAttribute("open");
    });
  });
}

/**
 * Preferred next-step order for the current pipeline tip type.
 * Unknown names sort after these, by kind then name.
 * @param {import("../lib/toolkit/types.js").RefinedType} from
 * @returns {string[]}
 */
function preferredNextOrder(from) {
  if (!from || from.base === "none") {
    return ["genkey", "random", "shares", "input", "decrypt", "passphrase", "ecdh", "wrap"];
  }
  if (from.base === "shares") {
    if (from.kind === "raw") {
      return ["blip39", "recover", "foreach", "inspect", "out", "encrypt", "tee", "text", "qr"];
    }
    return ["blip39", "foreach", "inspect", "out", "encrypt", "tee", "text", "qr"];
  }
  if (from.base === "keypair") {
    return ["export", "fanout", "inspect", "tee", "out", "text", "encrypt"];
  }
  if (from.base === "key") {
    return ["export", "inspect", "tee", "out", "text"];
  }
  if (from.base === "bytes" && from.kind === "scalar") {
    return [
      "import",
      "sss",
      "hex",
      "base64",
      "base64url",
      "inspect",
      "out",
      "tee",
      "text",
      "encrypt",
    ];
  }
  if (from.base === "bytes" && from.kind === "master") {
    return [
      "sss",
      "symdecrypt",
      "digest",
      "hkdf",
      "aesgcm",
      "hex",
      "base64",
      "base64url",
      "inspect",
      "out",
      "tee",
      "text",
      "encrypt",
    ];
  }
  if (from.base === "bytes") {
    return [
      "digest",
      "sign",
      "aesgcm",
      "hkdf",
      "pbkdf2",
      "symencrypt",
      "sss",
      "hex",
      "base64",
      "base64url",
      "utf8",
      "pem",
      "import",
      "inspect",
      "out",
      "tee",
      "text",
      "encrypt",
      "qr",
    ];
  }
  if (from.base === "text") {
    return [
      "digest",
      "sign",
      "aesgcm",
      "pbkdf2",
      "pem",
      "base64",
      "hex",
      "utf8",
      "encrypt",
      "qr",
      "out",
      "text",
      "inspect",
      "tee",
      "symencrypt",
      "import",
    ];
  }
  return ["inspect", "out", "tee", "text", "encrypt", "ecdh", "wrap"];
}

/**
 * Compatible next steps for the builder suggest drawer, ranked for the tip type.
 * @param {import("../lib/toolkit/types.js").RefinedType} from
 * @param {{ hasForeach?: boolean, terminal?: boolean }} [opts]
 * @returns {import("../lib/toolkit/registry.js").StepSpec[]}
 */
function suggestedNextSteps(from, opts = {}) {
  const hasForeach = !!opts.hasForeach;
  const terminal = !!opts.terminal;
  let list = stepsAccepting(from).filter((s) => {
    if (s.kind === "flow") {
      if (s.name === "foreach") return true;
      if (s.name === "merge") return hasForeach;
      return false;
    }
    return true;
  });
  if (terminal) {
    list = list.filter((s) =>
      s.name === "inspect" || s.name === "tee" || s.name === "out" || s.name === "text"
    );
  }
  const preferred = preferredNextOrder(from);
  const kindOrder = (k) => KIND_META[k]?.order ?? 9;
  return list.slice().sort((a, b) => {
    const ia = preferred.indexOf(a.name);
    const ib = preferred.indexOf(b.name);
    const ra = ia === -1 ? 500 + kindOrder(a.kind) : ia;
    const rb = ib === -1 ? 500 + kindOrder(b.kind) : ib;
    return ra - rb || a.name.localeCompare(b.name);
  });
}

/**
 * Contextual next-block drawer under the pipeline cards.
 */
function renderSuggestDrawer() {
  const host = document.getElementById("suggest-next");
  if (!host) return;

  const from = currentPipelineOutput();
  const last = steps[steps.length - 1];
  const terminal = !!(last && (isTerminalSink(last.name) || last.name === "inspect"));
  const hasForeach = steps.some((s) => s.name === "foreach");
  const next = suggestedNextSteps(from, { hasForeach, terminal });

  if (!next.length) {
    host.hidden = true;
    host.innerHTML = "";
    return;
  }

  const fromType = formatType(from);
  const heading = !steps.length
    ? "Start with"
    : terminal
      ? "Optional next"
      : `Next for <code>${escapeHtml(fromType)}</code>`;
  const blurb = !steps.length
    ? "Sources that begin a pipeline."
    : terminal
      ? "Pipeline already has a sink — these still accept the tip."
      : "Compatible blocks for the current tip type.";

  const primaryCount = !steps.length ? 3 : from.base === "shares" ? 2 : 3;

  host.hidden = false;
  host.innerHTML = `
    <div class="suggest-next-head">
      <p class="suggest-next-title mb-0">${heading}</p>
      <p class="muted fs-xs mb-0">${escapeHtml(blurb)}</p>
    </div>
    <div class="suggest-next-chips" role="list">
      ${next
        .map((s, i) => {
          const decode =
            s.name === "blip39" && from.base === "shares" && from.kind === "mnemonic";
          const params = { ...defaultParams(s), ...(decode ? { decode: true } : {}) };
          const resolved = resolveStepType(s, from, params);
          const outLabel =
            resolved.ok && resolved.output.base !== "none"
              ? formatType(resolved.output)
              : s.output || "";
          const primary = i < primaryCount ? " suggest-chip-primary" : "";
          const label = decode
            ? `${stepDisplayName(s) || s.name} -d`
            : stepDisplayName(s) || s.name;
          return `
            <button type="button" class="suggest-chip${primary}" role="listitem"
              data-suggest-op="${escapeHtml(s.name)}"
              data-suggest-decode="${decode ? "1" : "0"}"
              draggable="true"
              title="${escapeHtml(s.doc)}">
              ${toolboxBadgeHtml(s.toolbox)}
              <span class="suggest-chip-name">${escapeHtml(label)}</span>
              ${
                outLabel
                  ? `<span class="suggest-chip-out muted">→ ${escapeHtml(outLabel)}</span>`
                  : ""
              }
            </button>`;
        })
        .join("")}
    </div>`;

  host.querySelectorAll("[data-suggest-op]").forEach((el) => {
    const name = el.getAttribute("data-suggest-op") || "";
    const decode = el.getAttribute("data-suggest-decode") === "1";
    const overrides = decode ? { decode: true } : undefined;
    el.addEventListener("dragstart", (e) => {
      const dt = e.dataTransfer;
      if (!dt) return;
      dt.setData(STEP_MIME, name);
      dt.setData("text/plain", name);
      if (decode) dt.setData("application/x-basilisk-decode", "1");
      dt.effectAllowed = "copy";
      el.classList.add("ops-dragging");
    });
    el.addEventListener("dragend", () => el.classList.remove("ops-dragging"));
    el.addEventListener("click", () => addStepAt(name, undefined, overrides));
  });
}

/**
 * CyberChef-style operations drawer grouped by toolbox.
 */
function renderOpsDrawer() {
  const host = document.getElementById("ops-drawer");
  const hint = document.getElementById("ops-hint");
  if (!host) return;

  const q = opsFilter.trim().toLowerCase();
  const from = currentPipelineOutput();
  const suggested = new Set(stepsAccepting(from).map((s) => s.name));
  const all = listSteps().filter(
    (s) => s.kind !== "flow" || s.name === "foreach" || s.name === "merge"
  );

  /** @type {Map<string, typeof all>} */
  const byToolbox = new Map();
  for (const s of all) {
    if (q) {
      const hay =
        `${s.name} ${s.label || ""} ${s.toolbox} ${s.kind} ${s.doc} ${(s.aliases || []).join(" ")}`.toLowerCase();
      if (!hay.includes(q)) continue;
    }
    const tb = s.toolbox || "io";
    const list = byToolbox.get(tb) || [];
    list.push(s);
    byToolbox.set(tb, list);
  }

  const toolboxes = [...byToolbox.keys()].sort(
    (a, b) => (TOOLBOX_META[a]?.order ?? 9) - (TOOLBOX_META[b]?.order ?? 9)
  );

  if (!toolboxes.length) {
    host.innerHTML = `<p class="muted fs-sm">No operations match “${escapeHtml(opsFilter)}”.</p>`;
    return;
  }

  if (hint) {
    const fromType = formatType(from);
    if (!steps.length) {
      hint.textContent =
        "Drag onto the pipeline, or click to append. Badges show toolbox (WebCrypto, OpenPGP, SSS, …).";
    } else if (from.base === "shares" && from.kind === "raw") {
      hint.textContent = `Pipe type ${fromType} — suggested: blip39 (mnemonics) or recover (→ bytes/master). Highlighted ops accept this type.`;
    } else if (from.base === "shares") {
      hint.textContent = `Pipe type ${fromType} — suggested: blip39 -d → recover, or foreach. Highlighted ops accept this type.`;
    } else {
      hint.textContent = `Pipe type ${fromType} — highlighted ops accept it. Drag or click to add.`;
    }
  }

  host.innerHTML = toolboxes
    .map((tb) => {
      const meta = TOOLBOX_META[tb] || { label: tb };
      const collapsed = opsCollapsed.has(tb) && !q;
      const items = (byToolbox.get(tb) || []).slice().sort((a, b) => {
        const ka = KIND_META[a.kind]?.order ?? 9;
        const kb = KIND_META[b.kind]?.order ?? 9;
        return ka - kb || a.name.localeCompare(b.name);
      });
      return `
        <div class="ops-category" data-toolbox="${escapeHtml(tb)}">
          <button type="button" class="ops-category-toggle" data-toggle-toolbox="${escapeHtml(tb)}"
            aria-expanded="${collapsed ? "false" : "true"}">
            <span>${toolboxBadgeHtml(tb)} ${escapeHtml(meta.label)}</span>
            <span class="muted fs-xs">${items.length}</span>
          </button>
          <div class="ops-category-body ${collapsed ? "hidden" : ""}">
            ${items
              .map((s) => {
                const fit = !steps.length
                  ? s.kind === "source" || s.input === "none"
                  : suggested.has(s.name);
                const ioLabel = `${s.input} → ${s.output}`;
                const display = stepDisplayName(s);
                return `
                <button type="button" class="ops-item ${fit ? "ops-item-fit" : "ops-item-dim"}"
                  draggable="true" data-op="${escapeHtml(s.name)}"
                  title="${escapeHtml(s.doc)}&#10;&#10;Recipe: ${escapeHtml(s.name)} · ${escapeHtml(ioLabel)}">
                  <span class="ops-item-name">${escapeHtml(display)}</span>
                  ${
                    display !== s.name
                      ? `<span class="muted fs-xs ops-item-recipe">${escapeHtml(s.name)}</span>`
                      : ""
                  }
                  <span class="muted fs-xs ops-item-io">${escapeHtml(ioLabel)}</span>
                </button>`;
              })
              .join("")}
          </div>
        </div>`;
    })
    .join("");

  host.querySelectorAll("[data-toggle-toolbox]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tb = btn.getAttribute("data-toggle-toolbox") || "";
      if (opsCollapsed.has(tb)) opsCollapsed.delete(tb);
      else opsCollapsed.add(tb);
      renderOpsDrawer();
    });
  });

  host.querySelectorAll("[data-op]").forEach((el) => {
    const name = el.getAttribute("data-op") || "";
    el.addEventListener("dragstart", (e) => {
      const dt = e.dataTransfer;
      if (!dt) return;
      dt.setData(STEP_MIME, name);
      dt.setData("text/plain", name);
      dt.effectAllowed = "copy";
      el.classList.add("ops-dragging");
    });
    el.addEventListener("dragend", () => el.classList.remove("ops-dragging"));
    el.addEventListener("click", () => addStepAt(name));
  });
}

function renderBuilder() {
  const host = document.getElementById("builder-steps");
  if (!host) return;

  const modeHost = document.getElementById("pgp-mode-host");
  if (modeHost) {
    if (pipelineUsesOpenPgpEncrypt()) {
      modeHost.classList.remove("hidden");
      modeHost.innerHTML = renderPgpModeToggle("toolkit-pgp-mode-recipe");
      wirePgpModeToggles(modeHost);
    } else {
      modeHost.classList.add("hidden");
      modeHost.innerHTML = "";
    }
  }

  if (!steps.length) {
    host.innerHTML = `
      <div class="builder-dropzone builder-empty" data-insert="0">
        <p class="muted mb-0">Drop an operation here to start the pipeline</p>
        <p class="muted fs-xs mb-0">Sources like <code>genkey</code>, <code>random</code>, or <code>shares</code> work well first.</p>
      </div>`;
    wireDropZones(host);
    return;
  }

  let foreachOpen = false;
  /** @type {string[]} */
  const parts = [];
  const typeEdges = builderTypeEdges();
  parts.push(`<div class="builder-dropzone" data-insert="0" aria-label="Insert at start"></div>`);

  steps.forEach((step, i) => {
    syncWhichWithFormat(step);
    const spec = getStep(step.name);
    if (step.name === "foreach") foreachOpen = true;
    const inForeach =
      foreachOpen && step.name !== "foreach" && step.name !== "merge";
    if (step.name === "merge") foreachOpen = false;

    const edge = typeEdges[i];
    const inType = edge ? formatType(edge.input) : "—";
    const outType = edge?.output ? formatType(edge.output) : edge?.error ? "∅" : "—";
    const typeTitle = edge?.error
      ? edge.error
      : `${inType} → ${outType}`;

    const paramFields = (spec?.params || [])
      .map((p) => {
        const vis = paramVisibility(step.name, p, step.params || {});
        if (!vis.show) return "";
        const val =
          vis.forced != null
            ? vis.forced
            : step.params[p.name] ?? p.default ?? "";
        const title = p.doc ? ` title="${escapeHtml(p.doc)}"` : "";
        if (p.type === "bool") {
          const checked = val === true || val === "true";
          return `<label class="builder-param builder-param-bool"${title}>
            <span class="builder-param-name">${escapeHtml(p.name)}${p.flag ? ` <code>${escapeHtml(p.flag)}</code>` : ""}</span>
            <input type="checkbox" data-step="${i}" data-param="${escapeHtml(p.name)}"
              ${checked ? "checked" : ""}></label>`;
        }
        if (p.type === "enum") {
          const locked = !!vis.locked;
          return `<label class="builder-param"${title}>
            <span class="builder-param-name">${escapeHtml(p.name)}</span>
            <select data-step="${i}" data-param="${escapeHtml(p.name)}" class="text-input"
              ${locked ? "disabled" : ""}>
              ${(p.enum || [])
                .map(
                  (e) =>
                    `<option value="${escapeHtml(e)}" ${String(val) === e ? "selected" : ""}>${escapeHtml(e)}</option>`
                )
                .join("")}
            </select>${locked ? `<span class="muted fs-xs">locked by format</span>` : ""}</label>`;
        }
        return `<label class="builder-param"${title}>
          <span class="builder-param-name">${escapeHtml(p.name)}</span>
          <input class="text-input" data-step="${i}" data-param="${escapeHtml(p.name)}"
                 value="${escapeHtml(String(val))}" ${p.type === "int" ? 'type="number"' : 'type="text"'}></label>`;
      })
      .join("");

    const isOut = step.name === "out";
    const isText = step.name === "text";
    const usesPgpProfile = PGP_PROFILE_STEPS.has(step.name);
    const outSummary = isOut
      ? [
          step.params.name || "output",
          step.params.encoding && step.params.encoding !== "auto"
            ? String(step.params.encoding)
            : "",
          step.params.ext ? `.${String(step.params.ext).replace(/^\./, "")}` : "",
        ]
          .filter(Boolean)
          .join(" · ")
      : isText
        ? String(step.params.label || step.params.name || "text")
        : "";

    const pgpModeBlock = usesPgpProfile
      ? renderPgpModeToggle(`toolkit-pgp-mode-step-${i}`, { compact: true })
      : "";

    const typeHint =
      edge?.output?.base === "shares" && edge.output.kind === "raw"
        ? `<p class="builder-type-hint muted fs-xs mb-sm">Next usually <code>blip39</code> → mnemonics, or <code>recover</code> → <code>bytes/master</code>.</p>`
        : edge?.output?.base === "shares"
        ? `<p class="builder-type-hint muted fs-xs mb-sm">Next usually <code>blip39 -d</code> → raw shares, then <code>recover</code>; or <code>foreach</code> to map each mnemonic.</p>`
        : step.name === "recover"
          ? `<p class="builder-type-hint muted fs-xs mb-sm">Combines raw SSS shares into <code>bytes/master</code>. Decode mnemonics with <code>blip39 -d</code> first.</p>`
          : step.name === "sss"
            ? `<p class="builder-type-hint muted fs-xs mb-sm">Produces <code>shares/raw</code>. Pipe into <code>blip39</code> for word phrases.</p>`
            : "";

    parts.push(`
      <div class="builder-card ${inForeach ? "builder-foreach-child" : ""} ${step.name === "foreach" ? "builder-foreach" : ""} ${isOut ? "builder-out" : ""} ${isText ? "builder-text" : ""} ${usesPgpProfile ? "builder-pgp" : ""} ${edge && !edge.ok ? "builder-type-error" : ""}"
           draggable="true" data-index="${i}" data-step-card="${i}">
        <div class="builder-card-head">
          <span class="builder-drag" title="Drag to reorder">⠿</span>
          <span class="builder-step-num" aria-hidden="true">${i + 1}</span>
          <strong title="${escapeHtml(spec?.doc || "")}">${escapeHtml(stepDisplayName(spec) || step.name)}</strong>
          ${toolboxBadgeHtml(spec?.toolbox)}
          <code class="builder-type-chip" title="${escapeHtml(typeTitle)}">${escapeHtml(inType)} → ${escapeHtml(outType)}</code>
          ${
            isOut
              ? `<span class="badge pending" title="Named file — Encrypt attaches bytes">file · Encrypt as file</span>`
              : isText
                ? `<span class="badge pending" title="Message tile — Encrypt opens compose">message · Encrypt as message</span>`
                : `<span class="muted fs-xs">${escapeHtml(spec?.kind || "")}</span>`
          }
          ${outSummary ? `<span class="muted fs-xs">${escapeHtml(outSummary)}</span>` : ""}
          <button type="button" class="btn btn-ghost btn-compact text-error" data-remove="${i}">Remove</button>
        </div>
        <p class="muted mt-xs mb-sm fs-xs" title="${escapeHtml(spec?.doc || "")}">${escapeHtml(spec?.doc || "")}</p>
        ${typeHint}
        ${pgpModeBlock}
        <div class="builder-params">${paramFields}</div>
      </div>
      <div class="builder-dropzone" data-insert="${i + 1}" aria-label="Insert after ${escapeHtml(step.name)}"></div>`);
  });

  const finalType = currentPipelineOutput();
  const lastStep = steps[steps.length - 1];
  const dangling =
    steps.length &&
    finalType.base !== "none" &&
    finalType.base !== "artifact" &&
    finalType.base !== "bundle" &&
    lastStep &&
    !isTerminalSink(lastStep.name) &&
    lastStep.name !== "inspect";
  if (dangling) {
    parts.push(`
      <div class="builder-dangling" role="status">
        <div>
          <p class="mb-xs"><strong>Unhandled</strong> <code>${escapeHtml(formatType(finalType))}</code></p>
          <p class="muted fs-xs mb-0">Execute would auto-emit a result tile. Prefer an explicit sink.</p>
        </div>
        <div class="btn-row wrap">
          <button type="button" class="btn btn-compact" id="add-inspect-btn" title="Dump the value as text (default)">Add inspect</button>
          ${
            finalType.base === "shares" && finalType.kind === "raw"
              ? `<button type="button" class="btn btn-ghost btn-compact" id="add-recover-btn" title="Recover bytes/master">Add recover</button>
                 <button type="button" class="btn btn-ghost btn-compact" id="add-blip39-btn" title="Encode BLIP39 mnemonics">Add blip39</button>`
              : finalType.base === "shares"
              ? `<button type="button" class="btn btn-ghost btn-compact" id="add-blip39-decode-btn" title="Decode BLIP39 → raw SSS">Add blip39 -d</button>`
              : `<button type="button" class="btn btn-ghost btn-compact" id="add-out-btn" title="Named file tile">Add out</button>`
          }
        </div>
      </div>`);
  }

  host.innerHTML = parts.join("");

  host.querySelectorAll("[data-param]").forEach((el) => {
    el.addEventListener("change", () => {
      const i = Number(el.getAttribute("data-step"));
      const name = el.getAttribute("data-param");
      if (!name || !steps[i]) return;
      const spec = getStep(steps[i].name);
      const p = (spec?.params || []).find((x) => x.name === name);
      if (el instanceof HTMLInputElement && el.type === "checkbox") {
        steps[i].params[name] = el.checked;
      } else {
        const v =
          el instanceof HTMLInputElement || el instanceof HTMLSelectElement
            ? el.value
            : "";
        steps[i].params[name] = p?.type === "int" ? Number(v) : v;
      }
      if (name === "format") syncWhichWithFormat(steps[i]);
      setRecipeFromSteps();
    });
  });

  host.querySelector("#add-inspect-btn")?.addEventListener("click", () => {
    addStepAt("inspect");
  });
  host.querySelector("#add-recover-btn")?.addEventListener("click", () => {
    addStepAt("recover");
  });
  host.querySelector("#add-blip39-btn")?.addEventListener("click", () => {
    addStepAt("blip39");
  });
  host.querySelector("#add-blip39-decode-btn")?.addEventListener("click", () => {
    addStepAt("blip39", undefined, { decode: true });
  });
  host.querySelector("#add-out-btn")?.addEventListener("click", () => {
    addStepAt("out");
  });

  host.querySelectorAll("[data-remove]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-remove"));
      steps.splice(i, 1);
      setRecipeFromSteps();
    });
  });

  host.querySelectorAll(".builder-card").forEach((card) => {
    card.addEventListener("dragstart", (e) => {
      const i = Number(card.getAttribute("data-index"));
      const dt = e.dataTransfer;
      if (!dt) return;
      dt.setData(REORDER_MIME, String(i));
      dt.setData("text/plain", steps[i]?.name || "");
      dt.effectAllowed = "move";
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
  });

  wirePgpModeToggles(host);
  wireDropZones(host);
}

function renderCryptoPanel() {
  const host = document.getElementById("crypto-params-host");
  if (!host) return;

  const generatedKeys = steps
    .filter((step) => step.name === "genkey")
    .map((step) => {
      const alg = String(step.params.alg || "ec/p256");
      const usage = String(step.params.usage || "auto");
      return `<code>${escapeHtml(alg)}</code> <span class="muted">(${escapeHtml(usage)})</span>`;
    });
  const usesSss = steps.some(
    (step) => step.name === "sss" || step.name === "blip39" || step.name === "recover"
  );
  const usesSymEnvelope = steps.some(
    (step) => step.name === "symencrypt" || step.name === "symdecrypt"
  );
  const usesOpenPgp = steps.some(
    (step) =>
      step.name === "encrypt" ||
      step.name === "gpg" ||
      step.name === "symencrypt" ||
      step.name === "symdecrypt"
  );

  const profileHint =
    toolkitEncryptPreset === "auto"
      ? ""
      : ` · OpenPGP: ${toolkitEncryptPreset}`;

  host.innerHTML = `
    <details class="crypto-params-details mt-md" id="crypto-params-details" ${cryptoPanelOpen ? "open" : ""}>
      <summary class="muted fs-sm">Cryptographic parameters${escapeHtml(profileHint)}</summary>
      <p class="muted fs-sm mt-sm">
        Runtime settings — not written into pipeline text. Artifact metadata reports what was actually emitted.
      </p>

      <details class="expert-crypto-section" ${usesSss ? "open" : ""}>
        <summary><strong>SSS + BLIP39 (16/32-byte masters)</strong>${usesSss ? "" : ' <span class="muted">(no sss/blip39 step)</span>'}</summary>
        <dl class="crypto-param-list fs-sm">
          <div><dt>Master size</dt><dd>Exactly 16 or 32 bytes — random secrets, AES-256 keys, P-256 / Ed25519 / X25519 scalars via <code>export scalar</code></dd></div>
          <div><dt>SSS (<code>sss</code>)</dt><dd>GF(256) Shamir threshold → <code>shares/raw</code>; optional passphrase mask uses PBKDF2-SHA-256 (20,000 iterations)</dd></div>
          <div><dt>BLIP39 (<code>blip39</code>)</dt><dd>Mnemonic encode/decode of raw shares; official SLIP-39 wordlist + RS1024 (tag <code>basilisk-slip39-v1</code>)</dd></div>
          <div><dt>No auto-envelope</dt><dd>PEM / PKCS#8 / larger payloads must use <code>symencrypt</code> first — sss never invents a custom ciphertext</dd></div>
        </dl>
      </details>

      <details class="expert-crypto-section" ${usesSymEnvelope ? "open" : ""}>
        <summary><strong>OpenPGP symmetric envelope</strong>${usesSymEnvelope ? "" : ' <span class="muted">(no symencrypt/symdecrypt)</span>'}</summary>
        <dl class="crypto-param-list fs-sm">
          <div><dt>When</dt><dd>PEM, PKCS#8 DER, or any payload that is not already 16/32 bytes</dd></div>
          <div><dt>Master</dt><dd>32-byte CSPRNG secret — this is what <code>sss</code> splits; passphrase for stock gpg is lowercase hex of that master</dd></div>
          <div><dt>Ciphertext</dt><dd>Standard OpenPGP SKESK + SEIPD (<code>envelope.asc</code>) — profile below; no custom AES-GCM padding</dd></div>
          <div><dt>External recovery</dt><dd><code>blip39 -d | recover</code> → hex master → <code>gpg --decrypt envelope.asc</code></dd></div>
        </dl>
        <p class="status-row warn fs-sm">
          The OpenPGP envelope is not a share mnemonic. Keep <code>envelope.asc</code> with the share set; without it the master alone cannot unwrap the payload.
        </p>
      </details>

      <details class="expert-crypto-section" ${generatedKeys.length ? "open" : ""}>
        <summary><strong>Generated / ephemeral keys</strong>${generatedKeys.length ? "" : ' <span class="muted">(no genkey step)</span>'}</summary>
        <p class="fs-sm">
          ${generatedKeys.length
            ? `This pipeline generates: ${generatedKeys.join(", ")}. Change algorithm and usage directly on each <code>genkey</code> operation. For direct SSS use <code>export scalar</code> (P-256); P-384/P-521 scalars need the envelope path.`
            : "Add a genkey operation to choose EC, Ed25519, X25519, RSA, AES, or HMAC parameters."}
        </p>
        <p class="muted fs-sm">RSA uses exponent 65537 and SHA-256. All generated key material uses WebCrypto and remains inside the worker until encoded as an artifact.</p>
      </details>

      <details class="expert-crypto-section" ${usesOpenPgp ? "open" : ""}>
        <summary><strong>OpenPGP wrapping</strong>${usesOpenPgp ? "" : ' <span class="muted">(no encrypt / symencrypt step)</span>'}</summary>
        ${usesOpenPgp ? renderPgpModeToggle("toolkit-pgp-mode-expert") : ""}
        <div class="expert-crypto-grid mt-sm">
          <label class="builder-param">Cipher
            <select class="text-input" id="toolkit-pgp-cipher">
              ${["aes128", "aes192", "aes256"].map((v) => `<option value="${v}" ${toolkitEncryptProfile.cipher === v ? "selected" : ""}>${v.toUpperCase()}</option>`).join("")}
            </select>
          </label>
          <label class="builder-param">AEAD / packet format
            <select class="text-input" id="toolkit-pgp-aead">
              <option value="" ${!toolkitEncryptProfile.aead ? "selected" : ""}>Off — SEIPD v1</option>
              ${["ocb", "gcm", "eax"].map((v) => `<option value="${v}" ${toolkitEncryptProfile.aead === v ? "selected" : ""}>${v.toUpperCase()} — SEIPD v2</option>`).join("")}
            </select>
          </label>
          <label class="builder-param">S2K (passphrase / symencrypt)
            <select class="text-input" id="toolkit-pgp-s2k">
              <option value="argon2" ${toolkitEncryptProfile.s2k === "argon2" ? "selected" : ""}>Argon2 (WASM)</option>
              <option value="iterated" ${toolkitEncryptProfile.s2k === "iterated" ? "selected" : ""}>Iterated (no WASM)</option>
            </select>
          </label>
          <label class="builder-param">Compression
            <select class="text-input" id="toolkit-pgp-compression">
              <option value="uncompressed" ${toolkitEncryptProfile.compression === "uncompressed" ? "selected" : ""}>Off</option>
              <option value="zlib" ${toolkitEncryptProfile.compression === "zlib" ? "selected" : ""}>ZLIB</option>
              <option value="zip" ${toolkitEncryptProfile.compression === "zip" ? "selected" : ""}>ZIP</option>
            </select>
          </label>
        </div>
        <label class="field-label field-label-inline mt-sm">
          <input type="checkbox" id="toolkit-hide-recipients" ${toolkitHideRecipients ? "checked" : ""}>
          Hide recipient key IDs (anonymous PKESK)
        </label>
        <p class="muted fs-sm mt-sm">Auto requests AES-256 + OCB and safely falls back when a recipient lacks SEIPD v2 support. Compatible uses iterated S2K so Argon2 WASM is not required. Compression can leak length when attacker-controlled and secret data are mixed.</p>
      </details>
    </details>`;

  document.getElementById("crypto-params-details")?.addEventListener("toggle", (event) => {
    if (event.target instanceof HTMLDetailsElement) {
      cryptoPanelOpen = event.target.open;
    }
  });

  wirePgpModeToggles(host);

  for (const [id, key] of [
    ["toolkit-pgp-cipher", "cipher"],
    ["toolkit-pgp-aead", "aead"],
    ["toolkit-pgp-s2k", "s2k"],
    ["toolkit-pgp-compression", "compression"],
  ]) {
    document.getElementById(id)?.addEventListener("change", (event) => {
      if (!(event.target instanceof HTMLSelectElement)) return;
      toolkitEncryptProfile = {
        ...toolkitEncryptProfile,
        [key]: key === "aead" ? event.target.value || null : event.target.value,
      };
      toolkitEncryptPreset = "custom";
      renderBuilder();
      renderCryptoPanel();
    });
  }
  document.getElementById("toolkit-hide-recipients")?.addEventListener("change", (event) => {
    toolkitHideRecipients =
      event.target instanceof HTMLInputElement && event.target.checked;
  });
}

/**
 * @param {HTMLElement} host
 */
function wireDropZones(host) {
  const clearHi = () => {
    host.querySelectorAll(".builder-dropzone-active").forEach((z) => {
      z.classList.remove("builder-dropzone-active");
    });
  };

  host.querySelectorAll(".builder-dropzone").forEach((zone) => {
    zone.addEventListener("dragover", (e) => {
      e.preventDefault();
      const dt = e.dataTransfer;
      if (dt) {
        const types = Array.from(dt.types || []);
        dt.dropEffect = types.includes(REORDER_MIME) ? "move" : "copy";
      }
      clearHi();
      zone.classList.add("builder-dropzone-active");
    });
    zone.addEventListener("dragleave", () => {
      zone.classList.remove("builder-dropzone-active");
    });
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      clearHi();
      const insertAt = Number(zone.getAttribute("data-insert"));
      const dt = e.dataTransfer;
      if (!dt) return;

      const reorderRaw = dt.getData(REORDER_MIME);
      if (reorderRaw !== "") {
        const from = Number(reorderRaw);
        if (Number.isNaN(from) || from < 0 || from >= steps.length) return;
        let to = insertAt;
        if (from < to) to -= 1;
        if (to === from) return;
        const [moved] = steps.splice(from, 1);
        steps.splice(to, 0, moved);
        setRecipeFromSteps();
        return;
      }

      const name = dt.getData(STEP_MIME) || dt.getData("text/plain");
      if (name && getStep(name)) {
        const decode = dt.getData("application/x-basilisk-decode") === "1";
        addStepAt(name, insertAt, decode ? { decode: true } : undefined);
      }
    });
  });
}

function renderReference() {
  const body = document.getElementById("reference-body");
  if (!body) return;
  const steps = listSteps().slice().sort((a, b) => {
    const ta = TOOLBOX_META[a.toolbox]?.order ?? 9;
    const tb = TOOLBOX_META[b.toolbox]?.order ?? 9;
    return ta - tb || a.name.localeCompare(b.name);
  });
  body.innerHTML = steps
    .map((s) => {
      const params = (s.params || [])
        .map(
          (p) =>
            `<li><code>${escapeHtml(p.name)}</code> (${escapeHtml(p.type)}${
              p.enum ? `: ${p.enum.join("|")}` : ""
            }) — ${escapeHtml(p.doc || "")}</li>`
        )
        .join("");
      const aliases = (s.aliases || []).length
        ? `<p class="muted fs-xs">Aliases: ${(s.aliases || []).map(escapeHtml).join(", ")}</p>`
        : "";
      const labelNote =
        s.label && s.label !== s.name
          ? `<p class="muted fs-xs">UI label: ${escapeHtml(s.label)} (recipe token: <code>${escapeHtml(s.name)}</code>)</p>`
          : "";
      return `<details class="ref-step">
        <summary>${toolboxBadgeHtml(s.toolbox)} <code>${escapeHtml(s.name)}</code>
          <span class="muted">${escapeHtml(s.kind)}</span>
          · ${escapeHtml(s.input)} → ${escapeHtml(s.output)}</summary>
        <p class="fs-md">${escapeHtml(s.doc)}</p>
        ${labelNote}
        ${aliases}
        ${params ? `<ul class="fs-sm">${params}</ul>` : "<p class='muted'>No parameters.</p>"}
      </details>`;
    })
    .join("");
}

/**
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 * @param {number} i
 * @returns {string}
 */
function renderArtifactCard(a, i) {
  const masked = a.sensitive;
  const preview = masked
    ? "•••••••• (click Reveal)"
    : a.content.length > 400
      ? escapeHtml(a.content.slice(0, 400)) + "…"
      : escapeHtml(a.content);
  const isSvg = a.mime === "image/svg+xml";
  const suggestedFilename = a.filename || `artifact-${i + 1}.txt`;
  const role = a.role || "";
  const tags = Array.isArray(a.tags) ? a.tags : [];
  const metaBits = [
    role ? `<span class="badge approved" title="Artifact role">${escapeHtml(role)}</span>` : "",
    ...tags.map(
      (t) => `<span class="badge pending" title="Tag">${escapeHtml(String(t))}</span>`
    ),
    a.encoding ? `<span class="badge pending">${escapeHtml(a.encoding)}</span>` : "",
    a.mime && a.mime !== "text/plain; charset=utf-8" && a.mime !== "text/plain"
      ? `<span class="muted fs-xs">${escapeHtml(a.mime)}</span>`
      : "",
    a.shareIndex || a.traits?.shareOf
      ? `<span class="badge pending">share ${a.shareIndex || a.traits?.shareOf}${
          a.traits?.threshold ? ` · ${a.traits.threshold}-of-N` : ""
        }</span>`
      : "",
    a.recipientFingerprint
      ? `<span class="muted fs-xs">→ ${escapeHtml(formatFingerprint(a.recipientFingerprint))}</span>`
      : "",
    a.cryptoSummary
      ? `<span class="badge approved" title="Parameters parsed from or associated with this artifact">${escapeHtml(a.cryptoSummary)}</span>`
      : "",
  ]
    .filter(Boolean)
    .join(" ");
  const stepBadge = a.stepIndex
    ? `<button type="button" class="artifact-step-badge" data-step-link="${a.stepIndex}"
        title="Produced by pipeline step ${a.stepIndex} (${escapeHtml(a.stepName || "")}) — click to jump to it">
        ${a.stepIndex}&#8202;·&#8202;${escapeHtml(a.stepName || "step")}</button>`
    : "";
  return `
        <div class="card artifact-card" data-art="${i}">
          <div class="artifact-card-head">
            <div class="artifact-title-row">
              ${stepBadge}
              <p class="card-title m-0">${escapeHtml(a.label || `Artifact ${i + 1}`)}</p>
            </div>
            <div class="artifact-meta">
              <label class="artifact-filename-field">
                <span class="muted fs-xs">File</span>
                <input type="text" class="artifact-filename-input" data-art-filename="${i}"
                  value="${escapeHtml(suggestedFilename)}" aria-label="Suggested download filename"
                  spellcheck="false">
              </label>
              ${metaBits}
            </div>
          </div>
          ${
            isSvg && !masked
              ? `<div class="qr-preview">${a.content}</div>`
              : `<pre class="output-pre artifact-body" data-art="${i}">${preview}</pre>`
          }
          <div class="btn-row mt-sm wrap">
            ${masked ? `<button type="button" class="btn btn-ghost btn-compact" data-reveal="${i}">Reveal</button>` : ""}
            <button type="button" class="btn btn-ghost btn-compact" data-copy="${i}">Copy</button>
            <button type="button" class="btn btn-ghost btn-compact" data-download="${i}">Download</button>
            ${
              artifactLooksLikePgpCiphertext(a)
                ? `<button type="button" class="btn btn-ghost btn-compact btn-popout" data-decrypt="${i}"
                    title="Open this OpenPGP ciphertext in a separate Decrypt window">${popoutButtonHtml("Decrypt…")}</button>`
                : `<button type="button" class="btn btn-ghost btn-compact btn-popout" data-encrypt="${i}"
                    title="${
                      artifactIsMessage(a)
                        ? "Open as an Encrypt compose message in a new window"
                        : "Attach as a file in a separate Encrypt window"
                    }">${popoutButtonHtml(
                      artifactIsMessage(a) ? "Encrypt as message…" : "Encrypt as file…"
                    )}</button>`
            }
          </div>
        </div>`;
}

/**
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 */
function isShareArtifact(a) {
  return (
    a.role === "share" ||
    !!a.shareIndex ||
    /^Share\s+\d+/i.test(a.label || "")
  );
}

/**
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 */
function isEnvelopeArtifact(a) {
  return (
    a.role === "envelope" ||
    /\.asc$/i.test(a.filename || "") && /envelope/i.test(a.filename || "") ||
    /envelope/i.test(a.label || "")
  );
}

function renderResults() {
  const panel = document.getElementById("results-panel");
  const empty = document.getElementById("output-empty");
  if (!panel) return;
  if (!artifacts.length) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    empty?.classList.remove("hidden");
    return;
  }
  empty?.classList.add("hidden");
  panel.classList.remove("hidden");

  /** @type {number[]} */
  const shareIdxs = [];
  /** @type {number[]} */
  const envelopeIdxs = [];
  /** @type {number[]} */
  const otherIdxs = [];
  artifacts.forEach((a, i) => {
    if (isShareArtifact(a)) shareIdxs.push(i);
    else if (isEnvelopeArtifact(a)) envelopeIdxs.push(i);
    else otherIdxs.push(i);
  });

  const threshold =
    artifacts.find((a) => a.traits?.threshold)?.traits?.threshold ||
    shareIdxs.length ||
    0;
  const hasShareSet = shareIdxs.length > 0;
  const hasEnvelope = envelopeIdxs.length > 0;

  /** @type {string[]} */
  const blocks = [];
  blocks.push(`
    <div class="btn-row wrap mb-md items-center">
      <p class="muted mb-0 flex-1">Sensitive outputs are masked until revealed. Cleared after ${IDLE_CLEAR_MS / 60000} minutes of inactivity.</p>
      ${
        artifacts.length > 1
          ? `<button type="button" class="btn btn-ghost btn-compact" id="download-all-btn">Download all (${artifacts.length})</button>`
          : ""
      }
    </div>`);

  if (hasShareSet) {
    const kOfN =
      threshold && shareIdxs.length
        ? `${threshold}-of-${shareIdxs.length}`
        : `${shareIdxs.length} shares`;
    blocks.push(`
      <section class="share-set-group mb-md" aria-label="Share set">
        <div class="share-set-head mb-sm">
          <p class="card-title m-0">Share set (${escapeHtml(kOfN)})</p>
          <p class="muted fs-sm mb-0">${
            hasEnvelope
              ? "OpenPGP envelope path — keep <code>envelope.asc</code> with the mnemonics (envelope ≠ shares)."
              : "Direct secret / scalar — no envelope; recover yields the 16/32-byte master."
          }</p>
        </div>
        ${
          hasEnvelope
            ? `<p class="status-row warn mb-sm" role="status">The OpenPGP envelope unwraps the payload after recover; share mnemonics alone are not enough for PEM / large-payload recovery.</p>`
            : ""
        }
        ${envelopeIdxs.map((i) => renderArtifactCard(artifacts[i], i)).join("")}
        ${shareIdxs.map((i) => renderArtifactCard(artifacts[i], i)).join("")}
      </section>`);
  } else if (hasEnvelope) {
    blocks.push(envelopeIdxs.map((i) => renderArtifactCard(artifacts[i], i)).join(""));
  }

  blocks.push(otherIdxs.map((i) => renderArtifactCard(artifacts[i], i)).join(""));

  panel.innerHTML = blocks.join("");

  panel.querySelectorAll("[data-step-link]").forEach((badge) => {
    const stepIndex = Number(badge.getAttribute("data-step-link"));
    const cardFor = () =>
      document.querySelector(`.builder-card[data-step-card="${stepIndex - 1}"]`);
    badge.addEventListener("mouseenter", () => {
      cardFor()?.classList.add("builder-card-linked");
    });
    badge.addEventListener("mouseleave", () => {
      cardFor()?.classList.remove("builder-card-linked");
    });
    badge.addEventListener("click", () => {
      const card = cardFor();
      if (!card) return;
      card.scrollIntoView({ behavior: "smooth", block: "center" });
      card.classList.add("builder-card-linked");
      setTimeout(() => card.classList.remove("builder-card-linked"), 1600);
    });
  });
  panel.querySelectorAll("[data-art-filename]").forEach((input) => {
    input.addEventListener("input", () => {
      const i = Number(input.getAttribute("data-art-filename"));
      if (artifacts[i] && input instanceof HTMLInputElement) {
        artifacts[i].filename = input.value;
        touchActivity();
      }
    });
    input.addEventListener("change", () => {
      const i = Number(input.getAttribute("data-art-filename"));
      if (!artifacts[i] || !(input instanceof HTMLInputElement)) return;
      const filename = sanitizeFilename(input.value, `artifact-${i + 1}.txt`);
      artifacts[i].filename = filename;
      input.value = filename;
    });
  });
  panel.querySelectorAll("[data-reveal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-reveal"));
      const a = artifacts[i];
      const pre = panel.querySelector(`.artifact-body[data-art="${i}"]`);
      if (a && pre) {
        if (a.mime === "image/svg+xml") {
          // Render the QR image, same as the unmasked path (SVG is generated
          // locally by qrSvg, never from user input).
          const preview = document.createElement("div");
          preview.className = "qr-preview";
          preview.innerHTML = a.content;
          pre.replaceWith(preview);
        } else {
          pre.textContent = a.content;
        }
      }
      btn.remove();
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const i = Number(btn.getAttribute("data-copy"));
      await copyTextTransient(artifacts[i].content);
      btn.textContent = "Copied";
      setTimeout(() => {
        btn.textContent = "Copy";
      }, 1200);
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-download]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-download"));
      downloadArtifact(artifacts[i]);
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-encrypt]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-encrypt"));
      if (artifacts[i] && btn instanceof HTMLButtonElement) {
        openArtifactInEncrypt(artifacts[i], btn);
      }
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-decrypt]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-decrypt"));
      if (artifacts[i] && btn instanceof HTMLButtonElement) {
        openArtifactInDecrypt(artifacts[i], btn);
      }
      touchActivity();
    });
  });
  panel.querySelector("#download-all-btn")?.addEventListener("click", () => {
    downloadAllArtifacts();
    touchActivity();
  });
}

/**
 * Inline “open in new window” indicator for Encrypt/Decrypt popout buttons.
 * Kept as a constant so label updates only touch `.btn-label`.
 */
const NEW_WINDOW_ICON = `<svg class="icon-new-window" width="12" height="12" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path fill="currentColor" d="M10 1h5v5h-1.5V3.56L7.78 9.28 6.72 8.22l5.72-5.72H10V1zM2 2.5A1.5 1.5 0 0 1 3.5 1H8v1.5H3.5a.5.5 0 0 0-.5.5v9a.5.5 0 0 0 .5.5h9a.5.5 0 0 0 .5-.5V8H15v3.5A1.5 1.5 0 0 1 13.5 13h-10A1.5 1.5 0 0 1 2 11.5v-9z"/></svg>`;

/**
 * @param {string} text
 * @returns {string}
 */
function popoutButtonHtml(text) {
  return `<span class="btn-label">${escapeHtml(text)}</span>${NEW_WINDOW_ICON}`;
}

/**
 * @param {HTMLButtonElement} button
 * @param {string} text
 */
function setPopoutButtonLabel(button, text) {
  const label = button.querySelector(".btn-label");
  if (label) {
    label.textContent = text;
    return;
  }
  button.innerHTML = popoutButtonHtml(text);
}

/**
 * Whether Encrypt should open this artifact as a compose message (vs file).
 *
 * Disposition is recipe-driven (`text`/`print` → message, `out` → file).
 * Do NOT reintroduce hex/base64/armor sniffing here — that pushes secrets into
 * immutable JS strings and fights memory-safety.js rule 4.
 *
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 */
function artifactIsMessage(a) {
  return artifactIsTextualForEncrypt(a);
}

/**
 * Build a binary-safe Encrypt transfer payload.
 *
 * Messages send UTF-8 text (string unavoidable for compose). Files send a
 * Uint8Array so Encrypt can build a File without UTF-8 mangling and so the
 * handoff can transfer/wipe the buffer (see openArtifactInEncrypt).
 *
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} artifact
 */
function buildEncryptTransfer(artifact) {
  const label = artifact.label || "Toolkit artifact";
  const filename = sanitizeFilename(artifact.filename);
  const mime = artifact.mime || "application/octet-stream";
  const pipeType = artifact.pipeType || null;

  if (artifactIsMessage(artifact)) {
    return {
      disposition: "message",
      text: String(artifact.content ?? ""),
      label,
      filename,
      mime: mime.startsWith("text/") ? mime : "text/plain; charset=utf-8",
      encoding: artifact.encoding || "text",
      pipeType,
    };
  }

  return {
    disposition: "file",
    bytes: artifactToBytes(artifact),
    label,
    filename,
    mime,
    encoding: artifact.encoding || "binary",
    pipeType,
  };
}

/**
 * Recover raw octets for a file-disposition artifact.
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 * @returns {Uint8Array}
 */
function artifactToBytes(a) {
  if (a.bytes instanceof Uint8Array) {
    return a.bytes;
  }
  const enc = String(a.encoding || "").toLowerCase();
  const content = String(a.content ?? "");
  if (enc === "base64" || enc === "base64url" || /\.b64$/i.test(a.filename || "")) {
    try {
      return base64ToBytes(content.replace(/\s+/g, ""));
    } catch (_) {
      /* fall through */
    }
  }
  if (enc === "hex") {
    try {
      return hexToBytes(content);
    } catch (_) {
      /* fall through */
    }
  }
  return new TextEncoder().encode(content);
}

/**
 * Detect OpenPGP ciphertext so the Decrypt popout can replace Encrypt.
 * @param {{ content?: string, mime?: string, role?: string }} a
 */
function artifactLooksLikePgpCiphertext(a) {
  if (a?.role === "ciphertext" || a?.role === "envelope") return true;
  if (a?.mime === "application/pgp-encrypted") return true;
  return /-----BEGIN PGP MESSAGE-----/i.test(String(a?.content || ""));
}

/**
 * Open the Encrypt composer and transfer one artifact after it signals that
 * its crypto self-test and UI initialization have completed. Content travels
 * only through a same-origin window message; it is never put in a URL or
 * persistent browser storage.
 *
 * File dispositions: copy into a dedicated ArrayBuffer and *transfer* it via
 * postMessage’s transfer list so the opener’s view is detached (byteLength → 0)
 * instead of structured-clone duplicating the secret. Then wipe any still-live
 * view with inlined fill(0). See memory-safety.js and MDN Transferable objects.
 * Do not drop the transfer list “for simplicity”.
 *
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} artifact
 * @param {HTMLButtonElement} button
 */
function openArtifactInEncrypt(artifact, button) {
  const asMessage = artifactIsMessage(artifact);
  const idleLabel = asMessage ? "Encrypt as message…" : "Encrypt as file…";
  const transfer = buildEncryptTransfer(artifact);
  const popup = window.open(
    "/encrypt?source=toolkit",
    "_blank",
    "popup,width=1100,height=850"
  );
  if (!popup) {
    setPopoutButtonLabel(button, "Pop-up blocked");
    setTimeout(() => {
      setPopoutButtonLabel(button, idleLabel);
    }, 1800);
    return;
  }

  button.disabled = true;
  setPopoutButtonLabel(button, "Opening…");
  const timeout = setTimeout(() => {
    window.removeEventListener("message", onReady);
    button.disabled = false;
    setPopoutButtonLabel(button, idleLabel);
  }, 15_000);

  /** @param {MessageEvent} event */
  function onReady(event) {
    if (
      event.origin !== window.location.origin ||
      event.source !== popup ||
      event.data?.type !== "basilisk:encrypt-ready"
    ) {
      return;
    }
    clearTimeout(timeout);
    window.removeEventListener("message", onReady);

    /** @type {Transferable[]} */
    const transferList = [];
    // Own a tightly packed buffer so transfer does not detach pipeline
    // artifact.bytes (which may still back the Results download tile).
    if (
      transfer.disposition === "file" &&
      transfer.bytes instanceof Uint8Array &&
      transfer.bytes.byteLength > 0
    ) {
      const owned = new Uint8Array(transfer.bytes);
      transfer.bytes = owned;
      transferList.push(owned.buffer);
    }

    popup.postMessage(
      {
        type: "basilisk:encrypt-artifact",
        artifact: transfer,
      },
      window.location.origin,
      transferList
    );
    // Transfer usually detaches owned.buffer (byteLength → 0); wipe if still live.
    if (transfer.disposition === "file") {
      try {
        if (transfer.bytes?.byteLength > 0) transfer.bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
    }

    popup.focus();
    setPopoutButtonLabel(button, "Opened");
    setTimeout(() => {
      button.disabled = false;
      setPopoutButtonLabel(button, idleLabel);
    }, 1200);
  }

  window.addEventListener("message", onReady);
}

/**
 * Open Decrypt and transfer OpenPGP ciphertext after the page signals ready.
 * @param {{ label?: string, filename?: string, content: string, mime?: string }} artifact
 * @param {HTMLButtonElement} button
 */
function openArtifactInDecrypt(artifact, button) {
  const idleLabel = "Decrypt…";
  const popup = window.open(
    "/decrypt?source=toolkit",
    "_blank",
    "popup,width=1100,height=850"
  );
  if (!popup) {
    setPopoutButtonLabel(button, "Pop-up blocked");
    setTimeout(() => {
      setPopoutButtonLabel(button, idleLabel);
    }, 1800);
    return;
  }

  button.disabled = true;
  setPopoutButtonLabel(button, "Opening…");
  const timeout = setTimeout(() => {
    window.removeEventListener("message", onReady);
    button.disabled = false;
    setPopoutButtonLabel(button, idleLabel);
  }, 15_000);

  /** @param {MessageEvent} event */
  function onReady(event) {
    if (
      event.origin !== window.location.origin ||
      event.source !== popup ||
      event.data?.type !== "basilisk:decrypt-ready"
    ) {
      return;
    }
    clearTimeout(timeout);
    window.removeEventListener("message", onReady);
    popup.postMessage(
      {
        type: "basilisk:decrypt-ciphertext",
        artifact: {
          label: artifact.label || "Toolkit ciphertext",
          filename: sanitizeFilename(artifact.filename, "encrypted.asc"),
          content: artifact.content,
          mime: artifact.mime || "application/pgp-encrypted",
        },
      },
      window.location.origin
    );
    popup.focus();
    setPopoutButtonLabel(button, "Opened");
    setTimeout(() => {
      button.disabled = false;
      setPopoutButtonLabel(button, idleLabel);
    }, 1200);
  }

  window.addEventListener("message", onReady);
}

/**
 * @param {{ filename?: string, content: string, mime?: string }} a
 */
function downloadArtifact(a) {
  const blob = new Blob([a.content], {
    type: a.mime || "text/plain",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = sanitizeFilename(a.filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function downloadAllArtifacts() {
  if (artifacts.length < 2) {
    if (artifacts[0]) downloadArtifact(artifacts[0]);
    return;
  }
  const names = uniquifyFilenames(
    artifacts.map((a, i) =>
      sanitizeFilename(a.filename, `artifact-${i + 1}.txt`)
    )
  );
  const zip = buildZipStore(
    artifacts.map((a, i) => ({
      name: names[i],
      content: a.content,
    }))
  );
  const blob = new Blob([zip], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `toolkit-results-${artifacts.length}.zip`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/**
 * @param {import("../lib/toolkit/recipe.js").RecipeAst} ast
 * @param {{
 *   inputs?: import("../lib/toolkit/engine.js").RuntimeBindings["inputs"],
 *   privateKeyArmored?: string,
 *   passphrase?: string,
 *   encryption?: import("../lib/toolkit/engine.js").RuntimeBindings["encryption"],
 * }} [opts]
 */
async function runViaWorker(ast, opts = {}) {
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("../lib/crypto-worker.js", import.meta.url), {
        type: "module",
      });
    } catch (err) {
      reject(err);
      return;
    }
    activeWorker = worker;
    const finish = () => {
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      if (activeWorker === worker) activeWorker = null;
    };
    const id = `tk-${Date.now()}`;
    const timer = setTimeout(() => {
      finish();
      reject(new Error("Toolkit worker timed out"));
    }, 120_000);
    worker.onmessage = (ev) => {
      if (ev.data?.id !== id) return;
      clearTimeout(timer);
      finish();
      if (ev.data.ok) resolve(ev.data.artifacts || []);
      else reject(new Error(ev.data.error || "Toolkit run failed"));
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      finish();
      reject(err?.message ? new Error(err.message) : new Error("Worker error"));
    };
    worker.postMessage({
      id,
      type: "toolkit-run",
      ast,
      recipientKeysArmored: boundRecipients.map((r) => r.armoredKey),
      recipientFingerprints: boundRecipients.map((r) => r.fingerprint),
      inputs: opts.inputs || {},
      privateKeyArmored: opts.privateKeyArmored || "",
      passphrase: opts.passphrase || "",
      encryption: opts.encryption,
    });
  });
}

function setReferenceOpen(open) {
  referenceOpen = open;
  document.getElementById("reference-panel")?.classList.toggle("hidden", !referenceOpen);
  if (referenceOpen) renderReference();
}

document.getElementById("toggle-reference")?.addEventListener("click", () => {
  setReferenceOpen(!referenceOpen);
});

document.getElementById("close-reference")?.addEventListener("click", () => {
  setReferenceOpen(false);
});

document.getElementById("destroy-btn")?.addEventListener("click", () => {
  secureDestroy();
});

document.getElementById("clear-recipe-btn")?.addEventListener("click", () => {
  steps = [];
  setRecipeTitle("");
  setRecipeFromSteps();
});

document.getElementById("recipe-title")?.addEventListener("input", (e) => {
  const t = e.target;
  if (t instanceof HTMLInputElement) recipeTitle = t.value;
});

document.getElementById("ops-filter")?.addEventListener("input", (e) => {
  const t = e.target;
  opsFilter = t instanceof HTMLInputElement ? t.value : "";
  renderOpsDrawer();
});

let recipeTimer = 0;
document.getElementById("recipe-text")?.addEventListener("input", () => {
  clearTimeout(recipeTimer);
  recipeTimer = window.setTimeout(() => {
    const ta = document.getElementById("recipe-text");
    if (ta instanceof HTMLTextAreaElement) loadRecipeText(ta.value);
  }, 300);
});

document.getElementById("run-btn")?.addEventListener("click", async () => {
  if (!cryptoReady) {
    showError(errorEl, "Crypto self-test has not passed.");
    return;
  }
  try {
    await assertCryptoReady();
  } catch (err) {
    showError(
      errorEl,
      err instanceof CryptoModuleError
        ? `Refusing to run — crypto self-test failed: ${err.message}`
        : String(err)
    );
    return;
  }

  const source = serializeRecipe(steps);
  const { ast, validation } = compileRecipe(source);
  if (!ast || !validation.ok) {
    showError(errorEl, validation.errors.map((e) => e.message).join(" · "));
    return;
  }
  const need = unresolvedRecipients(ast);
  if (need.slots > 0) {
    if (boundRecipients.length < need.slots) {
      showError(
        errorEl,
        `Select ${need.slots} recipient${need.slots === 1 ? "" : "s"} and confirm fingerprints before running.`
      );
      return;
    }
  }

  const status = document.getElementById("run-status");
  const btn = document.getElementById("run-btn");
  if (status) {
    status.className = "status-row";
    status.textContent = "Running…";
    status.classList.remove("hidden");
  }
  if (btn) btn.disabled = true;
  errorEl.classList.add("hidden");

  /** Ephemeral vault key — scrubbed after postMessage. */
  let privateKeyArmored = "";
  try {
    const collected = await collectRuntimeInputs();
    privateKeyArmored = collected.privateKeyArmored;
    const gpgMessages = collected.inputs.gpg?.armoredMessages || [];
    const hasPgpCipher = gpgMessages.some((m) =>
      /-----BEGIN PGP MESSAGE-----/i.test(String(m || ""))
    );
    const shareMnemonics = collected.inputs.shares?.mnemonics || [];
    if (
      currentInputNeeds.includes("text") &&
      !(collected.inputs.text?.value || "").trim()
    ) {
      throw new Error("Paste input text or load it from a file before executing.");
    }
    if (currentInputNeeds.includes("gpg") && hasPgpCipher && !privateKeyArmored) {
      throw new Error(
        "OpenPGP ciphertext needs a vault/pasted private key, or decrypt those messages externally and paste the mnemonics in the share rows."
      );
    }
    if (
      currentInputNeeds.includes("shares") &&
      !currentInputNeeds.includes("gpg") &&
      !shareMnemonics.length
    ) {
      throw new Error("Paste at least one BLIP39 share mnemonic.");
    }
    if (
      currentInputNeeds.includes("gpg") &&
      !gpgMessages.length &&
      !shareMnemonics.length
    ) {
      throw new Error(
        "Paste OpenPGP ciphertext and/or already-decrypted share mnemonics."
      );
    }
    if (currentInputNeeds.includes("gpg") && hasPgpCipher) {
      status.textContent = "Unlocking key & running…";
    }
    artifacts = await runViaWorker(ast, {
      inputs: collected.inputs,
      privateKeyArmored,
      passphrase: collected.passphrase,
      encryption: {
        profile: { ...toolkitEncryptProfile },
        hideRecipients: toolkitHideRecipients,
      },
    });
    renderResults();
    touchActivity();
    if (status) {
      status.className = "status-row ok";
      status.textContent = `Done — ${artifacts.length} artifact${artifacts.length === 1 ? "" : "s"}.`;
    }
  } catch (err) {
    if (status) {
      status.className = "status-row err";
      status.textContent = err?.message || "Run failed";
    }
    showError(errorEl, err?.message || "Run failed");
  } finally {
    privateKeyArmored = "";
    const privEl = document.getElementById("input-privkey");
    // Do not clear pasted key unless from vault path — user may retry.
    const passEl = document.getElementById("input-key-pass");
    if (passEl instanceof HTMLInputElement) passEl.value = "";
    void privEl;
    if (btn) btn.disabled = false;
  }
});

async function startPage() {
  const status = document.getElementById("crypto-status");
  try {
    const result = await runCryptoSelfTests();
    if (!result.passed) {
      throw new CryptoModuleError(result.error || "POST failed");
    }
    cryptoReady = true;
    await refreshVaultKeys();
    if (status) {
      status.className = "app-status ok";
      status.textContent = formatCryptoVerifiedMessage(result);
      const fullRoot = result.moduleIntegrity?.root || "";
      if (fullRoot) status.title = `Module Merkle root (SHA-256): ${fullRoot}`;
    }
    const runBtn = document.getElementById("run-btn");
    if (runBtn) runBtn.disabled = false;
    // Re-render inputs so vault dropdown is populated.
    if (currentInputNeeds.length) renderInputsPanel(currentInputNeeds);
  } catch (err) {
    cryptoReady = false;
    if (status) {
      status.className = "app-status err";
      status.innerHTML =
        `<strong>Crypto self-test FAILED</strong> — toolkit disabled. ` +
        escapeHtml(err?.message || String(err));
    }
  }
}

renderPresets();
renderOpsDrawer();
loadRecipeText(PRESETS[0].recipe, { title: PRESETS[0].title });
startPage();

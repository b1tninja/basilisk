/**
 * Crypto Toolkit page — presets-first pipeline builder + recipe language.
 * Separate from /encrypt novice UX.
 */

import { Auth } from "../lib/auth.js";
import {
  CryptoModuleError,
  assertCryptoReady,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { mountRecipientBinder } from "../lib/recipient-picker.js";
import {
  splitArmoredMessages,
  stripArmoredMessages,
} from "../lib/pgp/armor.js";
import { validateShareMnemonic } from "../lib/slip39/slip39.js";
import { bytesToBase64, zeroBuffer } from "../lib/toolkit/encode.js";
import {
  PRESETS,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
  unresolvedInputs,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import { getStep, listSteps, stepsAccepting, effectiveIo } from "../lib/toolkit/registry.js";
import {
  copyTextTransient,
  escapeHtml,
  formatFingerprint,
  showError,
} from "../lib/utils.js";
import { buildZipStore, uniquifyFilenames } from "../lib/zip-store.js";
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
let referenceOpen = false;
/** @type {import("../lib/toolkit/engine.js").ToolkitArtifact[]} */
let artifacts = [];
/** @type {import("../lib/recipient-picker.js").Recipient[]} */
let boundRecipients = [];
/** @type {ReturnType<typeof mountRecipientBinder>|null} */
let binder = null;
/** @type {import("../lib/vault.js").VaultKeyMeta[]} */
let vaultKeys = [];
/** @type {("shares"|"gpg"|"text")[]} */
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
/** Ops drawer search query. */
let opsFilter = "";
/** Collapsed category keys in the ops drawer. */
/** @type {Set<string>} */
let opsCollapsed = new Set();

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
        <p class="muted fs-sm mb-md">Drop operations here. Reorder by dragging cards. Recipients are chosen at run time — never stored in the pipeline text.</p>
        <div id="builder-steps" class="builder-steps"></div>
        <details class="recipe-text-details mt-md">
          <summary class="muted fs-sm">Pipeline source (text)</summary>
          <textarea id="recipe-text" class="compose-message mt-sm" rows="3" spellcheck="false"
            placeholder="genkey ec/p256 | export pkcs8 | pem"></textarea>
          <p id="recipe-errors" class="status-row err hidden mt-sm"></p>
          <p id="recipe-warnings" class="muted mt-xs fs-sm"></p>
        </details>
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
 * JavaScript cannot guarantee zeroization: strings are immutable and managed by
 * the garbage collector, the engine may retain copies, and there is no way to
 * pin memory or mlock() pages. WebCrypto/W3C explicitly does not zeroize key
 * material when a CryptoKey is dropped. We therefore do the accepted best-effort
 * (per FIPS 140-3 CSP-zeroization guidance for JS modules):
 *   - terminate the crypto worker so its heap (decrypted private keys, plaintext,
 *     pipeline byte buffers) is discarded wholesale;
 *   - overwrite any Uint8Array we still own with zeros (done at each use site);
 *   - drop every reference to secret-bearing objects and strings so they become
 *     collectable;
 *   - clear all input/output DOM fields so revealed secrets leave the layout.
 * The pipeline definition itself is not a secret and is preserved (use Clear to
 * reset it).
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
    "input-envelope-gpg",
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
 */
function addStepAt(name, index) {
  const spec = getStep(name);
  if (!spec) return;
  const step = {
    name: spec.name,
    params: defaultParams(spec),
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
 * Output type after the last step (for suggesting compatible ops).
 * @returns {import("../lib/toolkit/registry.js").IoType|"none"}
 */
function currentPipelineOutput() {
  if (!steps.length) return "none";
  const last = steps[steps.length - 1];
  const spec = getStep(last.name);
  if (!spec) return "none";
  return effectiveIo(spec, last.params).output;
}

function loadRecipeText(text) {
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
  if (errEl) errEl.classList.add("hidden");
  validateAndBind();
  renderBuilder();
  renderOpsDrawer();
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
 * @param {("shares"|"gpg"|"text")[]} needs
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
    ? "Recombine"
    : needs.includes("gpg")
      ? "Decrypt"
      : "Input";
  /** @type {string[]} */
  const parts = [`<p class="card-title">${title}</p>`];
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
          <span class="field-label m-0">SLIP-39 share mnemonics</span>
          <button type="button" class="btn btn-ghost btn-compact" id="add-share-btn">+ Add share</button>
          <button type="button" class="btn btn-ghost btn-compact" id="load-shares-btn">Load from file…</button>
          <input type="file" id="load-shares-file" class="hidden" multiple accept=".txt,text/plain,*/*">
        </div>
        <p class="muted fs-sm mb-sm">${
          needs.includes("gpg")
            ? "Use these rows for mnemonics already decrypted outside the browser (Kleopatra/gpg/YubiKey). Mix with OpenPGP ciphertext below — the pipeline merges both before combine."
            : "One share per row. Paste multiple lines into a row to auto-split. K-of-N required to recover."
        }</p>
        <div id="share-rows">${rowsHtml}</div>
        <label class="field-label mt-md" for="input-envelope">Envelope ciphertext (base64)</label>
        <div class="btn-row wrap mb-xs">
          <button type="button" class="btn btn-ghost btn-compact" id="load-envelope-btn">Load envelope…</button>
          <input type="file" id="load-envelope-file" class="hidden" accept=".b64,.bin,.txt,*/*">
        </div>
        <textarea id="input-envelope" class="compose-message" rows="2" spellcheck="false"
          placeholder="Required when shares were created from a non-16/32-byte payload (e.g. PEM) — look for envelope.bin.b64 in Results">${escapeHtml(envelopeDraft)}</textarea>
        <label class="field-label mt-md" for="input-share-pass">Share passphrase (optional)</label>
        <input type="password" id="input-share-pass" class="text-input" autocomplete="off" value="${escapeHtml(sharePassDraft)}">
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
      <label class="field-label mt-md" for="input-envelope-gpg">Envelope ciphertext (base64, if needed)</label>
      <div class="btn-row wrap mb-xs">
        <button type="button" class="btn btn-ghost btn-compact" id="load-envelope-gpg-btn">Load envelope…</button>
        <input type="file" id="load-envelope-gpg-file" class="hidden" accept=".b64,.bin,.txt,*/*">
      </div>
      <textarea id="input-envelope-gpg" class="compose-message" rows="2" spellcheck="false"
        placeholder="Paste envelope.bin.b64 from the encrypt pipeline">${escapeHtml(
          needs.includes("shares") ? "" : envelopeDraft
        )}</textarea>
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
 * @param {("shares"|"gpg"|"text")[]} needs
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

    const envEl = host.querySelector("#input-envelope");
    envEl?.addEventListener("input", () => {
      if (envEl instanceof HTMLTextAreaElement) envelopeDraft = envEl.value;
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

    wireFileButton(host, "#load-envelope-btn", "#load-envelope-file", async (files) => {
      const f = files[0];
      if (!f) return;
      envelopeDraft = await readEnvelopeFile(f);
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

    wireFileButton(
      host,
      "#load-envelope-gpg-btn",
      "#load-envelope-gpg-file",
      async (files) => {
        const f = files[0];
        if (!f) return;
        const b64 = await readEnvelopeFile(f);
        envelopeDraft = b64;
        const envEl = host.querySelector("#input-envelope-gpg");
        if (envEl instanceof HTMLTextAreaElement) envEl.value = b64;
      }
    );
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
 * Read envelope as base64 (text passthrough, or binary → base64).
 * @param {File} file
 * @returns {Promise<string>}
 */
async function readEnvelopeFile(file) {
  const name = (file.name || "").toLowerCase();
  if (name.endsWith(".b64") || name.endsWith(".txt") || file.type.startsWith("text/")) {
    return (await file.text()).replace(/\s+/g, "");
  }
  // Heuristic: try text; if it looks like base64 keep it, else treat as binary.
  const buf = new Uint8Array(await file.arrayBuffer());
  try {
    const asText = new TextDecoder("utf-8", { fatal: true }).decode(buf).trim();
    if (/^[A-Za-z0-9+/=\s]+$/.test(asText) && asText.length > 16) {
      return asText.replace(/\s+/g, "");
    }
  } catch (_) {
    /* binary */
  }
  return bytesToBase64(buf);
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

  if (currentInputNeeds.includes("shares")) {
    // Sync from live DOM in case last keystroke wasn't flushed to shareRows.
    document.querySelectorAll("[data-share-input]").forEach((el) => {
      const i = Number(el.getAttribute("data-share-input"));
      if (el instanceof HTMLTextAreaElement && i >= 0) shareRows[i] = el.value;
    });
    const envEl = document.getElementById("input-envelope");
    const passEl = document.getElementById("input-share-pass");
    if (envEl instanceof HTMLTextAreaElement) envelopeDraft = envEl.value;
    if (passEl instanceof HTMLInputElement) sharePassDraft = passEl.value;
    const mnemonics = shareRows.map((m) => m.trim()).filter(Boolean);
    inputs.shares = {
      mnemonics,
      envelopeB64: envelopeDraft.trim(),
      passphrase: sharePassDraft,
    };
  }

  if (currentInputNeeds.includes("gpg")) {
    const ctEl = document.getElementById("input-ciphertext");
    const envEl = document.getElementById("input-envelope-gpg");
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
        zeroBuffer(opts.prfIkm);
      }
    }

    let envelopeB64 =
      envEl instanceof HTMLTextAreaElement ? envEl.value.trim() : "";
    if (envelopeB64) envelopeDraft = envelopeB64;
    else if (envelopeDraft.trim()) envelopeB64 = envelopeDraft.trim();
    inputs.gpg = {
      armoredMessages: [...messages, ...plainFromCt],
      privateKeyArmored,
      passphrase,
      envelopeB64,
    };
    // Merge ciphertext-box mnemonics + share rows for decrypt hybrid path
    if (plainFromCt.length || envelopeB64) {
      inputs.shares = inputs.shares || { mnemonics: [] };
      if (plainFromCt.length) {
        inputs.shares.mnemonics = [
          ...(inputs.shares.mnemonics || []),
          ...plainFromCt,
        ];
      }
      if (envelopeB64 && !inputs.shares.envelopeB64) {
        inputs.shares.envelopeB64 = envelopeB64;
      }
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
      loadRecipeText(preset.recipe);
      document.getElementById("preset-gallery")?.removeAttribute("open");
    });
  });
}

/**
 * CyberChef-style operations drawer grouped by kind.
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
  const byKind = new Map();
  for (const s of all) {
    if (q) {
      const hay = `${s.name} ${s.kind} ${s.doc} ${(s.aliases || []).join(" ")}`.toLowerCase();
      if (!hay.includes(q)) continue;
    }
    const list = byKind.get(s.kind) || [];
    list.push(s);
    byKind.set(s.kind, list);
  }

  const kinds = [...byKind.keys()].sort(
    (a, b) => (KIND_META[a]?.order ?? 9) - (KIND_META[b]?.order ?? 9)
  );

  if (!kinds.length) {
    host.innerHTML = `<p class="muted fs-sm">No operations match “${escapeHtml(opsFilter)}”.</p>`;
    return;
  }

  if (hint) {
    hint.textContent = steps.length
      ? `Suggested next (from ${from}): highlighted. Drag or click to add.`
      : "Drag onto the pipeline, or click to append.";
  }

  host.innerHTML = kinds
    .map((kind) => {
      const meta = KIND_META[kind] || { label: kind };
      const collapsed = opsCollapsed.has(kind) && !q;
      const items = byKind.get(kind) || [];
      return `
        <div class="ops-category" data-kind="${escapeHtml(kind)}">
          <button type="button" class="ops-category-toggle" data-toggle-kind="${escapeHtml(kind)}"
            aria-expanded="${collapsed ? "false" : "true"}">
            <span>${escapeHtml(meta.label)}</span>
            <span class="muted fs-xs">${items.length}</span>
          </button>
          <div class="ops-category-body ${collapsed ? "hidden" : ""}">
            ${items
              .map((s) => {
                const fit = !steps.length
                  ? s.kind === "source" || s.input === "none"
                  : suggested.has(s.name);
                return `
                <button type="button" class="ops-item ${fit ? "ops-item-fit" : "ops-item-dim"}"
                  draggable="true" data-op="${escapeHtml(s.name)}"
                  title="${escapeHtml(s.doc)}">
                  <span class="ops-item-name">${escapeHtml(s.name)}</span>
                  <span class="muted fs-xs ops-item-io">${escapeHtml(s.input)} → ${escapeHtml(s.output)}</span>
                </button>`;
              })
              .join("")}
          </div>
        </div>`;
    })
    .join("");

  host.querySelectorAll("[data-toggle-kind]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const kind = btn.getAttribute("data-toggle-kind") || "";
      if (opsCollapsed.has(kind)) opsCollapsed.delete(kind);
      else opsCollapsed.add(kind);
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

  if (!steps.length) {
    host.innerHTML = `
      <div class="builder-dropzone builder-empty" data-insert="0">
        <p class="muted mb-0">Drop an operation here to start the pipeline</p>
        <p class="muted fs-xs mb-0">Sources like <code>genkey</code>, <code>random</code>, or <code>recombine</code> work well first.</p>
      </div>`;
    wireDropZones(host);
    return;
  }

  let foreachOpen = false;
  /** @type {string[]} */
  const parts = [];
  parts.push(`<div class="builder-dropzone" data-insert="0" aria-label="Insert at start"></div>`);

  steps.forEach((step, i) => {
    const spec = getStep(step.name);
    if (step.name === "foreach") foreachOpen = true;
    const inForeach =
      foreachOpen && step.name !== "foreach" && step.name !== "merge";
    if (step.name === "merge") foreachOpen = false;

    const paramFields = (spec?.params || [])
      .map((p) => {
        const val = step.params[p.name] ?? p.default ?? "";
        if (p.type === "enum") {
          return `<label class="builder-param">${escapeHtml(p.name)}
            <select data-step="${i}" data-param="${escapeHtml(p.name)}" class="text-input">
              ${(p.enum || [])
                .map(
                  (e) =>
                    `<option value="${escapeHtml(e)}" ${String(val) === e ? "selected" : ""}>${escapeHtml(e)}</option>`
                )
                .join("")}
            </select></label>`;
        }
        return `<label class="builder-param">${escapeHtml(p.name)}
          <input class="text-input" data-step="${i}" data-param="${escapeHtml(p.name)}"
                 value="${escapeHtml(String(val))}" ${p.type === "int" ? 'type="number"' : 'type="text"'}></label>`;
      })
      .join("");

    const isOut = step.name === "out";
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
      : "";

    parts.push(`
      <div class="builder-card ${inForeach ? "builder-foreach-child" : ""} ${step.name === "foreach" ? "builder-foreach" : ""} ${isOut ? "builder-out" : ""}"
           draggable="true" data-index="${i}">
        <div class="builder-card-head">
          <span class="builder-drag" title="Drag to reorder">⠿</span>
          <strong>${escapeHtml(step.name)}</strong>
          ${isOut ? `<span class="badge pending">output tile</span>` : `<span class="muted fs-xs">${escapeHtml(spec?.kind || "")}</span>`}
          ${outSummary ? `<span class="muted fs-xs">${escapeHtml(outSummary)}</span>` : ""}
          <button type="button" class="btn btn-ghost btn-compact text-error" data-remove="${i}">Remove</button>
        </div>
        <p class="muted mt-xs mb-sm fs-xs">${escapeHtml(spec?.doc || "")}</p>
        <div class="builder-params">${paramFields}</div>
      </div>
      <div class="builder-dropzone" data-insert="${i + 1}" aria-label="Insert after ${escapeHtml(step.name)}"></div>`);
  });

  host.innerHTML = parts.join("");

  host.querySelectorAll("[data-param]").forEach((el) => {
    el.addEventListener("change", () => {
      const i = Number(el.getAttribute("data-step"));
      const name = el.getAttribute("data-param");
      if (!name || !steps[i]) return;
      const v =
        el instanceof HTMLInputElement || el instanceof HTMLSelectElement
          ? el.value
          : "";
      const spec = getStep(steps[i].name);
      const p = (spec?.params || []).find((x) => x.name === name);
      steps[i].params[name] = p?.type === "int" ? Number(v) : v;
      setRecipeFromSteps();
    });
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

  wireDropZones(host);
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
      if (name && getStep(name)) addStepAt(name, insertAt);
    });
  });
}

function renderReference() {
  const body = document.getElementById("reference-body");
  if (!body) return;
  body.innerHTML = listSteps()
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
      return `<details class="ref-step">
        <summary><code>${escapeHtml(s.name)}</code> <span class="muted">${escapeHtml(s.kind)}</span>
          · ${escapeHtml(s.input)} → ${escapeHtml(s.output)}</summary>
        <p class="fs-md">${escapeHtml(s.doc)}</p>
        ${aliases}
        ${params ? `<ul class="fs-sm">${params}</ul>` : "<p class='muted'>No parameters.</p>"}
      </details>`;
    })
    .join("");
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
  const hasEnvelope = artifacts.some(
    (a) => /envelope/i.test(a.label || "") || /envelope/i.test(a.filename || "")
  );
  const hasShares = artifacts.some((a) => a.shareIndex || /^Share\s+\d+/i.test(a.label || ""));
  panel.innerHTML = `
    <div class="btn-row wrap mb-md items-center">
      <p class="muted mb-0 flex-1">Sensitive outputs are masked until revealed. Cleared after ${IDLE_CLEAR_MS / 60000} minutes of inactivity.</p>
      ${
        artifacts.length > 1
          ? `<button type="button" class="btn btn-ghost btn-compact" id="download-all-btn">Download all (${artifacts.length})</button>`
          : ""
      }
    </div>
    ${
      hasEnvelope && hasShares
        ? `<p class="status-row warn mb-md" role="status">Keep <strong>envelope.bin.b64</strong> with the shares — it is required for recovery of PEM / non-16/32-byte secrets (not secret itself, but without it the shares cannot be unwrapped).</p>`
        : ""
    }
    ${artifacts
      .map((a, i) => {
        const masked = a.sensitive;
        const preview = masked
          ? "•••••••• (click Reveal)"
          : a.content.length > 400
            ? escapeHtml(a.content.slice(0, 400)) + "…"
            : escapeHtml(a.content);
        const isSvg = a.mime === "image/svg+xml";
        const metaBits = [
          a.filename ? `<code class="fs-xs">${escapeHtml(a.filename)}</code>` : "",
          a.encoding ? `<span class="badge pending">${escapeHtml(a.encoding)}</span>` : "",
          a.mime && a.mime !== "text/plain; charset=utf-8" && a.mime !== "text/plain"
            ? `<span class="muted fs-xs">${escapeHtml(a.mime)}</span>`
            : "",
          a.shareIndex ? `<span class="badge pending">share ${a.shareIndex}</span>` : "",
          a.recipientFingerprint
            ? `<span class="muted fs-xs">→ ${escapeHtml(formatFingerprint(a.recipientFingerprint))}</span>`
            : "",
        ]
          .filter(Boolean)
          .join(" ");
        return `
        <div class="card artifact-card" data-art="${i}">
          <div class="artifact-card-head">
            <p class="card-title m-0">${escapeHtml(a.label)}</p>
            <div class="artifact-meta">${metaBits}</div>
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
          </div>
        </div>`;
      })
      .join("")}`;

  panel.querySelectorAll("[data-reveal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-reveal"));
      const pre = panel.querySelector(`.artifact-body[data-art="${i}"]`);
      if (pre) pre.textContent = artifacts[i].content;
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
  panel.querySelector("#download-all-btn")?.addEventListener("click", () => {
    downloadAllArtifacts();
    touchActivity();
  });
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
  link.download = a.filename || "artifact.txt";
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
    artifacts.map((a, i) => a.filename || `artifact-${i + 1}.txt`)
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
  setRecipeFromSteps();
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
      throw new Error("Paste at least one SLIP-39 share mnemonic.");
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
      status.textContent = "Crypto module verified.";
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
loadRecipeText(PRESETS[0].recipe);
startPage();

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
import { bytesToBase64 } from "../lib/toolkit/encode.js";
import {
  PRESETS,
  compileRecipe,
  parseRecipe,
  serializeRecipe,
  unresolvedInputs,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import { getStep, listSteps, stepsAccepting } from "../lib/toolkit/registry.js";
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
let customizeOpen = false;
let referenceOpen = false;
/** @type {import("../lib/toolkit/engine.js").ToolkitArtifact[]} */
let artifacts = [];
/** @type {import("../lib/recipient-picker.js").Recipient[]} */
let boundRecipients = [];
/** @type {ReturnType<typeof mountRecipientBinder>|null} */
let binder = null;
/** @type {import("../lib/vault.js").VaultKeyMeta[]} */
let vaultKeys = [];
/** @type {("shares"|"gpg")[]} */
let currentInputNeeds = [];
/** Per-share mnemonic rows for the modular inputs UI (survives panel re-renders). */
/** @type {string[]} */
let shareRows = [""];
/** Envelope base64 retained across re-renders. */
let envelopeDraft = "";
/** Share passphrase retained across re-renders. */
let sharePassDraft = "";

const IDLE_CLEAR_MS = 5 * 60 * 1000;
let idleTimer = null;

app.innerHTML = `
  <div id="crypto-status" class="status-row" role="status">Verifying crypto module…</div>

  <div class="card toolkit-banner">
    <p class="m-0 fs-md">
      <strong>Advanced tool.</strong> This page generates extractable key material and shareable backups.
      Prefer hardware tokens for long-lived identity keys. Everyday messaging belongs on
      <a class="text-link" href="/encrypt">Encrypt</a>.
    </p>
  </div>

  <div id="preset-gallery" class="card">
    <p class="card-title">Templates</p>
    <p class="muted m-0-b-lg fs-md">One-click recipes. Customize afterward if you need a different pipeline.</p>
    <div class="preset-grid" id="preset-grid"></div>
  </div>

  <div class="btn-row my-lg">
    <button type="button" class="btn btn-ghost" id="toggle-customize">Customize pipeline</button>
    <button type="button" class="btn btn-ghost" id="toggle-reference">Reference</button>
  </div>

  <div id="customize-panel" class="hidden">
    <div class="card">
      <p class="card-title">Pipeline builder</p>
      <div id="builder-steps" class="builder-steps"></div>
      <div class="btn-row mt-md wrap">
        <select id="add-step-select" class="text-input maxw-220"></select>
        <button type="button" class="btn btn-compact" id="add-step-btn">Add step</button>
      </div>
    </div>

    <div class="card mt-lg">
      <p class="card-title">Recipe</p>
      <p class="muted m-0-b-sm fs-sm">
        Pipe-separated steps. Flow control: <code>foreach</code> / <code>merge</code>
        (aliases: map, each, fork / collect). Recipients are chosen at run time — never written into the recipe.
      </p>
      <textarea id="recipe-text" class="compose-message" rows="3" spellcheck="false"
        placeholder="genkey ec/p256 | export pkcs8 | pem"></textarea>
      <p id="recipe-errors" class="status-row err hidden mt-sm"></p>
      <p id="recipe-warnings" class="muted mt-xs fs-sm"></p>
      <div id="autocomplete" class="recipient-dropdown hidden"></div>
    </div>
  </div>

  <div id="reference-panel" class="card hidden mt-lg">
    <p class="card-title">Step reference</p>
    <div id="reference-body"></div>
  </div>

  <div class="card mt-lg">
    <p class="card-title">Run</p>
    <div id="inputs-host"></div>
    <div id="recipient-bind-host"></div>
    <div class="btn-row mt-md">
      <button type="button" class="btn" id="run-btn" disabled>Run recipe</button>
    </div>
    <p id="run-status" class="status-row hidden mt-sm"></p>
  </div>

  <div id="results-panel" class="hidden mt-lg"></div>
`;

function touchActivity() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    artifacts = [];
    renderResults();
    const rt = document.getElementById("recipe-text");
    // don't clear recipe — only sensitive outputs
  }, IDLE_CLEAR_MS);
}

function setRecipeFromSteps() {
  const ta = document.getElementById("recipe-text");
  if (ta instanceof HTMLTextAreaElement) {
    ta.value = serializeRecipe(steps);
  }
  validateAndBind();
  renderBuilder();
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
 * @param {("shares"|"gpg")[]} needs
 */
function renderInputsPanel(needs) {
  const host = document.getElementById("inputs-host");
  if (!host) return;
  if (!needs.length) {
    host.innerHTML = "";
    return;
  }
  if (!shareRows.length) shareRows = [""];

  /** @type {string[]} */
  const parts = ['<p class="card-title">Inputs</p>'];
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
 * @param {("shares"|"gpg")[]} needs
 */
function wireInputsPanel(host, needs) {
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
      if (meta?.protection === "passkey") {
        opts.prfIkm = await getPasskeyPrf();
      }
      privateKeyArmored = await vaultUnlockKey(vaultFpr, opts);
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
  grid.innerHTML = PRESETS.map(
    (p) => `
    <button type="button" class="preset-card" data-preset="${escapeHtml(p.id)}">
      <strong>${escapeHtml(p.title)}</strong>
      <span class="muted">${escapeHtml(p.blurb)}</span>
      <code class="preset-recipe">${escapeHtml(p.recipe)}</code>
    </button>`
  ).join("");
  grid.querySelectorAll("[data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-preset");
      const preset = PRESETS.find((p) => p.id === id);
      if (!preset) return;
      loadRecipeText(preset.recipe);
      customizeOpen = true;
      document.getElementById("customize-panel")?.classList.remove("hidden");
      document.getElementById("toggle-customize").textContent = "Hide pipeline";
    });
  });
}

function renderBuilder() {
  const host = document.getElementById("builder-steps");
  const addSelect = document.getElementById("add-step-select");
  if (!host) return;

  let foreachOpen = false;
  host.innerHTML = steps
    .map((step, i) => {
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

      return `
        <div class="builder-card ${inForeach ? "builder-foreach-child" : ""} ${step.name === "foreach" ? "builder-foreach" : ""}"
             draggable="true" data-index="${i}">
          <div class="builder-card-head">
            <span class="builder-drag" title="Drag to reorder">⠿</span>
            <strong>${escapeHtml(step.name)}</strong>
            <span class="muted fs-xs">${escapeHtml(spec?.kind || "")}</span>
            <button type="button" class="btn btn-ghost btn-compact text-error" data-remove="${i}">Remove</button>
          </div>
          <p class="muted mt-xs mb-sm fs-xs">${escapeHtml(spec?.doc || "")}</p>
          <div class="builder-params">${paramFields}</div>
        </div>`;
    })
    .join("");

  // Param change handlers
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

  // Drag reorder
  let dragFrom = -1;
  host.querySelectorAll(".builder-card").forEach((card) => {
    card.addEventListener("dragstart", () => {
      dragFrom = Number(card.getAttribute("data-index"));
      card.classList.add("dragging");
    });
    card.addEventListener("dragend", () => card.classList.remove("dragging"));
    card.addEventListener("dragover", (e) => e.preventDefault());
    card.addEventListener("drop", (e) => {
      e.preventDefault();
      const to = Number(card.getAttribute("data-index"));
      if (dragFrom < 0 || to < 0 || dragFrom === to) return;
      const [moved] = steps.splice(dragFrom, 1);
      steps.splice(to, 0, moved);
      setRecipeFromSteps();
    });
  });

  // Add-step select: suggest based on last output
  if (addSelect instanceof HTMLSelectElement) {
    const last = steps[steps.length - 1];
    const from = last ? getStep(last.name)?.output || "none" : "none";
    const candidates = stepsAccepting(from);
    const all = listSteps().filter((s) => s.kind !== "flow" || s.name === "foreach" || s.name === "merge");
    const list = candidates.length ? candidates : all;
    addSelect.innerHTML = list
      .map((s) => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} — ${escapeHtml(s.kind)}</option>`)
      .join("");
  }
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
  if (!panel) return;
  if (!artifacts.length) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }
  panel.classList.remove("hidden");
  const hasEnvelope = artifacts.some(
    (a) => /envelope/i.test(a.label || "") || /envelope/i.test(a.filename || "")
  );
  const hasShares = artifacts.some((a) => a.shareIndex || /^Share\s+\d+/i.test(a.label || ""));
  panel.innerHTML = `
    <h2>Results</h2>
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
        return `
        <div class="card artifact-card" data-art="${i}">
          <p class="card-title m-0-b-xs">${escapeHtml(a.label)}
            ${a.shareIndex ? `<span class="badge pending">share ${a.shareIndex}</span>` : ""}
            ${a.recipientFingerprint ? `<span class="muted fs-xs">→ ${escapeHtml(formatFingerprint(a.recipientFingerprint))}</span>` : ""}
          </p>
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
    const id = `tk-${Date.now()}`;
    const timer = setTimeout(() => {
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(new Error("Toolkit worker timed out"));
    }, 120_000);
    worker.onmessage = (ev) => {
      if (ev.data?.id !== id) return;
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      if (ev.data.ok) resolve(ev.data.artifacts || []);
      else reject(new Error(ev.data.error || "Toolkit run failed"));
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
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

document.getElementById("toggle-customize")?.addEventListener("click", () => {
  customizeOpen = !customizeOpen;
  document.getElementById("customize-panel")?.classList.toggle("hidden", !customizeOpen);
  document.getElementById("toggle-customize").textContent = customizeOpen
    ? "Hide pipeline"
    : "Customize pipeline";
});

document.getElementById("toggle-reference")?.addEventListener("click", () => {
  referenceOpen = !referenceOpen;
  document.getElementById("reference-panel")?.classList.toggle("hidden", !referenceOpen);
  if (referenceOpen) renderReference();
});

document.getElementById("add-step-btn")?.addEventListener("click", () => {
  const sel = document.getElementById("add-step-select");
  const name = sel instanceof HTMLSelectElement ? sel.value : "";
  const spec = getStep(name);
  if (!spec) return;
  /** @type {Record<string, string|number|boolean>} */
  const params = {};
  for (const p of spec.params || []) {
    if (p.default !== undefined) params[p.name] = p.default;
  }
  steps.push({ name: spec.name, params, start: 0, end: 0 });
  setRecipeFromSteps();
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
      status.className = "status-row ok";
      status.textContent = "Crypto module verified.";
    }
    const runBtn = document.getElementById("run-btn");
    if (runBtn) runBtn.disabled = false;
    // Re-render inputs so vault dropdown is populated.
    if (currentInputNeeds.length) renderInputsPanel(currentInputNeeds);
  } catch (err) {
    cryptoReady = false;
    if (status) {
      status.className = "status-row err";
      status.innerHTML =
        `<strong>Crypto self-test FAILED</strong> — toolkit disabled. ` +
        escapeHtml(err?.message || String(err));
    }
  }
}

renderPresets();
loadRecipeText(PRESETS[0].recipe);
startPage();

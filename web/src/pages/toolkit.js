/**
 * Crypto Toolkit page — notebook recipes, messaging quick-starts, and pipelines.
 * Everyday encrypt/decrypt lives here (`#encrypt` / `#decrypt`); legacy /encrypt|/decrypt redirect in.
 */

import { readKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import {
  buildKeyserverOptions,
  keyserverSelectFromOptionsHtml,
} from "../lib/keyserver-select.js";
import { getPreferredKeyserver } from "../lib/prefs.js";
import {
  CryptoModuleError,
  assertCryptoReady,
  formatSuiteStatusMessage,
  getSuiteStatus,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { getUpstreamConfig } from "../lib/upstream-config.js";
import { pageKeyserverOrigin } from "../lib/upstream-hkp.js";
import {
  FIPS_MODE_DISCLAIMER,
  getFipsMode,
  setFipsMode,
} from "../lib/fips-mode.js";
import { mountRecipientBinder } from "../lib/recipient-picker.js";
import {
  splitArmoredMessages,
  stripArmoredMessages,
} from "../lib/pgp/armor.js";
import { validateShareMnemonic } from "../lib/slip39/blip39.js";
import { base64ToBytes, hexToBytes } from "../lib/toolkit/encode.js";
import { glyphHtml } from "../lib/toolkit/glyphs.js";
import {
  DEFAULT_TOOLKIT_PREFS,
  getIdleClearMs,
  getToolkitPrefs,
  setToolkitPrefs,
} from "../lib/toolkit/prefs.js";
import {
  MESSAGING_STARTERS,
  hashForDecryptLink,
  hashForNotebook,
  hashForPreset,
  hashForRecipe,
  hashForStarter,
  parseToolkitHash,
  toolkitShareUrl,
  writeToolkitHash,
} from "../lib/toolkit/fragment.js";
import {
  deleteWorkspace,
  exportWorkspaceBlob,
  getWorkspace,
  listWorkspaces,
  parseWorkspaceFile,
  saveWorkspace,
  workspaceFingerprint,
} from "../lib/toolkit/workspace-store.js";
import {
  PRESETS,
  compileRecipe,
  canonicalizeRecipe,
  migrateRecipe,
  parseRecipe,
  recipeChains,
  serializeRecipe,
  unresolvedInputs,
  unresolvedRecipients,
  validateRecipe,
} from "../lib/toolkit/recipe.js";
import {
  resolvePresetPair,
  bridgeModeMeta,
  stitchPresetPair,
} from "../lib/toolkit/conjugate-stitch.js";
import {
  parseEncryptToToken,
  recipientResolutionKey,
} from "../lib/toolkit/recipients-ops.js";
import {
  lookupGlyphHtml,
  lookupRecipientsForPolicy,
  openRecipientResolveModal,
  resolutionForQuery,
  resolutionPillText,
} from "../lib/toolkit/recipient-resolve-ui.js";
import {
  CIPHER_PICKER_ALIASES,
  defaultCollapsedShelfKeys,
  getShelfMeta,
  getStep,
  instantiateCipherPick,
  instantiateFormatPick,
  KEY_FORMAT_PICKS,
  listCipherPickerSteps,
  listDrawerRows,
  listSteps,
  stepsAccepting,
  TOOLBOX_META,
} from "../lib/toolkit/registry.js";
import {
  INSPECT_FORMATS,
  inspectFromSnapshot,
} from "../lib/toolkit/inspect.js";
import {
  assertRecipeAllowedUnderFips,
  stepNameToSuite,
  suitesUsedBySteps,
  toolboxVerification,
  unverifiedSuitesAmong,
} from "../lib/toolkit/suite-gate.js";
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
  listKeys as vaultListKeys,
  sortKeysByLastUsed,
} from "../lib/vault.js";
import {
  sessionClear,
  sessionEarliestExpiry,
  sessionEvict,
  sessionList,
} from "../lib/vault-session.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { createKernel } from "../lib/toolkit/kernel.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/toolkit");

const errorEl = document.getElementById("error");
const app = document.getElementById("toolkit-app");

let cryptoReady = false;
/** FIPS-inspired verified-suites-only posture (persisted). */
let fipsMode = getFipsMode();
/** @type {import("../lib/toolkit/suite-gate.js").SuiteStatusMap} */
let suiteStatus = {
  openpgp: "unverified",
  webcrypto: "unverified",
  sss: "unverified",
};
/** @type {import("../lib/toolkit/recipe.js").RecipeStep[]} */
/** @type {{ steps: import("../lib/toolkit/recipe.js").RecipeStep[] }[]} */
let chains = [{ steps: [] }];
/** Focused notebook cell index (ops drawer / suggest-next apply here). */
let focusedCell = 0;
/** Collapsed cell indices */
/** @type {Set<number>} */
let cellCollapsed = new Set();
/** Variables drawer open */
let variablesOpen = false;
/** Expanded artifact previews: `${cellIndex}:${artIndex}` */
/** @type {Set<string>} */
let expandedArtifactKeys = new Set();
/** Focused cell steps — same array as chains[focusedCell].steps */
let steps = chains[0].steps;
/** Display title for the current pipeline (from preset or user edit). */
let recipeTitle = "";
let referenceOpen = false;
/** @type {ReturnType<typeof createKernel>} */
let kernel = createKernel();
/** Flat artifacts for legacy helpers (zip all / last run) — union of cell outputs */
/** @type {import("../lib/toolkit/engine.js").ToolkitArtifact[]} */
let artifacts = [];
/** @type {import("../lib/recipient-picker.js").Recipient[]} */
let boundRecipients = [];
/** @type {Map<number, ReturnType<typeof mountRecipientBinder>>} */
let cellBinders = new Map();
/** Email/query → chosen fingerprints for gpg.encrypt to= */
/** @type {Record<string, string[]>} */
let recipientResolutions = {};
/** Prefetched keyserver dropdown options for hkp.search / hkp.get */
/** @type {{ value: string, label: string }[]} */
let keyserverOptionsCache = buildKeyserverOptions({
  pageOrigin: pageKeyserverOrigin(),
});
/** Lookup field errors: step index → message */
/** @type {Map<string, string>} */
let lookupFieldErrors = new Map();
/** Agent strip countdown timer */
/** @type {ReturnType<typeof setInterval>|null} */
let agentStripTimer = null;
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
/** OpenPGP ciphertext for gpg.decrypt Inputs (not stored in recipe / URL). */
let ciphertextDraft = "";
/** Suppress hash→notebook feedback while we write the fragment. */
let fragmentWriteLock = false;
/** Last preset id loaded (for short `#t=` fragment form). */
let lastPresetId = /** @type {string|null} */ (null);
/** Last library workspace id (Save updates this entry). */
let lastWorkspaceId = /** @type {string|null} */ (null);
/** Fingerprint of title+recipe after last load/save (dirty tracking). */
let lastLoadedFingerprint = "";
/** @type {ReturnType<typeof setTimeout>|null} */
let fragmentSyncTimer = null;
/** WebCrypto JWK drafts for key-bound ops. */
let keyJwkDraft = "";
let peerJwkDraft = "";
let wrapJwkDraft = "";
let signatureDraft = "";
/** Ops drawer search query. */
let opsFilter = "";
/** Collapsed category keys in the ops drawer. */
/** @type {Set<string>} */
/** Toolbox sections collapsed in the ops drawer (WebAuthn starts closed). */
let opsCollapsed = new Set(["webauthn"]);
/** Shelf keys `${toolbox}:${shelf}` collapsed in the ops drawer. */
let opsShelfCollapsed = new Set(defaultCollapsedShelfKeys());
/**
 * Open Encrypt/Decrypt meta-picker (`null` = closed).
 * Instantiates a concrete cipher — never leaves an `encrypt` builder card.
 * @type {{ decode: boolean } | null}
 */
let cipherPickerState = null;
/**
 * Open Export/Import format picker (`null` = closed).
 * @type {{ direction: "export"|"import" } | null}
 */
let formatPickerState = null;
/** Whether the collapsed "Cryptographic parameters" section is expanded. */
let cryptoPanelOpen = false;
/** @type {"auto"|"compatible"|"modern"|"custom"} */
let toolkitEncryptPreset = "auto";
/** @type {import("../lib/pgp/types.js").EncryptProfile} */
let toolkitEncryptProfile = { ...PROFILE_AUTO };
let toolkitHideRecipients = false;

/** Steps that emit OpenPGP ciphertext and honor the encrypt profile. */
const PGP_PROFILE_STEPS = new Set(["gpg.symencrypt", "gpg.encrypt"]);

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
  return `Auto: prefers ${formatProfileSpec(PROFILE_MODERN)}; falls back to compatible for legacy recipient keys. Password envelopes (gpg.symencrypt) always follow the selected profile.`;
}

/**
 * Segmented Modern / Compatible / Auto control (notebook header).
 * @param {string} radioName  unique name= for this radio group
 * @param {{ advancedLink?: boolean }} [opts]
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
    <div class="pgp-mode">
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
      <p class="muted fs-xs pgp-mode-hint mb-0">${escapeHtml(toolkitPgpModeHint())}${
        opts.advancedLink
          ? ` <button type="button" class="text-link pgp-advanced-link" id="pgp-advanced-link">Advanced OpenPGP…</button>`
          : ""
      }</p>
    </div>`;
}

/** Open the expert crypto params panel (cipher / AEAD / S2K). */
function openCryptoParamsPanel() {
  const details = document.getElementById("crypto-params-details");
  if (details instanceof HTMLDetailsElement) {
    details.open = true;
    cryptoPanelOpen = true;
    details.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
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

/**
 * @param {import("../lib/toolkit/recipe.js").RecipeAst|null|undefined} ast
 * @param {(step: import("../lib/toolkit/recipe.js").RecipeStep) => boolean} pred
 */
function recipeSomeStep(ast, pred) {
  const visit = (stepList) => {
    for (const s of stepList || []) {
      if (pred(s)) return true;
      if (visit(s.body || [])) return true;
      for (const br of s.branches || []) {
        if (visit(br.body || [])) return true;
      }
    }
    return false;
  };
  return recipeChains(ast).some((c) => visit(c.steps || []));
}

/** @param {import("../lib/toolkit/recipe.js").RecipeAst|null|undefined} ast */
function recipeHasStep(ast, name) {
  return recipeSomeStep(ast, (s) => s.name === name);
}

/** @param {import("../lib/toolkit/recipe.js").RecipeAst|null|undefined} ast */
function recipeNeedsGpgSigningKey(ast) {
  return recipeSomeStep(
    ast,
    (s) => s.name === "gpg.sign" || (s.name === "gpg.encrypt" && !!s.params?.sign)
  );
}

/** @type {number} */
let lastActivityAt = Date.now();
/** @type {ReturnType<typeof setInterval>|null} */
let kernelChipTimer = null;
/** @type {ReturnType<typeof setTimeout>|null} */
let idleTimer = null;
/** Pending clipboard clear handles from copyTextTransient */
/** @type {Array<{ clear: () => void }>} */
let pendingClipboardClears = [];

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
 * CAST suite chip for crypto toolboxes (always shown when applicable).
 * @param {string|undefined|null} toolbox
 * @returns {string}
 */
function suiteChipHtml(toolbox) {
  const ver = toolboxVerification(toolbox, suiteStatus);
  if (ver === "none") return "";
  if (ver === "verified") {
    return `<span class="suite-chip suite-verified" title="POST/CAST verified for this toolbox">verified</span>`;
  }
  if (ver === "error") {
    return `<span class="suite-chip suite-error" title="Crypto module error">error</span>`;
  }
  return `<span class="suite-chip suite-unverified" title="No CAST for this toolbox yet. ${escapeHtml(FIPS_MODE_DISCLAIMER)}">⚠ unverified</span>`;
}

/**
 * @param {string} stepName
 * @returns {boolean} true if FIPS mode blocks adding/running this step
 */
function stepBlockedByFips(stepName) {
  if (!fipsMode) return false;
  const suite = stepNameToSuite(stepName);
  if (!suite) return false;
  return suiteStatus[suite] !== "verified";
}

/**
 * @returns {string[]} unverified suite names used by current pipeline
 */
function currentUnverifiedSuites() {
  return unverifiedSuitesAmong(suiteStatus, suitesUsedBySteps(steps));
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
        <p class="muted m-0-b-md fs-sm">One-click notebooks. Companion rows (⇄) can add forward and inverse together.</p>
        <div class="preset-grid" id="preset-grid"></div>
      </div>
    </details>
    <details class="toolbar-menu" id="more-menu">
      <summary class="btn btn-ghost btn-compact" title="More actions">
        ${glyphHtml("more", "ops-glyph toolbar-glyph")} More
      </summary>
      <div class="toolbar-popover toolbar-popover-menu">
        <button type="button" class="toolbar-menu-item" id="toggle-reference" title="Full step docs">Docs</button>
        <button type="button" class="toolbar-menu-item" id="focus-keyring-btn">Keyring</button>
        <button type="button" class="toolbar-menu-item" id="shortcuts-btn">
          ${glyphHtml("shortcuts", "ops-glyph toolbar-glyph")} Keyboard shortcuts
        </button>
        <hr class="toolbar-menu-sep">
        <button type="button" class="toolbar-menu-item" id="workspace-save-btn"
          title="Save title + recipe to this browser’s library">Save notebook</button>
        <button type="button" class="toolbar-menu-item" id="copy-recipe-btn"
          title="Copy canonical recipe text to the clipboard">Copy recipe</button>
        <button type="button" class="toolbar-menu-item" id="workspace-library-btn"
          title="Open saved notebooks from this browser">Library…</button>
        <button type="button" class="toolbar-menu-item" id="workspace-export-btn"
          title="Download title + recipe as .basilisk.json">Export file</button>
        <button type="button" class="toolbar-menu-item" id="workspace-import-btn"
          title="Load a .basilisk.json or plain recipe file">Import file…</button>
        <hr class="toolbar-menu-sep">
        <button type="button" class="toolbar-menu-item" id="reset-notebook-btn"
          title="Clear sensitive and reset to one empty cell">Reset notebook</button>
        <button type="button" class="toolbar-menu-item text-error" id="destroy-btn"
          title="Zeroize all in-memory secrets, inputs, and outputs (best-effort)">Destroy</button>
      </div>
    </details>
    <input type="file" id="workspace-import-file" class="hidden"
      accept=".json,.txt,.recipe,.basilisk.json,application/json,text/plain">
    <dialog id="workspace-library-dialog" class="toolkit-dialog">
      <form method="dialog" class="toolkit-dialog-body">
        <header class="toolkit-dialog-head">
          <strong>Notebook library</strong>
          <button type="submit" class="btn btn-ghost btn-compact" aria-label="Close">✕</button>
        </header>
        <p class="muted fs-xs mt-0">Saved in this browser only (title + recipe). Inputs and keys are never stored here.</p>
        <div id="workspace-library-list" class="workspace-library-list"></div>
      </form>
    </dialog>
    <div class="app-toolbar-end">
      <span id="crypto-status" class="app-status" role="status">Verifying crypto suites…</span>
      <details class="toolbar-menu" id="prefs-menu">
        <summary class="btn btn-ghost btn-compact" title="Toolkit preferences">
          ${glyphHtml("gear", "ops-glyph toolbar-glyph")} Preferences
        </summary>
        <div class="toolbar-popover toolbar-popover-narrow" id="prefs-popover">
          <!-- filled by renderPrefsForm -->
        </div>
      </details>
    </div>
  </div>
  <p id="fips-hint" class="muted fs-xs fips-mode-hint ${fipsMode ? "" : "hidden"}" role="note">${escapeHtml(FIPS_MODE_DISCLAIMER)}</p>
  <dialog id="shortcuts-dialog" class="toolkit-dialog">
    <form method="dialog" class="toolkit-dialog-body">
      <header class="toolkit-dialog-head">
        <strong>Keyboard shortcuts</strong>
        <button type="submit" class="btn btn-ghost btn-compact" aria-label="Close">✕</button>
      </header>
      <dl class="shortcuts-list">
        <div><dt>Shift+Enter</dt><dd>Run focused cell</dd></div>
        <div><dt>Alt+Enter</dt><dd>Run from focused cell</dd></div>
        <div><dt>A / B</dt><dd>Insert cell above / below (when not typing)</dd></div>
        <div><dt>Escape</dt><dd>Close pickers / Variables</dd></div>
      </dl>
    </form>
  </dialog>

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
        <p class="muted fs-xs mt-xs mb-sm" id="ops-hint">Drag onto the focused cell, or click to append.</p>
        <div id="ops-drawer" class="ops-drawer"></div>
      </div>
    </aside>

    <div class="pane-splitter" data-resize="ops" role="separator" aria-orientation="vertical"
      aria-label="Resize Operations panel" title="Drag to resize · double-click to reset"></div>

    <section class="chef-recipe chef-pane chef-notebook" aria-label="Notebook">
      <div class="pane-head">
        <p class="pane-title">Notebook</p>
      </div>
      <div class="pane-body notebook-body">
        <div class="notebook-header" id="notebook-header">
          <div class="notebook-header-top">
            <label class="recipe-heading notebook-title-wrap">
              <span class="sr-only">Notebook title</span>
              <input type="text" id="recipe-title" class="recipe-title-input" maxlength="120"
                placeholder="Untitled notebook" autocomplete="off" spellcheck="false">
            </label>
            <div class="notebook-quickstarts btn-row wrap" role="group" aria-label="Messaging quick starts">
              <button type="button" class="btn btn-compact" id="qs-encrypt"
                title="Insert encrypt cell (shareable #encrypt)">
                ${glyphHtml("openpgp", "ops-glyph toolbar-glyph")} Encrypt
              </button>
              <button type="button" class="btn btn-compact" id="qs-decrypt"
                title="Insert decrypt cell (shareable #decrypt)">
                ${glyphHtml("openpgp", "ops-glyph toolbar-glyph")} Decrypt
              </button>
              <button type="button" class="btn btn-ghost btn-compact" id="qs-symencrypt"
                title="Password-based encrypt (#symencrypt)">Password</button>
            </div>
            <div class="notebook-header-actions btn-row wrap">
              <button type="button" class="btn btn-compact notebook-run-primary" id="run-btn" disabled title="Run all cells">Run all</button>
              <button type="button" class="btn btn-ghost btn-compact" id="clear-sensitive-btn"
                title="Wipe kernel slots, outputs, and inputs — keep cell recipes">Clear sensitive</button>
              <button type="button" class="btn btn-ghost btn-compact" id="copy-share-link"
                title="Copy shareable toolkit link (recipe in URL fragment)">Copy link</button>
              <button type="button" class="kernel-chip btn btn-ghost btn-compact" id="kernel-chip"
                aria-expanded="false" aria-controls="variables-drawer"
                title="Session variables (kernel slots)">
                ${glyphHtml("variables", "ops-glyph kernel-chip-glyph")}<span id="kernel-chip-label">0 slots</span>
              </button>
            </div>
          </div>
          <div class="notebook-header-context">
            <details id="keyring-panel" class="keyring-panel">
              <summary class="muted fs-sm">${glyphHtml("agent", "ops-glyph toolbar-glyph")} Keyring (My Keys)</summary>
              <div id="keyring-body" class="keyring-body mt-sm"></div>
            </details>
            <div id="pgp-mode-host" class="pgp-mode-host hidden"></div>
          </div>
          <p id="fragment-status" class="muted fs-xs mb-0 hidden" role="status"></p>
          <div id="stale-banner" class="stale-banner hidden" role="status"></div>
          <div id="agent-session-host" class="agent-session-host"></div>
          <p id="run-status" class="status-row hidden mt-sm"></p>
        </div>
        <div id="variables-drawer" class="variables-drawer hidden" hidden></div>
        <div id="notebook-cells" class="notebook-cells"></div>
        <div class="notebook-add-row">
          <button type="button" class="btn btn-ghost btn-compact" id="add-cell-btn">+ Cell</button>
          <span class="muted fs-xs notebook-kbd-hint">Shift+Enter run · Alt+Enter from here · A/B insert cell</span>
        </div>
        <details class="recipe-text-details mt-md">
          <summary class="muted fs-sm">Notebook source (text)</summary>
          <textarea id="recipe-text" class="compose-message mt-sm" rows="3" spellcheck="false"
            placeholder="hkp.search alice@example.org | out @alices

input | gpg.encrypt to=@alices"></textarea>
          <p id="recipe-errors" class="status-row err hidden mt-sm"></p>
          <p id="recipe-upgrade-host" class="mt-xs hidden">
            <button type="button" class="btn btn-compact" id="upgrade-recipe-btn">Upgrade recipe</button>
            <span class="muted fs-sm"> Rewrite removed step names (aesgcm → aes-gcm, encrypt gpg → gpg.encrypt, wa-* → webauthn.*, …).</span>
          </p>
          <p id="recipe-warnings" class="muted mt-xs fs-sm"></p>
        </details>
        <div id="crypto-params-host"></div>
        <!-- Legacy single-builder host kept for transitional wiring; notebook renders into #notebook-cells -->
        <div id="builder-steps" class="builder-steps hidden" hidden aria-hidden="true"></div>
        <div id="results-panel" class="hidden" hidden aria-hidden="true"></div>
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
  ws.classList.add("notebook-workspace");

  const layout = loadLayout();
  const w = Number(layout.opsW);
  if (Number.isFinite(w) && w >= PANE_LIMITS.ops.min) {
    ws.style.setProperty("--ops-w", `${w}px`);
  }
  ws.classList.toggle("ops-collapsed", !!layout.opsCollapsed);
  // Drop legacy run-pane collapse class if present
  ws.classList.remove("run-collapsed");

  ws.querySelectorAll("[data-collapse]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const side = btn.getAttribute("data-collapse");
      if (side !== "ops") return;
      const collapsed = ws.classList.toggle("ops-collapsed");
      saveLayout({ opsCollapsed: collapsed || null });
    });
  });

  ws.querySelectorAll('.pane-splitter[data-resize="ops"]').forEach((split) => {
    if (!(split instanceof HTMLElement)) return;
    const limits = PANE_LIMITS.ops;

    split.addEventListener("dblclick", () => {
      ws.style.removeProperty("--ops-w");
      saveLayout({ opsW: null });
    });

    split.addEventListener("pointerdown", (e) => {
      if (ws.classList.contains("ops-collapsed")) return;
      e.preventDefault();
      split.setPointerCapture(e.pointerId);
      split.classList.add("dragging");
      let width = NaN;

      const onMove = (ev) => {
        const rect = ws.getBoundingClientRect();
        width = Math.round(
          Math.max(limits.min, Math.min(limits.max, ev.clientX - rect.left))
        );
        ws.style.setProperty("--ops-w", `${width}px`);
      };
      const onUp = () => {
        split.classList.remove("dragging");
        split.removeEventListener("pointermove", onMove);
        if (Number.isFinite(width)) saveLayout({ opsW: width });
      };
      split.addEventListener("pointermove", onMove);
      split.addEventListener("pointerup", onUp, { once: true });
      split.addEventListener("pointercancel", onUp, { once: true });
    });
  });
}

initWorkspaceLayout();

/**
 * Keep `steps` aliased to the focused cell.
 * @param {number} [index]
 */
function focusCell(index) {
  if (!chains.length) chains = [{ steps: [] }];
  focusedCell = Math.max(0, Math.min(Number(index) || 0, chains.length - 1));
  if (!chains[focusedCell]) chains[focusedCell] = { steps: [] };
  if (!chains[focusedCell].steps) chains[focusedCell].steps = [];
  steps = chains[focusedCell].steps;
}

/**
 * @param {number} [at]
 */
function insertCell(at) {
  const idx = at == null ? chains.length : Math.max(0, Math.min(at, chains.length));
  chains.splice(idx, 0, { steps: [] });
  kernel.remapCells((i) => (i >= idx ? i + 1 : i));
  focusCell(idx);
  setRecipeFromSteps();
}

/**
 * @param {number} index
 */
function deleteCell(index) {
  if (chains.length <= 1) {
    chains = [{ steps: [] }];
    focusCell(0);
    kernel.clearCellOutputs(0);
    setRecipeFromSteps();
    return;
  }
  chains.splice(index, 1);
  kernel.remapCells((i) => (i === index ? null : i > index ? i - 1 : i));
  focusCell(Math.min(focusedCell, chains.length - 1));
  setRecipeFromSteps();
}

/**
 * Move cell `from` to index `to` (0-based). Marks all cells with outputs stale.
 * @param {number} from
 * @param {number} to
 */
function moveCell(from, to) {
  if (from === to || from < 0 || to < 0 || from >= chains.length || to >= chains.length) {
    return;
  }
  const [cell] = chains.splice(from, 1);
  chains.splice(to, 0, cell);
  kernel.remapCells((i) => {
    if (i === from) return to;
    if (from < to) {
      // [from+1..to] shift left
      if (i > from && i <= to) return i - 1;
    } else {
      // [to..from-1] shift right
      if (i >= to && i < from) return i + 1;
    }
    return i;
  });
  kernel.markAllWithOutputsStale();
  focusCell(to);
  setRecipeFromSteps();
}

/**
 * Unmet runtime needs for a cell (filled-state aware) — drives badges + Run gating.
 * @param {import("../lib/toolkit/recipe.js").RecipeChain} chain
 * @returns {string[]}
 */
function cellUnmetNeeds(chain) {
  /** @type {string[]} */
  const badges = [];
  if (!chain?.steps?.length) return badges;
  const needs = cellRuntimeNeeds(chain);
  if (needs.includes("text") && !String(inputTextDraft || "").trim()) {
    badges.push("needs input");
  }
  if (needs.includes("shares") && !shareRows.some((m) => String(m || "").trim())) {
    badges.push("needs shares");
  }
  if (needs.includes("gpg") && !String(ciphertextDraft || "").trim()) {
    badges.push("needs ciphertext");
  }
  if (needs.includes("envelope") && !String(envelopeDraft || "").trim()) {
    badges.push("needs envelope");
  }
  if (needs.includes("key") && !String(keyJwkDraft || "").trim()) {
    badges.push("needs key");
  }
  const info = cellRecipientInfo(chain);
  if (info.slots > 0) {
    const filled = boundRecipients.filter((r) => r && r.fingerprint).length;
    if (filled < info.slots) badges.push("needs recipients");
  }
  try {
    const v = validateRecipe({ chains: [chain], steps: chain.steps, source: "" });
    for (const err of v.errors || []) {
      const m = String(err.message || "").match(/unknown slot.*?(@[\w-]+)/i);
      if (m) {
        const ref = m[1].startsWith("@") ? m[1] : `@${m[1]}`;
        if (!kernel.slots.has(ref)) badges.push("needs slot");
      }
    }
  } catch (_) {
    /* ignore */
  }
  return [...new Set(badges)];
}

/**
 * Badges for cells that still need runtime inputs / binder before Run.
 * @param {import("../lib/toolkit/recipe.js").RecipeChain} chain
 * @returns {string[]}
 */
function cellNeedBadges(chain) {
  return cellUnmetNeeds(chain);
}

/**
 * Human-readable first readiness blocker across runnable cells, or "".
 * @returns {string}
 */
function notebookReadinessBlocker() {
  for (let i = 0; i < chains.length; i++) {
    const chain = chains[i];
    if (!chain?.steps?.length) continue;
    const unmet = cellUnmetNeeds(chain);
    if (!unmet.length) continue;
    const label = unmet[0];
    if (label === "needs input") return "Add input text before running";
    if (label === "needs shares") return "Paste share mnemonics before running";
    if (label === "needs ciphertext") return "Paste OpenPGP ciphertext before running";
    if (label === "needs envelope") return "Paste envelope.asc before running";
    if (label === "needs key") return "Paste a key JWK before running";
    if (label === "needs recipients") return "Add recipients before running";
    if (label === "needs slot") return "Resolve missing @slots before running";
    return label;
  }
  return "";
}

function syncArtifactsFromKernel() {
  artifacts = [];
  for (let i = 0; i < chains.length; i++) {
    artifacts.push(...kernel.getCellOutputs(i));
  }
}

/**
 * @returns {string}
 */
function formatMsCountdown(ms) {
  const left = Math.max(0, ms);
  const mins = Math.floor(left / 60000);
  const secs = Math.floor((left % 60000) / 1000);
  return `${mins}m ${String(secs).padStart(2, "0")}s`;
}

function updateKernelChip() {
  const el = document.getElementById("kernel-chip");
  const labelEl = document.getElementById("kernel-chip-label");
  if (!el) return;
  const n = kernel.slotCount();
  const stale = kernel.staleCellIndices().length;
  const unlocked = sessionList().length;
  const cellsRun = chains.reduce(
    (acc, _, i) => acc + (kernel.getCellStatus(i) === "ok" || kernel.getCellStatus(i) === "stale" ? 1 : 0),
    0
  );
  const parts = [`${n} slot${n === 1 ? "" : "s"}`];
  if (cellsRun) parts.push(`${cellsRun} run`);
  if (stale) parts.push(`${stale} stale`);
  if (unlocked) parts.push(`agent ${unlocked}`);
  const idleMs = getIdleClearMs();
  if (idleMs > 0 && (n || unlocked || artifacts.length)) {
    const idleLeft = idleMs - (Date.now() - lastActivityAt);
    parts.push(`clears ${formatMsCountdown(idleLeft)}`);
  }
  const text = parts.join(" · ");
  if (labelEl) labelEl.textContent = text;
  else el.textContent = text;
  el.classList.toggle("kernel-chip-active", variablesOpen);
  el.classList.toggle("kernel-chip-has-slots", n > 0);
  el.setAttribute("aria-expanded", variablesOpen ? "true" : "false");

  const needTick = n > 0 || unlocked > 0 || artifacts.length > 0;
  if (needTick && !kernelChipTimer) {
    kernelChipTimer = setInterval(updateKernelChip, 1000);
  } else if (!needTick && kernelChipTimer) {
    clearInterval(kernelChipTimer);
    kernelChipTimer = null;
  }
}

function updateStaleBanner() {
  const el = document.getElementById("stale-banner");
  if (!el) return;
  const stale = kernel.staleCellIndices();
  if (!stale.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  el.innerHTML = `
    <span>Upstream changed — ${stale.length} cell${stale.length === 1 ? "" : "s"} stale.</span>
    <button type="button" class="btn btn-compact" id="rerun-stale-btn">Re-run stale</button>`;
  document.getElementById("rerun-stale-btn")?.addEventListener("click", () => {
    void runStaleCells();
  });
}

/**
 * @param {import("../lib/toolkit/slot-registry.js").SlotMeta} m
 * @returns {"recipients"|"openpgp-private"|"openpgp-public"|"other"}
 */
function slotMetaKind(m) {
  const t = String(m?.type || "").toLowerCase();
  if (t.startsWith("recipients") || t === "recipients") return "recipients";
  if (t.includes("openpgp-key") && (t.includes("private") || m.sensitive)) {
    return "openpgp-private";
  }
  if (t.includes("openpgp-key")) return "openpgp-public";
  return "other";
}

function renderVariablesDrawer() {
  const el = document.getElementById("variables-drawer");
  if (!el) return;
  if (!variablesOpen) {
    el.hidden = true;
    el.classList.add("hidden");
    el.innerHTML = "";
    updateKernelChip();
    return;
  }
  el.hidden = false;
  el.classList.remove("hidden");
  const metas = kernel.listSlots();
  el.innerHTML = `
    <div class="variables-drawer-inner">
      <div class="variables-drawer-head">
        <div>
          <strong>Kernel variables</strong>
          <p class="muted fs-xs mb-0">Live <code>@slots</code> for this session — metas only, no private armor.</p>
        </div>
        <button type="button" class="btn btn-ghost btn-compact" id="close-variables" aria-label="Close variables">✕</button>
      </div>
      ${
        metas.length
          ? `<ul class="variables-list">${metas
              .map((m) => {
                const kind = slotMetaKind(m);
                const bits = [
                  m.fingerprint
                    ? `<span class="mono fs-xs" title="Fingerprint">…${escapeHtml(m.fingerprint.slice(-8))}</span>`
                    : "",
                  m.recipients != null
                    ? `<span class="muted fs-xs">${m.recipients} key${m.recipients === 1 ? "" : "s"}</span>`
                    : "",
                  m.length != null && m.recipients == null
                    ? `<span class="muted fs-xs">${m.length} B</span>`
                    : "",
                ]
                  .filter(Boolean)
                  .join("");
                /** @type {string[]} */
                const actions = [];
                if (kind === "recipients") {
                  actions.push(
                    `<button type="button" class="btn btn-compact" data-slot-action="encrypt" data-use-slot="${escapeHtml(m.label)}">Encrypt to…</button>`
                  );
                }
                if (kind === "openpgp-private") {
                  actions.push(
                    `<button type="button" class="btn btn-compact" data-slot-action="sign" data-use-slot="${escapeHtml(m.label)}">Sign with…</button>`
                  );
                }
                if (kind === "openpgp-public" || kind === "recipients") {
                  actions.push(
                    `<button type="button" class="btn btn-ghost btn-compact" data-slot-action="to" data-use-slot="${escapeHtml(m.label)}" title="Set to=@ on focused encrypt step">to=@</button>`
                  );
                }
                if (kind === "openpgp-private" || kind === "openpgp-public") {
                  actions.push(
                    `<button type="button" class="btn btn-ghost btn-compact" data-slot-action="key" data-use-slot="${escapeHtml(m.label)}" title="Set key=@ on focused sign/encrypt step">key=@</button>`
                  );
                }
                actions.push(
                  `<button type="button" class="btn btn-ghost btn-compact" data-slot-action="in" data-use-slot="${escapeHtml(m.label)}" title="Insert in @${escapeHtml(m.label)} at cell start">in @</button>`
                );
                return `<li class="variables-item">
                  <div class="variables-item-main">
                    <code class="variables-slot">@${escapeHtml(m.label)}</code>
                    <span class="variables-type badge pending">${escapeHtml(m.type)}</span>
                    ${bits}
                  </div>
                  <div class="btn-row wrap variables-item-actions">${actions.join("")}</div>
                </li>`;
              })
              .join("")}</ul>`
          : `<p class="muted fs-sm mb-0">No slots yet — run a cell that ends with <code>out @label</code> (e.g. HKP search).</p>`
      }
    </div>`;
  document.getElementById("close-variables")?.addEventListener("click", () => {
    variablesOpen = false;
    renderVariablesDrawer();
  });
  el.querySelectorAll("[data-use-slot]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const label = btn.getAttribute("data-use-slot") || "";
      const action = btn.getAttribute("data-slot-action") || "in";
      insertKernelSlotIntoFocused(label, action);
    });
  });
  updateKernelChip();
}

/**
 * @param {string} label
 * @param {"encrypt"|"sign"|"to"|"key"|"in"} [action]
 */
function insertKernelSlotIntoFocused(label, action = "in") {
  const clean = String(label || "").replace(/^@/, "");
  if (!clean) return;
  focusCell(focusedCell);

  if (action === "encrypt") {
    applyCompositionChip(`encrypt-to:${clean}`);
    variablesOpen = false;
    renderVariablesDrawer();
    return;
  }
  if (action === "sign") {
    applyCompositionChip(`sign-with:${clean}`);
    variablesOpen = false;
    renderVariablesDrawer();
    return;
  }
  if (action === "to") {
    const enc = steps.find((s) => s.name === "gpg.encrypt");
    if (enc) {
      enc.params.to = `@${clean}`;
      setRecipeFromSteps();
      return;
    }
    applyCompositionChip(`encrypt-to:${clean}`);
    return;
  }
  if (action === "key") {
    const sign = steps.find(
      (s) => s.name === "gpg.sign" || s.name === "gpg.verify" || s.name === "gpg.encrypt"
    );
    if (sign) {
      sign.params.key = `@${clean}`;
      if (sign.name === "gpg.encrypt") sign.params.sign = true;
      setRecipeFromSteps();
      return;
    }
    applyCompositionChip(`sign-with:${clean}`);
    return;
  }
  // in @label
  if (!steps.length || steps[0]?.name !== "in") {
    steps.unshift({
      name: "in",
      params: { ref: `@${clean}` },
      start: 0,
      end: 0,
    });
  } else {
    steps[0].params.ref = `@${clean}`;
  }
  setRecipeFromSteps();
}

function touchActivity() {
  lastActivityAt = Date.now();
  clearTimeout(idleTimer);
  idleTimer = null;
  const ms = getIdleClearMs();
  if (ms > 0) {
    idleTimer = setTimeout(() => {
      // Idle auto-scrub: wipe secrets, inputs and outputs but keep the pipeline
      // definition (it is not secret) so the user can re-run after stepping away.
      secureDestroy({ quiet: true });
    }, ms);
  }
  updateKernelChip();
}

/**
 * Apply collapse-advanced preference to ops drawer sets.
 * @param {boolean} [force]
 */
function applyCollapsePrefs(force = false) {
  const p = getToolkitPrefs();
  if (!p.collapseAdvanced && !force) return;
  if (p.collapseAdvanced) {
    opsCollapsed.add("webauthn");
    for (const key of defaultCollapsedShelfKeys()) {
      opsShelfCollapsed.add(key);
    }
  }
}

function renderPrefsForm() {
  const host = document.getElementById("prefs-popover");
  if (!host) return;
  const p = getToolkitPrefs();
  host.innerHTML = `
    <p class="muted fs-sm m-0-b-md">Session and defaults for this browser. Not written into recipe text.</p>
    <label class="prefs-field">
      <span>Idle clear</span>
      <select id="pref-idle" class="text-input">
        <option value="0" ${p.idleClearMinutes === 0 ? "selected" : ""}>Never</option>
        <option value="1" ${p.idleClearMinutes === 1 ? "selected" : ""}>1 minute</option>
        <option value="5" ${p.idleClearMinutes === 5 ? "selected" : ""}>5 minutes</option>
        <option value="15" ${p.idleClearMinutes === 15 ? "selected" : ""}>15 minutes</option>
        <option value="60" ${p.idleClearMinutes === 60 ? "selected" : ""}>60 minutes</option>
      </select>
    </label>
    ${
      p.idleClearMinutes === 0
        ? `<p class="prefs-warn" role="status">Idle clear is off — kernel slots, artifacts, and Inputs persist until Clear sensitive / Destroy / tab hide.</p>`
        : ""
    }
    <label class="prefs-field">
      <span>Default encrypt mode</span>
      <select id="pref-mode" class="text-input">
        <option value="separate" ${p.defaultEncryptMode === "separate" ? "selected" : ""}>separate (N ciphertexts)</option>
        <option value="combined" ${p.defaultEncryptMode === "combined" ? "selected" : ""}>combined (one message)</option>
      </select>
    </label>
    <label class="prefs-field">
      <span>Default email policy</span>
      <select id="pref-policy" class="text-input">
        <option value="ask" ${p.defaultEncryptPolicy === "ask" ? "selected" : ""}>ask (modal if ambiguous)</option>
        <option value="one" ${p.defaultEncryptPolicy === "one" ? "selected" : ""}>one (exactly one key)</option>
        <option value="all" ${p.defaultEncryptPolicy === "all" ? "selected" : ""}>all (every approved)</option>
      </select>
    </label>
    <label class="prefs-check" title="${escapeHtml(FIPS_MODE_DISCLAIMER)}">
      <input type="checkbox" id="fips-mode" ${fipsMode ? "checked" : ""}>
      <span>FIPS mode <span class="muted fs-xs">(verified suites only)</span></span>
    </label>
    <label class="prefs-check">
      <input type="checkbox" id="pref-collapse" ${p.collapseAdvanced ? "checked" : ""}>
      <span>Collapse advanced shelves <span class="muted fs-xs">(Cipher, Wrap, WebAuthn)</span></span>
    </label>
    <label class="prefs-check" title="Skips the 5-minute vault-session cache only. Private keys can still live in kernel @slots until Clear / Lock all / tab hide.">
      <input type="checkbox" id="pref-session-off" ${p.sessionOff ? "checked" : ""}>
      <span>Session off <span class="muted fs-xs">(no agent TTL cache)</span></span>
    </label>
    ${
      p.sessionOff
        ? `<p class="prefs-warn" role="status">Session off ≠ no secrets in memory — unlocked keys in <code>@slots</code> still need Lock all or Clear sensitive.</p>`
        : ""
    }
    <p class="muted fs-xs mt-sm mb-0">Tab hide always scrubs secrets (like Encrypt). Defaults: idle ${DEFAULT_TOOLKIT_PREFS.idleClearMinutes}m · mode ${DEFAULT_TOOLKIT_PREFS.defaultEncryptMode} · policy ${DEFAULT_TOOLKIT_PREFS.defaultEncryptPolicy}.</p>
  `;
  wirePrefsForm(host);
}

/**
 * @param {HTMLElement} host
 */
function wirePrefsForm(host) {
  const save = () => {
    const idleEl = host.querySelector("#pref-idle");
    const modeEl = host.querySelector("#pref-mode");
    const policyEl = host.querySelector("#pref-policy");
    const collapseEl = host.querySelector("#pref-collapse");
    const sessionEl = host.querySelector("#pref-session-off");
    const fipsEl = host.querySelector("#fips-mode");
    let idleMins =
      idleEl instanceof HTMLSelectElement ? Number(idleEl.value) : 5;
    if (
      idleMins === 0 &&
      getToolkitPrefs().idleClearMinutes !== 0 &&
      !window.confirm(
        "Turn off idle clear?\n\nKernel slots, artifacts, and Inputs will stay in memory until you Clear sensitive, Destroy, or hide this tab."
      )
    ) {
      if (idleEl instanceof HTMLSelectElement) {
        idleEl.value = String(getToolkitPrefs().idleClearMinutes || 5);
      }
      return;
    }
    setToolkitPrefs({
      idleClearMinutes: idleMins,
      defaultEncryptMode:
        modeEl instanceof HTMLSelectElement && modeEl.value === "combined"
          ? "combined"
          : "separate",
      defaultEncryptPolicy:
        policyEl instanceof HTMLSelectElement &&
        ["ask", "one", "all"].includes(policyEl.value)
          ? /** @type {"ask"|"one"|"all"} */ (policyEl.value)
          : "ask",
      collapseAdvanced:
        collapseEl instanceof HTMLInputElement ? collapseEl.checked : true,
      sessionOff: sessionEl instanceof HTMLInputElement ? sessionEl.checked : false,
    });
    if (fipsEl instanceof HTMLInputElement) {
      fipsMode = fipsEl.checked;
      setFipsMode(fipsMode);
      document.getElementById("fips-hint")?.classList.toggle("hidden", !fipsMode);
    }
    applyCollapsePrefs(true);
    touchActivity();
    validateAndBind();
    renderOpsDrawer();
    renderSuggestDrawer();
    renderNotebook();
    renderPrefsForm();
  };
  host.querySelectorAll("select, input").forEach((el) => {
    el.addEventListener("change", save);
  });
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
/**
 * Wipe kernel + outputs + inputs; keep cell recipes (Clear sensitive / idle).
 * @param {{ quiet?: boolean }} [opts]
 */
function flushPendingClipboardClears() {
  for (const h of pendingClipboardClears) {
    try {
      h.clear();
    } catch (_) {
      /* ignore */
    }
  }
  pendingClipboardClears = [];
}

/**
 * Lock agent session + evict private kernel slots / wipe outputs.
 * Stronger than sessionClear alone (private @slots would otherwise remain).
 */
function lockAllAgentMaterial() {
  if (activeWorker) {
    try {
      activeWorker.terminate();
    } catch (_) {
      /* ignore */
    }
    activeWorker = null;
  }
  sessionClear();
  kernel.lockSensitive();
  artifacts = [];
  expandedArtifactKeys = new Set();
  flushPendingClipboardClears();
  syncArtifactsFromKernel();
  renderNotebook();
  renderSuggestDrawer();
  renderOpsDrawer();
  renderAgentChrome();
  updateKernelChip();
  updateStaleBanner();
  renderVariablesDrawer();
  const status = document.getElementById("run-status");
  if (status) {
    status.className = "status-row ok";
    status.textContent =
      "Locked — agent session cleared; private slots and outputs wiped.";
    status.classList.remove("hidden");
  }
}

function clearSensitiveData(opts = {}) {
  if (activeWorker) {
    try {
      activeWorker.terminate();
    } catch (_) {
      /* ignore */
    }
    activeWorker = null;
  }
  sessionClear();
  kernel.clearSensitive();
  artifacts = [];
  expandedArtifactKeys = new Set();
  boundRecipients = [];
  recipientResolutions = {};
  lookupFieldErrors = new Map();
  flushPendingClipboardClears();
  if (kernelChipTimer) {
    clearInterval(kernelChipTimer);
    kernelChipTimer = null;
  }
  destroyCellBinders();
  shareRows = [""];
  envelopeDraft = "";
  sharePassDraft = "";
  inputTextDraft = "";
  ciphertextDraft = "";
  keyJwkDraft = "";
  peerJwkDraft = "";
  wrapJwkDraft = "";
  signatureDraft = "";

  document.querySelectorAll("[data-rt]").forEach((el) => {
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      el.value = "";
    } else if (el instanceof HTMLSelectElement) {
      el.selectedIndex = 0;
    }
  });
  document.querySelectorAll(".share-mnemonic").forEach((el) => {
    if (el instanceof HTMLTextAreaElement) el.value = "";
  });

  validateAndBind();
  renderNotebook();
  renderSuggestDrawer();
  renderOpsDrawer();
  renderAgentChrome();
  updateKernelChip();
  updateStaleBanner();
  renderVariablesDrawer();
  clearTimeout(idleTimer);
  idleTimer = null;
  if (!opts.skipIdleReschedule) touchActivity();

  if (!opts.quiet) {
    const status = document.getElementById("run-status");
    if (status) {
      status.className = "status-row ok";
      status.textContent =
        "Cleared sensitive data — recipes kept, kernel and outputs wiped.";
      status.classList.remove("hidden");
    }
  }
}

/** Clear sensitive + single empty cell. */
function resetNotebook() {
  clearSensitiveData({ quiet: true });
  chains = [{ steps: [] }];
  cellCollapsed = new Set();
  focusCell(0);
  setRecipeTitle("");
  lastPresetId = null;
  lastWorkspaceId = null;
  lastLoadedFingerprint = "";
  setRecipeFromSteps();
  const status = document.getElementById("run-status");
  if (status) {
    status.className = "status-row ok";
    status.textContent = "Notebook reset.";
    status.classList.remove("hidden");
  }
}

/** @returns {boolean} */
function notebookIsEmpty() {
  return chains.length === 1 && !(chains[0]?.steps || []).length;
}

/** @param {string} [msg] */
function setFragmentStatus(msg) {
  const el = document.getElementById("fragment-status");
  if (!el) return;
  if (!msg) {
    el.textContent = "";
    el.classList.add("hidden");
    return;
  }
  el.textContent = msg;
  el.classList.remove("hidden");
}

function scheduleFragmentSync() {
  if (fragmentWriteLock) return;
  if (fragmentSyncTimer) clearTimeout(fragmentSyncTimer);
  fragmentSyncTimer = setTimeout(() => {
    fragmentSyncTimer = null;
    syncFragmentFromNotebook();
  }, 250);
}

function syncFragmentFromNotebook() {
  if (fragmentWriteLock) return;
  const recipe = serializeRecipe({ chains });
  const preset = lastPresetId
    ? PRESETS.find((p) => p.id === lastPresetId)
    : null;
  const result = hashForNotebook(recipe, {
    presetId: lastPresetId,
    presetRecipe: preset?.recipe ?? null,
  });
  if (!result.ok) {
    setFragmentStatus(
      result.reason || "Recipe too long for URL — use Copy recipe"
    );
    return;
  }
  setFragmentStatus("");
  fragmentWriteLock = true;
  writeToolkitHash(result.hash, { replace: true });
  queueMicrotask(() => {
    fragmentWriteLock = false;
  });
}

function scrollFocusedCellIntoView() {
  requestAnimationFrame(() => {
    const el = document.querySelector(
      `.notebook-cell[data-cell="${focusedCell}"]`
    );
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
    if (el instanceof HTMLElement) el.focus({ preventScroll: true });
  });
}

/**
 * Parse starter recipe text into notebook chains.
 * @param {string} recipe
 * @returns {{ steps: import("../lib/toolkit/recipe.js").RecipeStep[] }[] | null}
 */
function chainsFromRecipeText(recipe) {
  let source = String(recipe || "");
  source = migrateRecipe(source).recipe;
  const { ast, errors } = canonicalizeRecipe(source);
  if (errors.length || !ast) {
    showError(
      errorEl,
      errors.map((e) => e.message).join(" · ") || "Recipe parse failed"
    );
    return null;
  }
  return recipeChains(ast).map((c) => ({
    steps: (c.steps || []).map((s) => cloneBuilderStep(s)),
  }));
}

/**
 * Insert or replace a messaging quick-start cell.
 * @param {import("../lib/toolkit/fragment.js").MessagingStarter} starter
 * @param {{ replace?: boolean, skipFragmentWrite?: boolean }} [opts]
 *   replace=true always replaces (nav / hash boot);
 *   skipFragmentWrite=true when caller will write a seeded hash
 */
function insertMessagingCell(starter, opts = {}) {
  const spec = MESSAGING_STARTERS[starter];
  if (!spec) return;
  const forceReplace = opts.replace === true;
  const skipFragmentWrite = opts.skipFragmentWrite === true;
  const loaded = chainsFromRecipeText(spec.recipe);
  if (!loaded?.length) return;

  lastPresetId = null;
  if (forceReplace || notebookIsEmpty()) {
    if (forceReplace) {
      if (!skipFragmentWrite) fragmentWriteLock = true;
      loadRecipeText(spec.recipe, { title: spec.title, migrate: true });
      if (!skipFragmentWrite) {
        writeToolkitHash(hashForStarter(starter), { replace: true });
        queueMicrotask(() => {
          fragmentWriteLock = false;
        });
      }
    } else {
      chains = loaded;
      cellCollapsed = new Set();
      focusCell(0);
      if (!recipeTitle) setRecipeTitle(spec.title);
      if (!skipFragmentWrite) fragmentWriteLock = true;
      setRecipeFromSteps();
      if (!skipFragmentWrite) {
        writeToolkitHash(hashForStarter(starter), { replace: true });
        queueMicrotask(() => {
          fragmentWriteLock = false;
        });
      }
    }
  } else {
    const start = chains.length;
    chains.push(...loaded);
    focusCell(start);
    setRecipeFromSteps();
  }
  scrollFocusedCellIntoView();
}

/**
 * Seed Inputs from a fragment action (after recipe load / clearSensitive).
 * @param {import("../lib/toolkit/fragment.js").ToolkitHashAction & { seedError?: string }} action
 */
function applyInputSeeds(action) {
  if (action.seedError) {
    setFragmentStatus(action.seedError);
    return;
  }
  const armored = action.inputs?.ctArmored;
  if (armored == null) return;
  if (!armored) {
    setFragmentStatus("Could not load ciphertext from link.");
    return;
  }
  ciphertextDraft = armored;
  validateAndBind();
  setFragmentStatus("Ciphertext loaded from link — private key stays local.");
}

/**
 * Normalize hash string to include leading #.
 * @param {string} hash
 */
function normalizeHashString(hash) {
  const h = String(hash || "");
  if (!h || h === "#") return "#";
  return h.startsWith("#") ? h : `#${h}`;
}

/**
 * Apply location.hash to the notebook (replace).
 * @param {string} [hash]
 * @param {{ boot?: boolean }} [opts]
 */
function applyToolkitHash(hash, opts = {}) {
  if (fragmentWriteLock) return;
  const rawHash = hash ?? (typeof location !== "undefined" ? location.hash : "");
  const action = parseToolkitHash(rawHash);
  const hasCtSeed =
    !!action.inputs?.ctArmored ||
    !!(/** @type {{ seedError?: string }} */ (action).seedError);

  if (action.kind === "empty" || action.kind === "unknown") {
    if (opts.boot && PRESETS[0]) {
      // Keep URL hash empty until the user edits or picks a starter/preset.
      lastPresetId = PRESETS[0].id;
      fragmentWriteLock = true;
      loadRecipeText(PRESETS[0].recipe, {
        title: PRESETS[0].title,
        migrate: true,
      });
      queueMicrotask(() => {
        fragmentWriteLock = false;
      });
    }
    return;
  }
  if (action.kind === "starter") {
    fragmentWriteLock = true;
    insertMessagingCell(action.starter, {
      replace: true,
      skipFragmentWrite: true,
    });
    applyInputSeeds(action);
    // Keep seeded hash so refresh reloads ciphertext; otherwise short starter form.
    writeToolkitHash(
      hasCtSeed ? normalizeHashString(rawHash) : hashForStarter(action.starter),
      { replace: true }
    );
    queueMicrotask(() => {
      fragmentWriteLock = false;
    });
    return;
  }
  if (action.kind === "preset") {
    const preset = PRESETS.find((p) => p.id === action.id);
    if (!preset) {
      if (opts.boot && PRESETS[0]) {
        lastPresetId = PRESETS[0].id;
        loadRecipeText(PRESETS[0].recipe, {
          title: PRESETS[0].title,
          migrate: true,
        });
      }
      return;
    }
    lastPresetId = preset.id;
    fragmentWriteLock = true;
    loadRecipeText(preset.recipe, { title: preset.title, migrate: true });
    applyInputSeeds(action);
    writeToolkitHash(
      hasCtSeed ? normalizeHashString(rawHash) : hashForPreset(preset.id),
      { replace: true }
    );
    queueMicrotask(() => {
      fragmentWriteLock = false;
    });
    scrollFocusedCellIntoView();
    return;
  }
  if (action.kind === "recipe") {
    lastPresetId = null;
    fragmentWriteLock = true;
    loadRecipeText(action.recipe, { migrate: true });
    applyInputSeeds(action);
    if (hasCtSeed) {
      writeToolkitHash(normalizeHashString(rawHash), { replace: true });
    } else {
      const written = hashForRecipe(action.recipe);
      if (written.ok) writeToolkitHash(written.hash, { replace: true });
      else setFragmentStatus(written.reason || "");
    }
    queueMicrotask(() => {
      fragmentWriteLock = false;
    });
    scrollFocusedCellIntoView();
  }
}

async function copyShareLink() {
  const recipe = serializeRecipe({ chains });
  const preset = lastPresetId
    ? PRESETS.find((p) => p.id === lastPresetId)
    : null;
  const result = hashForNotebook(recipe, {
    presetId: lastPresetId,
    presetRecipe: preset?.recipe ?? null,
  });
  if (!result.ok) {
    setFragmentStatus(
      result.reason || "Recipe too long for URL — use Copy recipe"
    );
    return;
  }
  const url = toolkitShareUrl(result.hash);
  try {
    await navigator.clipboard.writeText(url);
    setFragmentStatus("Share link copied.");
    setTimeout(() => setFragmentStatus(""), 2000);
  } catch {
    setFragmentStatus("Could not copy — copy the address bar instead.");
  }
}

/** @returns {{ title: string, recipe: string }} */
function currentNotebookSnapshot() {
  return {
    title: recipeTitle || "",
    recipe: serializeRecipe({ chains }),
  };
}

function markWorkspaceClean(workspaceId = lastWorkspaceId) {
  const { title, recipe } = currentNotebookSnapshot();
  lastLoadedFingerprint = workspaceFingerprint(title, recipe);
  if (workspaceId != null) lastWorkspaceId = workspaceId;
}

function notebookIsDirty() {
  if (!lastLoadedFingerprint) return false;
  const { title, recipe } = currentNotebookSnapshot();
  return workspaceFingerprint(title, recipe) !== lastLoadedFingerprint;
}

/**
 * @param {{ title?: string, recipe: string, id?: string|null }} ws
 */
function applyWorkspaceToNotebook(ws) {
  lastPresetId = null;
  loadRecipeText(ws.recipe, {
    title: ws.title != null ? ws.title : recipeTitle,
    migrate: true,
  });
  if (ws.title != null) setRecipeTitle(ws.title);
  lastWorkspaceId = ws.id || null;
  markWorkspaceClean(lastWorkspaceId);
  scrollFocusedCellIntoView();
}

async function copyRecipeText() {
  const recipe = serializeRecipe({ chains }).trim();
  if (!recipe) {
    setFragmentStatus("Notebook is empty.");
    return;
  }
  try {
    await navigator.clipboard.writeText(recipe);
    setFragmentStatus("Recipe copied.");
    setTimeout(() => setFragmentStatus(""), 2000);
  } catch {
    setFragmentStatus("Could not copy — use Notebook source (text) instead.");
  }
}

function saveCurrentWorkspace() {
  const { title, recipe } = currentNotebookSnapshot();
  const name = window.prompt(
    "Save notebook as:",
    title || "Untitled notebook"
  );
  if (name === null) {
    setFragmentStatus("Save cancelled.");
    return;
  }
  const result = saveWorkspace({
    id: lastWorkspaceId || undefined,
    title: name.trim() || title || "Untitled notebook",
    recipe,
  });
  if (!result.ok) {
    setFragmentStatus(result.reason || "Save failed.");
    return;
  }
  setRecipeTitle(result.workspace.title);
  markWorkspaceClean(result.workspace.id);
  setFragmentStatus(`Saved “${result.workspace.title}” to library.`);
  setTimeout(() => setFragmentStatus(""), 2500);
}

function downloadWorkspaceFile(ws) {
  const blob = new Blob([exportWorkspaceBlob(ws)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = sanitizeFilename(
    `${ws.title || "notebook"}.basilisk.json`,
    "notebook.basilisk.json"
  );
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function exportCurrentWorkspaceFile() {
  const { title, recipe } = currentNotebookSnapshot();
  if (!recipe.trim()) {
    setFragmentStatus("Nothing to export — notebook is empty.");
    return;
  }
  try {
    downloadWorkspaceFile({
      v: 1,
      id: lastWorkspaceId || "export",
      title: title || "Untitled notebook",
      recipe,
      updatedAt: new Date().toISOString(),
    });
    setFragmentStatus("Workspace file downloaded.");
    setTimeout(() => setFragmentStatus(""), 2000);
  } catch (err) {
    setFragmentStatus(err?.message || "Export failed.");
  }
}

function formatWorkspaceDate(iso) {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return "";
  }
}

function renderWorkspaceLibrary() {
  const host = document.getElementById("workspace-library-list");
  if (!host) return;
  const list = listWorkspaces();
  if (!list.length) {
    host.innerHTML = `<p class="muted fs-sm">No saved notebooks yet. Use <strong>Save</strong> in the notebook header.</p>`;
    return;
  }
  host.innerHTML = list
    .map((w) => {
      const when = formatWorkspaceDate(w.updatedAt);
      return `
      <article class="workspace-library-item" data-ws-id="${escapeHtml(w.id)}">
        <div class="workspace-library-meta">
          <strong class="workspace-library-title">${escapeHtml(w.title)}</strong>
          ${when ? `<span class="muted fs-xs">${escapeHtml(when)}</span>` : ""}
        </div>
        <div class="btn-row wrap">
          <button type="button" class="btn btn-compact" data-ws-open="${escapeHtml(w.id)}">Open</button>
          <button type="button" class="btn btn-ghost btn-compact" data-ws-export="${escapeHtml(w.id)}">Export</button>
          <button type="button" class="btn btn-ghost btn-compact text-error" data-ws-delete="${escapeHtml(w.id)}">Delete</button>
        </div>
      </article>`;
    })
    .join("");

  host.querySelectorAll("[data-ws-open]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const id = btn.getAttribute("data-ws-open");
      const ws = id ? getWorkspace(id) : null;
      if (!ws) return;
      if (
        notebookIsDirty() &&
        !window.confirm(
          `Replace the current notebook with “${ws.title}”?\n\nUnsaved changes to the recipe will be lost. Inputs and kernel are cleared.`
        )
      ) {
        return;
      }
      applyWorkspaceToNotebook(ws);
      const dlg = document.getElementById("workspace-library-dialog");
      if (dlg instanceof HTMLDialogElement) dlg.close();
      setFragmentStatus(`Opened “${ws.title}”.`);
      setTimeout(() => setFragmentStatus(""), 2000);
    });
  });
  host.querySelectorAll("[data-ws-export]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const id = btn.getAttribute("data-ws-export");
      const ws = id ? getWorkspace(id) : null;
      if (!ws) return;
      downloadWorkspaceFile(ws);
    });
  });
  host.querySelectorAll("[data-ws-delete]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const id = btn.getAttribute("data-ws-delete");
      const ws = id ? getWorkspace(id) : null;
      if (!ws) return;
      if (!window.confirm(`Delete “${ws.title}” from this browser’s library?`)) {
        return;
      }
      const result = deleteWorkspace(ws.id);
      if (!result.ok) {
        setFragmentStatus(result.reason || "Delete failed.");
        return;
      }
      if (lastWorkspaceId === ws.id) lastWorkspaceId = null;
      renderWorkspaceLibrary();
    });
  });
}

function openWorkspaceLibrary() {
  renderWorkspaceLibrary();
  const dlg = document.getElementById("workspace-library-dialog");
  if (dlg instanceof HTMLDialogElement) dlg.showModal();
}

/**
 * @param {File} file
 */
async function importWorkspaceFile(file) {
  const text = await file.text();
  const parsed = parseWorkspaceFile(text, { filename: file.name });
  if (!parsed.ok) {
    setFragmentStatus(parsed.reason || "Import failed.");
    return;
  }
  if (
    notebookIsDirty() &&
    !window.confirm(
      `Replace the current notebook with “${parsed.workspace.title}”?\n\nUnsaved recipe changes will be lost. Inputs and kernel are cleared.`
    )
  ) {
    return;
  }
  applyWorkspaceToNotebook({
    title: parsed.workspace.title,
    recipe: parsed.workspace.recipe,
    id: parsed.workspace.id || null,
  });
  setFragmentStatus(`Imported “${parsed.workspace.title}”.`);
  setTimeout(() => setFragmentStatus(""), 2000);
}

function secureDestroy(opts = {}) {
  // Destroy = Clear sensitive (keep recipes), matching prior Destroy semantics.
  clearSensitiveData(opts);
  if (!opts.quiet) {
    const status = document.getElementById("run-status");
    if (status) {
      status.textContent =
        "Destroyed — in-memory secrets, inputs and outputs cleared (best-effort).";
    }
  }
}

function setRecipeFromSteps() {
  if (!chains.length) {
    chains = [{ steps: steps || [] }];
    focusedCell = 0;
  }
  chains[focusedCell] = { steps };
  steps = chains[focusedCell].steps;
  const ta = document.getElementById("recipe-text");
  if (ta instanceof HTMLTextAreaElement) {
    ta.value = serializeRecipe({ chains });
  }
  validateAndBind();
  renderNotebook();
  renderSuggestDrawer();
  renderCryptoPanel();
  renderOpsDrawer();
  renderAgentChrome();
  updateKernelChip();
  updateStaleBanner();
  renderVariablesDrawer();
  scheduleFragmentSync();
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
  if (spec?.name === "gpg.encrypt") {
    const prefs = getToolkitPrefs();
    params.mode = prefs.defaultEncryptMode;
    params.policy = prefs.defaultEncryptPolicy;
  }
  // hkp.* keyserver defaults to "" (This site) — never silent preferred upstream.
  return params;
}

async function prefetchKeyserverOptions() {
  try {
    const cfg = await getUpstreamConfig();
    keyserverOptionsCache = buildKeyserverOptions({
      allowlist: cfg.enabled ? cfg.allowlist || [] : [],
      preferred: cfg.enabled ? getPreferredKeyserver() : "",
      pageOrigin: pageKeyserverOrigin(),
    });
  } catch (_) {
    keyserverOptionsCache = buildKeyserverOptions({
      pageOrigin: pageKeyserverOrigin(),
    });
  }
}

/**
 * @param {import("../lib/toolkit/recipe.js").RecipeStep} s
 * @returns {import("../lib/toolkit/recipe.js").RecipeStep}
 */
function cloneBuilderStep(s) {
  /** @type {import("../lib/toolkit/recipe.js").RecipeStep} */
  const out = {
    name: s.name,
    params: { ...s.params },
    start: s.start || 0,
    end: s.end || 0,
  };
  if (s.body?.length) {
    out.body = s.body.map((b) => cloneBuilderStep(b));
  }
  if (s.branches?.length) {
    out.branches = s.branches.map((br) => ({
      member: br.member,
      start: br.start,
      end: br.end,
      body: (br.body || []).map((b) => cloneBuilderStep(b)),
    }));
  }
  return out;
}

/**
 * Focus for suggest-next / insert: stem index, optional body index under tee/foreach.
 * `null` body means “append to that block’s body” when the stem step is tee/foreach.
 * @type {{ stem: number, body?: number | null } | null}
 */
let insertFocus = null;

/**
 * @param {string} name
 * @param {number} [index]
 * @param {Record<string, string|number|boolean>} [paramOverrides]
 */
function addStepAt(name, index, paramOverrides) {
  const spec = getStep(name);
  if (!spec) return;
  if (stepBlockedByFips(spec.name)) {
    showError(
      errorEl,
      `FIPS mode: cannot add unverified ${spec.toolbox} op “${spec.name}”.`
    );
    return;
  }
  const step = {
    name: spec.name,
    params: { ...defaultParams(spec), ...(paramOverrides || {}) },
    start: 0,
    end: 0,
  };

  // Prefer inserting into a focused tee/foreach body.
  if (
    insertFocus &&
    index == null &&
    steps[insertFocus.stem] &&
    (steps[insertFocus.stem].name === "tee" ||
      steps[insertFocus.stem].name === "foreach")
  ) {
    const parent = steps[insertFocus.stem];
    if (!parent.body) parent.body = [];
    const at =
      insertFocus.body == null || Number.isNaN(insertFocus.body)
        ? parent.body.length
        : Math.max(0, Math.min(parent.body.length, insertFocus.body + 1));
    parent.body.splice(at, 0, step);
    insertFocus = { stem: insertFocus.stem, body: at };
    setRecipeFromSteps();
    return;
  }

  const at =
    index == null || Number.isNaN(index)
      ? steps.length
      : Math.max(0, Math.min(steps.length, index));
  steps.splice(at, 0, step);
  // Focus tee/foreach so the next suggested add goes into the list body.
  if (step.name === "foreach") {
    if (!step.body) step.body = [];
    insertFocus = { stem: at, body: null };
  } else if (step.name === "tee") {
    if (!step.body) step.body = [];
    // Seed selector branches when teeing a keypair.
    const prefix = walkPipelineTypes(steps.slice(0, at), { getStep });
    if (prefix.final?.base === "keypair" && !step.branches?.length) {
      step.branches = [
        {
          member: "private",
          selector: ".private",
          body: [
            { name: "inspect", params: { format: "auto" }, start: 0, end: 0 },
          ],
        },
        {
          member: "public",
          selector: ".public",
          body: [
            {
              name: "export",
              params: { format: "spki", which: "public" },
              start: 0,
              end: 0,
            },
            { name: "pem", params: {}, start: 0, end: 0 },
            { name: "out", params: { name: "@public" }, start: 0, end: 0 },
          ],
        },
      ];
    }
    insertFocus = { stem: at, body: null };
  } else {
    insertFocus = { stem: at };
  }
  setRecipeFromSteps();
}

/**
 * Refined output type after walking the builder pipeline (for suggesting ops).
 * Respects insertFocus so tee/foreach body lanes suggest against the nest type.
 * @returns {import("../lib/toolkit/types.js").RefinedType}
 */
function currentPipelineOutput() {
  const walked = walkPipelineTypes(steps, { getStep });
  if (
    insertFocus &&
    steps[insertFocus.stem] &&
    (steps[insertFocus.stem].name === "tee" ||
      steps[insertFocus.stem].name === "foreach")
  ) {
    const edge = walked.edges[insertFocus.stem];
    const parent = steps[insertFocus.stem];
    if (parent.name === "foreach") {
      const item =
        edge?.input?.kind === "raw"
          ? { base: /** @type {const} */ ("bytes"), kind: "opaque" }
          : { base: /** @type {const} */ ("text"), kind: "mnemonic" };
      if (edge?.body?.length) {
        const bi =
          insertFocus.body == null
            ? edge.body.length - 1
            : insertFocus.body;
        const be = edge.body[Math.max(0, bi)];
        return be?.output || item;
      }
      return item;
    }
    // tee body: start from stem type at tee
    if (edge?.body?.length) {
      const bi =
        insertFocus.body == null ? edge.body.length - 1 : insertFocus.body;
      const be = edge.body[Math.max(0, bi)];
      return be?.output || edge.input;
    }
    return edge?.input || walked.final;
  }
  return walked.final;
}

/**
 * Per-step refined type edges for the builder.
 * @returns {ReturnType<typeof walkPipelineTypes>["edges"]}
 */
function builderTypeEdges() {
  return walkPipelineTypes(steps, { getStep }).edges;
}

/**
 * Sync export `which` when format locks the key half.
 * @param {import("../lib/toolkit/recipe.js").RecipeStep} step
 */
function syncWhichWithFormat(step) {
  if (step.name !== "export") return;
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
  if (stepName === "export") {
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
 * @param {{ title?: string, reformat?: boolean }} [opts]
 *   reformat (default true): rewrite the textarea to canonical recipe text
 */
function loadRecipeText(text, opts = {}) {
  const reformat = opts.reformat !== false;
  const migrate = opts.migrate === true;
  let source = String(text ?? "");
  if (migrate) {
    source = migrateRecipe(source).recipe;
  }
  const { text: canonical, ast, errors, changed } = canonicalizeRecipe(source);
  const errEl = document.getElementById("recipe-errors");
  const upgradeHost = document.getElementById("recipe-upgrade-host");
  const legacyPending = migrateRecipe(String(text ?? "")).changes.length > 0;
  if (errors.length || !ast) {
    if (errEl) {
      errEl.textContent = errors.map((e) => e.message).join(" · ");
      errEl.classList.remove("hidden");
    }
    if (upgradeHost) {
      upgradeHost.classList.toggle("hidden", !legacyPending);
    }
    return;
  }
  if (upgradeHost) upgradeHost.classList.add("hidden");
  const loaded = recipeChains(ast).map((c) => ({
    steps: (c.steps || []).map((s) => cloneBuilderStep(s)),
  }));
  // Full scrub (session, worker, drafts, DOM) — not just kernel slots.
  clearSensitiveData({ quiet: true });
  chains = loaded.length ? loaded : [{ steps: [] }];
  cellCollapsed = new Set();
  focusCell(0);
  if (opts.title != null) setRecipeTitle(opts.title);
  if (errEl) errEl.classList.add("hidden");

  const ta = document.getElementById("recipe-text");
  if (reformat && ta instanceof HTMLTextAreaElement && (changed || ta.value !== canonical)) {
    const focused = document.activeElement === ta;
    const sel = focused ? ta.selectionStart : null;
    ta.value = canonical;
    if (focused && sel != null) {
      // Keep caret near end of edit when length shrinks from whitespace cleanup.
      const pos = Math.min(sel, canonical.length);
      ta.setSelectionRange(pos, pos);
    }
  }

  validateAndBind();
  renderNotebook();
  renderSuggestDrawer();
  renderCryptoPanel();
  renderOpsDrawer();
  updateKernelChip();
  updateStaleBanner();
  scheduleFragmentSync();
}

/** @param {string} title */
function setRecipeTitle(title) {
  recipeTitle = String(title || "").trim();
  const el = document.getElementById("recipe-title");
  if (el instanceof HTMLInputElement && el.value !== recipeTitle) {
    el.value = recipeTitle;
  }
}

/**
 * Soften compile errors for slots that already exist in the live kernel.
 * @param {import("../lib/toolkit/recipe.js").ValidationResult} validation
 */
function softenValidationWithKernel(validation) {
  if (!validation || validation.ok) return validation;
  /** @type {typeof validation.errors} */
  const hard = [];
  /** @type {string[]} */
  const soft = [];
  for (const err of validation.errors || []) {
    const msg = String(err.message || "");
    const m = msg.match(/out (@[\w-]+)|unknown slot.*?(@[\w-]+)/i);
    const ref = m?.[1] || m?.[2];
    if (ref && kernel.slots.has(ref)) {
      soft.push(`${ref} is bound in the kernel session`);
      continue;
    }
    hard.push(err);
  }
  return {
    ...validation,
    ok: hard.length === 0,
    errors: hard,
    warnings: [...(validation.warnings || []), ...soft],
  };
}

function validateAndBind() {
  if (!chains.length) {
    chains = [{ steps: steps || [] }];
    focusedCell = 0;
  }
  chains[focusedCell] = { steps };
  steps = chains[focusedCell].steps;
  const compiled = compileRecipe(serializeRecipe({ chains }));
  const ast = compiled.ast;
  const validation = softenValidationWithKernel(compiled.validation);
  const errEl = document.getElementById("recipe-errors");
  const warnEl = document.getElementById("recipe-warnings");
  const runBtn = document.getElementById("run-btn");

  const unverified = currentUnverifiedSuites();
  let fipsBlock = false;
  if (fipsMode && unverified.length && validation.ok) {
    fipsBlock = true;
    if (errEl) {
      try {
        assertRecipeAllowedUnderFips(ast, suiteStatus, true);
      } catch (err) {
        errEl.textContent = err?.message || String(err);
        errEl.classList.remove("hidden");
      }
    }
  }

  const readiness = notebookReadinessBlocker();
  if (!validation.ok) {
    if (errEl) {
      errEl.textContent = validation.errors.map((e) => e.message).join(" · ");
      errEl.classList.remove("hidden");
    }
    if (runBtn) {
      runBtn.disabled = true;
      runBtn.title = "Fix recipe errors before running";
    }
  } else if (fipsBlock) {
    if (runBtn) {
      runBtn.disabled = true;
      runBtn.title = "Blocked by FIPS mode";
    }
  } else {
    if (errEl && !fipsBlock) errEl.classList.add("hidden");
    if (runBtn) {
      const blocked = !cryptoReady || !!readiness;
      runBtn.disabled = blocked;
      runBtn.title = !cryptoReady
        ? "Crypto self-test has not passed"
        : readiness || "Run all cells";
    }
  }
  updateCellRunButtons(readiness);

  /** @type {string[]} */
  const warnParts = [...(validation.warnings || [])];
  if (!fipsMode && unverified.length) {
    warnParts.push(
      `Uses unverified suites (${unverified.join(", ")}) — enable FIPS mode to block`
    );
  }
  if (warnEl) {
    warnEl.textContent = warnParts.join(" · ");
  }

  // Runtime inputs / binders live inside the cells that need them.
  // Painted from renderNotebook (and explicit refresh) so hosts exist.
  currentInputNeeds = validation.inputNeeds || (ast ? unresolvedInputs(ast) : []);
  if (document.getElementById("cell-inputs-0") || document.querySelector(".cell-inputs")) {
    renderAllCellRuntimePanels();
  }
}

/**
 * Soft-disable Run all + per-cell Run when readiness unmet (does not re-render panels).
 */
function applyRunReadiness() {
  const runBtn = document.getElementById("run-btn");
  const readiness = notebookReadinessBlocker();
  if (runBtn instanceof HTMLButtonElement && !runBtn.dataset.forceDisabled) {
    // Only adjust when recipe validation left the button manageable — if recipe
    // is invalid, validateAndBind already disabled with a stronger reason.
    const recipeErr = document.getElementById("recipe-errors");
    const recipeBroken =
      recipeErr && !recipeErr.classList.contains("hidden") && recipeErr.textContent?.trim();
    if (!recipeBroken) {
      const blocked = !cryptoReady || !!readiness;
      runBtn.disabled = blocked;
      runBtn.title = !cryptoReady
        ? "Crypto self-test has not passed"
        : readiness || "Run all cells";
    }
  }
  updateCellRunButtons(readiness);
  for (let i = 0; i < chains.length; i++) syncCellRuntimeChrome(i);
}

/**
 * Soft-disable per-cell Run / From here when that cell (or notebook) is not ready.
 * @param {string} [notebookBlocker]
 */
function updateCellRunButtons(notebookBlocker) {
  const globalBlock = notebookBlocker ?? notebookReadinessBlocker();
  document.querySelectorAll("[data-run-cell]").forEach((btn) => {
    if (!(btn instanceof HTMLButtonElement)) return;
    const i = Number(btn.getAttribute("data-run-cell"));
    const chain = chains[i];
    const nSteps = (chain?.steps || []).length;
    const unmet = nSteps ? cellUnmetNeeds(chain) : [];
    const reason = !nSteps
      ? "Cell is empty"
      : unmet[0]
        ? unmet[0] === "needs recipients"
          ? "Add recipients before running"
          : unmet[0] === "needs input"
            ? "Add input text before running"
            : unmet[0]
        : "";
    btn.disabled = !nSteps || !!reason || !cryptoReady;
    btn.title = reason || (cryptoReady ? "Run this cell" : "Crypto not ready");
  });
  document.querySelectorAll("[data-run-from]").forEach((btn) => {
    if (!(btn instanceof HTMLButtonElement)) return;
    const blocked = !!globalBlock || !cryptoReady;
    btn.disabled = blocked;
    btn.title = globalBlock || (cryptoReady ? "Run this cell and all below" : "Crypto not ready");
  });
}

/**
 * Refresh need badges on a cell chrome without rebuilding the notebook.
 * @param {number} cellIndex
 */
function syncCellNeedBadges(cellIndex) {
  const chrome = document.querySelector(
    `.notebook-cell[data-cell="${cellIndex}"] .notebook-cell-chrome`
  );
  if (!chrome) return;
  chrome.querySelectorAll(".cell-need-badge").forEach((el) => el.remove());
  const statusEl = chrome.querySelector(".cell-status");
  const unmet = cellNeedBadges(chains[cellIndex] || { steps: [] });
  const html = unmet
    .map(
      (b) =>
        `<span class="cell-need-badge" title="${escapeHtml(b)}">${escapeHtml(b)}</span>`
    )
    .join("");
  statusEl?.insertAdjacentHTML("afterend", html);
  syncCellRuntimeChrome(cellIndex, unmet);
}

/**
 * Mark runtime input / binder panels as needing attention vs ready.
 * @param {number} cellIndex
 * @param {string[]} [unmet]
 */
function syncCellRuntimeChrome(cellIndex, unmet) {
  const needs = unmet ?? cellUnmetNeeds(chains[cellIndex] || { steps: [] });
  const inputNeedsAttention = needs.some((n) =>
    ["needs input", "needs shares", "needs ciphertext", "needs envelope", "needs key"].includes(n)
  );
  const recipNeedsAttention = needs.includes("needs recipients");
  const inputsHost = document.getElementById(`cell-inputs-${cellIndex}`);
  if (inputsHost && !inputsHost.hidden) {
    inputsHost.classList.toggle("cell-runtime-needs", inputNeedsAttention);
    inputsHost.classList.toggle("cell-runtime-ready", !inputNeedsAttention);
  }
  const bindHost = document.getElementById(`cell-bind-${cellIndex}`);
  if (bindHost && bindHost.childElementCount) {
    bindHost.classList.toggle("cell-runtime-needs", recipNeedsAttention);
    bindHost.classList.toggle("cell-runtime-ready", !recipNeedsAttention);
  }
}

/**
 * Destroy per-cell recipient binders.
 */
function destroyCellBinders() {
  for (const b of cellBinders.values()) {
    try {
      b.destroy();
    } catch (_) {
      /* ignore */
    }
  }
  cellBinders.clear();
}

/**
 * Input needs for a single notebook cell.
 * @param {import("../lib/toolkit/recipe.js").RecipeChain} chain
 * @returns {("shares"|"gpg"|"gpgPass"|"text"|"envelope"|"key")[]}
 */
function cellRuntimeNeeds(chain) {
  if (!chain?.steps?.length) return [];
  try {
    const v = validateRecipe({
      chains: [chain],
      steps: chain.steps,
      source: "",
    });
    return /** @type {("shares"|"gpg"|"gpgPass"|"text"|"envelope"|"key")[]} */ (
      v.inputNeeds || []
    );
  } catch (_) {
    return [];
  }
}

/**
 * Recipient binder slots for a single cell.
 * @param {import("../lib/toolkit/recipe.js").RecipeChain} chain
 * @returns {{ slots: number, foreach: boolean }}
 */
function cellRecipientInfo(chain) {
  if (!chain?.steps?.length) return { slots: 0, foreach: false };
  try {
    return unresolvedRecipients({
      chains: [chain],
      steps: chain.steps,
      source: "",
    });
  } catch (_) {
    return { slots: 0, foreach: false };
  }
}

/**
 * Paint Share mnemonics / Decrypt / Input / binder UI into each owning cell.
 */
function renderAllCellRuntimePanels() {
  destroyCellBinders();
  for (let i = 0; i < chains.length; i++) {
    const needs = cellRuntimeNeeds(chains[i]);
    const inputsHost = document.getElementById(`cell-inputs-${i}`);
    if (inputsHost) {
      renderInputsPanel(needs, inputsHost, i);
    }
    const bindHost = document.getElementById(`cell-bind-${i}`);
    if (!bindHost) continue;
    const info = cellRecipientInfo(chains[i]);
    if (info.slots > 0) {
      bindHost.classList.add("cell-bind-messaging", "cell-runtime-zone");
      const binder = mountRecipientBinder(bindHost, {
        slots: info.slots,
        foreach: info.foreach,
        onChange: (recs) => {
          boundRecipients = recs;
          applyRunReadiness();
          syncCellNeedBadges(i);
        },
      });
      cellBinders.set(i, binder);
    } else {
      bindHost.classList.remove(
        "cell-bind-messaging",
        "cell-runtime-zone",
        "cell-runtime-needs",
        "cell-runtime-ready"
      );
      bindHost.innerHTML = "";
    }
    syncCellRuntimeChrome(i);
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
 * @param {("shares"|"gpg"|"gpgPass"|"text"|"envelope"|"key")[]} needs
 * @param {HTMLElement} [host]
 * @param {number} [cellIndex]
 */
function renderInputsPanel(needs, host, cellIndex = 0) {
  if (!host) return;
  if (!needs.length) {
    host.innerHTML = "";
    host.hidden = true;
    host.classList.remove(
      "cell-inputs-compact",
      "cell-inputs-expanded",
      "cell-runtime-zone",
      "cell-runtime-needs",
      "cell-runtime-ready"
    );
    return;
  }
  host.hidden = false;
  host.classList.add("cell-runtime-zone");
  if (!shareRows.length) shareRows = [""];
  const p = `c${cellIndex}-`;

  const title = needs.includes("shares")
    ? "Share mnemonics"
    : needs.includes("gpg")
      ? "Decrypt"
      : needs.includes("key")
        ? "WebCrypto key"
        : needs.includes("envelope")
          ? "Envelope"
          : "Message";
  const textEmpty = needs.includes("text") && !String(inputTextDraft || "").trim();
  const gpgEmpty = needs.includes("gpg") && !String(ciphertextDraft || "").trim();
  const compactEmpty =
    (textEmpty || gpgEmpty) &&
    !needs.includes("shares") &&
    !needs.includes("key") &&
    !needs.includes("envelope");
  host.classList.toggle("cell-inputs-compact", compactEmpty);
  host.classList.toggle("cell-inputs-expanded", !compactEmpty);
  /** @type {string[]} */
  const parts = [
    `<div class="cell-runtime-panel" data-cell-runtime="${cellIndex}">`,
    `<div class="cell-runtime-head">
      <span class="cell-runtime-kicker">Required at run</span>
      <p class="card-title mb-0">${title}</p>
    </div>`,
  ];
  if (needs.includes("shares")) {
    parts.push(
      `<p class="muted fs-sm mb-sm">Runtime binding for this cell’s <code>shares</code> source → <code>shares/mnemonic</code>. Pipe into <code>blip39 -d</code> then <code>recover</code>.</p>`
    );
  }
  if (needs.includes("key")) {
    parts.push(`
      <p class="muted fs-sm mb-sm">Bound WebCrypto key for <code>sign</code> / <code>verify</code> / <code>aes-gcm</code> / <code>ecdh</code> / <code>wrap</code>. Paste a JWK from <code>genkey | export jwk</code>.</p>
      <label class="field-label" for="${p}input-wc-jwk">Key JWK</label>
      <textarea id="${p}input-wc-jwk" data-rt="wc-jwk" class="compose-message" rows="4" spellcheck="false"
        placeholder='{"kty":"EC","crv":"P-256",…} or oct AES/HMAC'>${escapeHtml(keyJwkDraft)}</textarea>
      <label class="field-label mt-sm" for="${p}input-wc-peer">Peer public JWK (ecdh)</label>
      <textarea id="${p}input-wc-peer" data-rt="wc-peer" class="compose-message" rows="3" spellcheck="false"
        placeholder="Peer public JWK for ecdh">${escapeHtml(peerJwkDraft)}</textarea>
      <label class="field-label mt-sm" for="${p}input-wc-wrap">Key-to-wrap JWK (wrap)</label>
      <textarea id="${p}input-wc-wrap" data-rt="wc-wrap" class="compose-message" rows="3" spellcheck="false"
        placeholder="oct JWK to wrap">${escapeHtml(wrapJwkDraft)}</textarea>
      <label class="field-label mt-sm" for="${p}input-wc-sig">Signature base64url (verify)</label>
      <input type="text" id="${p}input-wc-sig" data-rt="wc-sig" class="text-input" spellcheck="false"
        value="${escapeHtml(signatureDraft)}" placeholder="base64url signature">
    `);
  }
  if (needs.includes("text")) {
    const rows = textEmpty ? 2 : 6;
    parts.push(`
      <div class="btn-row wrap mb-xs">
        <label class="field-label m-0" for="${p}input-text">Message</label>
        <button type="button" class="btn btn-ghost btn-compact" data-rt-btn="load-text">Load from file…</button>
        <input type="file" data-rt-file="load-text" class="hidden" multiple accept="*/*">
      </div>
      <textarea id="${p}input-text" data-rt="text" class="compose-message cell-input-expandable" rows="${rows}" spellcheck="false"
        placeholder="Paste or load the message — not stored in the recipe.">${escapeHtml(inputTextDraft)}</textarea>
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
          <button type="button" class="btn btn-ghost btn-compact" data-rt-btn="add-share">+ Add share</button>
          <button type="button" class="btn btn-ghost btn-compact" data-rt-btn="load-shares">Load from file…</button>
          <input type="file" data-rt-file="load-shares" class="hidden" multiple accept=".txt,text/plain,*/*">
        </div>
        <p class="muted fs-sm mb-sm">${
          needs.includes("gpg")
            ? "Use these rows for mnemonics already decrypted outside the browser (Kleopatra/gpg/YubiKey). Mix with OpenPGP ciphertext below — the pipeline merges both before blip39 -d | sss.combine."
            : "One share per row. Paste multiple lines into a row to auto-split. K-of-N required to recover. Direct 16/32-byte splits need no envelope."
        }</p>
        <div data-rt="share-rows">${rowsHtml}</div>
        <label class="field-label mt-md" for="${p}input-share-pass">Share passphrase (optional)</label>
        <input type="password" id="${p}input-share-pass" data-rt="share-pass" class="text-input" autocomplete="off" value="${escapeHtml(sharePassDraft)}">
      </div>
    `);
  }
  if (needs.includes("envelope")) {
    parts.push(`
      <div class="envelope-inputs mt-md">
        <div class="btn-row wrap mb-xs">
          <label class="field-label m-0" for="${p}input-envelope">OpenPGP envelope (armored)</label>
          <button type="button" class="btn btn-ghost btn-compact" data-rt-btn="load-envelope">Load envelope.asc…</button>
          <input type="file" data-rt-file="load-envelope" class="hidden" accept=".asc,.pgp,.txt,*/*">
        </div>
        <textarea id="${p}input-envelope" data-rt="envelope" class="compose-message" rows="6" spellcheck="false"
          placeholder="-----BEGIN PGP MESSAGE-----&#10;…&#10;-----END PGP MESSAGE-----&#10;Required for gpg.symdecrypt (PEM / large-payload path). Not used for direct scalar splits.">${escapeHtml(envelopeDraft)}</textarea>
        <p class="muted fs-sm mt-xs">OpenPGP symmetric ciphertext from <code>gpg.symencrypt</code> — distinct from BLIP39 share mnemonics.</p>
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
        <label class="field-label m-0" for="${p}input-ciphertext">OpenPGP ciphertext</label>
        <button type="button" class="btn btn-ghost btn-compact" data-rt-btn="load-ciphertext">Load from file…</button>
        <input type="file" data-rt-file="load-ciphertext" class="hidden" multiple accept=".asc,.pgp,.txt,*/*">
      </div>
      <textarea id="${p}input-ciphertext" data-rt="ciphertext" class="compose-message cell-input-expandable" rows="${gpgEmpty ? 3 : 8}" spellcheck="false"
        placeholder="Paste -----BEGIN PGP MESSAGE----- blocks (and/or already-decrypted mnemonics).">${escapeHtml(ciphertextDraft)}</textarea>
      <label class="field-label mt-md" for="${p}input-vault-key">Vault private key (only for ciphertext you can decrypt here)</label>
      <select id="${p}input-vault-key" data-rt="vault-key" class="text-input">
        <option value="">— paste key below / not needed if all shares are plaintext —</option>
        ${vaultOpts}
      </select>
      <label class="field-label mt-md" for="${p}input-privkey">Armored private key (optional if using vault)</label>
      <textarea id="${p}input-privkey" data-rt="privkey" class="compose-message" rows="4" spellcheck="false"
        placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"></textarea>
      <label class="field-label mt-md" for="${p}input-key-pass">Key passphrase</label>
      <input type="password" id="${p}input-key-pass" data-rt="key-pass" class="text-input" autocomplete="off"
        placeholder="If the OpenPGP key is locked">
      <p class="muted mt-xs fs-sm">Software/vault keys unlock only for this run. OpenPGP smartcards are not accessible from the browser.</p>
    `);
  } else if (needs.includes("gpgPass")) {
    parts.push(`
      <label class="field-label mt-md" for="${p}input-key-pass">OpenPGP key passphrase</label>
      <input type="password" id="${p}input-key-pass" data-rt="key-pass" class="text-input" autocomplete="off"
        placeholder="If the key slot / vault key is S2K-locked">
      <p class="muted mt-xs fs-sm">Needed when <code>key=@slot</code> armor is still passphrase-locked, or for <code>agent.save protection=passphrase</code>.</p>
    `);
  }
  parts.push(`</div>`);
  host.innerHTML = parts.join("\n");
  wireInputsPanel(host, needs, cellIndex);
}

/**
 * @param {HTMLElement} host
 * @param {("shares"|"gpg"|"gpgPass"|"text"|"envelope"|"key")[]} needs
 * @param {number} cellIndex
 */
function wireInputsPanel(host, needs, cellIndex) {
  const rerender = () => {
    const h = document.getElementById(`cell-inputs-${cellIndex}`);
    if (h) renderInputsPanel(needs, h, cellIndex);
  };

  const refreshReadiness = () => {
    applyRunReadiness();
    syncCellNeedBadges(cellIndex);
  };

  const expandInputsOnFocus = (el) => {
    el?.addEventListener("focus", () => {
      host.classList.remove("cell-inputs-compact");
      host.classList.add("cell-inputs-expanded");
      if (el instanceof HTMLTextAreaElement && Number(el.rows) < 6) el.rows = 6;
    });
  };

  if (needs.includes("text")) {
    const textEl = host.querySelector("[data-rt=text]");
    expandInputsOnFocus(textEl);
    textEl?.addEventListener("input", () => {
      if (textEl instanceof HTMLTextAreaElement) {
        inputTextDraft = textEl.value;
        if (inputTextDraft.trim()) {
          host.classList.remove("cell-inputs-compact");
          host.classList.add("cell-inputs-expanded");
          if (Number(textEl.rows) < 6) textEl.rows = 6;
        }
      }
      refreshReadiness();
    });
    wireFileButton(host, "[data-rt-btn=load-text]", "[data-rt-file=load-text]", async (files) => {
      /** @type {string[]} */
      const chunks = [];
      for (const f of files) chunks.push(await f.text());
      const joined = chunks.join("\n").replace(/\n+$/, "");
      if (!joined) return;
      inputTextDraft = inputTextDraft.trim()
        ? `${inputTextDraft.replace(/\n+$/, "")}\n${joined}`
        : joined;
      if (textEl instanceof HTMLTextAreaElement) textEl.value = inputTextDraft;
      refreshReadiness();
    });
  }

  if (needs.includes("shares")) {
    host.querySelector("[data-rt-btn=add-share]")?.addEventListener("click", () => {
      shareRows.push("");
      rerender();
    });

    host.querySelectorAll("[data-remove-share]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.getAttribute("data-remove-share"));
        if (shareRows.length <= 1) return;
        shareRows.splice(i, 1);
        rerender();
      });
    });

    host.querySelectorAll("[data-share-input]").forEach((el) => {
      el.addEventListener("input", () => {
        const i = Number(el.getAttribute("data-share-input"));
        if (!(el instanceof HTMLTextAreaElement) || i < 0) return;
        const parts = splitSharePaste(el.value);
        if (parts.length > 1) {
          shareRows.splice(i, 1, ...parts);
          rerender();
          return;
        }
        shareRows[i] = el.value;
        const row = el.closest(".share-row");
        const badge = row?.querySelector(".share-badge");
        if (badge) {
          badge.outerHTML = shareChecksumBadge(el.value);
        }
        refreshReadiness();
      });
    });

    const passEl = host.querySelector("[data-rt=share-pass]");
    passEl?.addEventListener("input", () => {
      if (passEl instanceof HTMLInputElement) sharePassDraft = passEl.value;
    });

    wireFileButton(host, "[data-rt-btn=load-shares]", "[data-rt-file=load-shares]", async (files) => {
      /** @type {string[]} */
      const loaded = [];
      for (const f of files) {
        const text = await f.text();
        loaded.push(...splitSharePaste(text));
      }
      if (!loaded.length) return;
      const nonempty = shareRows.filter((s) => s.trim());
      shareRows = nonempty.length ? [...nonempty, ...loaded] : loaded;
      rerender();
    });
  }

  if (needs.includes("envelope")) {
    const envEl = host.querySelector("[data-rt=envelope]");
    envEl?.addEventListener("input", () => {
      if (envEl instanceof HTMLTextAreaElement) envelopeDraft = envEl.value;
    });
    wireFileButton(host, "[data-rt-btn=load-envelope]", "[data-rt-file=load-envelope]", async (files) => {
      const f = files[0];
      if (!f) return;
      envelopeDraft = await readEnvelopeAscFile(f);
      rerender();
    });
  }

  if (needs.includes("gpg")) {
    const ctEl = host.querySelector("[data-rt=ciphertext]");
    expandInputsOnFocus(ctEl);
    ctEl?.addEventListener("input", () => {
      if (ctEl instanceof HTMLTextAreaElement) {
        ciphertextDraft = ctEl.value;
        if (ciphertextDraft.trim()) {
          host.classList.remove("cell-inputs-compact");
          host.classList.add("cell-inputs-expanded");
          if (Number(ctEl.rows) < 8) ctEl.rows = 8;
        }
      }
      refreshReadiness();
    });
    wireFileButton(host, "[data-rt-btn=load-ciphertext]", "[data-rt-file=load-ciphertext]", async (files) => {
      const box = host.querySelector("[data-rt=ciphertext]");
      if (!(box instanceof HTMLTextAreaElement)) return;
      /** @type {string[]} */
      const chunks = [];
      for (const f of files) chunks.push(await f.text());
      const joined = chunks.join("\n\n").trim();
      ciphertextDraft = box.value.trim()
        ? `${box.value.trim()}\n\n${joined}`
        : joined;
      box.value = ciphertextDraft;
      refreshReadiness();
    });
  }

  if (needs.includes("key")) {
    const jwkEl = host.querySelector("[data-rt=wc-jwk]");
    jwkEl?.addEventListener("input", () => {
      if (jwkEl instanceof HTMLTextAreaElement) keyJwkDraft = jwkEl.value;
      refreshReadiness();
    });
    const peerEl = host.querySelector("[data-rt=wc-peer]");
    peerEl?.addEventListener("input", () => {
      if (peerEl instanceof HTMLTextAreaElement) peerJwkDraft = peerEl.value;
    });
    const wrapEl = host.querySelector("[data-rt=wc-wrap]");
    wrapEl?.addEventListener("input", () => {
      if (wrapEl instanceof HTMLTextAreaElement) wrapJwkDraft = wrapEl.value;
    });
    const sigEl = host.querySelector("[data-rt=wc-sig]");
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
    vaultKeys = sortKeysByLastUsed(await vaultListKeys());
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

  /** @param {string} name @returns {Element|null} */
  const rt = (name) => document.querySelector(`[data-rt="${name}"]`);

  if (currentInputNeeds.includes("text")) {
    const textEl = rt("text");
    if (textEl instanceof HTMLTextAreaElement) inputTextDraft = textEl.value;
    inputs.text = { value: inputTextDraft };
  }

  if (currentInputNeeds.includes("key")) {
    const jwkEl = rt("wc-jwk");
    const peerEl = rt("wc-peer");
    const wrapEl = rt("wc-wrap");
    const sigEl = rt("wc-sig");
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
    document.querySelectorAll("[data-share-input]").forEach((el) => {
      const i = Number(el.getAttribute("data-share-input"));
      if (el instanceof HTMLTextAreaElement && i >= 0) shareRows[i] = el.value;
    });
    const passEl = rt("share-pass");
    if (passEl instanceof HTMLInputElement) sharePassDraft = passEl.value;
    const mnemonics = shareRows.map((m) => m.trim()).filter(Boolean);
    inputs.shares = {
      mnemonics,
      passphrase: sharePassDraft,
    };
  }

  if (currentInputNeeds.includes("envelope")) {
    const envEl = rt("envelope");
    if (envEl instanceof HTMLTextAreaElement) envelopeDraft = envEl.value;
    const armored = envelopeDraft.trim();
    if (armored) {
      inputs.envelope = { armored };
      if (inputs.shares) inputs.shares.envelopeArmored = armored;
    }
  }

  if (currentInputNeeds.includes("gpg") || currentInputNeeds.includes("gpgPass")) {
    const ctEl = rt("ciphertext");
    const vaultEl = rt("vault-key");
    const privEl = rt("privkey");
    const passEl = rt("key-pass");
    if (ctEl instanceof HTMLTextAreaElement) ciphertextDraft = ctEl.value;
    const armored = ciphertextDraft.trim();
    const messages = splitArmoredMessages(armored);
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
      const unlocked = await unlockVaultForUse(vaultFpr, {
        meta,
        openPgpPassphrase: passphrase,
        skipSession: getToolkitPrefs().sessionOff,
      });
      privateKeyArmored = unlocked.armored;
    }

    inputs.gpg = {
      armoredMessages: [...messages, ...plainFromCt],
      privateKeyArmored,
      passphrase,
      envelopeArmored: inputs.envelope?.armored || "",
    };
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
    <div class="preset-card-wrap">
      <button type="button" class="preset-card" data-preset="${escapeHtml(p.id)}" title="Replace notebook with this template">
        <strong>${escapeHtml(p.title)}</strong>
        <span class="muted">${escapeHtml(p.blurb)}</span>
        <code class="preset-recipe">${escapeHtml(p.recipe)}</code>
      </button>
      <button type="button" class="btn btn-ghost btn-compact preset-append-btn" data-preset-append="${escapeHtml(p.id)}"
        title="Append this template’s chains as new cells">Append</button>
    </div>`;

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
        const st = stitchPresetPair(p, next);
        const meta = bridgeModeMeta(st.mode, st.bridge);
        const labelId = `preset-pair-${escapeHtml(p.pair)}`;
        items += `
          <div class="preset-pair" role="group" aria-labelledby="${labelId}">
            <div class="preset-pair-head">
              <div class="preset-pair-head-text">
                <span class="preset-pair-kicker" id="${labelId}">Companion</span>
                <span class="badge preset-bridge-badge" data-bridge="${escapeHtml(st.mode)}">${escapeHtml(meta.badge)}</span>
              </div>
              <button type="button" class="btn btn-compact preset-pair-both-btn"
                data-preset-pair="${escapeHtml(p.pair)}"
                title="${escapeHtml(meta.hint)}">Add both ⇄</button>
            </div>
            <div class="preset-pair-body">
              ${card(p)}
              <span class="preset-pair-link" aria-hidden="true" title="Companion pipelines">⇄</span>
              ${card(next)}
            </div>
            <p class="preset-pair-hint muted">${escapeHtml(meta.hint)}</p>
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
      const hasContent =
        chains.some((c) => (c.steps || []).length > 0) || kernel.slotCount() > 0;
      if (
        hasContent &&
        !window.confirm(
          `Replace the notebook with “${preset.title}”?\n\nKernel slots and cell outputs will be cleared. Use Append on the template card to add cells instead.`
        )
      ) {
        return;
      }
      lastPresetId = preset.id;
      fragmentWriteLock = true;
      loadRecipeText(preset.recipe, { title: preset.title, migrate: true });
      writeToolkitHash(hashForPreset(preset.id), { replace: true });
      queueMicrotask(() => {
        fragmentWriteLock = false;
      });
      document.getElementById("preset-gallery")?.removeAttribute("open");
      scrollFocusedCellIntoView();
    });
  });
  grid.querySelectorAll("[data-preset-append]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const id = btn.getAttribute("data-preset-append");
      const preset = PRESETS.find((p) => p.id === id);
      if (!preset) return;
      lastPresetId = null;
      appendPresetAsCells(preset);
      document.getElementById("preset-gallery")?.removeAttribute("open");
      scrollFocusedCellIntoView();
    });
  });
  grid.querySelectorAll("[data-preset-pair]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const pairId = btn.getAttribute("data-preset-pair") || "";
      const pair = resolvePresetPair(pairId);
      if (!pair) return;
      lastPresetId = null;
      const st = appendPresetPairAsCells(pair.forward, pair.reverse);
      document.getElementById("preset-gallery")?.removeAttribute("open");
      scrollFocusedCellIntoView();
      const status = document.getElementById("run-status");
      if (status && st) {
        const meta = bridgeModeMeta(st.mode, st.bridge);
        status.className = "status-row ok";
        status.textContent = meta.toast;
        status.classList.remove("hidden");
      }
    });
  });
}

/**
 * Append recipe chains as new notebook cells (keep current cells + kernel).
 * @param {string} source
 * @param {{ title?: string }} [opts]
 */
function appendRecipeAsCells(source, opts = {}) {
  let text = migrateRecipe(String(source || "")).recipe;
  const { ast, errors } = canonicalizeRecipe(text);
  if (errors.length || !ast) {
    showError(errorEl, errors.map((e) => e.message).join(" · ") || "Recipe parse failed");
    return;
  }
  const loaded = recipeChains(ast).map((c) => ({
    steps: (c.steps || []).map((s) => cloneBuilderStep(s)),
  }));
  if (!loaded.length) return;
  const start = chains.length;
  // Drop a trailing empty cell before append
  if (chains.length === 1 && !(chains[0].steps || []).length) {
    chains = loaded;
    focusCell(0);
  } else {
    chains.push(...loaded);
    focusCell(start);
  }
  if (!recipeTitle && opts.title) setRecipeTitle(opts.title);
  setRecipeFromSteps();
}

/**
 * Append a preset’s chains as new notebook cells (keep current cells + kernel).
 * @param {typeof PRESETS[number]} preset
 */
function appendPresetAsCells(preset) {
  appendRecipeAsCells(preset.recipe, { title: preset.title });
}

/**
 * Append companion presets (forward then inverse), stitched for slot/inputs bridge.
 * @param {typeof PRESETS[number]} forward
 * @param {typeof PRESETS[number]} reverse
 * @returns {import("../lib/toolkit/conjugate-stitch.js").StitchResult|null}
 */
function appendPresetPairAsCells(forward, reverse) {
  const st = stitchPresetPair(forward, reverse);
  if (st.errors?.length) {
    showError(errorEl, st.errors.join(" · "));
    return null;
  }
  const title =
    forward.pair || forward.title
      ? `${forward.title} ⇄ ${reverse.title}`
      : undefined;
  appendRecipeAsCells(st.recipe, { title });
  return st;
}

/**
 * Preferred next-step order for the current pipeline tip type.
 * Unknown names sort after these, by kind then name.
 * @param {import("../lib/toolkit/types.js").RefinedType} from
 * @returns {string[]}
 */
function preferredNextOrder(from) {
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
  if (from.base === "bytes" && from.kind === "scalar") {
    return [
      "import",
      "sss.split",
      "hex",
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
      "hex",
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
      "hex",
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
 * Compatible next steps for the builder suggest drawer, ranked for the tip type.
 * @param {import("../lib/toolkit/types.js").RefinedType} from
 * @param {{ hasForeach?: boolean, terminal?: boolean }} [opts]
 * @returns {import("../lib/toolkit/registry.js").StepSpec[]}
 */
function suggestedNextSteps(from, opts = {}) {
  const hasForeach = !!opts.hasForeach;
  const terminal = !!opts.terminal;
  void hasForeach;
  let list = stepsAccepting(from).filter((s) => {
    if (s.kind === "flow") {
      return s.name === "foreach";
    }
    return true;
  });
  if (terminal) {
    list = list.filter((s) =>
      s.name === "inspect" ||
      s.name === "tee" ||
      s.name === "peek" ||
      s.name === "out" ||
      s.name === "text"
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
 * Contextual next-block drawer under the focused cell’s pipeline.
 */
function renderSuggestDrawer() {
  const host = document.getElementById("suggest-next");
  if (!host) return;

  const from = currentPipelineOutput();
  const last = steps[steps.length - 1];
  const terminal = !!(last && (isTerminalSink(last.name) || last.name === "inspect"));
  const hasForeach = steps.some((s) => s.name === "foreach");
  const next = suggestedNextSteps(from, { hasForeach, terminal });
  const composeChips = compositionSuggestChipsHtml(from);

  if (!next.length && !composeChips) {
    host.hidden = true;
    host.innerHTML = "";
    return;
  }

  const fromType = formatType(from);
  const heading = !steps.length
    ? composeChips && !next.length
      ? `Cell [${focusedCell}] · compose`
      : `Cell [${focusedCell}] · start with`
    : terminal
      ? `Cell [${focusedCell}] · optional next`
      : `Cell [${focusedCell}] · next for <code>${escapeHtml(fromType)}</code>`;
  const blurb = !steps.length
    ? composeChips && !next.length
      ? "Kernel slots ready — add a new cell that uses them."
      : "Sources that begin a pipeline."
    : terminal
      ? "Pipeline already has a sink — these still accept the tip."
      : "Compatible blocks for the current tip type.";

  const primaryCount = !steps.length ? 3 : from.base === "shares" ? 2 : 3;

  host.hidden = false;
  host.innerHTML = `
    <div class="suggest-next-head">
      <p class="suggest-next-title mb-0">${heading}</p>
      <p class="muted fs-xs mb-0">${blurb}</p>
    </div>
    ${composeChips}
    ${
      next.length
        ? `<div class="suggest-next-chips" role="list">
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
          const blocked = stepBlockedByFips(s.name);
          return `
            <button type="button" class="suggest-chip${primary}${blocked ? " suggest-chip-fips-blocked" : ""}" role="listitem"
              data-suggest-op="${escapeHtml(s.name)}"
              data-suggest-decode="${decode ? "1" : "0"}"
              draggable="${blocked ? "false" : "true"}"
              ${blocked ? "aria-disabled=\"true\"" : ""}
              title="${escapeHtml(blocked ? `FIPS mode: blocked — ${s.toolbox} unverified` : s.doc)}">
              ${toolboxBadgeHtml(s.toolbox)}
              ${suiteChipHtml(s.toolbox)}
              <span class="suggest-chip-name">${escapeHtml(label)}</span>
              ${
                outLabel
                  ? `<span class="suggest-chip-out muted">→ ${escapeHtml(outLabel)}</span>`
                  : ""
              }
            </button>`;
        })
        .join("")}
    </div>`
        : ""
    }`;

  host.querySelectorAll("[data-suggest-compose]").forEach((el) => {
    el.addEventListener("click", () => {
      const kind = el.getAttribute("data-suggest-compose") || "";
      applyCompositionChip(kind);
    });
  });

  host.querySelectorAll("[data-suggest-op]").forEach((el) => {
    const name = el.getAttribute("data-suggest-op") || "";
    const decode = el.getAttribute("data-suggest-decode") === "1";
    const overrides = decode ? { decode: true } : undefined;
    el.addEventListener("dragstart", (e) => {
      if (stepBlockedByFips(name)) {
        e.preventDefault();
        return;
      }
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
 * Tip-type + kernel-slot composition chips (new cells that consume @slots).
 * @param {import("../lib/toolkit/types.js").RefinedType} from
 * @returns {string}
 */
function compositionSuggestChipsHtml(from) {
  /** @type {string[]} */
  const chips = [];
  /** @type {Set<string>} */
  const seen = new Set();

  const push = (id, label, primary = false) => {
    if (seen.has(id)) return;
    seen.add(id);
    chips.push(`
      <button type="button" class="suggest-chip suggest-chip-compose${primary ? " suggest-chip-primary" : ""}"
        data-suggest-compose="${escapeHtml(id)}">
        <span class="suggest-chip-name">${escapeHtml(label)}</span>
      </button>`);
  };

  if (from && steps.length) {
    if (from.base === "recipients") {
      push("encrypt-to", "Encrypt message to this set", true);
    }
    if (from.base === "openpgp-key" && from.which === "private") {
      push("sign-with", "Sign with this key", true);
    }
  }

  for (const m of kernel.listSlots()) {
    const kind = slotMetaKind(m);
    if (kind === "recipients") {
      push(
        `encrypt-to:${m.label}`,
        `Encrypt to @${m.label}${m.recipients != null ? ` (${m.recipients})` : ""}`,
        !chips.length
      );
    } else if (kind === "openpgp-private") {
      push(`sign-with:${m.label}`, `Sign with @${m.label}`, !chips.length);
    }
  }

  if (!chips.length) return "";
  return `<div class="suggest-next-chips suggest-compose-chips mb-sm" role="list">
    <span class="suggest-compose-label muted fs-xs">Compose</span>
    ${chips.join("")}
  </div>`;
}

/**
 * @param {string} kind  encrypt-to | encrypt-to:label | sign-with | sign-with:label
 */
function applyCompositionChip(kind) {
  const raw = String(kind || "");
  const colon = raw.indexOf(":");
  const base = colon >= 0 ? raw.slice(0, colon) : raw;
  const forcedLabel = colon >= 0 ? raw.slice(colon + 1).replace(/^@/, "") : "";
  const last = steps[steps.length - 1];

  if (base === "encrypt-to") {
    let label = forcedLabel || "alices";
    if (!forcedLabel) {
      if (last?.name === "out") {
        label = String(last.params?.name || "alices").replace(/^@/, "") || "alices";
      } else {
        const outSpec = getStep("out");
        steps.push({
          name: "out",
          params: { ...defaultParams(outSpec || { params: [] }), name: `@${label}` },
          start: 0,
          end: 0,
        });
      }
    }
    const encSpec = getStep("gpg.encrypt");
    chains.push({
      steps: [
        {
          name: "input",
          params: { ...defaultParams(getStep("input") || { params: [] }) },
          start: 0,
          end: 0,
        },
        {
          name: "gpg.encrypt",
          params: {
            ...defaultParams(encSpec || { params: [] }),
            to: `@${label}`,
          },
          start: 0,
          end: 0,
        },
      ],
    });
    focusCell(chains.length - 1);
    setRecipeFromSteps();
    return;
  }
  if (base === "sign-with") {
    let label = forcedLabel || "me";
    if (!forcedLabel) {
      if (last?.name === "out") {
        label = String(last.params?.name || "me").replace(/^@/, "") || "me";
      } else {
        steps.push({
          name: "out",
          params: { ...defaultParams(getStep("out") || { params: [] }), name: `@${label}` },
          start: 0,
          end: 0,
        });
      }
    }
    const signSpec = getStep("gpg.sign");
    chains.push({
      steps: [
        {
          name: "input",
          params: { ...defaultParams(getStep("input") || { params: [] }) },
          start: 0,
          end: 0,
        },
        {
          name: "gpg.sign",
          params: {
            ...defaultParams(signSpec || { params: [] }),
            key: `@${label}`,
          },
          start: 0,
          end: 0,
        },
      ],
    });
    focusCell(chains.length - 1);
    setRecipeFromSteps();
  }
}

/**
 * @param {import("../lib/toolkit/registry.js").StepSpec} s
 * @param {Set<string>} suggested
 * @param {{ decode?: boolean, cellClass?: string }} [opts]
 * @returns {string}
 */
function opsItemHtml(s, suggested, opts = {}) {
  const decode = !!opts.decode;
  const from = currentPipelineOutput();
  let fit;
  if (!steps.length) {
    fit = s.kind === "source" || s.input === "none";
  } else if (decode) {
    const resolved = resolveStepType(s, from, { ...defaultParams(s), decode: true });
    fit = !!(resolved && resolved.ok);
  } else {
    fit = suggested.has(s.name);
  }
  const io = s.effectiveIo
    ? s.effectiveIo({ ...defaultParams(s), ...(decode ? { decode: true } : {}) })
    : { input: s.input, output: s.output };
  const ioLabel = `${io.input} → ${io.output}`;
  const display = stepDisplayName(s);
  const nameLabel = decode ? `${display} -d` : display;
  const blocked = stepBlockedByFips(s.name);
  const title = blocked
    ? `FIPS mode: blocked — ${s.toolbox} suite unverified. ${FIPS_MODE_DISCLAIMER}`
    : `${s.doc}\n\nRecipe: ${s.name}${decode ? " -d" : ""} · ${ioLabel}`;
  const cellClass = opts.cellClass || "";
  return `
    <button type="button" class="ops-item ${cellClass} ${fit ? "ops-item-fit" : "ops-item-dim"}${blocked ? " ops-item-fips-blocked" : ""}"
      draggable="${blocked ? "false" : "true"}" data-op="${escapeHtml(s.name)}"
      data-op-decode="${decode ? "1" : "0"}"
      ${blocked ? "aria-disabled=\"true\"" : ""}
      title="${escapeHtml(title)}">
      <span class="ops-item-name">${escapeHtml(nameLabel)}</span>
      ${
        display !== s.name || decode
          ? `<span class="muted fs-xs ops-item-recipe">${escapeHtml(s.name)}${decode ? " -d" : ""}</span>`
          : ""
      }
      <span class="muted fs-xs ops-item-io">${escapeHtml(ioLabel)}</span>
    </button>`;
}

/**
 * @param {import("../lib/toolkit/registry.js").DrawerRow} row
 * @param {Set<string>} suggested
 * @returns {string}
 */
function opsDrawerRowHtml(row, suggested) {
  if (row.type === "solo" && row.step) {
    return `<div class="ops-pair ops-pair-solo">${opsItemHtml(row.step, suggested, { cellClass: "ops-pair-cell" })}</div>`;
  }
  if (row.type !== "pair" || !row.forward) return "";
  const caption = row.caption
    ? `<div class="ops-pair-caption muted fs-xs">${escapeHtml(row.caption)}</div>`
    : "";
  if (row.decodeTwin) {
    return `
      <div class="ops-pair">
        ${caption}
        ${opsItemHtml(row.forward, suggested, { cellClass: "ops-pair-cell" })}
        ${opsItemHtml(row.forward, suggested, { decode: true, cellClass: "ops-pair-cell" })}
      </div>`;
  }
  if (!row.reverse) {
    return `<div class="ops-pair ops-pair-solo">${caption}${opsItemHtml(row.forward, suggested, { cellClass: "ops-pair-cell" })}</div>`;
  }
  return `
    <div class="ops-pair">
      ${caption}
      ${opsItemHtml(row.forward, suggested, { cellClass: "ops-pair-cell" })}
      ${opsItemHtml(row.reverse, suggested, { cellClass: "ops-pair-cell" })}
    </div>`;
}

/**
 * Whether the Cipher kit strip should show under the current ops filter.
 * @param {string} q
 */
function cipherKitMatchesFilter(q) {
  if (!q) return true;
  return /encrypt|decrypt|cipher|aes|rsa|gcm|cbc|ctr|oaep|pkcs|jce|pick/i.test(
    q
  );
}

function formatKitMatchesFilter(q) {
  if (!q) return true;
  return /export|import|format|jwk|pkcs|spki|raw|scalar|key/i.test(q);
}

function macKitMatchesFilter(q) {
  if (!q) return true;
  return /hmac|mac|sign|verify/i.test(q);
}

/**
 * Meta Encrypt/Decrypt entry + cipher-subset picker (WebCrypto only).
 * @param {Set<string>} suggested
 * @returns {string}
 */
function cipherKitHtml(suggested) {
  const open = cipherPickerState;
  const encOpen = open && !open.decode;
  const decOpen = open && open.decode;
  const picks = listCipherPickerSteps();
  const panel = open
    ? `
      <div class="ops-cipher-picker" role="listbox" aria-label="Choose cipher">
        <p class="muted fs-xs mb-0">Inserts a concrete op${
          open.decode ? " with decrypt (-d)" : ""
        } — not an <code>encrypt</code> card.</p>
        ${picks
          .map((s) => {
            const aliases = CIPHER_PICKER_ALIASES[s.name] || [];
            const fit = suggested.has(s.name);
            const blocked = stepBlockedByFips(s.name);
            return `
              <button type="button" class="ops-item ops-cipher-pick${
                fit ? " ops-item-fit" : " ops-item-dim"
              }${blocked ? " ops-item-fips-blocked" : ""}"
                data-cipher-pick="${escapeHtml(s.name)}"
                role="option"
                ${blocked ? "aria-disabled=\"true\"" : ""}
                title="${escapeHtml(blocked ? `FIPS mode: blocked — ${s.toolbox} unverified` : s.doc)}">
                <span class="ops-item-name">${escapeHtml(s.name)}</span>
                ${
                  aliases.length
                    ? `<span class="ops-item-io muted">${escapeHtml(aliases.join(" · "))}</span>`
                    : ""
                }
              </button>`;
          })
          .join("")}
      </div>`
    : "";

  return `
    <div class="ops-cipher-kit" data-cipher-kit>
      <p class="ops-pair-caption">Pick a cipher</p>
      <div class="ops-pair">
        <div class="ops-pair-cell">
          <button type="button" class="ops-item ops-cipher-meta${encOpen ? " ops-cipher-meta-open" : ""}"
            data-cipher-meta="encrypt"
            aria-expanded="${encOpen ? "true" : "false"}"
            title="Choose a WebCrypto cipher to insert (encrypt)">
            <span class="ops-item-name">Encrypt</span>
            <span class="ops-item-io muted">meta → aes-gcm / …</span>
          </button>
        </div>
        <div class="ops-pair-cell">
          <button type="button" class="ops-item ops-cipher-meta${decOpen ? " ops-cipher-meta-open" : ""}"
            data-cipher-meta="decrypt"
            aria-expanded="${decOpen ? "true" : "false"}"
            title="Choose a WebCrypto cipher to insert (decrypt / -d)">
            <span class="ops-item-name">Decrypt</span>
            <span class="ops-item-io muted">meta → aes-gcm -d / …</span>
          </button>
        </div>
      </div>
      ${panel}
    </div>`;
}

/**
 * Key formats meta: Export | Import → pick jwk/pkcs8/… → concrete export/import card.
 * @returns {string}
 */
function formatKitHtml() {
  const open = formatPickerState;
  const expOpen = open?.direction === "export";
  const impOpen = open?.direction === "import";
  const panel = open
    ? `
      <div class="ops-cipher-picker" role="listbox" aria-label="Choose key format">
        <p class="muted fs-xs mb-0">Inserts <code>${escapeHtml(open.direction)}</code> with format pre-filled.</p>
        ${KEY_FORMAT_PICKS.map(
          (fmt) => `
            <button type="button" class="ops-item ops-cipher-pick"
              data-format-pick="${escapeHtml(fmt)}"
              role="option"
              title="${escapeHtml(`${open.direction} ${fmt}`)}">
              <span class="ops-item-name">${escapeHtml(fmt)}</span>
            </button>`
        ).join("")}
      </div>`
    : "";
  return `
    <div class="ops-cipher-kit" data-format-kit>
      <p class="ops-pair-caption">Key formats</p>
      <div class="ops-pair">
        <div class="ops-pair-cell">
          <button type="button" class="ops-item ops-cipher-meta${expOpen ? " ops-cipher-meta-open" : ""}"
            data-format-meta="export" aria-expanded="${expOpen ? "true" : "false"}">
            <span class="ops-item-name">Export</span>
            <span class="ops-item-io muted">meta → export jwk / …</span>
          </button>
        </div>
        <div class="ops-pair-cell">
          <button type="button" class="ops-item ops-cipher-meta${impOpen ? " ops-cipher-meta-open" : ""}"
            data-format-meta="import" aria-expanded="${impOpen ? "true" : "false"}">
            <span class="ops-item-name">Import</span>
            <span class="ops-item-io muted">meta → import jwk / …</span>
          </button>
        </div>
      </div>
      ${panel}
    </div>`;
}

/** HMAC meta: inserts sign / verify (recipe sugar: hmac / hmac.verify). */
function macKitHtml() {
  return `
    <div class="ops-cipher-kit" data-mac-kit>
      <p class="ops-pair-caption">HMAC</p>
      <div class="ops-pair">
        <div class="ops-pair-cell">
          <button type="button" class="ops-item" data-mac-meta="sign"
            title="Insert sign (HMAC keys via genkey hmac/sha256)">
            <span class="ops-item-name">hmac</span>
            <span class="ops-item-io muted">→ sign</span>
          </button>
        </div>
        <div class="ops-pair-cell">
          <button type="button" class="ops-item" data-mac-meta="verify"
            title="Insert verify (recipe sugar: hmac.verify)">
            <span class="ops-item-name">hmac.verify</span>
            <span class="ops-item-io muted">→ verify</span>
          </button>
        </div>
      </div>
    </div>`;
}

/**
 * Render ops for one toolbox — shelves + conjugate pair rows.
 * @param {string} tb
 * @param {import("../lib/toolkit/registry.js").StepSpec[]} items
 * @param {Set<string>} suggested
 * @param {boolean} filterActive
 * @returns {string}
 */
function renderToolboxOpsBody(tb, items, suggested, filterActive) {
  const sorted = items.slice().sort((a, b) => {
    const sa = getShelfMeta(a.shelf).order;
    const sb = getShelfMeta(b.shelf).order;
    const ka = KIND_META[a.kind]?.order ?? 9;
    const kb = KIND_META[b.kind]?.order ?? 9;
    return sa - sb || ka - kb || a.name.localeCompare(b.name);
  });
  const usesShelves = sorted.some((s) => s.shelf);
  const q = opsFilter.trim();
  let kit = "";
  if (tb === "webcrypto") {
    if (formatKitMatchesFilter(q)) kit += formatKitHtml();
    if (cipherKitMatchesFilter(q)) kit += cipherKitHtml(suggested);
    if (macKitMatchesFilter(q)) kit += macKitHtml();
  }

  /**
   * @param {typeof sorted} shelfItems
   */
  const rowsHtml = (shelfItems) =>
    listDrawerRows(shelfItems)
      .map((row) => opsDrawerRowHtml(row, suggested))
      .join("");

  if (!usesShelves) {
    return kit + rowsHtml(sorted);
  }

  /** @type {Map<string, typeof sorted>} */
  const byShelf = new Map();
  for (const s of sorted) {
    const shelf = s.shelf || "other";
    const list = byShelf.get(shelf) || [];
    list.push(s);
    byShelf.set(shelf, list);
  }
  const shelves = [...byShelf.keys()].sort(
    (a, b) => getShelfMeta(a).order - getShelfMeta(b).order
  );

  return (
    kit +
    shelves
      .map((shelf) => {
        const key = `${tb}:${shelf}`;
        const meta = getShelfMeta(shelf);
        const collapsed = opsShelfCollapsed.has(key) && !filterActive;
        const shelfItems = byShelf.get(shelf) || [];
        const visibleCount = listDrawerRows(shelfItems).length;
        return `
        <div class="ops-shelf" data-shelf="${escapeHtml(key)}">
          <button type="button" class="ops-shelf-toggle" data-toggle-shelf="${escapeHtml(key)}"
            aria-expanded="${collapsed ? "false" : "true"}">
            <span class="ops-shelf-label">${glyphHtml(meta.glyph, "ops-glyph ops-glyph-shelf")}<span>${escapeHtml(meta.label)}</span></span>
            <span class="muted fs-xs">${visibleCount}</span>
          </button>
          <div class="ops-shelf-body ${collapsed ? "hidden" : ""}">
            ${rowsHtml(shelfItems)}
          </div>
        </div>`;
      })
      .join("")
  );
}

/**
 * CyberChef-style operations drawer grouped by toolbox (and shelves within).
 */
function renderOpsDrawer() {
  const host = document.getElementById("ops-drawer");
  const hint = document.getElementById("ops-hint");
  if (!host) return;

  const q = opsFilter.trim().toLowerCase();
  const from = currentPipelineOutput();
  const suggested = new Set(stepsAccepting(from).map((s) => s.name));
  const all = listSteps().filter(
    (s) =>
      s.kind !== "flow" ||
      s.name === "foreach" ||
      s.name === "tee" ||
      s.name === "in" ||
      s.name === "as"
  );

  /** @type {Map<string, typeof all>} */
  const byToolbox = new Map();
  for (const s of all) {
    if (q) {
      const shelfLabel = s.shelf ? getShelfMeta(s.shelf).label : "";
      const hay =
        `${s.name} ${s.label || ""} ${s.toolbox} ${s.shelf || ""} ${shelfLabel} ${s.kind} ${s.doc} ${(s.aliases || []).join(" ")}`.toLowerCase();
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
    const slotN = kernel.slotCount();
    const recipSlots = kernel.listSlots().filter((m) => slotMetaKind(m) === "recipients");
    const slotHint = slotN
      ? ` · ${slotN} slot${slotN === 1 ? "" : "s"} in Variables`
      : "";
    if (!steps.length) {
      hint.textContent =
        recipSlots.length
          ? `Cell [${focusedCell}] empty — add input, or compose Encrypt to @${recipSlots[0].label} from Suggest.`
          : "Focused cell is empty — drag a source (genkey, hkp.search, input) or click to append." +
            slotHint;
    } else if (from.base === "shares" && from.kind === "raw") {
      hint.textContent = `Cell [${focusedCell}] tip ${fromType} — blip39 or recover.${slotHint}`;
    } else if (from.base === "shares") {
      hint.textContent = `Cell [${focusedCell}] tip ${fromType} — blip39 -d → recover, or foreach.${slotHint}`;
    } else if (from.base === "recipients") {
      hint.textContent = `Cell [${focusedCell}] tip recipients — compose Encrypt in a new cell (stem stays the message).${slotHint}`;
    } else {
      hint.textContent = `Cell [${focusedCell}] tip ${fromType} — highlighted ops fit the tip.${slotHint}`;
    }
  }

  host.innerHTML = toolboxes
    .map((tb) => {
      const meta = TOOLBOX_META[tb] || { label: tb };
      const collapsed = opsCollapsed.has(tb) && !q;
      const items = byToolbox.get(tb) || [];
      return `
        <div class="ops-category" data-toolbox="${escapeHtml(tb)}">
          <button type="button" class="ops-category-toggle" data-toggle-toolbox="${escapeHtml(tb)}"
            aria-expanded="${collapsed ? "false" : "true"}">
            <span class="ops-category-label">${glyphHtml(meta.glyph, "ops-glyph ops-glyph-toolbox")} ${toolboxBadgeHtml(tb)} ${escapeHtml(meta.label)} ${suiteChipHtml(tb)}</span>
            <span class="muted fs-xs">${items.length}</span>
          </button>
          <div class="ops-category-body ${collapsed ? "hidden" : ""}">
            ${renderToolboxOpsBody(tb, items, suggested, !!q)}
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

  host.querySelectorAll("[data-toggle-shelf]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const key = btn.getAttribute("data-toggle-shelf") || "";
      if (opsShelfCollapsed.has(key)) opsShelfCollapsed.delete(key);
      else opsShelfCollapsed.add(key);
      renderOpsDrawer();
    });
  });

  host.querySelectorAll("[data-op]").forEach((el) => {
    const name = el.getAttribute("data-op") || "";
    const decode = el.getAttribute("data-op-decode") === "1";
    const overrides = decode ? { decode: true } : undefined;
    el.addEventListener("dragstart", (e) => {
      if (stepBlockedByFips(name)) {
        e.preventDefault();
        return;
      }
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

  wireCipherKit(host);
  wireFormatKit(host);
  wireMacKit(host);
}

/**
 * Encrypt/Decrypt meta chips → cipher subset → concrete addStepAt.
 * @param {HTMLElement} host
 */
function wireCipherKit(host) {
  host.querySelectorAll("[data-cipher-meta]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const mode = btn.getAttribute("data-cipher-meta") || "encrypt";
      const decode = mode === "decrypt";
      formatPickerState = null;
      if (cipherPickerState && cipherPickerState.decode === decode) {
        cipherPickerState = null;
      } else {
        cipherPickerState = { decode };
      }
      renderOpsDrawer();
    });
  });

  host.querySelectorAll("[data-cipher-pick]").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      const name = el.getAttribute("data-cipher-pick") || "";
      if (stepBlockedByFips(name)) return;
      const decode = !!cipherPickerState?.decode;
      try {
        const pick = instantiateCipherPick(name, decode);
        cipherPickerState = null;
        addStepAt(pick.name, undefined, pick.params.decode ? { decode: true } : undefined);
        renderOpsDrawer();
      } catch (_) {
        /* ignore unknown */
      }
    });
  });
}

/**
 * @param {HTMLElement} host
 */
function wireFormatKit(host) {
  host.querySelectorAll("[data-format-meta]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const direction =
        btn.getAttribute("data-format-meta") === "import" ? "import" : "export";
      cipherPickerState = null;
      if (formatPickerState && formatPickerState.direction === direction) {
        formatPickerState = null;
      } else {
        formatPickerState = { direction };
      }
      renderOpsDrawer();
    });
  });

  host.querySelectorAll("[data-format-pick]").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      const fmt = el.getAttribute("data-format-pick") || "";
      const direction = formatPickerState?.direction || "export";
      try {
        const pick = instantiateFormatPick(direction, fmt);
        formatPickerState = null;
        addStepAt(pick.name, undefined, pick.params);
        renderOpsDrawer();
      } catch (_) {
        /* ignore */
      }
    });
  });
}

/**
 * @param {HTMLElement} host
 */
function wireMacKit(host) {
  host.querySelectorAll("[data-mac-meta]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const kind = btn.getAttribute("data-mac-meta") || "sign";
      const name = kind === "verify" ? "verify" : "sign";
      if (stepBlockedByFips(name)) return;
      addStepAt(name);
    });
  });
}

/**
 * @param {import("../lib/toolkit/recipe.js").RecipeStep} step
 * @param {*} val
 * @param {string} dataAttrs
 * @param {{ bodyIndex?: number, parentStem?: number }} nest
 * @param {number} i
 */
function encryptToParamHtml(step, val, dataAttrs, nest, i) {
  const raw = String(val || "");
  const token = parseEncryptToToken(raw);
  const errKey =
    nest.parentStem != null
      ? `${nest.parentStem}:${nest.bodyIndex}:to`
      : `${i}:to`;
  const err = lookupFieldErrors.get(errKey) || "";
  let stateClass = "";
  let statusHtml = "";
  if (token.kind === "email") {
    const fps = resolutionForQuery(token.query, recipientResolutions);
    if (err) {
      stateClass = "encrypt-to-failed";
      statusHtml = `<span class="encrypt-to-status text-error fs-xs">${escapeHtml(err)}</span>`;
    } else if (fps?.length) {
      stateClass = "encrypt-to-resolved";
      const stepRef =
        nest.parentStem != null
          ? `data-stem="${nest.parentStem}" data-body="${nest.bodyIndex}"`
          : `data-step="${i}"`;
      statusHtml = `<span class="encrypt-to-status encrypt-to-pill fs-xs">
        ${escapeHtml(resolutionPillText(fps))}
        <button type="button" class="btn btn-ghost btn-compact" data-to-change="1" ${stepRef}>Change…</button>
      </span>`;
    } else if (raw) {
      stateClass = "encrypt-to-unresolved";
      statusHtml = `<span class="encrypt-to-status muted fs-xs">Unresolved — look up</span>`;
    }
  } else if (token.kind === "slot" || token.kind === "fpr") {
    stateClass = "encrypt-to-bound";
  }
  const stepRef =
    nest.parentStem != null
      ? `data-stem="${nest.parentStem}" data-body="${nest.bodyIndex}"`
      : `data-step="${i}"`;
  return `<div class="builder-param builder-param-to ${stateClass}">
    <span class="builder-param-name">to</span>
    <div class="encrypt-to-row">
      <input class="text-input encrypt-to-input" ${dataAttrs}
             value="${escapeHtml(raw)}" type="text"
             placeholder="@slot, email, or fpr:…"
             autocomplete="off" spellcheck="false">
      <button type="button" class="btn btn-ghost btn-compact encrypt-to-lookup" ${stepRef}
              data-to-lookup="1" aria-label="Look up recipients" title="Look up recipients">
        ${lookupGlyphHtml()}
      </button>
    </div>
    ${statusHtml}
  </div>`;
}

/**
 * @param {HTMLElement} host
 */
function wireEncryptToControls(host) {
  const resolveTarget = (el) => {
    const stemAttr = el.getAttribute("data-stem");
    if (stemAttr != null) {
      const stem = Number(stemAttr);
      const body = Number(el.getAttribute("data-body"));
      return steps[stem]?.body?.[body] || null;
    }
    const i = Number(el.getAttribute("data-step"));
    return steps[i] || null;
  };
  const errKeyFor = (el) => {
    const stemAttr = el.getAttribute("data-stem");
    if (stemAttr != null) {
      return `${stemAttr}:${el.getAttribute("data-body")}:to`;
    }
    return `${el.getAttribute("data-step")}:to`;
  };

  host.querySelectorAll("[data-to-lookup], [data-to-change]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const target = resolveTarget(btn);
      if (!target || target.name !== "gpg.encrypt") return;
      const forceModal = btn.hasAttribute("data-to-change");
      if (forceModal) {
        const token = parseEncryptToToken(target.params?.to);
        if (token.kind === "email") {
          delete recipientResolutions[recipientResolutionKey(token.query)];
        }
      }
      await runEncryptToLookup(target, errKeyFor(btn), { forceModal });
    });
  });

  host.querySelectorAll(".encrypt-to-input").forEach((input) => {
    input.addEventListener("keydown", async (e) => {
      if (!(e instanceof KeyboardEvent)) return;
      if (e.key === "Enter" || (e.key === "k" && (e.ctrlKey || e.metaKey))) {
        e.preventDefault();
        const target = resolveTarget(input);
        if (!target) return;
        // Sync value first
        target.params.to = /** @type {HTMLInputElement} */ (input).value;
        setRecipeFromSteps();
        await runEncryptToLookup(target, errKeyFor(input));
      }
    });
  });
}

/**
 * @param {import("../lib/toolkit/recipe.js").RecipeStep} step
 * @param {string} errKey
 * @param {{ forceModal?: boolean }} [opts]
 */
async function runEncryptToLookup(step, errKey, opts = {}) {
  const raw = String(step.params?.to || "").trim();
  const token = parseEncryptToToken(raw);
  const policy = String(step.params?.policy || "ask").toLowerCase();

  if (token.kind === "empty") {
    lookupFieldErrors.set(errKey, "Enter an email or name first");
    renderBuilder();
    return;
  }
  if (token.kind === "slot" || token.kind === "fpr") {
    lookupFieldErrors.delete(errKey);
    renderBuilder();
    return;
  }
  if (token.kind !== "email") return;

  const query = token.query;
  try {
    const result = await lookupRecipientsForPolicy({ query, policy });
    if (result.status === "none" || result.status === "fail") {
      lookupFieldErrors.set(errKey, result.message || "Lookup failed");
      delete recipientResolutions[recipientResolutionKey(query)];
      renderBuilder();
      return;
    }
    if (
      !opts.forceModal &&
      result.status === "bound" &&
      result.fingerprints?.length
    ) {
      recipientResolutions[recipientResolutionKey(query)] = result.fingerprints;
      lookupFieldErrors.delete(errKey);
      renderBuilder();
      return;
    }
    // ask / all with 2+ (or Change…) → modal
    const picked = await openRecipientResolveModal({ query, policy });
    if (!picked?.fingerprints?.length) {
      lookupFieldErrors.set(errKey, "Select recipients to continue");
      renderBuilder();
      return;
    }
    recipientResolutions[recipientResolutionKey(query)] = picked.fingerprints;
    lookupFieldErrors.delete(errKey);
    renderBuilder();
  } catch (err) {
    lookupFieldErrors.set(
      errKey,
      err instanceof Error ? err.message : String(err)
    );
    renderBuilder();
  }
}

/**
 * Soft-block: unresolved email to= on encrypt steps.
 * @param {import("../lib/toolkit/recipe.js").RecipeAst} ast
 * @returns {{ ok: boolean, message?: string }}
 */
function checkEncryptToResolutions(ast) {
  const walk = (list) => {
    for (const step of list || []) {
      if (step.name === "gpg.encrypt") {
        const token = parseEncryptToToken(step.params?.to);
        if (token.kind === "email") {
          const fps = resolutionForQuery(token.query, recipientResolutions);
          if (!fps?.length) {
            return {
              ok: false,
              message: `Look up recipients for to=${token.query} before running`,
            };
          }
        }
      }
      if (step.body?.length) {
        const inner = walk(step.body);
        if (!inner.ok) return inner;
      }
      for (const br of step.branches || []) {
        const inner = walk(br.body);
        if (!inner.ok) return inner;
      }
    }
    return { ok: true };
  };
  for (const chain of recipeChains(ast)) {
    const r = walk(chain.steps);
    if (!r.ok) return r;
  }
  return { ok: true };
}

function renderAgentChrome() {
  const host = document.getElementById("agent-session-host");
  if (host) {
    const unlocked = sessionList();
    if (!unlocked.length) {
      host.innerHTML = "";
      if (agentStripTimer) {
        clearInterval(agentStripTimer);
        agentStripTimer = null;
      }
    } else {
      const paint = () => {
        const list = sessionList();
        if (!list.length) {
          host.innerHTML = "";
          if (agentStripTimer) {
            clearInterval(agentStripTimer);
            agentStripTimer = null;
          }
          return;
        }
        const earliest = sessionEarliestExpiry();
        const msLeft = earliest ? Math.max(0, earliest - Date.now()) : 0;
        const mins = Math.floor(msLeft / 60000);
        const secs = Math.floor((msLeft % 60000) / 1000);
        const ttl = `${mins}m ${String(secs).padStart(2, "0")}s`;
        host.innerHTML = `
          <div class="agent-session-strip" role="status">
            <span>Unlocked: <strong>${list.length}</strong> · clears in ${escapeHtml(ttl)}</span>
            <div class="btn-row wrap">
              ${list
                .map(
                  (e) =>
                    `<button type="button" class="btn btn-ghost btn-compact" data-agent-lock="${escapeHtml(e.fingerprint)}" title="${escapeHtml(formatFingerprint(e.fingerprint))}">Lock …${escapeHtml(e.fingerprint.slice(-8))}</button>`
                )
                .join("")}
              <button type="button" class="btn btn-compact" data-agent-lock-all
                title="Clear agent session, private @slots, and cell outputs">Lock all</button>
            </div>
          </div>`;
        host.querySelector("[data-agent-lock-all]")?.addEventListener("click", () => {
          lockAllAgentMaterial();
        });
        host.querySelectorAll("[data-agent-lock]").forEach((btn) => {
          btn.addEventListener("click", () => {
            sessionEvict(btn.getAttribute("data-agent-lock") || "");
            renderAgentChrome();
          });
        });
        updateKernelChip();
      };
      paint();
      if (!agentStripTimer) {
        agentStripTimer = setInterval(paint, 1000);
      }
    }
  }

  const body = document.getElementById("keyring-body");
  if (!body) return;
  if (!vaultKeys.length) {
    body.innerHTML = `<p class="muted fs-sm mb-0">No keys in My Keys yet. Generate one or use <code>agent.save</code>.</p>`;
    return;
  }
  body.innerHTML = `
    <ul class="keyring-list">
      ${vaultKeys
        .map((k) => {
          const fpr = k.fingerprint || "";
          const unlocked = sessionList().some((e) => e.fingerprint === fpr);
          const slotHint = unusedOutSlotName("@me", fpr);
          return `<li class="keyring-item">
            <div class="keyring-meta">
              <strong>${escapeHtml(k.uid || k.email || "Key")}</strong>
              <a class="text-link mono fs-xs" href="/key?fpr=${escapeHtml(fpr)}" target="_blank" rel="noopener">${escapeHtml(formatFingerprint(fpr))}</a>
              <span class="muted fs-xs">${escapeHtml(k.protection || "device")}${unlocked ? " · unlocked" : ""}</span>
            </div>
            <div class="keyring-actions">
              ${
                unlocked
                  ? `<button type="button" class="btn btn-ghost btn-compact btn-icon" data-kr-lock="${escapeHtml(fpr)}"
                      title="Lock session — clear this key from the agent cache"
                      aria-label="Lock session">${glyphHtml("lock", "ops-glyph")}</button>`
                  : `<button type="button" class="btn btn-ghost btn-compact btn-icon" data-kr-unlock="${escapeHtml(fpr)}"
                      title="Unlock into session — cache the private key for decrypt/sign without a recipe step"
                      aria-label="Unlock into session">${glyphHtml("unlock", "ops-glyph")}</button>`
              }
              <button type="button" class="btn btn-ghost btn-compact btn-icon" data-kr-insert="${escapeHtml(fpr)}"
                title="Add notebook cell: agent.unlock … | out ${slotHint}"
                aria-label="Add unlock cell to ${slotHint}">${glyphHtml("unlock", "ops-glyph")} <span class="fs-xs">→ ${escapeHtml(slotHint)}</span></button>
              <button type="button" class="btn btn-ghost btn-compact btn-icon" data-kr-copy="${escapeHtml(fpr)}"
                title="Copy fingerprint"
                aria-label="Copy fingerprint">${glyphHtml("fingerprint", "ops-glyph")}</button>
              <button type="button" class="btn btn-ghost btn-compact btn-icon" data-kr-pub="${escapeHtml(fpr)}"
                title="Add notebook cell: agent.pub … | out @… (public only, no unlock)"
                aria-label="Add public key cell">Pub→slot</button>
            </div>
          </li>`;
        })
        .join("")}
    </ul>`;

  body.querySelectorAll("[data-kr-unlock]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const fpr = btn.getAttribute("data-kr-unlock") || "";
      try {
        await unlockVaultForUse(fpr, {
          openPgpPassphrase: "",
          skipSession: getToolkitPrefs().sessionOff,
        });
        renderAgentChrome();
        touchActivity();
      } catch (err) {
        showError(errorEl, err?.message || "Unlock failed");
      }
    });
  });
  body.querySelectorAll("[data-kr-lock]").forEach((btn) => {
    btn.addEventListener("click", () => {
      sessionEvict(btn.getAttribute("data-kr-lock") || "");
      renderAgentChrome();
    });
  });
  body.querySelectorAll("[data-kr-insert]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const fpr = btn.getAttribute("data-kr-insert") || "";
      const slot = unusedOutSlotName("@me", fpr);
      addVaultSourceCell("agent.unlock", fpr, slot);
    });
  });
  body.querySelectorAll("[data-kr-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      void copyTextTransient(btn.getAttribute("data-kr-copy") || "");
    });
  });
  body.querySelectorAll("[data-kr-pub]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const fpr = btn.getAttribute("data-kr-pub") || "";
      const short = `@${(fpr.slice(-8) || "pub").toLowerCase()}`;
      addVaultSourceCell("agent.pub", fpr, short);
    });
  });
}

/**
 * Collect `out` slot names already used across notebook cells.
 * @returns {Set<string>}
 */
function usedOutSlotNames() {
  /** @type {Set<string>} */
  const used = new Set();
  for (const c of chains) {
    for (const s of c.steps || []) {
      if (s.name !== "out") continue;
      const n = String(s.params?.name || "").trim();
      if (!n) continue;
      used.add(n.startsWith("@") ? n : `@${n}`);
    }
  }
  return used;
}

/**
 * Prefer preferred slot (`@me`); fall back to `@` + last 8 of fpr.
 * @param {string} preferred
 * @param {string} fpr
 * @returns {string}
 */
function unusedOutSlotName(preferred, fpr) {
  const used = usedOutSlotNames();
  const pref = preferred.startsWith("@") ? preferred : `@${preferred}`;
  if (!used.has(pref)) return pref;
  const short = `@${String(fpr || "key")
    .replace(/[^0-9A-Fa-f]/g, "")
    .slice(-8)
    .toLowerCase() || "key"}`;
  if (!used.has(short)) return short;
  let i = 2;
  while (used.has(`${short}${i}`)) i += 1;
  return `${short}${i}`;
}

/**
 * Append (or fill empty focused cell with) `source fpr | out @slot`.
 * Avoids splicing a source into the middle of an existing pipeline.
 * @param {"agent.unlock"|"agent.pub"} stepName
 * @param {string} fpr
 * @param {string} outName
 */
function addVaultSourceCell(stepName, fpr, outName) {
  const sourceSpec = getStep(stepName);
  const outSpec = getStep("out");
  if (!sourceSpec || !outSpec) return;
  const chain = {
    steps: [
      {
        name: stepName,
        params: { ...defaultParams(sourceSpec), fpr },
        start: 0,
        end: 0,
      },
      {
        name: "out",
        params: {
          ...defaultParams(outSpec),
          name: outName.startsWith("@") ? outName : `@${outName}`,
        },
        start: 0,
        end: 0,
      },
    ],
  };
  chains[focusedCell] = { steps };
  const emptyFocus =
    chains.length === 1 &&
    focusedCell === 0 &&
    !(chains[0].steps?.length);
  if (emptyFocus) {
    chains = [chain];
    focusedCell = 0;
  } else {
    chains = [...chains, chain];
    focusedCell = chains.length - 1;
  }
  steps = chains[focusedCell].steps;
  setRecipeFromSteps();
}

/**
 * One-line summary for a collapsed cell.
 * @param {import("../lib/toolkit/recipe.js").RecipeStep[]} cellSteps
 */
function cellSummary(cellSteps) {
  if (!cellSteps?.length) return "(empty)";
  const names = cellSteps.map((s) => s.name);
  const outs = cellSteps
    .filter((s) => s.name === "out")
    .map((s) => String(s.params?.name || "@out"));
  const head = names.slice(0, 4).join(" → ");
  const more = names.length > 4 ? "…" : "";
  const out = outs.length ? ` → ${outs.join(", ")}` : "";
  return `${head}${more}${out}`;
}

function renderNotebook() {
  const host = document.getElementById("notebook-cells");
  if (!host) return;

  const modeHost = document.getElementById("pgp-mode-host");
  if (modeHost) {
    const anyPgp = chains.some((c) =>
      (c.steps || []).some(
        (s) =>
          s.name === "gpg.encrypt" ||
          s.name === "gpg.symencrypt" ||
          s.name === "gpg.decrypt"
      )
    );
    if (anyPgp) {
      modeHost.classList.remove("hidden");
      modeHost.innerHTML = renderPgpModeToggle("toolkit-pgp-mode-recipe", {
        advancedLink: true,
      });
      wirePgpModeToggles(modeHost);
      modeHost.querySelector("#pgp-advanced-link")?.addEventListener("click", () => {
        openCryptoParamsPanel();
      });
    } else {
      modeHost.classList.add("hidden");
      modeHost.innerHTML = "";
    }
  }

  if (!chains.length) chains = [{ steps: [] }];
  destroyCellBinders();
  const savedFocus = focusedCell;
  /** @type {string[]} */
  const parts = [];
  chains.forEach((chain, i) => {
    if (i > 0) {
      parts.push(`
        <div class="notebook-cell-gutter" aria-hidden="false">
          <button type="button" class="notebook-insert-btn" data-insert-at="${i}" title="Insert cell here">+</button>
        </div>`);
    }
    const status = kernel.getCellStatus(i);
    const collapsed = cellCollapsed.has(i);
    const focused = i === savedFocus;
    const nSteps = (chain.steps || []).length;
    const needBadges = cellNeedBadges(chain)
      .map(
        (b) =>
          `<span class="cell-need-badge" title="${escapeHtml(b)}">${escapeHtml(b)}</span>`
      )
      .join("");
    const statusTitle =
      status === "stale"
        ? "Upstream changed — re-run this cell"
        : status === "ok"
          ? "Last run succeeded"
          : status === "error"
            ? "Last run failed"
            : status === "running"
              ? "Running…"
              : "Not run yet";
    parts.push(`
      <article class="notebook-cell ${focused ? "notebook-cell-focused" : ""} ${status === "stale" ? "notebook-cell-stale" : ""} ${collapsed ? "notebook-cell-collapsed" : ""}"
        data-cell="${i}" tabindex="0">
        <header class="notebook-cell-chrome">
          <span class="cell-drag" draggable="true" data-cell-drag="${i}" title="Drag to reorder">⠿</span>
          <button type="button" class="btn btn-ghost btn-compact cell-focus-btn" data-focus-cell="${i}" title="Focus cell">[${i}]</button>
          <span class="cell-status cell-status-${escapeHtml(status)}" title="${escapeHtml(statusTitle)}">${escapeHtml(status)}</span>
          ${needBadges}
          <span class="cell-summary muted fs-xs ${collapsed ? "" : "hidden"}">${escapeHtml(cellSummary(chain.steps || []))}</span>
          <div class="btn-row wrap cell-chrome-actions">
            <button type="button" class="btn btn-compact" data-run-cell="${i}" ${!nSteps ? "disabled" : ""}>Run</button>
            <button type="button" class="btn btn-ghost btn-compact" data-run-from="${i}" title="Run this cell and all below">From here</button>
            <button type="button" class="btn btn-ghost btn-compact" data-toggle-cell="${i}" title="${collapsed ? "Expand" : "Collapse"}">${collapsed ? "Expand" : "▾"}</button>
            <button type="button" class="btn btn-ghost btn-compact" data-add-below="${i}" title="Add cell below">+</button>
            <button type="button" class="btn btn-ghost btn-compact text-error" data-del-cell="${i}" ${chains.length <= 1 ? "disabled" : ""} title="Delete cell">✕</button>
          </div>
        </header>
        <div class="notebook-cell-body ${collapsed ? "hidden" : ""}">
          <div class="cell-inputs" id="cell-inputs-${i}" data-cell="${i}" hidden></div>
          <div class="cell-bind" id="cell-bind-${i}" data-cell="${i}"></div>
          <div class="builder-steps cell-builder builder-spine" id="cell-builder-${i}" data-cell="${i}"></div>
          ${
            focused
              ? `<div id="suggest-next" class="suggest-next suggest-next-cell" hidden></div>`
              : ""
          }
        </div>
        <div class="cell-output" id="cell-output-${i}" data-cell="${i}"></div>
      </article>`);
  });
  host.innerHTML = parts.join("");

  for (let i = 0; i < chains.length; i++) {
    focusCell(i);
    const builderHost = document.getElementById(`cell-builder-${i}`);
    if (builderHost) renderBuilderInto(builderHost, i);
    renderCellOutputs(i);
  }
  focusCell(savedFocus);
  renderAllCellRuntimePanels();
  applyRunReadiness();
  renderSuggestDrawer();

  host.querySelectorAll("[data-focus-cell]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      focusCell(Number(btn.getAttribute("data-focus-cell")));
      renderNotebook();
      renderSuggestDrawer();
      renderOpsDrawer();
    });
  });
  host.querySelectorAll(".notebook-cell").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (
        e.target instanceof HTMLElement &&
        (e.target.closest("button") ||
          e.target.closest("input") ||
          e.target.closest("select") ||
          e.target.closest("textarea"))
      ) {
        return;
      }
      const i = Number(el.getAttribute("data-cell"));
      if (i !== focusedCell) {
        focusCell(i);
        renderNotebook();
        renderSuggestDrawer();
        renderOpsDrawer();
      }
    });
  });
  host.querySelectorAll("[data-run-cell]").forEach((btn) => {
    btn.addEventListener("click", () => {
      void runNotebookCell(Number(btn.getAttribute("data-run-cell")));
    });
  });
  host.querySelectorAll("[data-run-from]").forEach((btn) => {
    btn.addEventListener("click", () => {
      void runNotebookFrom(Number(btn.getAttribute("data-run-from")));
    });
  });
  host.querySelectorAll("[data-toggle-cell]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-toggle-cell"));
      if (cellCollapsed.has(i)) cellCollapsed.delete(i);
      else cellCollapsed.add(i);
      renderNotebook();
    });
  });
  host.querySelectorAll("[data-add-below]").forEach((btn) => {
    btn.addEventListener("click", () => {
      insertCell(Number(btn.getAttribute("data-add-below")) + 1);
    });
  });
  host.querySelectorAll("[data-insert-at]").forEach((btn) => {
    btn.addEventListener("click", () => {
      insertCell(Number(btn.getAttribute("data-insert-at")));
    });
  });
  host.querySelectorAll("[data-del-cell]").forEach((btn) => {
    btn.addEventListener("click", () => {
      deleteCell(Number(btn.getAttribute("data-del-cell")));
    });
  });

  /** Cell drag-reorder */
  host.querySelectorAll("[data-cell-drag]").forEach((handle) => {
    handle.addEventListener("dragstart", (e) => {
      const i = Number(handle.getAttribute("data-cell-drag"));
      e.dataTransfer?.setData("text/cell-index", String(i));
      e.dataTransfer?.setData("text/plain", `cell:${i}`);
      if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
      handle.closest(".notebook-cell")?.classList.add("notebook-cell-dragging");
    });
    handle.addEventListener("dragend", () => {
      host
        .querySelectorAll(".notebook-cell-dragging, .notebook-cell-drop-target")
        .forEach((el) => {
          el.classList.remove("notebook-cell-dragging", "notebook-cell-drop-target");
        });
    });
  });
  host.querySelectorAll(".notebook-cell").forEach((el) => {
    el.addEventListener("dragover", (e) => {
      if (![...(e.dataTransfer?.types || [])].includes("text/cell-index")) return;
      e.preventDefault();
      el.classList.add("notebook-cell-drop-target");
    });
    el.addEventListener("dragleave", () => {
      el.classList.remove("notebook-cell-drop-target");
    });
    el.addEventListener("drop", (e) => {
      el.classList.remove("notebook-cell-drop-target");
      const raw = e.dataTransfer?.getData("text/cell-index");
      if (raw == null || raw === "") return;
      e.preventDefault();
      const from = Number(raw);
      const to = Number(el.getAttribute("data-cell"));
      if (Number.isFinite(from) && Number.isFinite(to) && from !== to) {
        moveCell(from, to);
      }
    });
  });

  updateKernelChip();
  updateStaleBanner();
}

/** @deprecated use renderNotebook — kept as alias for stray callers */
function renderBuilder() {
  renderNotebook();
}

/**
 * @param {HTMLElement} host
 * @param {number} cellIndex
 */
function renderBuilderInto(host, cellIndex) {
  if (!host) return;
  void cellIndex;

  if (!steps.length) {
    host.innerHTML = `
      <div class="builder-dropzone builder-empty" data-insert="0" data-cell="${cellIndex}">
        <p class="muted mb-0">Drop an operation here to start this cell</p>
        <p class="muted fs-xs mb-0">Sources like <code>genkey</code>, <code>hkp.search</code>, or <code>input</code>.</p>
      </div>`;
    wireDropZones(host);
    return;
  }

  /** @type {string[]} */
  const parts = [];
  const typeEdges = builderTypeEdges();
  parts.push(
    `<div class="builder-dropzone" data-insert="0" data-cell="${cellIndex}" aria-label="Insert at start"></div>`
  );

  /**
   * @param {import("../lib/toolkit/recipe.js").RecipeStep} step
   * @param {number} i
   * @param {{ bodyIndex?: number, parentStem?: number }} [nest]
   */
  const renderOneCard = (step, i, nest = {}) => {
    syncWhichWithFormat(step);
    const spec = getStep(step.name);
    const inFlatForeach = false;

    const edge =
      nest.parentStem != null
        ? typeEdges[nest.parentStem]?.body?.[nest.bodyIndex ?? -1]
        : typeEdges[i];
    const inType = edge ? formatType(edge.input) : "—";
    const outType = edge?.output ? formatType(edge.output) : edge?.error ? "∅" : "—";
    const typeTitle = edge?.error ? edge.error : `${inType} → ${outType}`;

    const stepAttr =
      nest.parentStem != null
        ? `data-stem="${nest.parentStem}" data-body="${nest.bodyIndex}"`
        : `data-step="${i}"`;
    const focusStem = nest.parentStem != null ? nest.parentStem : i;
    const focusBody = nest.bodyIndex;
    const focused =
      insertFocus &&
      insertFocus.stem === focusStem &&
      (focusBody == null
        ? insertFocus.body == null &&
          (step.name === "tee" || step.name === "foreach")
        : insertFocus.body === focusBody);

    const paramFields = (spec?.params || [])
      .map((p) => {
        const vis = paramVisibility(step.name, p, step.params || {});
        if (!vis.show) return "";
        const val =
          vis.forced != null
            ? vis.forced
            : step.params[p.name] ?? p.default ?? "";
        const title = p.doc ? ` title="${escapeHtml(p.doc)}"` : "";
        const dataAttrs =
          nest.parentStem != null
            ? `data-stem="${nest.parentStem}" data-body="${nest.bodyIndex}" data-param="${escapeHtml(p.name)}"`
            : `data-step="${i}" data-param="${escapeHtml(p.name)}"`;
        if (p.type === "bool") {
          const checked = val === true || val === "true";
          return `<label class="builder-param builder-param-bool"${title}>
            <span class="builder-param-name">${escapeHtml(p.name)}${p.flag ? ` <code>${escapeHtml(p.flag)}</code>` : ""}</span>
            <input type="checkbox" ${dataAttrs}
              ${checked ? "checked" : ""}></label>`;
        }
        if (p.type === "enum") {
          const locked = !!vis.locked;
          return `<label class="builder-param"${title}>
            <span class="builder-param-name">${escapeHtml(p.name)}</span>
            <select ${dataAttrs} class="text-input"
              ${locked ? "disabled" : ""}>
              ${(p.enum || [])
                .map(
                  (e) =>
                    `<option value="${escapeHtml(e)}" ${String(val) === e ? "selected" : ""}>${escapeHtml(e)}</option>`
                )
                .join("")}
            </select>${locked ? `<span class="muted fs-xs">locked by format</span>` : ""}</label>`;
        }
        if (step.name === "gpg.encrypt" && p.name === "to") {
          return encryptToParamHtml(step, val, dataAttrs, nest, i);
        }
        if (
          (step.name === "hkp.search" || step.name === "hkp.get") &&
          p.name === "keyserver"
        ) {
          const select = keyserverSelectFromOptionsHtml({
            options: keyserverOptionsCache,
            selected: String(val ?? ""),
            dataAttrs,
          });
          return `<label class="builder-param"${title}>
            <span class="builder-param-name">${escapeHtml(p.name)}</span>
            ${select}</label>`;
        }
        return `<label class="builder-param"${title}>
          <span class="builder-param-name">${escapeHtml(p.name)}</span>
          <input class="text-input" ${dataAttrs}
                 value="${escapeHtml(String(val))}" ${p.type === "int" ? 'type="number"' : 'type="text"'}></label>`;
      })
      .join("");

    const needsVaultFprPick =
      (step.name === "agent.unlock" || step.name === "agent.pub") &&
      !String(step.params?.fpr || "").trim() &&
      vaultKeys.length;
    const vaultFprPick = needsVaultFprPick
      ? `<label class="builder-param" title="Write fingerprint into this step">
          <span class="builder-param-name">vault key</span>
          <select class="text-input" ${
            nest.parentStem != null
              ? `data-stem="${nest.parentStem}" data-body="${nest.bodyIndex}" data-vault-fpr="1"`
              : `data-step="${i}" data-vault-fpr="1"`
          }>
            <option value="">— pick My Keys fingerprint —</option>
            ${vaultKeys
              .map(
                (k) =>
                  `<option value="${escapeHtml(k.fingerprint)}">${escapeHtml(
                    formatFingerprint(k.fingerprint)
                  )}${k.email ? ` · ${escapeHtml(k.email)}` : ""}</option>`
              )
              .join("")}
          </select>
        </label>`
      : "";

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

    const typeHint =
      edge?.output?.base === "shares" && edge.output.kind === "raw"
        ? `<p class="builder-type-hint muted fs-xs mb-sm">Next usually <code>blip39</code> → mnemonics, or <code>recover</code> → <code>bytes/master</code>.</p>`
        : edge?.output?.base === "shares"
          ? `<p class="builder-type-hint muted fs-xs mb-sm">Next usually <code>foreach</code> (list body), <code>at N</code>, or <code>blip39 -d</code> → <code>recover</code>.</p>`
          : step.name === "sss.combine"
            ? `<p class="builder-type-hint muted fs-xs mb-sm">Combines raw SSS shares into <code>bytes/master</code>. Decode mnemonics with <code>blip39 -d</code> first.</p>`
            : step.name === "sss.split"
              ? `<p class="builder-type-hint muted fs-xs mb-sm">Produces <code>shares/raw</code>. Pipe into <code>blip39</code> for word phrases.</p>`
              : step.name === "foreach"
                ? `<p class="builder-type-hint muted fs-xs mb-sm">Add child steps as an indented list (<code>- out @share</code>) or brace body. Optional <code>foreach .items</code>.</p>`
                : step.name === "tee"
                  ? `<p class="builder-type-hint muted fs-xs mb-sm">Body runs on a copy; use <code>- .public | …</code> for selector branches. Stem unchanged. Use <code>peek</code> for a side inspect.</p>`
                  : "";

    const blocked = stepBlockedByFips(step.name);
    const nestClass =
      nest.bodyIndex != null
        ? "builder-foreach-child builder-nest-child"
        : inFlatForeach
          ? "builder-foreach-child"
          : "";

    return `
      <div class="builder-card ${nestClass} ${step.name === "foreach" ? "builder-foreach" : ""} ${step.name === "tee" && step.body?.length ? "builder-tee" : ""} ${isOut ? "builder-out" : ""} ${isText ? "builder-text" : ""} ${usesPgpProfile ? "builder-pgp" : ""} ${edge && !edge.ok ? "builder-type-error" : ""} ${blocked ? "builder-fips-blocked" : ""} ${focused ? "builder-card-focused" : ""}"
           draggable="${nest.bodyIndex == null ? "true" : "false"}" data-index="${i}" data-step-card="${i}"
           data-focus-stem="${focusStem}" ${focusBody != null ? `data-focus-body="${focusBody}"` : ""}>
        <div class="builder-card-head">
          <span class="builder-drag" title="Drag to reorder">⠿</span>
          <span class="builder-step-num" aria-hidden="true">${
            nest.bodyIndex != null ? `${focusStem + 1}.${focusBody + 1}` : i + 1
          }</span>
          <strong title="${escapeHtml(spec?.doc || "")}">${escapeHtml(stepDisplayName(spec) || step.name)}</strong>
          ${toolboxBadgeHtml(spec?.toolbox)}
          ${suiteChipHtml(spec?.toolbox)}
          <code class="builder-type-chip" title="${escapeHtml(typeTitle)}">${escapeHtml(inType)} → ${escapeHtml(outType)}</code>
          ${
            isOut
              ? `<span class="badge pending" title="Named file — Encrypt attaches bytes">file</span>`
              : isText
                ? `<span class="badge pending" title="Message tile">message</span>`
                : ""
          }
          ${outSummary ? `<span class="muted fs-xs">${escapeHtml(outSummary)}</span>` : ""}
          <button type="button" class="btn btn-ghost btn-compact text-error" data-remove-stem="${focusStem}" ${
            focusBody != null ? `data-remove-body="${focusBody}"` : ""
          }>Remove</button>
        </div>
        ${
          usesPgpProfile
            ? ""
            : `<p class="muted mt-xs mb-sm fs-xs builder-card-doc" title="${escapeHtml(spec?.doc || "")}">${escapeHtml(spec?.doc || "")}</p>`
        }
        ${typeHint}
        <div class="builder-params">${paramFields}${vaultFprPick}</div>
      </div>`;
  };

  steps.forEach((step, i) => {
    parts.push(renderOneCard(step, i));
    if (
      (step.name === "tee" || step.name === "foreach") &&
      (step.body?.length ||
        step.branches?.length ||
        (insertFocus?.stem === i && insertFocus.body == null))
    ) {
      if (!step.body) step.body = [];
      parts.push(`<div class="builder-nest" data-nest-stem="${i}">`);
      parts.push(
        `<p class="builder-nest-label muted fs-xs">${
          step.name === "tee" ? "tee body (side chain)" : "foreach body (per share)"
        }</p>`
      );
      step.body.forEach((b, bi) => {
        parts.push(renderOneCard(b, i, { bodyIndex: bi, parentStem: i }));
      });
      for (const br of step.branches || []) {
        const sel = br.selector || `.${br.member}`;
        const chain = (br.body || []).map((s) => s.name).join(" | ");
        parts.push(`
          <div class="builder-tee-branch" title="Selector branch">
            <code class="fs-xs">${escapeHtml(sel)}</code>
            <span class="muted fs-xs">|</span>
            <code class="fs-xs">${escapeHtml(chain)}</code>
          </div>`);
      }
      parts.push(
        `<div class="builder-dropzone builder-nest-drop" data-body-insert-stem="${i}" aria-label="Add step to ${escapeHtml(step.name)} body"></div>`
      );
      parts.push(`</div>`);
    }
    parts.push(
      `<div class="builder-dropzone" data-insert="${i + 1}" aria-label="Insert after ${escapeHtml(step.name)}"></div>`
    );
  });

  for (let ci = 1; ci < chains.length; ci++) {
    const chainText = serializeRecipe({ chains: [chains[ci]] });
    parts.push(`
      <div class="builder-chain-sep muted fs-xs" role="separator">
        Chain ${ci + 1} (edit in recipe text)
      </div>
      <pre class="builder-chain-preview fs-xs">${escapeHtml(chainText)}</pre>`);
  }

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
  wireEncryptToControls(host);

  host.querySelectorAll("[data-vault-fpr]").forEach((el) => {
    el.addEventListener("change", () => {
      if (!(el instanceof HTMLSelectElement) || !el.value) return;
      const stemAttr = el.getAttribute("data-stem");
      /** @type {import("../lib/toolkit/recipe.js").RecipeStep|undefined} */
      let target;
      if (stemAttr != null) {
        const stem = Number(stemAttr);
        const body = Number(el.getAttribute("data-body"));
        target = steps[stem]?.body?.[body];
      } else {
        const i = Number(el.getAttribute("data-step"));
        target = steps[i];
      }
      if (!target) return;
      target.params.fpr = el.value;
      setRecipeFromSteps();
      renderBuilder();
      validateAndBind();
    });
  });

  host.querySelectorAll("[data-param]").forEach((el) => {
    el.addEventListener("change", () => {
      const name = el.getAttribute("data-param");
      if (!name) return;
      const stemAttr = el.getAttribute("data-stem");
      /** @type {import("../lib/toolkit/recipe.js").RecipeStep|undefined} */
      let target;
      if (stemAttr != null) {
        const stem = Number(stemAttr);
        const body = Number(el.getAttribute("data-body"));
        target = steps[stem]?.body?.[body];
      } else {
        const i = Number(el.getAttribute("data-step"));
        target = steps[i];
      }
      if (!target) return;
      const spec = getStep(target.name);
      const p = (spec?.params || []).find((x) => x.name === name);
      if (el instanceof HTMLInputElement && el.type === "checkbox") {
        target.params[name] = el.checked;
      } else {
        const v =
          el instanceof HTMLInputElement || el instanceof HTMLSelectElement
            ? el.value
            : "";
        target.params[name] = p?.type === "int" ? Number(v) : v;
      }
      if (name === "format") syncWhichWithFormat(target);
      setRecipeFromSteps();
    });
  });

  host.querySelectorAll("[data-focus-stem]").forEach((card) => {
    card.addEventListener("click", (e) => {
      if (
        e.target instanceof HTMLElement &&
        (e.target.closest("button") ||
          e.target.closest("input") ||
          e.target.closest("select") ||
          e.target.closest("label"))
      ) {
        return;
      }
      const stem = Number(card.getAttribute("data-focus-stem"));
      const bodyAttr = card.getAttribute("data-focus-body");
      insertFocus =
        bodyAttr != null
          ? { stem, body: Number(bodyAttr) }
          : { stem, body: null };
      renderBuilder();
      renderSuggestDrawer();
    });
  });

  host.querySelectorAll("[data-body-insert-stem]").forEach((zone) => {
    zone.addEventListener("click", () => {
      const stem = Number(zone.getAttribute("data-body-insert-stem"));
      insertFocus = { stem, body: null };
      renderSuggestDrawer();
      renderBuilder();
    });
  });

  host.querySelector("#add-inspect-btn")?.addEventListener("click", () => {
    addStepAt("inspect");
  });
  host.querySelector("#add-recover-btn")?.addEventListener("click", () => {
    addStepAt("sss.combine");
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

  host.querySelectorAll("[data-remove-stem]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const stem = Number(btn.getAttribute("data-remove-stem"));
      const bodyAttr = btn.getAttribute("data-remove-body");
      if (bodyAttr != null) {
        const body = Number(bodyAttr);
        steps[stem]?.body?.splice(body, 1);
      } else {
        steps.splice(stem, 1);
      }
      insertFocus = null;
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
    (step) => step.name === "sss.split" || step.name === "blip39" || step.name === "sss.combine"
  );
  const usesSymEnvelope = steps.some(
    (step) => step.name === "gpg.symencrypt" || step.name === "gpg.symdecrypt"
  );
  const usesOpenPgp = steps.some(
    (step) =>
      step.name === "gpg.encrypt" ||
      step.name === "gpg.sign" ||
      step.name === "gpg.verify" ||
      step.name === "gpg.genkey" ||
      step.name === "gpg.inspect" ||
      step.name === "gpg.symencrypt" ||
      step.name === "gpg.symdecrypt"
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
          <div><dt>No auto-envelope</dt><dd>PEM / PKCS#8 / larger payloads must use <code>gpg.symencrypt</code> first — sss never invents a custom ciphertext</dd></div>
        </dl>
      </details>

      <details class="expert-crypto-section" ${usesSymEnvelope ? "open" : ""}>
        <summary><strong>OpenPGP symmetric envelope</strong>${usesSymEnvelope ? "" : ' <span class="muted">(no gpg.symencrypt/gpg.symdecrypt)</span>'}</summary>
        <dl class="crypto-param-list fs-sm">
          <div><dt>When</dt><dd>PEM, PKCS#8 DER, or any payload that is not already 16/32 bytes</dd></div>
          <div><dt>Master</dt><dd>32-byte CSPRNG secret — this is what <code>sss.split</code> splits; passphrase for stock gpg is lowercase hex of that master</dd></div>
          <div><dt>Ciphertext</dt><dd>Standard OpenPGP SKESK + SEIPD (<code>envelope.asc</code>) — profile below; no custom AES-GCM padding</dd></div>
          <div><dt>External recovery</dt><dd><code>blip39 -d | sss.combine</code> → hex master → <code>gpg --decrypt envelope.asc</code></dd></div>
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
        <summary><strong>OpenPGP wrapping</strong>${usesOpenPgp ? "" : ' <span class="muted">(no encrypt / gpg.symencrypt step)</span>'}</summary>
        <p class="muted fs-xs mt-sm mb-0">Mode is set in the notebook header (Modern / Compatible / Auto). Override cipher, AEAD, and S2K below.</p>
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
          <label class="builder-param">S2K (passphrase / gpg.symencrypt)
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
      const cellAttr =
        zone.getAttribute("data-cell") ||
        host.getAttribute("data-cell") ||
        host.closest?.("[data-cell]")?.getAttribute("data-cell");
      if (cellAttr != null && cellAttr !== "") {
        focusCell(Number(cellAttr));
      }
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
    const sa = getShelfMeta(a.shelf).order;
    const sb = getShelfMeta(b.shelf).order;
    return ta - tb || sa - sb || a.name.localeCompare(b.name);
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
      const shelfNote = s.shelf
        ? `<p class="muted fs-xs">Shelf: ${escapeHtml(getShelfMeta(s.shelf).label)}</p>`
        : "";
      return `<details class="ref-step">
        <summary>${toolboxBadgeHtml(s.toolbox)} <code>${escapeHtml(s.name)}</code>
          <span class="muted">${escapeHtml(s.kind)}</span>
          · ${escapeHtml(s.input)} → ${escapeHtml(s.output)}</summary>
        <p class="fs-md">${escapeHtml(s.doc)}</p>
        ${labelNote}
        ${shelfNote}
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
/**
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 * @returns {boolean}
 */
function artifactHasLiveInspect(a) {
  return !!(a?.inspectSnapshot && (a.role === "inspect" || a.inspectFormat));
}

/**
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 * @param {number} i
 * @returns {string}
 */
function inspectFormatSelectHtml(a, i) {
  if (!artifactHasLiveInspect(a)) return "";
  const current = String(a.inspectFormat || "auto");
  const options = INSPECT_FORMATS.map(
    (f) =>
      `<option value="${escapeHtml(f)}"${f === current ? " selected" : ""}>${escapeHtml(f)}</option>`
  ).join("");
  return `
    <label class="artifact-inspect-format" title="Change dump format without re-running the recipe">
      <span class="muted fs-xs">Format</span>
      <select class="artifact-inspect-select" data-inspect-format="${i}" aria-label="Inspect format">
        ${options}
      </select>
    </label>`;
}

/**
 * Safe SVG preview — data-URL &lt;img&gt; so script/event handlers never run.
 * @param {string} svgText
 * @returns {string}
 */
function svgPreviewImgHtml(svgText) {
  const encoded = encodeURIComponent(String(svgText || ""))
    .replace(/'/g, "%27")
    .replace(/"/g, "%22");
  return `<img class="qr-preview-img" alt="QR code" src="data:image/svg+xml;charset=utf-8,${encoded}">`;
}

/**
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} a
 * @param {number} i
 * @param {{ cellIndex?: number }} [opts]
 */
function renderArtifactCard(a, i, opts = {}) {
  const cellIndex = opts.cellIndex ?? focusedCell;
  const artKey = `${cellIndex}:${i}`;
  const masked = a.sensitive;
  const COLLAPSE_AT = 400;
  const long = !masked && typeof a.content === "string" && a.content.length > COLLAPSE_AT;
  const expanded = expandedArtifactKeys.has(artKey);
  const preview = masked
    ? "•••••••• (click Reveal)"
    : long && !expanded
      ? escapeHtml(a.content.slice(0, COLLAPSE_AT)) + "…"
      : escapeHtml(a.content);
  const isSvg = a.mime === "image/svg+xml";
  const suggestedFilename = a.filename || `artifact-${i + 1}.txt`;
  // SVG never injected as HTML (scriptable). Use img data-URL — scripts do not run.
  const role = a.role || "";
  const tags = Array.isArray(a.tags) ? a.tags : [];
  const metaBits = [
    role ? `<span class="badge approved" title="Artifact role">${escapeHtml(role)}</span>` : "",
    ...tags.map((t) => {
      const label = String(t);
      const discouraged =
        label === "discouraged" ||
        label === "legacy" ||
        label === "sha-1" ||
        label === "rsaes-pkcs1-v1_5";
      const cls = discouraged ? "badge discouraged" : "badge pending";
      const title = discouraged
        ? "Discouraged / legacy algorithm — prefer modern alternatives"
        : "Tag";
      return `<span class="${cls}" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`;
    }),
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
  const liveInspect = artifactHasLiveInspect(a);
  const showMoreBtn =
    long && !masked
      ? `<button type="button" class="btn btn-ghost btn-compact" data-toggle-art-expand="${escapeHtml(artKey)}">${
          expanded ? "Show less" : "Show more"
        }</button>`
      : "";
  return `
        <div class="card artifact-card${liveInspect ? " artifact-card-inspect" : ""}" data-art="${i}">
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
              ${inspectFormatSelectHtml(a, i)}
              ${metaBits}
            </div>
          </div>
          ${
            isSvg && !masked
              ? svgPreviewImgHtml(a.content)
              : `<pre class="output-pre artifact-body${long && !expanded ? " artifact-body-collapsed" : ""}" data-art="${i}">${preview}</pre>`
          }
          ${showMoreBtn ? `<div class="artifact-expand-row">${showMoreBtn}</div>` : ""}
          <div class="btn-row mt-sm wrap">
            ${masked ? `<button type="button" class="btn btn-ghost btn-compact" data-reveal="${i}">Reveal</button>` : ""}
            <button type="button" class="btn btn-ghost btn-compact" data-copy="${i}">Copy</button>
            <button type="button" class="btn btn-ghost btn-compact" data-download="${i}">Download</button>
            ${
              artifactLooksLikePgpCiphertext(a)
                ? `<button type="button" class="btn btn-ghost btn-compact" data-copy-decrypt-link="${i}"
                    title="Copy a Toolkit link that opens Decrypt with this ciphertext prefilled">Copy decrypt link</button>
                  <button type="button" class="btn btn-ghost btn-compact btn-popout" data-decrypt="${i}"
                    title="Insert a decrypt cell and seed ciphertext Inputs">${popoutButtonHtml("Decrypt…")}</button>`
                : `<button type="button" class="btn btn-ghost btn-compact btn-popout" data-encrypt="${i}"
                    title="${
                      artifactIsMessage(a)
                        ? "Insert an encrypt cell and seed plaintext Inputs"
                        : "Insert an encrypt cell with this file as text input"
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

/**
 * @param {number} cellIndex
 */
function renderCellOutputs(cellIndex) {
  const panel = document.getElementById(`cell-output-${cellIndex}`);
  if (!panel) return;
  const cellArts = kernel.getCellOutputs(cellIndex);
  const status = kernel.getCellStatus(cellIndex);
  if (!cellArts.length) {
    panel.innerHTML =
      status === "error"
        ? `<p class="status-row err fs-sm mb-0">Cell failed — see status above.</p>`
        : status === "stale"
          ? `<p class="muted fs-sm mb-0">Stale — re-run this cell.</p>`
          : "";
    return;
  }

  /** @type {string[]} */
  const blocks = [];
  blocks.push(`
    <div class="cell-output-toolbar btn-row wrap mb-sm items-center">
      <span class="muted fs-xs flex-1">${cellArts.length} output${cellArts.length === 1 ? "" : "s"}${status === "stale" ? " · stale" : ""}</span>
      <button type="button" class="btn btn-ghost btn-compact" data-clear-cell-out="${cellIndex}">Clear outputs</button>
    </div>`);
  blocks.push(
    cellArts.map((a, i) => renderArtifactCard(a, i, { cellIndex })).join("")
  );
  panel.innerHTML = blocks.join("");
  panel.classList.toggle("cell-output-stale", status === "stale");

  panel.querySelector(`[data-clear-cell-out="${cellIndex}"]`)?.addEventListener(
    "click",
    () => {
      kernel.clearCellOutputs(cellIndex);
      syncArtifactsFromKernel();
      renderCellOutputs(cellIndex);
      updateKernelChip();
    }
  );
  panel.querySelectorAll("[data-toggle-art-expand]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-toggle-art-expand") || "";
      if (expandedArtifactKeys.has(key)) expandedArtifactKeys.delete(key);
      else expandedArtifactKeys.add(key);
      renderCellOutputs(cellIndex);
    });
  });

  wireArtifactPanel(panel, cellArts);
}

/** Alias — notebook uses per-cell outputs */
function renderResults() {
  syncArtifactsFromKernel();
  for (let i = 0; i < chains.length; i++) renderCellOutputs(i);
}

/**
 * @param {HTMLElement} panel
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact[]} arts
 */
function wireArtifactPanel(panel, arts) {
  /** @type {import("../lib/toolkit/engine.js").ToolkitArtifact[]} */
  const list = arts;
  panel.querySelectorAll("[data-step-link]").forEach((badge) => {
    const stepIndex = Number(badge.getAttribute("data-step-link"));
    const cardFor = () =>
      panel
        .closest(".notebook-cell")
        ?.querySelector(`.builder-card[data-step-card="${stepIndex - 1}"]`) ||
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
      if (list[i] && input instanceof HTMLInputElement) {
        list[i].filename = input.value;
        touchActivity();
      }
    });
    input.addEventListener("change", () => {
      const i = Number(input.getAttribute("data-art-filename"));
      if (!list[i] || !(input instanceof HTMLInputElement)) return;
      const filename = sanitizeFilename(input.value, `artifact-${i + 1}.txt`);
      list[i].filename = filename;
      input.value = filename;
    });
  });
  panel.querySelectorAll("[data-inspect-format]").forEach((sel) => {
    sel.addEventListener("change", () => {
      if (!(sel instanceof HTMLSelectElement)) return;
      const i = Number(sel.getAttribute("data-inspect-format"));
      const a = list[i];
      if (!a?.inspectSnapshot) return;
      const format = sel.value || "auto";
      a.inspectFormat = format;
      a.content = inspectFromSnapshot(a.inspectSnapshot, format);
      const card = panel.querySelector(`.artifact-card[data-art="${i}"]`);
      const pre = card?.querySelector(`.artifact-body[data-art="${i}"]`);
      const revealBtn = card?.querySelector(`[data-reveal="${i}"]`);
      if (pre instanceof HTMLElement) {
        if (!revealBtn) pre.textContent = a.content;
      }
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-reveal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-reveal"));
      const a = list[i];
      const pre = panel.querySelector(`.artifact-body[data-art="${i}"]`);
      if (a && pre) {
        if (a.mime === "image/svg+xml") {
          const wrap = document.createElement("div");
          wrap.className = "qr-preview";
          wrap.innerHTML = svgPreviewImgHtml(a.content);
          pre.replaceWith(wrap);
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
      try {
        const handle = await copyTextTransient(list[i].content);
        pendingClipboardClears.push(handle);
      } catch (_) {
        /* ignore */
      }
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
      downloadArtifact(list[i]);
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-encrypt]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-encrypt"));
      if (list[i] && btn instanceof HTMLButtonElement) {
        openArtifactInEncrypt(list[i], btn);
      }
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-decrypt]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-decrypt"));
      if (list[i] && btn instanceof HTMLButtonElement) {
        openArtifactInDecrypt(list[i], btn);
      }
      touchActivity();
    });
  });
  panel.querySelectorAll("[data-copy-decrypt-link]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const i = Number(btn.getAttribute("data-copy-decrypt-link"));
      if (list[i] && btn instanceof HTMLButtonElement) {
        void copyDecryptShareLink(list[i], btn);
      }
      touchActivity();
    });
  });
}

/**
 * Copy `/toolkit#decrypt&ct=…` for a ciphertext/envelope artifact.
 * @param {{ content?: string, label?: string }} artifact
 * @param {HTMLButtonElement} button
 */
async function copyDecryptShareLink(artifact, button) {
  const idle = "Copy decrypt link";
  const result = hashForDecryptLink(String(artifact.content ?? ""));
  if (!result.ok) {
    setFragmentStatus(
      result.reason ||
        "Message too long for a link — copy the ciphertext instead."
    );
    button.textContent = "Too long";
    setTimeout(() => {
      button.textContent = idle;
    }, 1800);
    return;
  }
  const url = toolkitShareUrl(result.hash);
  try {
    await navigator.clipboard.writeText(url);
    setFragmentStatus("Decrypt link copied — ciphertext is in the URL fragment.");
    button.textContent = "Copied link";
    setTimeout(() => {
      button.textContent = idle;
      setFragmentStatus("");
    }, 2000);
  } catch {
    setFragmentStatus("Could not copy — copy the address bar after opening the link.");
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = idle;
    }, 1800);
  }
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
 * Seed plaintext for an in-page encrypt cell (never put secrets in the URL).
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} artifact
 * @returns {string}
 */
function plaintextSeedFromArtifact(artifact) {
  if (artifactIsMessage(artifact)) {
    return String(artifact.content ?? "");
  }
  const content = String(artifact.content ?? "");
  if (content) return content;
  const bytes = artifactToBytes(artifact);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes);
  }
}

/**
 * Insert an encrypt cell and seed Inputs with this artifact (in-page; no popout).
 * @param {import("../lib/toolkit/engine.js").ToolkitArtifact} artifact
 * @param {HTMLButtonElement} button
 */
function openArtifactInEncrypt(artifact, button) {
  const asMessage = artifactIsMessage(artifact);
  const idleLabel = asMessage ? "Encrypt as message…" : "Encrypt as file…";
  const seed = plaintextSeedFromArtifact(artifact);
  insertMessagingCell("encrypt");
  inputTextDraft = seed;
  validateAndBind();
  setPopoutButtonLabel(button, "Cell added");
  setTimeout(() => {
    setPopoutButtonLabel(button, idleLabel);
  }, 1200);
}

/**
 * Insert a decrypt cell and seed ciphertext Inputs (in-page; no popout).
 * @param {{ label?: string, filename?: string, content: string, mime?: string }} artifact
 * @param {HTMLButtonElement} button
 */
function openArtifactInDecrypt(artifact, button) {
  const idleLabel = "Decrypt…";
  const seed = String(artifact.content ?? "");
  insertMessagingCell("decrypt");
  ciphertextDraft = seed;
  validateAndBind();
  setPopoutButtonLabel(button, "Cell added");
  setTimeout(() => {
    setPopoutButtonLabel(button, idleLabel);
  }, 1200);
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
      recipientResolutions: opts.recipientResolutions || {},
      inputs: opts.inputs || {},
      privateKeyArmored: opts.privateKeyArmored || "",
      passphrase: opts.passphrase || "",
      encryption: opts.encryption,
      fipsMode,
      suiteStatus: { ...suiteStatus },
    });
  });
}

function setReferenceOpen(open) {
  referenceOpen = open;
  document.getElementById("reference-panel")?.classList.toggle("hidden", !referenceOpen);
  if (referenceOpen) renderReference();
}

document.getElementById("toggle-reference")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  setReferenceOpen(!referenceOpen);
});

document.getElementById("close-reference")?.addEventListener("click", () => {
  setReferenceOpen(false);
});

document.getElementById("destroy-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  secureDestroy();
});
document.getElementById("focus-keyring-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  const panel = document.getElementById("keyring-panel");
  if (panel instanceof HTMLDetailsElement) {
    panel.open = true;
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
  renderAgentChrome();
});
document.getElementById("shortcuts-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  const dlg = document.getElementById("shortcuts-dialog");
  if (dlg instanceof HTMLDialogElement) dlg.showModal();
});
document.getElementById("clear-sensitive-btn")?.addEventListener("click", () => {
  clearSensitiveData();
});
document.getElementById("reset-notebook-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  resetNotebook();
});
document.getElementById("add-cell-btn")?.addEventListener("click", () => {
  insertCell(chains.length);
});
document.getElementById("qs-encrypt")?.addEventListener("click", () => {
  insertMessagingCell("encrypt");
});
document.getElementById("qs-decrypt")?.addEventListener("click", () => {
  insertMessagingCell("decrypt");
});
document.getElementById("qs-symencrypt")?.addEventListener("click", () => {
  insertMessagingCell("symencrypt");
});
document.getElementById("copy-share-link")?.addEventListener("click", () => {
  void copyShareLink();
});
document.getElementById("copy-recipe-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  void copyRecipeText();
});
document.getElementById("workspace-save-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  saveCurrentWorkspace();
});
document.getElementById("workspace-library-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  openWorkspaceLibrary();
});
document.getElementById("workspace-export-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  exportCurrentWorkspaceFile();
});
document.getElementById("workspace-import-btn")?.addEventListener("click", () => {
  document.getElementById("more-menu")?.removeAttribute("open");
  document.getElementById("workspace-import-file")?.click();
});
document.getElementById("workspace-import-file")?.addEventListener("change", (e) => {
  const input = e.target;
  if (!(input instanceof HTMLInputElement) || !input.files?.length) return;
  const file = input.files[0];
  input.value = "";
  if (file) void importWorkspaceFile(file);
});
document.getElementById("kernel-chip")?.addEventListener("click", () => {
  variablesOpen = !variablesOpen;
  renderVariablesDrawer();
});
document.getElementById("prefs-menu")?.addEventListener("toggle", (e) => {
  const d = e.target;
  if (d instanceof HTMLDetailsElement && d.open) {
    renderPrefsForm();
    document.getElementById("more-menu")?.removeAttribute("open");
    document.getElementById("preset-gallery")?.removeAttribute("open");
  }
});
document.getElementById("more-menu")?.addEventListener("toggle", (e) => {
  const d = e.target;
  if (d instanceof HTMLDetailsElement && d.open) {
    document.getElementById("prefs-menu")?.removeAttribute("open");
    document.getElementById("preset-gallery")?.removeAttribute("open");
  }
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

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (cipherPickerState || formatPickerState) {
      cipherPickerState = null;
      formatPickerState = null;
      renderOpsDrawer();
      return;
    }
    if (variablesOpen) {
      variablesOpen = false;
      renderVariablesDrawer();
    }
    return;
  }
  // Notebook shortcuts when not typing in an input
  const t = e.target;
  const typing =
    t instanceof HTMLInputElement ||
    t instanceof HTMLTextAreaElement ||
    t instanceof HTMLSelectElement ||
    (t instanceof HTMLElement && t.isContentEditable);
  if (typing) return;
  if (e.key === "Enter" && e.shiftKey) {
    e.preventDefault();
    void runNotebookCell(focusedCell);
  } else if (e.key === "Enter" && e.altKey) {
    e.preventDefault();
    void runNotebookFrom(focusedCell);
  } else if (e.key === "a" || e.key === "A") {
    e.preventDefault();
    insertCell(focusedCell);
  } else if (e.key === "b" || e.key === "B") {
    e.preventDefault();
    insertCell(focusedCell + 1);
  }
});

document.addEventListener("click", (e) => {
  if (!cipherPickerState && !formatPickerState) return;
  const t = e.target;
  if (!(t instanceof Node)) return;
  const cipherKit = document.querySelector("[data-cipher-kit]");
  const formatKit = document.querySelector("[data-format-kit]");
  if (cipherKit && cipherKit.contains(t)) return;
  if (formatKit && formatKit.contains(t)) return;
  cipherPickerState = null;
  formatPickerState = null;
  renderOpsDrawer();
});

let recipeTimer = 0;
const recipeTa = document.getElementById("recipe-text");
recipeTa?.addEventListener("input", () => {
  clearTimeout(recipeTimer);
  recipeTimer = window.setTimeout(() => {
    const ta = document.getElementById("recipe-text");
    if (ta instanceof HTMLTextAreaElement) loadRecipeText(ta.value);
  }, 300);
});
recipeTa?.addEventListener("paste", () => {
  // Value updates after paste; canonicalize on the next tick.
  clearTimeout(recipeTimer);
  recipeTimer = window.setTimeout(() => {
    const ta = document.getElementById("recipe-text");
    if (ta instanceof HTMLTextAreaElement) loadRecipeText(ta.value);
  }, 0);
});
recipeTa?.addEventListener("blur", () => {
  clearTimeout(recipeTimer);
  const ta = document.getElementById("recipe-text");
  if (ta instanceof HTMLTextAreaElement) loadRecipeText(ta.value);
});

/**
 * @returns {Promise<import("../lib/toolkit/engine.js").RuntimeBindings>}
 */
async function buildNotebookBindings() {
  const collected = await collectRuntimeInputs();
  /** @type {import("openpgp").Key[]} */
  const recipients = [];
  for (const armored of boundRecipients.map((r) => r.armoredKey).filter(Boolean)) {
    recipients.push(await readKey({ armoredKey: armored }));
  }
  /** @type {import("../lib/toolkit/engine.js").RuntimeBindings["inputs"]} */
  const inputs = collected.inputs ? { ...collected.inputs } : {};
  if (collected.privateKeyArmored && inputs.gpg) {
    inputs.gpg = {
      ...inputs.gpg,
      privateKeyArmored: String(collected.privateKeyArmored),
      passphrase: collected.passphrase || inputs.gpg.passphrase || "",
    };
  }
  return {
    recipients,
    recipientFingerprints: boundRecipients.map((r) => r.fingerprint),
    recipientResolutions: { ...recipientResolutions },
    inputs,
    encryption: {
      profile: { ...toolkitEncryptProfile },
      hideRecipients: toolkitHideRecipients,
    },
    fipsMode,
    suiteStatus: { ...suiteStatus },
  };
}

/**
 * @param {number} cellIndex
 */
async function runNotebookCell(cellIndex) {
  if (!cryptoReady) {
    showError(errorEl, "Crypto self-test has not passed.");
    return;
  }
  focusCell(cellIndex);
  const chain = chains[cellIndex];
  if (!chain?.steps?.length) {
    showError(errorEl, "Cell is empty");
    return;
  }
  const status = document.getElementById("run-status");
  const btn = document.getElementById("run-btn");
  if (status) {
    status.className = "status-row";
    status.textContent = `Running cell ${cellIndex}…`;
    status.classList.remove("hidden");
  }
  if (btn) btn.disabled = true;
  errorEl.classList.add("hidden");
  try {
    await assertCryptoReady();
    const cellAst = {
      chains: [chain],
      steps: chain.steps,
      source: "",
    };
    assertRecipeAllowedUnderFips(cellAst, suiteStatus, fipsMode);
    const lookupAst = compileRecipe(serializeRecipe({ chains })).ast;
    if (lookupAst) {
      const lookup = checkEncryptToResolutions(lookupAst);
      if (!lookup.ok) {
        throw new Error(lookup.message || "Look up recipients before running");
      }
    }
    const bindings = await buildNotebookBindings();
    // Notebook v1: main thread (kernel holds live slots).
    await kernel.runCell(cellIndex, chain, bindings);
    syncArtifactsFromKernel();
    renderNotebook();
    renderSuggestDrawer();
    renderOpsDrawer();
    renderAgentChrome();
    touchActivity();
    if (status) {
      const n = kernel.getCellOutputs(cellIndex).length;
      status.className = "status-row ok";
      status.textContent = `Cell ${cellIndex} done — ${n} output${n === 1 ? "" : "s"}.`;
    }
  } catch (err) {
    renderNotebook();
    if (status) {
      status.className = "status-row err";
      status.textContent = err?.message || "Run failed";
    }
    showError(errorEl, err?.message || "Run failed");
  } finally {
    document.querySelectorAll("[data-rt=key-pass]").forEach((el) => {
      if (el instanceof HTMLInputElement) el.value = "";
    });
    applyRunReadiness();
  }
}

/**
 * @param {number} from
 */
async function runNotebookFrom(from) {
  if (!cryptoReady) {
    showError(errorEl, "Crypto self-test has not passed.");
    return;
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
  try {
    await assertCryptoReady();
    const source = serializeRecipe({ chains });
    const { ast, validation } = compileRecipe(source);
    if (!ast || !validation.ok) {
      throw new Error(validation.errors.map((e) => e.message).join(" · "));
    }
    assertRecipeAllowedUnderFips(ast, suiteStatus, fipsMode);
    const lookup = checkEncryptToResolutions(ast);
    if (!lookup.ok) {
      throw new Error(lookup.message || "Look up recipients before running");
    }
    const need = unresolvedRecipients(ast);
    if (need.slots > 0 && boundRecipients.length < need.slots) {
      throw new Error(
        `Select ${need.slots} recipient${need.slots === 1 ? "" : "s"} before running.`
      );
    }
    const bindings = await buildNotebookBindings();
    for (let i = from; i < chains.length; i++) {
      if (!chains[i]?.steps?.length) continue;
      if (status) status.textContent = `Running cell ${i}…`;
      await kernel.runCell(i, chains[i], bindings);
    }
    syncArtifactsFromKernel();
    renderNotebook();
    renderSuggestDrawer();
    renderOpsDrawer();
    renderAgentChrome();
    touchActivity();
    if (status) {
      status.className = "status-row ok";
      status.textContent = `Done — ${artifacts.length} artifact${artifacts.length === 1 ? "" : "s"}.`;
    }
  } catch (err) {
    renderNotebook();
    renderSuggestDrawer();
    if (status) {
      status.className = "status-row err";
      status.textContent = err?.message || "Run failed";
    }
    showError(errorEl, err?.message || "Run failed");
  } finally {
    document.querySelectorAll("[data-rt=key-pass]").forEach((el) => {
      if (el instanceof HTMLInputElement) el.value = "";
    });
    applyRunReadiness();
  }
}

async function runStaleCells() {
  const stale = kernel.staleCellIndices();
  if (!stale.length) return;
  await runNotebookFrom(stale[0]);
}

document.getElementById("run-btn")?.addEventListener("click", () => {
  void runNotebookFrom(0);
});

async function startPage() {
  const status = document.getElementById("crypto-status");
  try {
    const result = await runCryptoSelfTests();
    if (!result.passed) {
      throw new CryptoModuleError(result.error || "POST failed");
    }
    cryptoReady = true;
    suiteStatus = getSuiteStatus();
    await Promise.all([refreshVaultKeys(), prefetchKeyserverOptions()]);
    if (status) {
      status.className = "app-status ok";
      status.textContent = formatSuiteStatusMessage(result);
      const fullRoot = result.moduleIntegrity?.root || "";
      if (fullRoot) status.title = `Module Merkle root (SHA-256): ${fullRoot}`;
    }
    validateAndBind();
    renderOpsDrawer();
    renderBuilder();
    renderAgentChrome();
    // Re-render cell runtime panels so vault dropdown is populated.
    renderAllCellRuntimePanels();
  } catch (err) {
    cryptoReady = false;
    suiteStatus = getSuiteStatus();
    if (status) {
      status.className = "app-status err";
      status.innerHTML =
        `<strong>Crypto self-test FAILED</strong> — toolkit disabled. ` +
        escapeHtml(err?.message || String(err));
    }
  }
}

applyCollapsePrefs();
renderPrefsForm();
renderPresets();
renderOpsDrawer();
document.getElementById("upgrade-recipe-btn")?.addEventListener("click", () => {
  const ta = document.getElementById("recipe-text");
  if (!(ta instanceof HTMLTextAreaElement)) return;
  const { recipe, changes } = migrateRecipe(ta.value);
  if (!changes.length) return;
  loadRecipeText(recipe, { migrate: false, reformat: true });
});

/** Tab hide / pagehide — scrub secrets (Encrypt clears session; toolkit clears kernel too). */
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearSensitiveData({ quiet: true, skipIdleReschedule: true });
  }
});
window.addEventListener("pagehide", () => {
  clearSensitiveData({ quiet: true, skipIdleReschedule: true });
});

/** Close toolbar menus on outside click */
document.addEventListener("click", (e) => {
  const t = e.target;
  if (!(t instanceof Node)) return;
  for (const id of ["prefs-menu", "more-menu", "preset-gallery"]) {
    const menu = document.getElementById(id);
    if (menu instanceof HTMLDetailsElement && menu.open && !menu.contains(t)) {
      menu.removeAttribute("open");
    }
  }
});

applyToolkitHash(location.hash, { boot: true });
window.addEventListener("hashchange", () => {
  if (fragmentWriteLock) return;
  applyToolkitHash(location.hash);
});
touchActivity();
startPage();

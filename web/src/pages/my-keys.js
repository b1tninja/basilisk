import { Auth } from "../lib/auth.js";
import { generateKeyViaWorker } from "../lib/generate-key.js";
import { escapeHtml, fetchJson, formatFingerprint, showError } from "../lib/utils.js";
import { renderKeysTable, renderUploadCard, wireUploadForm } from "../lib/keys.js";
import { estimatePassphraseStrength } from "../lib/pgp/passphrase.js";

/**
 * Lazy-load the EFF wordlist passphrase generator (the 7776-word list is
 * ~44 KB gzipped — only fetch it when the user asks for a suggestion).
 * @param {number} words
 * @returns {Promise<{ passphrase: string, bits: number, words: number }>}
 */
async function suggestPassphrase(words = 6) {
  const { generateWordPassphrase } = await import("../lib/passphrase-gen.js");
  return generateWordPassphrase(words);
}
import {
  armoredToBinary,
  armoredToQrSvg,
  downloadFile,
  ensurePassphraseProtected,
  inspectPrivateKey,
  isArmoredKeyLocked,
  paperBackupHtml,
} from "../lib/key-export.js";
import { getDeviceLabel, setDeviceLabel } from "../lib/prefs.js";
import {
  EXPIRY_PRESETS,
  createPasskeyPrf,
  deleteKey as vaultDeleteKey,
  expiryIsoFromPreset,
  getPasskeyPrf,
  isPasskeyPrfAvailable,
  listKeys as vaultListKeys,
  saveKey as vaultSaveKey,
  unlockKey as vaultUnlockKey,
} from "../lib/vault.js";
import "../css/site.css";

const content = document.getElementById("content");
const error = document.getElementById("error");

/** @type {boolean} */
let passkeyAvailable = false;
/** @type {boolean} */
let vaultActionsWired = false;
/** @type {Record<string, import("../lib/vault.js").VaultKeyMeta>} */
let vaultMetaByFpr = {};

async function renderSignedOut() {
  const providers = await Auth.getProviders();
  const buttons = Auth.providerButtons("/my-keys", providers);
  const hint =
    providers.includes("google") && providers.includes("microsoft")
      ? "Sign in with your Microsoft or Google account to view and claim keys associated with your email address."
      : providers.includes("google")
        ? "Sign in with your Google account to view and claim keys associated with your email address."
        : "Sign in with your Microsoft account to view and claim keys associated with your email address.";
  content.innerHTML = `
    ${renderUploadCard({ signedIn: false })}
    <div class="card" style="max-width:440px">
      <p class="card-title">Sign in to manage your keys</p>
      <p class="muted" style="margin-bottom:1.25rem">${hint}</p>
      ${buttons || "<p class='muted'>Sign-in is not configured.</p>"}
    </div>`;
}

/** Render an inline label editor (key label or device label). */
function renderLabelEditor({ id, currentValue, placeholder, note }) {
  const escaped = escapeHtml(currentValue || "");
  return `
    <div class="label-editor" id="${escapeHtml(id)}">
      <span class="label-current">${escaped ? `<span class="key-label">🏷 ${escaped}</span>` : `<span class="muted">None</span>`}</span>
      <button type="button" class="btn btn-ghost btn-compact label-edit-trigger"
              data-editor="${escapeHtml(id)}">${currentValue ? "Edit" : "Add"}</button>
      <form class="label-form hidden" data-editor="${escapeHtml(id)}" autocomplete="off">
        <input type="text" class="label-input" maxlength="200"
               placeholder="${escapeHtml(placeholder)}"
               value="${escaped}" />
        <button type="submit" class="btn btn-compact">Save</button>
        <button type="button" class="btn btn-ghost btn-compact label-cancel"
                data-editor="${escapeHtml(id)}">Cancel</button>
        ${currentValue ? `<button type="button" class="btn btn-ghost btn-compact text-error label-clear" data-editor="${escapeHtml(id)}">Remove</button>` : ""}
      </form>
      ${note ? `<p class="muted label-note">${note}</p>` : ""}
    </div>`;
}

function renderKeyLabelsSection(keys) {
  if (!keys || !keys.length) return "";
  const cards = keys
    .map((item) => {
      const fpr = item.fingerprint || "";
      const fpDisplay = formatFingerprint(fpr);
      const deviceLabel = getDeviceLabel(fpr);

      return `
        <details class="key-label-details">
          <summary class="key-label-summary">
            <code class="fpr">${escapeHtml(fpDisplay)}</code>
            ${item.label ? `<span class="key-label">🏷 ${escapeHtml(item.label)}</span>` : ""}
          </summary>
          <div class="key-label-body">
            <div class="key-label-row">
              <div>
                <p class="label-section-title">Key label <span class="badge approved" style="font-size:0.7rem;vertical-align:middle">public</span></p>
                <p class="muted label-description">Shown to anyone who views this key. Use it to describe the key's purpose.</p>
              </div>
              ${renderLabelEditor({
                id: `key-label-${fpr}`,
                currentValue: item.label || "",
                placeholder: "e.g. Work signing key",
                note: "",
              })}
            </div>
            <hr class="label-divider" />
            <div class="key-label-row">
              <div>
                <p class="label-section-title">Device label <span class="muted" style="font-size:0.75rem">(private, this browser only)</span></p>
                <p class="muted label-description">Stored only in your browser. Use it to identify which physical card or device holds this key without exposing hardware serial numbers.</p>
              </div>
              ${renderLabelEditor({
                id: `device-label-${fpr}`,
                currentValue: deviceLabel,
                placeholder: "e.g. Blue YubiKey 5C",
                note: "",
              })}
            </div>
          </div>
        </details>`;
    })
    .join("");

  return `
    <h2>Key labels</h2>
    <p class="muted" style="margin-bottom:0.75rem">
      <strong>Key labels</strong> are public and stored on the server.
      <strong>Device labels</strong> are private and stored only in this browser — use them to distinguish physical smart cards without sharing hardware identifiers.
    </p>
    <div class="key-labels-list">${cards}</div>`;
}

function renderGenerateCard(userEmail) {
  const passkeyOpt = passkeyAvailable
    ? `<label class="radio-row"><input type="radio" name="vault-protection" value="passkey"> Passkey (WebAuthn PRF) — hardware-gated unlock</label>`
    : `<p class="muted" style="font-size:0.85rem">Passkey (PRF) protection is not available in this browser.</p>`;

  return `
    <div class="card" id="generate-key-card">
      <p class="card-title">Generate a key in your browser</p>
      <p class="muted" style="margin:0 0 1rem;font-size:0.88rem">
        Creates a Curve25519 OpenPGP keypair locally, stores the private key in an encrypted browser vault
        (IndexedDB), and publishes the public key under your verified email.
        Convenience for short-lived keys — not a replacement for hardware tokens.
        CSP and Subresource Integrity protect against XSS; passphrase and passkey modes keep a stolen vault dump useless.
      </p>
      <form id="generate-key-form" autocomplete="off">
        <label class="field-label" for="gen-name">Display name (optional)</label>
        <input type="text" id="gen-name" class="text-input" maxlength="100" placeholder="Your name">

        <label class="field-label" for="gen-email" style="margin-top:0.75rem">Email</label>
        <input type="email" id="gen-email" class="text-input" value="${escapeHtml(userEmail)}" readonly>

        <label class="field-label" for="gen-expiry" style="margin-top:0.75rem">Key expiration</label>
        <select id="gen-expiry" class="text-input">
          <option value="1w">1 week</option>
          <option value="1d">1 day</option>
          <option value="1m" selected>1 month</option>
          <option value="1y">1 year</option>
          <option value="none">No expiration</option>
        </select>

        <p class="field-label" style="margin-top:0.75rem">Private key protection</p>
        <div class="vault-protection-options">
          <label class="radio-row"><input type="radio" name="vault-protection" value="passphrase" checked> Passphrase (Argon2) — recommended</label>
          ${passkeyOpt}
          <label class="radio-row"><input type="radio" name="vault-protection" value="device"> Device-only — weakest (any script on this origin can use it while the page is open)</label>
        </div>
        <p id="device-only-warn" class="status-row err hidden" style="margin-top:0.5rem">
          Device-only mode does not require a passphrase or passkey. Prefer passphrase protection for sensitive use.
        </p>

        <div id="gen-passphrase-row" style="margin-top:0.75rem">
          <label class="field-label" for="gen-passphrase">Passphrase</label>
          <input type="password" id="gen-passphrase" class="text-input" autocomplete="new-password">
          <label class="field-label" for="gen-passphrase-confirm" style="margin-top:0.5rem">Confirm passphrase</label>
          <input type="password" id="gen-passphrase-confirm" class="text-input" autocomplete="new-password">
          <div class="btn-row" style="margin-top:0.5rem">
            <button type="button" class="btn btn-ghost btn-compact" id="gen-suggest-pw">Suggest a passphrase</button>
          </div>
          <p id="gen-suggested-pw" class="suggested-pw hidden"></p>
          <div id="gen-pw-strength-meter" class="pw-strength-meter" data-strength="empty" style="margin-top:0.5rem">
            <div class="pw-strength-fill"></div>
          </div>
          <p id="gen-pw-strength-label" class="pw-strength-label muted"></p>
        </div>

        <div class="btn-row" style="margin-top:1rem">
          <button type="submit" class="btn" id="gen-submit-btn">Generate &amp; publish</button>
        </div>
        <div id="gen-status" class="hidden" style="margin-top:0.75rem"></div>
      </form>
    </div>`;
}

function protectionBadge(mode) {
  if (mode === "passphrase") return `<span class="badge approved">passphrase</span>`;
  if (mode === "passkey") return `<span class="badge approved">passkey</span>`;
  return `<span class="badge pending">device-only</span>`;
}

function formatExpiryCountdown(expires) {
  if (!expires) return "No expiration";
  const t = Date.parse(expires);
  if (Number.isNaN(t)) return escapeHtml(expires);
  const ms = t - Date.now();
  if (ms <= 0) return "Expired";
  const days = Math.floor(ms / 86400000);
  if (days >= 2) return `Expires in ${days} days`;
  const hours = Math.floor(ms / 3600000);
  if (hours >= 1) return `Expires in ${hours}h`;
  return "Expires soon";
}

/**
 * @param {import("../lib/vault.js").VaultKeyMeta} k
 */
function renderExportPanel(k) {
  const fpr = escapeHtml(k.fingerprint);
  const needsExportPassphrase = k.protection !== "passphrase";
  const passphraseBlock = needsExportPassphrase
    ? `
      <p class="muted" style="font-size:0.85rem;margin:0 0 0.5rem">
        This key is not passphrase-protected in the vault. Exports are always
        passphrase-protected (GnuPG-compatible) — set one to encrypt the exported key.
      </p>
      <div class="btn-row" style="align-items:center;flex-wrap:wrap">
        <input type="password" class="text-input export-passphrase" style="max-width:280px"
               placeholder="Export passphrase" autocomplete="new-password" data-fpr="${fpr}">
        <button type="button" class="btn btn-ghost btn-compact" data-export-suggest="${fpr}">Suggest</button>
      </div>
      <p class="suggested-pw hidden" data-export-suggested="${fpr}"></p>`
    : `
      <p class="muted" style="font-size:0.85rem;margin:0 0 0.5rem">
        Exports keep the key's existing passphrase protection — GnuPG will ask
        for your passphrase when you use the imported key.
      </p>`;

  return `
    <tr class="vault-export-row hidden" data-export-panel="${fpr}">
      <td colspan="5">
        <div class="vault-export-panel">
          ${passphraseBlock}
          <div class="btn-row" style="margin-top:0.5rem;flex-wrap:wrap">
            <button type="button" class="btn btn-compact" data-export-format="asc" data-fpr="${fpr}">Armored (.asc)</button>
            <button type="button" class="btn btn-compact" data-export-format="gpg" data-fpr="${fpr}">Binary (.gpg)</button>
            <button type="button" class="btn btn-compact" data-export-format="qr" data-fpr="${fpr}">QR code (.svg)</button>
            <button type="button" class="btn btn-compact" data-export-format="paper" data-fpr="${fpr}">Paper backup (.html)</button>
          </div>
          <p class="muted" style="font-size:0.8rem;margin:0.5rem 0 0">
            Restore anywhere with <code>gpg --import</code>. The paper backup includes
            a QR code and printed instructions — store it like cash.
          </p>
          <p class="status-row err hidden" data-export-status="${fpr}"></p>
        </div>
      </td>
    </tr>`;
}

/**
 * @param {import("../lib/vault.js").VaultKeyMeta[]} vaultKeys
 */
function renderVaultSection(vaultKeys) {
  if (!vaultKeys.length) {
    return `
      <h2>Your browser vault</h2>
      <p class="muted">No private keys stored in this browser yet. Generate one above or import an existing key below.</p>
      ${renderImportCard()}`;
  }
  const rows = vaultKeys
    .map((k) => {
      const fpr = formatFingerprint(k.fingerprint);
      return `
        <tr>
          <td><code class="fpr">${escapeHtml(fpr)}</code></td>
          <td>${escapeHtml(k.uid || k.email || "")}</td>
          <td>${protectionBadge(k.protection)}</td>
          <td class="muted">${formatExpiryCountdown(k.expires)}</td>
          <td class="btn-row">
            <button type="button" class="btn btn-ghost btn-compact" data-vault-export-toggle="${escapeHtml(k.fingerprint)}">Export</button>
            <button type="button" class="btn btn-ghost btn-compact text-error" data-vault-delete="${escapeHtml(k.fingerprint)}">Delete</button>
          </td>
        </tr>
        ${renderExportPanel(k)}`;
    })
    .join("");

  return `
    <h2>Your browser vault</h2>
    <p class="muted" style="margin-bottom:0.75rem">
      Private keys stored only in this browser (IndexedDB), envelope-encrypted with a device-bound key.
      Every export is passphrase-protected in GnuPG-compatible format (armored, binary, QR, or printable paper backup).
    </p>
    <div class="card" style="overflow-x:auto">
      <table class="keys-table">
        <thead>
          <tr><th>Fingerprint</th><th>UID</th><th>Protection</th><th>Expiry</th><th></th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${renderImportCard()}`;
}

function renderImportCard() {
  return `
    <div class="card" id="vault-import-card" style="margin-top:1rem">
      <p class="card-title">Import an existing private key</p>
      <p class="muted" style="margin:0 0 0.75rem;font-size:0.88rem">
        Paste an ASCII-armored private key (from <code>gpg --armor --export-secret-keys</code>).
        Passphrase-protected keys are stored as-is; unprotected keys must be given a passphrase.
      </p>
      <form id="vault-import-form" autocomplete="off">
        <textarea id="import-armored" class="text-input" rows="6" spellcheck="false"
                  placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"></textarea>
        <div id="import-passphrase-row" class="hidden" style="margin-top:0.75rem">
          <label class="field-label" for="import-passphrase">Passphrase to protect this key</label>
          <div class="btn-row" style="align-items:center;flex-wrap:wrap">
            <input type="password" id="import-passphrase" class="text-input" style="max-width:280px" autocomplete="new-password">
            <button type="button" class="btn btn-ghost btn-compact" id="import-suggest-pw">Suggest</button>
          </div>
          <p id="import-suggested-pw" class="suggested-pw hidden"></p>
        </div>
        <div class="btn-row" style="margin-top:0.75rem">
          <button type="submit" class="btn" id="import-submit-btn">Import into vault</button>
        </div>
        <p id="import-status" class="status-row hidden" style="margin-top:0.5rem"></p>
      </form>
    </div>`;
}

async function renderSignedIn(user, keys) {
  const userInfo = `<p style="margin-bottom:1.25rem">Signed in as
      <strong>${escapeHtml(user.email)}</strong></p>`;

  let vaultKeys = [];
  try {
    vaultKeys = await vaultListKeys();
  } catch (_) {
    vaultKeys = [];
  }
  vaultMetaByFpr = Object.fromEntries(vaultKeys.map((k) => [k.fingerprint, k]));

  const keysSection =
    keys && keys.length
      ? `<h2>Your keys</h2>
         <p class="muted" style="margin-bottom:0.75rem">Unclaimed pending keys expire after 30 days. Claimed keys can be deleted below.</p>
         ${renderKeysTable(keys, { showClaim: true, showDelete: true })}
         ${renderKeyLabelsSection(keys)}`
      : `<p class="muted">No keys on file yet for your account. Generate one below or submit a public key above.</p>`;

  content.innerHTML =
    userInfo +
    renderUploadCard({ signedIn: true }) +
    renderGenerateCard(user.email || "") +
    renderVaultSection(vaultKeys) +
    keysSection;
  wireKeyLabelEditors(keys || []);
  wireGenerateForm(user);
  wireImportForm();
  wireVaultActions();
}

/** Wire up all inline label editors in the rendered content. */
function wireKeyLabelEditors(keys) {
  // Map fpr -> current server label for quick lookup
  const serverLabels = Object.fromEntries(
    (keys || []).map((k) => [k.fingerprint, k.label || ""])
  );

  content.addEventListener("click", handleLabelClick);
  content.addEventListener("submit", handleLabelSubmit);

  function handleLabelClick(e) {
    // Toggle edit form open
    const trigger = e.target.closest?.(".label-edit-trigger");
    if (trigger) {
      const editorId = trigger.dataset.editor;
      const editor = document.getElementById(editorId);
      if (!editor) return;
      const form = editor.querySelector(".label-form");
      if (!form) return;
      form.classList.toggle("hidden");
      if (!form.classList.contains("hidden")) {
        form.querySelector(".label-input")?.focus();
      }
      return;
    }

    // Cancel
    const cancelBtn = e.target.closest?.(".label-cancel");
    if (cancelBtn) {
      const editorId = cancelBtn.dataset.editor;
      document.getElementById(editorId)?.querySelector(".label-form")?.classList.add("hidden");
      return;
    }

    // Clear (remove)
    const clearBtn = e.target.closest?.(".label-clear");
    if (clearBtn) {
      const editorId = clearBtn.dataset.editor;
      applyLabel(editorId, "");
    }
  }

  function handleLabelSubmit(e) {
    const form = e.target.closest?.(".label-form");
    if (!form) return;
    e.preventDefault();
    const editorId = form.dataset.editor;
    const val = (form.querySelector(".label-input")?.value || "").trim();
    applyLabel(editorId, val);
  }

  async function applyLabel(editorId, value) {
    const editor = document.getElementById(editorId);
    if (!editor) return;

    const isDevice = editorId.startsWith("device-label-");
    const fpr = editorId.replace(/^(key|device)-label-/, "");

    if (isDevice) {
      setDeviceLabel(fpr, "", value);
      refreshEditorDisplay(editor, value);
      editor.querySelector(".label-form")?.classList.add("hidden");
      return;
    }

    // Server key label
    const submitBtn = editor.querySelector("button[type=submit]");
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Saving…"; }
    try {
      const result = await fetchJson(
        `/api/v1/me/keys/${encodeURIComponent(fpr)}/label`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ label: value }),
        }
      );
      const saved = result.label || "";
      serverLabels[fpr] = saved;
      refreshEditorDisplay(editor, saved);
      editor.querySelector(".label-form")?.classList.add("hidden");

      // Also update the summary badge
      const details = editor.closest("details");
      const summary = details?.querySelector(".key-label-summary");
      if (summary) {
        const existing = summary.querySelector(".key-label");
        if (existing) existing.remove();
        if (saved) {
          const badge = document.createElement("span");
          badge.className = "key-label";
          badge.textContent = `🏷 ${saved}`;
          summary.appendChild(badge);
        }
      }
    } catch (err) {
      showError(error, err.message || "Label save failed");
    } finally {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "Save"; }
    }
  }

  function refreshEditorDisplay(editor, newValue) {
    const current = editor.querySelector(".label-current");
    if (current) {
      current.innerHTML = newValue
        ? `<span class="key-label">🏷 ${escapeHtml(newValue)}</span>`
        : `<span class="muted">None</span>`;
    }
    const trigger = editor.querySelector(".label-edit-trigger");
    if (trigger) trigger.textContent = newValue ? "Edit" : "Add";

    // Re-render the form (so the clear button appears/disappears correctly)
    const form = editor.querySelector(".label-form");
    if (form) {
      const input = form.querySelector(".label-input");
      if (input) input.value = newValue;
      const clearBtn = form.querySelector(".label-clear");
      if (newValue && !clearBtn) {
        const cancelBtn = form.querySelector(".label-cancel");
        if (cancelBtn) {
          const newClear = document.createElement("button");
          newClear.type = "button";
          newClear.className = "btn btn-ghost btn-compact text-error label-clear";
          newClear.dataset.editor = editor.id;
          newClear.textContent = "Remove";
          cancelBtn.insertAdjacentElement("afterend", newClear);
        }
      } else if (!newValue && clearBtn) {
        clearBtn.remove();
      }
    }
  }
}

/**
 * @param {{ email?: string }} user
 */
function wireGenerateForm(user) {
  const form = document.getElementById("generate-key-form");
  if (!form) return;

  const updateProtectionUi = () => {
    const mode =
      form.querySelector('input[name="vault-protection"]:checked')?.value ||
      "passphrase";
    const pwRow = document.getElementById("gen-passphrase-row");
    const warn = document.getElementById("device-only-warn");
    if (pwRow) pwRow.classList.toggle("hidden", mode !== "passphrase");
    if (warn) warn.classList.toggle("hidden", mode !== "device");
  };
  form.querySelectorAll('input[name="vault-protection"]').forEach((el) => {
    el.addEventListener("change", updateProtectionUi);
  });
  updateProtectionUi();

  const pwEl = document.getElementById("gen-passphrase");
  const updateMeter = () => {
    const meter = document.getElementById("gen-pw-strength-meter");
    const label = document.getElementById("gen-pw-strength-label");
    if (!meter || !label) return;
    const est = estimatePassphraseStrength(pwEl?.value || "");
    meter.dataset.strength = est.label;
    const fill = meter.querySelector(".pw-strength-fill");
    if (fill instanceof HTMLElement) {
      fill.style.width = `${Math.min(100, Math.round((est.bits / 80) * 100))}%`;
    }
    label.textContent =
      est.label === "empty" ? "" : `${est.label} (~${est.bits} bits). ${est.hint}`;
    label.className = `pw-strength-label muted${est.label === "weak" ? " pw-weak" : ""}`;
  };
  pwEl?.addEventListener("input", updateMeter);

  document.getElementById("gen-suggest-pw")?.addEventListener("click", async () => {
    const { passphrase, bits } = await suggestPassphrase(6);
    const p1 = document.getElementById("gen-passphrase");
    const p2 = document.getElementById("gen-passphrase-confirm");
    if (p1 instanceof HTMLInputElement) p1.value = passphrase;
    if (p2 instanceof HTMLInputElement) p2.value = passphrase;
    const out = document.getElementById("gen-suggested-pw");
    if (out) {
      out.textContent = `${passphrase} (~${bits} bits — write it down before continuing)`;
      out.classList.remove("hidden");
    }
    updateMeter();
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const status = document.getElementById("gen-status");
    const btn = document.getElementById("gen-submit-btn");
    const mode =
      form.querySelector('input[name="vault-protection"]:checked')?.value ||
      "passphrase";
    const name = /** @type {HTMLInputElement} */ (document.getElementById("gen-name"))
      ?.value?.trim() || "";
    const email = (user.email || "").trim();
    const expiryPreset =
      /** @type {HTMLSelectElement} */ (document.getElementById("gen-expiry"))?.value ||
      "1m";
    const passphrase =
      /** @type {HTMLInputElement} */ (document.getElementById("gen-passphrase"))
        ?.value || "";
    const confirm =
      /** @type {HTMLInputElement} */ (document.getElementById("gen-passphrase-confirm"))
        ?.value || "";

    if (!email) {
      showError(error, "Signed-in email is required to publish a key.");
      return;
    }
    if (mode === "passphrase") {
      if (!passphrase) {
        showError(error, "Enter a passphrase to protect the private key.");
        return;
      }
      if (passphrase !== confirm) {
        showError(error, "Passphrases do not match.");
        return;
      }
    }

    if (status) {
      status.className = "status-row";
      status.textContent = "Generating keypair…";
      status.classList.remove("hidden");
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Working…";
    }
    error.classList.add("hidden");

    let armoredPrivate = "";
    try {
      const keyExpirationTime = EXPIRY_PRESETS[expiryPreset] ?? null;
      const gen = await generateKeyViaWorker({
        email,
        name,
        keyExpirationTime,
        passphrase: mode === "passphrase" ? passphrase : "",
      });
      armoredPrivate = gen.armoredPrivate;

      /** @type {Uint8Array|undefined} */
      let prfIkm;
      if (mode === "passkey") {
        if (status) status.textContent = "Create or confirm passkey…";
        prfIkm = await createPasskeyPrf(email);
      }

      if (status) status.textContent = "Storing in browser vault…";
      const uid = name ? `${name} <${email}>` : email;
      await vaultSaveKey({
        fingerprint: gen.fingerprint,
        armoredPrivate,
        uid,
        email,
        name,
        expires: expiryIsoFromPreset(expiryPreset),
        protection: /** @type {"passphrase"|"passkey"|"device"} */ (mode),
        prfIkm,
      });

      // Best-effort wipe of the in-memory armored private string reference
      armoredPrivate = "";

      if (status) status.textContent = "Publishing public key…";
      const result = await fetchJson("/api/v1/me/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: gen.armoredPublic }),
      });

      if (status) {
        status.className = "status-row ok";
        status.innerHTML =
          `Key generated and published — fingerprint ` +
          `<code>${escapeHtml(formatFingerprint(gen.fingerprint))}</code>` +
          (result.claimed ? ", ownership claimed." : ".");
      }
      document.dispatchEvent(
        new CustomEvent("basilisk:key-submitted", { detail: result })
      );
      // Clear passphrase fields
      const p1 = document.getElementById("gen-passphrase");
      const p2 = document.getElementById("gen-passphrase-confirm");
      if (p1 instanceof HTMLInputElement) p1.value = "";
      if (p2 instanceof HTMLInputElement) p2.value = "";
      updateMeter();
      setTimeout(loadMyKeys, 600);
    } catch (err) {
      if (status) {
        status.className = "status-row err";
        status.textContent = err?.message || "Key generation failed";
      }
      showError(error, err?.message || "Key generation failed");
    } finally {
      armoredPrivate = "";
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Generate & publish";
      }
    }
  });
}

function wireVaultActions() {
  if (vaultActionsWired) return;
  vaultActionsWired = true;
  content.addEventListener("click", async (e) => {
    const delBtn = e.target.closest?.("[data-vault-delete]");
    if (delBtn) {
      const fpr = delBtn.getAttribute("data-vault-delete");
      if (!fpr) return;
      if (!confirm(`Delete private key ${fpr} from this browser vault?`)) return;
      delBtn.disabled = true;
      try {
        await vaultDeleteKey(fpr);
        await loadMyKeys();
      } catch (err) {
        showError(error, err?.message || "Vault delete failed");
        delBtn.disabled = false;
      }
      return;
    }

    const toggleBtn = e.target.closest?.("[data-vault-export-toggle]");
    if (toggleBtn) {
      const fpr = toggleBtn.getAttribute("data-vault-export-toggle");
      content
        .querySelector(`[data-export-panel="${CSS.escape(fpr)}"]`)
        ?.classList.toggle("hidden");
      return;
    }

    const suggestBtn = e.target.closest?.("[data-export-suggest]");
    if (suggestBtn) {
      const fpr = suggestBtn.getAttribute("data-export-suggest");
      const { passphrase, bits } = await suggestPassphrase(6);
      const input = content.querySelector(
        `.export-passphrase[data-fpr="${CSS.escape(fpr)}"]`
      );
      if (input instanceof HTMLInputElement) input.value = passphrase;
      const out = content.querySelector(
        `[data-export-suggested="${CSS.escape(fpr)}"]`
      );
      if (out) {
        out.textContent = `${passphrase} (~${bits} bits — write it down; you need it to import the key)`;
        out.classList.remove("hidden");
      }
      return;
    }

    const fmtBtn = e.target.closest?.("[data-export-format]");
    if (fmtBtn) {
      const fpr = fmtBtn.getAttribute("data-fpr");
      const format = fmtBtn.getAttribute("data-export-format");
      if (!fpr || !format) return;
      await runVaultExport(fpr, format, fmtBtn);
    }
  });
}

/**
 * Unlock a vault key, ensure passphrase protection, and download in `format`.
 * @param {string} fpr
 * @param {string} format  asc | gpg | qr | paper
 * @param {HTMLElement} btn
 */
async function runVaultExport(fpr, format, btn) {
  const meta = vaultMetaByFpr[fpr];
  const statusEl = content.querySelector(
    `[data-export-status="${CSS.escape(fpr)}"]`
  );
  const setStatus = (msg) => {
    if (!statusEl) return;
    if (msg) {
      statusEl.textContent = msg;
      statusEl.classList.remove("hidden");
    } else {
      statusEl.classList.add("hidden");
    }
  };
  setStatus("");
  btn.disabled = true;
  try {
    /** @type {{ passphrase?: string, prfIkm?: Uint8Array }} */
    const unlockOpts = {};
    if (meta?.protection === "passkey") {
      unlockOpts.prfIkm = await getPasskeyPrf();
    }
    let armored = await vaultUnlockKey(fpr, unlockOpts);

    // Vault entries without OpenPGP passphrase protection (device / passkey
    // modes) must be locked before leaving the browser.
    if (!(await isArmoredKeyLocked(armored))) {
      const input = content.querySelector(
        `.export-passphrase[data-fpr="${CSS.escape(fpr)}"]`
      );
      const exportPw =
        input instanceof HTMLInputElement ? input.value : "";
      if (!exportPw) {
        setStatus("Set an export passphrase first — exports must be protected.");
        return;
      }
      const est = estimatePassphraseStrength(exportPw);
      if (est.label === "weak") {
        setStatus(`Passphrase too weak (~${est.bits} bits). ${est.hint}`);
        return;
      }
      armored = await ensurePassphraseProtected(armored, exportPw);
    }

    const shortId = fpr.slice(-8).toLowerCase();
    if (format === "asc") {
      downloadFile(`${shortId}-private.asc`, armored, "application/pgp-keys");
    } else if (format === "gpg") {
      const binary = await armoredToBinary(armored);
      downloadFile(`${shortId}-private.gpg`, binary, "application/octet-stream");
    } else if (format === "qr") {
      const svg = armoredToQrSvg(armored);
      downloadFile(`${shortId}-private-qr.svg`, svg, "image/svg+xml");
    } else if (format === "paper") {
      const html = paperBackupHtml({
        armored,
        fingerprint: fpr,
        uid: meta?.uid || meta?.email || "",
        expires: meta?.expires || null,
      });
      downloadFile(`${shortId}-paper-backup.html`, html, "text/html");
    }
    armored = "";
  } catch (err) {
    setStatus(err?.message || "Export failed");
  } finally {
    btn.disabled = false;
  }
}

/** Wire the "import an existing private key" card. */
function wireImportForm() {
  const form = document.getElementById("vault-import-form");
  if (!form || form.dataset.wired) return;
  form.dataset.wired = "1";

  const armoredEl = /** @type {HTMLTextAreaElement|null} */ (
    document.getElementById("import-armored")
  );
  const pwRow = document.getElementById("import-passphrase-row");
  const statusEl = document.getElementById("import-status");
  const setStatus = (msg, ok = false) => {
    if (!statusEl) return;
    statusEl.textContent = msg;
    statusEl.className = `status-row ${ok ? "ok" : "err"}`;
    statusEl.classList.toggle("hidden", !msg);
  };

  // Reveal the passphrase row only when the pasted key is unprotected.
  let checkTimer = 0;
  armoredEl?.addEventListener("input", () => {
    clearTimeout(checkTimer);
    checkTimer = window.setTimeout(async () => {
      const text = armoredEl.value.trim();
      if (!text.includes("PRIVATE KEY BLOCK")) {
        pwRow?.classList.add("hidden");
        return;
      }
      try {
        const locked = await isArmoredKeyLocked(text);
        pwRow?.classList.toggle("hidden", locked);
      } catch (_) {
        pwRow?.classList.add("hidden");
      }
    }, 400);
  });

  document.getElementById("import-suggest-pw")?.addEventListener("click", async () => {
    const { passphrase, bits } = await suggestPassphrase(6);
    const input = document.getElementById("import-passphrase");
    if (input instanceof HTMLInputElement) input.value = passphrase;
    const out = document.getElementById("import-suggested-pw");
    if (out) {
      out.textContent = `${passphrase} (~${bits} bits — write it down)`;
      out.classList.remove("hidden");
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("import-submit-btn");
    let armored = (armoredEl?.value || "").trim();
    if (!armored.includes("PRIVATE KEY BLOCK")) {
      setStatus("Paste an armored PRIVATE key block (-----BEGIN PGP PRIVATE KEY BLOCK-----).");
      return;
    }
    if (btn) btn.disabled = true;
    setStatus("");
    try {
      const info = await inspectPrivateKey(armored);
      if (!info.locked) {
        const input = document.getElementById("import-passphrase");
        const pw = input instanceof HTMLInputElement ? input.value : "";
        if (!pw) {
          pwRow?.classList.remove("hidden");
          setStatus("This key has no passphrase. Set one to protect it in the vault.");
          return;
        }
        const est = estimatePassphraseStrength(pw);
        if (est.label === "weak") {
          setStatus(`Passphrase too weak (~${est.bits} bits). ${est.hint}`);
          return;
        }
        armored = await ensurePassphraseProtected(armored, pw);
      }
      await vaultSaveKey({
        fingerprint: info.fingerprint,
        armoredPrivate: armored,
        uid: info.uid,
        email: info.email,
        expires: info.expires,
        protection: "passphrase",
      });
      armored = "";
      if (armoredEl) armoredEl.value = "";
      const pwInput = document.getElementById("import-passphrase");
      if (pwInput instanceof HTMLInputElement) pwInput.value = "";
      setStatus(`Imported ${formatFingerprint(info.fingerprint)} into the vault.`, true);
      setTimeout(loadMyKeys, 800);
    } catch (err) {
      setStatus(err?.message || "Import failed — is this a valid armored private key?");
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}

async function loadMyKeys() {
  try {
    passkeyAvailable = await isPasskeyPrfAvailable();
    const user = await Auth.getUser();
    if (!user || !user.authenticated) {
      await renderSignedOut();
      return;
    }
    const payload = await fetchJson("/api/v1/me/keys");
    await renderSignedIn(user, payload.keys);
  } catch (err) {
    if (err.status === 401) {
      await renderSignedOut();
    } else {
      showError(error, err.message);
    }
  }
}

wireUploadForm();
document.addEventListener("basilisk:key-submitted", () => {
  setTimeout(loadMyKeys, 800);
});

document.addEventListener("click", async (e) => {
  const btn = e.target.closest?.("[data-delete-fpr]");
  if (!btn) return;
  const fpr = btn.getAttribute("data-delete-fpr");
  if (!fpr) return;
  if (!confirm(`Delete / unpublish key ${fpr}? This cannot be undone.`)) return;
  btn.disabled = true;
  try {
    await fetchJson(`/api/v1/me/keys/${encodeURIComponent(fpr)}`, { method: "DELETE" });
    await loadMyKeys();
  } catch (err) {
    showError(error, err.message || "Delete failed");
    btn.disabled = false;
  }
});

Auth.initWidget(document.getElementById("auth-widget"), "/my-keys");
loadMyKeys();

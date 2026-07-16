import { readKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import { runCryptoSelfTests } from "../lib/crypto-self-test.js";
import { badgeClass } from "../lib/keys.js";
import {
  PROFILE_COMPATIBLE,
  PROFILE_MODERN,
  encryptArtifacts,
  summarizeEncryption,
} from "../lib/pgp/encrypt.js";
import {
  copyText,
  escapeHtml,
  extractEmail,
  fetchJson,
  fetchText,
  formatFingerprint,
  queryParam,
  showError,
  uidEmail,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/compose");

const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
const ENCRYPT_FLAG = 0x04 | 0x08;

const errorEl = document.getElementById("error");
const app = document.getElementById("compose-app");

// ── Crypto self-test: verify OpenPGP.js is functional before first encrypt ───
(async () => {
  const banner = document.createElement("div");
  banner.id = "crypto-status";
  banner.className = "status-row";
  banner.setAttribute("role", "status");
  banner.setAttribute("aria-live", "polite");
  banner.textContent = "Verifying crypto module…";
  app.before(banner);

  const result = await runCryptoSelfTests();
  if (result.passed) {
    banner.className = "status-row ok";
    banner.textContent = `Crypto module verified (${result.elapsed} ms).`;
    setTimeout(() => banner.classList.add("hidden"), 4000);
  } else {
    banner.className = "status-row err";
    banner.textContent =
      `Crypto self-test FAILED — encryption may be unreliable. ` +
      (result.error ? `Error: ${result.error}` : "");
  }
})();

/** @type {Map<string, Recipient>} */
const recipients = new Map();
/** @type {File[]} */
let files = [];
let activeTab = "message";
/** @type {Array<{ label: string, filename: string, armored: string, summary?: string }>} */
let outputs = [];
/** Last honest encryption summary from packet re-parse */
let lastEncryptSummary = "";
let searchTimer = null;
let encrypting = false;
/** @type {"compatible"|"modern"|"custom"} */
let encryptPreset = "compatible";

/**
 * @typedef {{
 *   fingerprint: string,
 *   keyId: string,
 *   label: string,
 *   email: string,
 *   approvalState: string,
 *   revoked: boolean,
 *   valid: boolean,
 *   error: string,
 *   pgpKey: import("openpgp").Key | null,
 * }} Recipient
 */

function shortFpr(fpr) {
  const c = String(fpr || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return c.length > 8 ? c.slice(-8) : c;
}

function uidLabel(uids) {
  const list = uids || [];
  if (!list.length) return "";
  const uid = list[0];
  if (uid && typeof uid === "object") {
    const email = uid.email || "";
    const name = (uid.name || "").trim();
    if (name && email) return `${name} <${email}>`;
    return email || uid.raw || "";
  }
  return typeof uid === "string" ? uid : "";
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function totalFileBytes() {
  return files.reduce((sum, f) => sum + f.size, 0);
}

function hasEncryptCapability(pgpKey) {
  try {
    const keys = [pgpKey, ...(pgpKey.subkeys || []).map((s) => s)];
    for (const k of keys) {
      const pkt = k.keyPacket || k;
      if (pkt && pkt.flags != null && pkt.flags & ENCRYPT_FLAG) return true;
    }
  } catch (_) {
    /* fall through */
  }
  return false;
}

async function loadRecipientKey(fingerprint) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const [meta, armored] = await Promise.all([
    fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`),
    fetchText(`/pks/lookup?op=get&search=${encodeURIComponent(`0x${clean}`)}`),
  ]);
  if (!String(armored).includes("BEGIN PGP")) {
    throw new Error("Could not fetch public key");
  }
  const pgpKey = await readKey({ armoredKey: armored });
  const uids = meta.approved_uids || meta.pending_uids || [];
  const label = uidLabel(uids) || formatFingerprint(clean);
  const email = uidEmail(uids[0]) || "";
  let valid = true;
  let err = "";
  if (meta.revoked) {
    valid = false;
    err = "Key is revoked";
  } else if (meta.approval_state !== "approved") {
    valid = false;
    err = `Key is ${meta.approval_state || "not approved"}`;
  } else if (!hasEncryptCapability(pgpKey)) {
    // Still try getEncryptionKey — OpenPGP.js is authoritative
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  if (valid) {
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  /** @type {Recipient} */
  const recipient = {
    fingerprint: clean,
    keyId: meta.key_id || clean.slice(-16),
    label,
    email,
    approvalState: meta.approval_state || "",
    revoked: !!meta.revoked,
    valid,
    error: err,
    pgpKey: valid ? pgpKey : null,
  };
  return recipient;
}

function validRecipients() {
  return [...recipients.values()].filter((r) => r.valid && r.pgpKey);
}

function passphraseEnabled() {
  return !!document.getElementById("use-passphrase")?.checked;
}

function passphraseValues() {
  const pw = document.getElementById("msg-passphrase")?.value || "";
  const confirm = document.getElementById("msg-passphrase-confirm")?.value || "";
  return { pw, confirm };
}

function canEncrypt() {
  if (encrypting) return false;
  const keys = validRecipients();
  const usePw = passphraseEnabled();
  const { pw, confirm } = passphraseValues();
  if (!keys.length && !usePw) return false;
  if (usePw) {
    if (!pw || pw !== confirm) return false;
  }
  const hasMsg = !!(document.getElementById("compose-message")?.value || "").trim();
  const hasFiles = files.length > 0;
  if (!hasMsg && !hasFiles) return false;
  if (totalFileBytes() > MAX_TOTAL_BYTES) return false;
  return true;
}

function updateEncryptButton() {
  const btn = document.getElementById("encrypt-btn");
  if (btn) btn.disabled = !canEncrypt();
  const tally = document.getElementById("size-tally");
  if (tally) {
    const total = totalFileBytes();
    const over = total > MAX_TOTAL_BYTES;
    tally.textContent = `${formatBytes(total)} / ${formatBytes(MAX_TOTAL_BYTES)}`;
    tally.classList.toggle("over", over);
  }
}

function renderPills() {
  const el = document.getElementById("recipient-pills");
  if (!el) return;
  if (!recipients.size) {
    el.innerHTML = `<p class="muted" style="margin:0">No recipients yet. Search by email, fingerprint, or key ID.</p>`;
    return;
  }
  el.innerHTML = [...recipients.values()]
    .map((r) => {
      const initial = (r.email || r.label || "?").charAt(0).toUpperCase();
      const title = r.error || formatFingerprint(r.fingerprint);
      return `<span class="recipient-pill${r.valid ? "" : " invalid"}" title="${escapeHtml(title)}" data-fpr="${escapeHtml(r.fingerprint)}">
        <span class="pill-avatar">${escapeHtml(initial)}</span>
        <span class="pill-body">
          <span class="pill-label">${escapeHtml(r.label)}</span>
          <span class="pill-fpr muted">${escapeHtml(shortFpr(r.fingerprint))}</span>
        </span>
        ${r.valid ? "" : `<span class="pill-warn" title="${escapeHtml(r.error)}">!</span>`}
        <button type="button" class="pill-remove" data-remove-fpr="${escapeHtml(r.fingerprint)}" aria-label="Remove recipient">×</button>
      </span>`;
    })
    .join("");
}

function renderFiles() {
  const el = document.getElementById("file-list");
  if (!el) return;
  if (!files.length) {
    el.innerHTML = "";
    updateEncryptButton();
    return;
  }
  el.innerHTML = `<ul class="file-list">${files
    .map(
      (f, i) => `<li>
      <span class="file-name">${escapeHtml(f.name)}</span>
      <span class="muted">${escapeHtml(formatBytes(f.size))}</span>
      <button type="button" class="btn btn-ghost btn-compact" data-remove-file="${i}">Remove</button>
    </li>`
    )
    .join("")}</ul>`;
  updateEncryptButton();
}

function renderDropdown(results) {
  const el = document.getElementById("recipient-dropdown");
  if (!el) return;
  if (!results || !results.length) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  el.innerHTML = results
    .map((item) => {
      const fp = item.fingerprint || "";
      const uids = item.approved_uids || item.uids || [];
      const label = uidLabel(uids) || formatFingerprint(fp);
      const state = item.approval_state || "";
      const already = recipients.has(fp.toUpperCase());
      return `<button type="button" class="recipient-hit" data-add-fpr="${escapeHtml(fp)}" ${already ? "disabled" : ""}>
        <span class="hit-main">
          <span class="hit-label">${escapeHtml(label)}</span>
          <code class="hit-fpr muted">${escapeHtml(formatFingerprint(fp))}</code>
        </span>
        <span class="${badgeClass(state)}">${escapeHtml(state)}</span>
        ${already ? `<span class="muted">Added</span>` : ""}
      </button>`;
    })
    .join("");
}

function truncateArmored(text, maxLines = 40) {
  const lines = String(text).split("\n");
  if (lines.length <= maxLines) {
    return { html: escapeHtml(text), truncated: false };
  }
  const head = lines.slice(0, maxLines).join("\n");
  return {
    html: escapeHtml(head) + "\n…",
    truncated: true,
    full: text,
  };
}

function renderOutput() {
  const el = document.getElementById("compose-output");
  if (!el) return;
  if (!outputs.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  const summaryHtml = lastEncryptSummary
    ? `<p class="encrypt-summary muted" style="margin:0.35rem 0 0">Used: <strong>${escapeHtml(lastEncryptSummary)}</strong></p>`
    : "";
  el.innerHTML = `
    <div class="card-title-row">
      <div>
        <p class="card-title" style="margin:0">Encrypted output</p>
        ${summaryHtml}
      </div>
      <div class="btn-row">
        <button type="button" class="btn btn-ghost" id="clear-output-btn">Encrypt another</button>
      </div>
    </div>
    ${outputs
      .map((o, i) => {
        const trunc = truncateArmored(o.armored);
        return `<div class="output-artifact" data-output-idx="${i}">
          <div class="card-title-row" style="margin-bottom:0.5rem">
            <p style="margin:0;font-weight:600">${escapeHtml(o.label)}</p>
            <div class="btn-row">
              <button type="button" class="btn btn-ghost btn-compact" data-copy-output="${i}">Copy</button>
              <button type="button" class="btn btn-ghost btn-compact" data-download-output="${i}">Download</button>
            </div>
          </div>
          <pre class="output-pre${trunc.truncated ? " output-truncated" : ""}" data-output-pre="${i}">${trunc.html}</pre>
          ${
            trunc.truncated
              ? `<button type="button" class="text-link output-expand" data-expand-output="${i}">Show full ciphertext</button>`
              : ""
          }
        </div>`;
      })
      .join("")}`;
}

/**
 * @returns {import("../lib/pgp/types.js").EncryptProfile}
 */
function readEncryptProfile() {
  const cipher =
    /** @type {"aes128"|"aes192"|"aes256"} */ (
      document.getElementById("enc-cipher")?.value || "aes256"
    );
  const aeadRaw = document.getElementById("enc-aead")?.value || "off";
  const aead =
    aeadRaw === "off"
      ? null
      : /** @type {"gcm"|"ocb"|"eax"} */ (aeadRaw);
  const compression =
    /** @type {"uncompressed"|"zlib"|"zip"} */ (
      document.getElementById("enc-compression")?.value || "uncompressed"
    );
  const s2k =
    /** @type {"argon2"|"iterated"} */ (
      document.getElementById("enc-s2k")?.value || "iterated"
    );
  return { cipher, aead, compression, s2k };
}

/**
 * Apply a named preset to the advanced controls.
 * @param {"compatible"|"modern"} name
 */
function applyPreset(name) {
  encryptPreset = name;
  const profile = name === "modern" ? PROFILE_MODERN : PROFILE_COMPATIBLE;
  const cipher = document.getElementById("enc-cipher");
  const aead = document.getElementById("enc-aead");
  const compression = document.getElementById("enc-compression");
  const s2k = document.getElementById("enc-s2k");
  if (cipher) cipher.value = profile.cipher;
  if (aead) aead.value = profile.aead || "off";
  if (compression) compression.value = profile.compression;
  if (s2k) s2k.value = profile.s2k;
  updateEncryptOptionsUI();
}

function updateEncryptOptionsUI() {
  const aead = document.getElementById("enc-aead")?.value || "off";
  const warn = document.getElementById("aead-interop-warn");
  if (warn) warn.classList.toggle("hidden", aead === "off");

  const s2kRow = document.getElementById("s2k-row");
  if (s2kRow) s2kRow.classList.toggle("hidden", !passphraseEnabled());

  const presetRadios = document.querySelectorAll('input[name="enc-preset"]');
  presetRadios.forEach((el) => {
    if (el instanceof HTMLInputElement) {
      el.checked = el.value === encryptPreset;
    }
  });

  const hint = document.getElementById("enc-preset-hint");
  if (hint) {
    if (encryptPreset === "modern") {
      hint.textContent =
        "Requires GnuPG 2.4+ / modern clients. AEAD applies when encrypting with a passphrase, or to keys that advertise RFC 9580 SEIPDv2.";
    } else if (encryptPreset === "custom") {
      hint.textContent = "Custom options — verify recipients can decrypt. Output summary reflects what was actually written.";
    } else {
      hint.textContent = "Works with all GnuPG versions (SEIPD v1 / iterated S2K).";
    }
  }
}

function markCustomIfAdvancedChanged() {
  const profile = readEncryptProfile();
  const matchCompatible =
    profile.cipher === PROFILE_COMPATIBLE.cipher &&
    profile.aead === PROFILE_COMPATIBLE.aead &&
    profile.compression === PROFILE_COMPATIBLE.compression &&
    profile.s2k === PROFILE_COMPATIBLE.s2k;
  const matchModern =
    profile.cipher === PROFILE_MODERN.cipher &&
    profile.aead === PROFILE_MODERN.aead &&
    profile.compression === PROFILE_MODERN.compression &&
    profile.s2k === PROFILE_MODERN.s2k;
  if (matchCompatible) encryptPreset = "compatible";
  else if (matchModern) encryptPreset = "modern";
  else encryptPreset = "custom";
  updateEncryptOptionsUI();
}

function setTab(name) {
  activeTab = name;
  document.querySelectorAll(".compose-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
  const msg = document.getElementById("tab-message");
  const filesTab = document.getElementById("tab-files");
  if (msg) msg.classList.toggle("hidden", name !== "message");
  if (filesTab) filesTab.classList.toggle("hidden", name !== "files");
}

async function addRecipient(fingerprint) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (!clean || recipients.has(clean)) return;
  // Optimistic placeholder
  recipients.set(clean, {
    fingerprint: clean,
    keyId: clean.slice(-16),
    label: "Loading…",
    email: "",
    approvalState: "",
    revoked: false,
    valid: false,
    error: "Loading",
    pgpKey: null,
  });
  renderPills();
  updateEncryptButton();
  try {
    const recipient = await loadRecipientKey(clean);
    recipients.set(clean, recipient);
  } catch (err) {
    recipients.set(clean, {
      fingerprint: clean,
      keyId: clean.slice(-16),
      label: formatFingerprint(clean),
      email: "",
      approvalState: "",
      revoked: false,
      valid: false,
      error: err.message || "Failed to load key",
      pgpKey: null,
    });
  }
  renderPills();
  updateEncryptButton();
  renderDropdown([]);
  const input = document.getElementById("recipient-search");
  if (input) input.value = "";
}

function removeRecipient(fingerprint) {
  recipients.delete(
    String(fingerprint)
      .toUpperCase()
      .replace(/[^0-9A-F]/g, "")
  );
  renderPills();
  updateEncryptButton();
}

function addFiles(fileList) {
  const incoming = [...fileList];
  for (const f of incoming) {
    if (files.some((x) => x.name === f.name && x.size === f.size && x.lastModified === f.lastModified)) {
      continue;
    }
    files.push(f);
  }
  renderFiles();
}

function downloadBlob(filename, text) {
  const blob = new Blob([text], { type: "application/pgp-encrypted" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function runEncrypt() {
  errorEl.classList.add("hidden");
  if (!canEncrypt()) return;
  const keys = validRecipients().map((r) => r.pgpKey);
  const usePw = passphraseEnabled();
  const { pw, confirm } = passphraseValues();
  if (usePw && pw !== confirm) {
    showError(errorEl, "Passphrases do not match.");
    return;
  }
  const messageText = (document.getElementById("compose-message")?.value || "").trim();
  encrypting = true;
  updateEncryptButton();
  const status = document.getElementById("encrypt-status");
  if (status) {
    status.classList.remove("hidden");
    status.textContent = "Encrypting…";
  }
  try {
    /** @type {import("../lib/pgp/types.js").EncryptPayload[]} */
    const payloads = [];
    if (messageText) {
      payloads.push({ kind: "text", text: messageText });
    }
    for (const file of files) {
      const buf = new Uint8Array(await file.arrayBuffer());
      payloads.push({ kind: "file", bytes: buf, filename: file.name });
    }
    const profile = readEncryptProfile();
    const next = await encryptArtifacts({
      recipients: keys,
      passwords: usePw ? [pw] : [],
      payloads,
      profile,
    });
    lastEncryptSummary = next.length
      ? await summarizeEncryption(next[0].armored)
      : "";
    outputs = next;
    renderOutput();

    // Clear sensitive plaintext / passphrase now that it is encrypted.
    const msgEl = document.getElementById("compose-message");
    if (msgEl) msgEl.value = "";
    files = [];
    const fileInput = document.getElementById("compose-files");
    if (fileInput) fileInput.value = "";
    const pwEl = document.getElementById("msg-passphrase");
    const pwConfirm = document.getElementById("msg-passphrase-confirm");
    if (pwEl) pwEl.value = "";
    if (pwConfirm) pwConfirm.value = "";
    renderFiles();
    updateEncryptButton();

    const parts = [];
    if (keys.length) parts.push(`${keys.length} recipient${keys.length === 1 ? "" : "s"}`);
    if (usePw) parts.push("passphrase");
    if (status) {
      const used = lastEncryptSummary ? ` · ${lastEncryptSummary}` : "";
      status.textContent = `Encrypted ${next.length} artifact${next.length === 1 ? "" : "s"} for ${parts.join(" + ")}. Plaintext cleared.${used}`;
      status.className = "status-row ok";
    }
  } catch (err) {
    showError(errorEl, err.message || "Encryption failed");
    if (status) {
      status.textContent = err.message || "Encryption failed";
      status.className = "status-row err";
    }
  } finally {
    encrypting = false;
    updateEncryptButton();
  }
}


function renderApp() {
  app.innerHTML = `
    <div class="card">
      <p class="card-title">Recipients</p>
      <div id="recipient-pills" class="recipient-pills"></div>
      <div class="recipient-input-row">
        <input type="search" id="recipient-search" placeholder="Add recipient by email, fingerprint, or key ID…" autocomplete="off">
        <div id="recipient-dropdown" class="recipient-dropdown" hidden></div>
      </div>
    </div>

    <div class="card">
      <div class="compose-tabs" role="tablist">
        <button type="button" class="compose-tab active" data-tab="message" role="tab">Message</button>
        <button type="button" class="compose-tab" data-tab="files" role="tab">Files</button>
      </div>
      <div id="tab-message" role="tabpanel">
        <label class="sr-only" for="compose-message">Message</label>
        <textarea id="compose-message" class="compose-message" rows="10"
          placeholder="Type your message… (optional if you attach files)"></textarea>
      </div>
      <div id="tab-files" class="hidden" role="tabpanel">
        <div id="drop-zone" class="drop-zone" tabindex="0">
          <p><strong>Drop files here</strong> or</p>
          <label class="file-label" for="compose-files">Choose files</label>
          <input type="file" id="compose-files" multiple hidden>
          <p class="muted" style="margin-top:0.75rem">Max total ${formatBytes(MAX_TOTAL_BYTES)}. Each file becomes its own encrypted .asc.</p>
        </div>
        <div id="file-list"></div>
        <p class="size-tally muted" id="size-tally">0 B / ${formatBytes(MAX_TOTAL_BYTES)}</p>
      </div>
    </div>

    <div class="card">
      <p class="card-title">Passphrase (optional)</p>
      <label class="field-label" style="display:flex;align-items:center;gap:0.5rem;font-weight:500">
        <input type="checkbox" id="use-passphrase">
        Protect with a shared passphrase (SKESK)
      </label>
      <div id="passphrase-fields" class="hidden" style="margin-top:0.75rem">
        <label class="field-label" for="msg-passphrase">Passphrase</label>
        <input type="password" id="msg-passphrase" class="text-input" autocomplete="new-password" placeholder="Shared secret">
        <label class="field-label" for="msg-passphrase-confirm" style="margin-top:0.65rem">Confirm</label>
        <input type="password" id="msg-passphrase-confirm" class="text-input" autocomplete="new-password" placeholder="Repeat passphrase">
        <p class="muted" style="margin-top:0.5rem">Works alone or together with recipient keys — either can open the message. Cleared after encrypt.</p>
      </div>
    </div>

    <details class="card encrypt-options" id="encrypt-options">
      <summary class="card-title" style="cursor:pointer;list-style-position:outside">Encryption options</summary>
      <div class="encrypt-options-body" style="margin-top:0.85rem">
        <fieldset class="enc-preset-fieldset" style="border:none;margin:0;padding:0">
          <legend class="field-label">Preset</legend>
          <label class="enc-preset-option">
            <input type="radio" name="enc-preset" value="compatible" checked>
            <span><strong>Compatible</strong> — AES-256, SEIPD v1, iterated S2K</span>
          </label>
          <label class="enc-preset-option">
            <input type="radio" name="enc-preset" value="modern">
            <span><strong>Modern (RFC 9580)</strong> — AES-256-OCB, Argon2</span>
          </label>
          <p id="enc-preset-hint" class="muted" style="margin:0.4rem 0 0">Works with all GnuPG versions (SEIPD v1 / iterated S2K).</p>
        </fieldset>

        <details class="enc-advanced" style="margin-top:1rem">
          <summary class="field-label" style="cursor:pointer">Advanced</summary>
          <div class="enc-advanced-grid" style="margin-top:0.75rem;display:grid;gap:0.75rem;grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">
            <div>
              <label class="field-label" for="enc-cipher">Cipher</label>
              <select id="enc-cipher" class="text-input">
                <option value="aes256" selected>AES-256</option>
                <option value="aes192">AES-192</option>
                <option value="aes128">AES-128</option>
              </select>
            </div>
            <div>
              <label class="field-label" for="enc-aead">AEAD</label>
              <select id="enc-aead" class="text-input">
                <option value="off" selected>Off (SEIPD v1)</option>
                <option value="gcm">GCM</option>
                <option value="ocb">OCB</option>
                <option value="eax">EAX</option>
              </select>
            </div>
            <div>
              <label class="field-label" for="enc-compression">Compression</label>
              <select id="enc-compression" class="text-input">
                <option value="uncompressed" selected>Off</option>
                <option value="zlib">ZLIB</option>
                <option value="zip">ZIP</option>
              </select>
            </div>
            <div id="s2k-row" class="hidden">
              <label class="field-label" for="enc-s2k">S2K (passphrase)</label>
              <select id="enc-s2k" class="text-input">
                <option value="iterated" selected>Iterated</option>
                <option value="argon2">Argon2</option>
              </select>
            </div>
          </div>
          <p id="aead-interop-warn" class="status-row err hidden" style="margin-top:0.75rem" role="status">
            AEAD (SEIPD v2) requires GnuPG 2.4+ or other modern OpenPGP clients. Older clients cannot decrypt.
          </p>
        </details>
      </div>
    </details>

    <div class="btn-row" style="margin:1rem 0">
      <button type="button" class="btn" id="encrypt-btn" disabled>Encrypt</button>
      <span id="encrypt-status" class="hidden"></span>
    </div>

    <div id="compose-output" class="card compose-output hidden"></div>

    <p class="muted" style="margin-top:1.5rem">
      Encrypt-only — no signing. Recipients decrypt with their private keys or the shared passphrase
      (<code>gpg --decrypt file.asc</code>).
    </p>
  `;

  renderPills();
  renderFiles();
  applyPreset("compatible");
  updateEncryptButton();
}

function wireEvents() {
  app.addEventListener("input", (e) => {
    if (e.target && e.target.id === "compose-message") updateEncryptButton();
    if (e.target && (e.target.id === "msg-passphrase" || e.target.id === "msg-passphrase-confirm")) {
      updateEncryptButton();
    }
    if (e.target && e.target.id === "recipient-search") {
      const q = e.target.value.trim();
      clearTimeout(searchTimer);
      if (!q) {
        renderDropdown([]);
        return;
      }
      searchTimer = setTimeout(async () => {
        try {
          const payload = await fetchJson(`/api/v1/search?q=${encodeURIComponent(q)}`);
          renderDropdown(payload.results || []);
        } catch (_) {
          renderDropdown([]);
        }
      }, 250);
    }
  });

  app.addEventListener("change", (e) => {
    if (e.target && e.target.id === "use-passphrase") {
      const fields = document.getElementById("passphrase-fields");
      if (fields) fields.classList.toggle("hidden", !e.target.checked);
      updateEncryptButton();
      updateEncryptOptionsUI();
    }
    if (e.target && e.target.name === "enc-preset") {
      const val = e.target.value;
      if (val === "compatible" || val === "modern") applyPreset(val);
    }
    if (
      e.target &&
      (e.target.id === "enc-cipher" ||
        e.target.id === "enc-aead" ||
        e.target.id === "enc-compression" ||
        e.target.id === "enc-s2k")
    ) {
      markCustomIfAdvancedChanged();
    }
  });

  app.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const tab = t.closest(".compose-tab");
    if (tab) {
      setTab(tab.dataset.tab);
      return;
    }

    const hit = t.closest("[data-add-fpr]");
    if (hit) {
      await addRecipient(hit.getAttribute("data-add-fpr"));
      return;
    }

    const rem = t.closest("[data-remove-fpr]");
    if (rem) {
      removeRecipient(rem.getAttribute("data-remove-fpr"));
      return;
    }

    const remFile = t.closest("[data-remove-file]");
    if (remFile) {
      const idx = Number(remFile.getAttribute("data-remove-file"));
      files.splice(idx, 1);
      renderFiles();
      return;
    }

    if (t.id === "encrypt-btn" || t.closest("#encrypt-btn")) {
      await runEncrypt();
      return;
    }

    if (t.id === "clear-output-btn") {
      outputs = [];
      lastEncryptSummary = "";
      renderOutput();
      const status = document.getElementById("encrypt-status");
      if (status) {
        status.className = "hidden";
        status.textContent = "";
      }
      return;
    }

    const copyBtn = t.closest("[data-copy-output]");
    if (copyBtn) {
      const i = Number(copyBtn.getAttribute("data-copy-output"));
      const o = outputs[i];
      if (!o) return;
      const original = copyBtn.textContent;
      try {
        await copyText(o.armored);
        copyBtn.textContent = "Copied";
        setTimeout(() => {
          copyBtn.textContent = original;
        }, 1500);
      } catch (_) {
        copyBtn.textContent = "Failed";
        setTimeout(() => {
          copyBtn.textContent = original;
        }, 1500);
      }
      return;
    }

    const dlBtn = t.closest("[data-download-output]");
    if (dlBtn) {
      const i = Number(dlBtn.getAttribute("data-download-output"));
      const o = outputs[i];
      if (o) downloadBlob(o.filename, o.armored);
      return;
    }

    const expand = t.closest("[data-expand-output]");
    if (expand) {
      const i = Number(expand.getAttribute("data-expand-output"));
      const o = outputs[i];
      const pre = document.querySelector(`[data-output-pre="${i}"]`);
      if (o && pre) {
        pre.textContent = o.armored;
        pre.classList.remove("output-truncated");
        expand.remove();
      }
    }
  });

  app.addEventListener("change", (e) => {
    if (e.target && e.target.id === "compose-files") {
      addFiles(e.target.files || []);
      e.target.value = "";
    }
  });

  // Drag and drop
  app.addEventListener("dragover", (e) => {
    const zone = e.target.closest?.("#drop-zone");
    if (!zone) return;
    e.preventDefault();
    zone.classList.add("dragover");
  });
  app.addEventListener("dragleave", (e) => {
    const zone = e.target.closest?.("#drop-zone");
    if (!zone) return;
    zone.classList.remove("dragover");
  });
  app.addEventListener("drop", (e) => {
    const zone = e.target.closest?.("#drop-zone");
    if (!zone) return;
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files);
  });

  // Close dropdown on outside click
  document.addEventListener("click", (e) => {
    const row = document.querySelector(".recipient-input-row");
    if (row && !row.contains(e.target)) renderDropdown([]);
  });

  // Keyboard navigation for recipient dropdown
  app.addEventListener("keydown", async (e) => {
    const dropdown = document.getElementById("recipient-dropdown");
    if (!dropdown || dropdown.hidden) return;
    const hits = [...dropdown.querySelectorAll(".recipient-hit:not(:disabled)")];
    if (!hits.length) return;
    const active = dropdown.querySelector(".recipient-hit.active");
    let idx = hits.indexOf(active);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      idx = Math.min(hits.length - 1, idx + 1);
      hits.forEach((h) => h.classList.remove("active"));
      hits[idx].classList.add("active");
      hits[idx].focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      idx = Math.max(0, idx < 0 ? 0 : idx - 1);
      hits.forEach((h) => h.classList.remove("active"));
      hits[idx].classList.add("active");
      hits[idx].focus();
    } else if (e.key === "Enter" && active) {
      e.preventDefault();
      await addRecipient(active.getAttribute("data-add-fpr"));
    } else if (e.key === "Escape") {
      renderDropdown([]);
    }
  });
}

async function init() {
  renderApp();
  wireEvents();
  const fpr = queryParam("fpr");
  if (fpr) {
    await addRecipient(fpr);
  }
  setTab(activeTab);
}

init().catch((err) => showError(errorEl, err.message || "Failed to load composer"));

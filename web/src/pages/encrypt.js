import { Auth } from "../lib/auth.js";
import {
  CryptoModuleError,
  SELF_TEST_LABELS,
  assertCryptoReady,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { badgeClass } from "../lib/keys.js";
import {
  summarizeRecipientCapabilities,
} from "../lib/pgp/capabilities.js";
import {
  PROFILE_AUTO,
  PROFILE_COMPATIBLE,
  PROFILE_MODERN,
  encryptArtifacts,
  summarizeEncryption,
} from "../lib/pgp/encrypt.js";
import { estimatePassphraseStrength } from "../lib/pgp/passphrase.js";
import { getExpertMode, setExpertMode } from "../lib/prefs.js";
import { loadRecipientKey } from "../lib/recipient-picker.js";
import {
  copyText,
  escapeHtml,
  extractEmail,
  fetchJson,
  formatFingerprint,
  queryParam,
  showError,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/encrypt");

const MAX_TOTAL_BYTES = 50 * 1024 * 1024;

const errorEl = document.getElementById("error");
const app = document.getElementById("compose-app");

/** True once the POST has passed. Gated by startEncryptPage(). */
let cryptoReady = false;

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
/** @type {"auto"|"compatible"|"modern"|"custom"} */
let encryptPreset = "auto";
let expertMode = getExpertMode();

/**
 * @typedef {import("../lib/recipient-picker.js").Recipient} Recipient
 */

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

function shortFpr(fpr) {
  const c = String(fpr || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return c.length > 8 ? c.slice(-8) : c;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function totalFileBytes() {
  return files.reduce((sum, f) => sum + f.size, 0);
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
    el.innerHTML = `<p class="muted m-0">No recipients yet. Search by email, fingerprint, or key ID.</p>`;
    updateCapabilityHint();
    return;
  }
  el.innerHTML = [...recipients.values()]
    .map((r) => {
      const initial = (r.email || r.label || "?").charAt(0).toUpperCase();
      const title = r.error || formatFingerprint(r.fingerprint);
      const modernBadge =
        r.valid && r.modernCapable
          ? `<span class="pill-cap modern" title="Key advertises RFC 9580 SEIPDv2">modern</span>`
          : r.valid
            ? `<span class="pill-cap legacy" title="Compatible format (SEIPD v1)">compat</span>`
            : "";
      return `<span class="recipient-pill${r.valid ? "" : " invalid"}" title="${escapeHtml(title)}" data-fpr="${escapeHtml(r.fingerprint)}">
        <span class="pill-avatar">${escapeHtml(initial)}</span>
        <span class="pill-body">
          <span class="pill-label">${escapeHtml(r.label)}</span>
          <span class="pill-fpr muted">${escapeHtml(shortFpr(r.fingerprint))}</span>
        </span>
        ${modernBadge}
        ${r.valid ? "" : `<span class="pill-warn" title="${escapeHtml(r.error)}">!</span>`}
        <button type="button" class="pill-remove" data-remove-fpr="${escapeHtml(r.fingerprint)}" aria-label="Remove recipient">×</button>
      </span>`;
    })
    .join("");
  updateCapabilityHint();
}

async function updateCapabilityHint() {
  const hint = document.getElementById("recipient-cap-hint");
  if (!hint) return;
  const caps = await summarizeRecipientCapabilities([...recipients.values()]);
  if (!caps.total) {
    hint.textContent = "";
    hint.classList.add("hidden");
    return;
  }
  hint.classList.remove("hidden");
  if (caps.legacy === 0) {
    hint.textContent = `All ${caps.total} recipient${caps.total === 1 ? "" : "s"} support modern (SEIPDv2) encryption.`;
  } else if (caps.modern === 0) {
    hint.textContent = `Recipients use the compatible format (SEIPD v1). Auto will still encrypt safely.`;
  } else {
    hint.textContent = `${caps.legacy} of ${caps.total} recipients lack SEIPDv2 — Auto/Modern will use the compatible format for this message.`;
  }
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
    ? `<p class="encrypt-summary muted mt-xs">Used: <strong>${escapeHtml(lastEncryptSummary)}</strong></p>`
    : "";
  el.innerHTML = `
    <div class="card-title-row">
      <div>
        <p class="card-title m-0">Encrypted output</p>
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
          <div class="card-title-row mb-sm">
            <p class="m-0 fw-600">${escapeHtml(o.label)}</p>
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
 * @param {"auto"|"compatible"|"modern"} name
 */
function applyPreset(name) {
  encryptPreset = name;
  const profile =
    name === "compatible"
      ? PROFILE_COMPATIBLE
      : name === "modern"
        ? PROFILE_MODERN
        : PROFILE_AUTO;
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

  const compression = document.getElementById("enc-compression")?.value || "uncompressed";
  const compWarn = document.getElementById("compression-warn");
  if (compWarn) compWarn.classList.toggle("hidden", compression === "uncompressed");

  const s2kRow = document.getElementById("s2k-row");
  if (s2kRow) s2kRow.classList.toggle("hidden", !passphraseEnabled());

  const hideRow = document.getElementById("hide-recipients-row");
  if (hideRow) hideRow.classList.toggle("hidden", !expertMode);

  const presetRadios = document.querySelectorAll('input[name="enc-preset"]');
  presetRadios.forEach((el) => {
    if (el instanceof HTMLInputElement) {
      el.checked = el.value === encryptPreset;
    }
  });

  const hint = document.getElementById("enc-preset-hint");
  if (hint) {
    if (encryptPreset === "auto") {
      hint.textContent =
        "Requests modern encryption; OpenPGP.js uses SEIPD v1 automatically when any recipient key lacks RFC 9580 support.";
    } else if (encryptPreset === "modern") {
      hint.textContent =
        "Requires GnuPG 2.4+ / modern clients. AEAD applies when encrypting with a passphrase, or to keys that advertise RFC 9580 SEIPDv2.";
    } else if (encryptPreset === "custom") {
      hint.textContent =
        "Custom options — verify recipients can decrypt. Output summary reflects what was actually written.";
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
  // Auto uses the same controls as Modern; prefer Auto if that radio was last selected
  // only when user hasn't diverged — if controls match Modern and preset was auto, keep auto.
  if (matchCompatible) encryptPreset = "compatible";
  else if (matchModern) {
    if (encryptPreset !== "auto") encryptPreset = "modern";
  } else encryptPreset = "custom";
  updateEncryptOptionsUI();
}

function applyExpertModeUI() {
  const toggle = document.getElementById("expert-mode-toggle");
  if (toggle instanceof HTMLInputElement) toggle.checked = expertMode;
  const options = document.getElementById("encrypt-options");
  if (options) options.classList.toggle("hidden", !expertMode);
  updateEncryptOptionsUI();
}

function updatePassphraseMeter() {
  const meter = document.getElementById("pw-strength-meter");
  const label = document.getElementById("pw-strength-label");
  if (!meter || !label) return;
  const { pw } = passphraseValues();
  const est = estimatePassphraseStrength(pw);
  meter.dataset.strength = est.label;
  meter.style.setProperty("--pw-bits", String(Math.min(100, Math.round((est.bits / 80) * 100))));
  const fill = meter.querySelector(".pw-strength-fill");
  if (fill instanceof HTMLElement) {
    fill.style.width = `${Math.min(100, Math.round((est.bits / 80) * 100))}%`;
  }
  label.textContent = est.label === "empty" ? "" : `${est.label} (~${est.bits} bits). ${est.hint}`;
  label.className = `pw-strength-label muted${est.label === "weak" ? " pw-weak" : ""}`;
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
    modernCapable: false,
    armoredKey: "",
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
      modernCapable: false,
      armoredKey: "",
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
  // CAST gate: refuse to encrypt if the module self-test did not pass.
  try {
    await assertCryptoReady();
  } catch (err) {
    showError(errorEl, err instanceof CryptoModuleError
      ? `Encryption refused — crypto self-test failed: ${err.message}`
      : String(err));
    return;
  }
  errorEl.classList.add("hidden");
  if (!canEncrypt()) return;
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
    // Re-validate recipient keys against the keyserver before encrypting.
    await revalidateRecipients();
    const keys = validRecipients().map((r) => r.pgpKey);
    if (!keys.length && !usePw) {
      throw new Error("No valid recipients remain after key re-check.");
    }

    /** @type {import("../lib/pgp/types.js").EncryptPayload[]} */
    const payloads = [];
    if (messageText) {
      payloads.push({ kind: "text", text: messageText });
    }
    for (const file of files) {
      const buf = new Uint8Array(await file.arrayBuffer());
      payloads.push({
        kind: "file",
        bytes: buf,
        filename: file.name,
      });
    }
    const profile = readEncryptProfile();
    const hideRecipients =
      expertMode && !!document.getElementById("hide-recipients")?.checked;

    let next;
    try {
      next = await encryptWithWorker({
        recipients: validRecipients(),
        passwords: usePw ? [pw] : [],
        payloads,
        profile,
        hideRecipients,
      });
    } catch (_) {
      // Fallback: main-thread encrypt (e.g. worker / CSP failure).
      next = await encryptArtifacts({
        recipients: keys,
        passwords: usePw ? [pw] : [],
        payloads,
        profile,
        hideRecipients,
      });
    }
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
    updatePassphraseMeter();
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

/**
 * Re-fetch key metadata; mark revoked/expired recipients invalid.
 */
async function revalidateRecipients() {
  const list = [...recipients.values()].filter((r) => r.valid);
  await Promise.all(
    list.map(async (r) => {
      try {
        const meta = await fetchJson(`/api/v1/key/${encodeURIComponent(r.fingerprint)}`);
        if (meta.revoked) {
          r.valid = false;
          r.revoked = true;
          r.error = "Key is revoked";
          r.pgpKey = null;
        } else if (meta.approval_state && meta.approval_state !== "approved") {
          r.valid = false;
          r.error = `Key is ${meta.approval_state}`;
          r.pgpKey = null;
        } else if (meta.key_expiration) {
          const exp = new Date(meta.key_expiration);
          if (!Number.isNaN(exp.getTime()) && exp.getTime() < Date.now()) {
            r.valid = false;
            r.error = "Key is expired";
            r.pgpKey = null;
          }
        }
        recipients.set(r.fingerprint, r);
      } catch (err) {
        // Network failure: keep prior state but surface a soft warning via throw if all fail.
        throw new Error(
          `Could not re-check key ${formatFingerprint(r.fingerprint)}: ${err.message || "network error"}`
        );
      }
    })
  );
  renderPills();
  updateEncryptButton();
  const stillValid = validRecipients();
  if (list.length && !stillValid.length && !passphraseEnabled()) {
    throw new Error("All recipients became invalid (revoked, expired, or unapproved).");
  }
}

/**
 * Encrypt via Web Worker when available.
 * Structured-clones payload bytes (no transfer list) so main-thread fallback
 * still works if the worker fails.
 * @param {{
 *   recipients: Recipient[],
 *   passwords: string[],
 *   payloads: import("../lib/pgp/types.js").EncryptPayload[],
 *   profile: import("../lib/pgp/types.js").EncryptProfile,
 *   hideRecipients: boolean,
 * }} opts
 */
function encryptWithWorker(opts) {
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
    const id = `enc-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const timer = setTimeout(() => {
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(new Error("Encrypt worker timed out"));
    }, 120000);
    worker.onmessage = (ev) => {
      const data = ev.data || {};
      if (data.id !== id) return;
      clearTimeout(timer);
      worker.terminate();
      if (data.ok) resolve(data.artifacts || []);
      else reject(new Error(data.error || "Encrypt worker failed"));
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(err?.message ? new Error(err.message) : new Error("Encrypt worker error"));
    };

    const serialPayloads = opts.payloads.map((p) => {
      if (p.kind === "file" && p.bytes instanceof Uint8Array) {
        // Copy into a fresh ArrayBuffer so the worker gets its own bytes
        // without detaching the main-thread view (needed for fallback).
        const copy = p.bytes.slice().buffer;
        return {
          kind: "file",
          filename: p.filename,
          bytes: copy,
        };
      }
      return { kind: "text", text: p.text || "" };
    });

    worker.postMessage({
      id,
      type: "encrypt",
      recipientKeysArmored: opts.recipients.map((r) => r.armoredKey).filter(Boolean),
      passwords: opts.passwords,
      payloads: serialPayloads,
      profile: opts.profile,
      hideRecipients: opts.hideRecipients,
    });
  });
}


function renderApp() {
  app.innerHTML = `
    <div class="compose-toolbar">
      <label class="expert-toggle" title="Show advanced encryption options and technical details">
        <input type="checkbox" id="expert-mode-toggle" ${expertMode ? "checked" : ""}>
        <span>Expert mode</span>
      </label>
    </div>

    <div class="card">
      <p class="card-title">Recipients</p>
      <div id="recipient-pills" class="recipient-pills"></div>
      <p id="recipient-cap-hint" class="muted hidden mt-sm fs-sm"></p>
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
          <p class="muted mt-md">Max total ${formatBytes(MAX_TOTAL_BYTES)}. Each file becomes its own encrypted .asc.</p>
        </div>
        <div id="file-list"></div>
        <p class="size-tally muted" id="size-tally">0 B / ${formatBytes(MAX_TOTAL_BYTES)}</p>
      </div>
    </div>

    <div class="card">
      <p class="card-title">Passphrase (optional)</p>
      <label class="field-label field-label-inline">
        <input type="checkbox" id="use-passphrase">
        Protect with a shared passphrase (SKESK)
      </label>
      <div id="passphrase-fields" class="hidden mt-md">
        <label class="field-label" for="msg-passphrase">Passphrase</label>
        <input type="password" id="msg-passphrase" class="text-input" autocomplete="new-password" placeholder="Shared secret">
        <div id="pw-strength-meter" class="pw-strength-meter" data-strength="empty" aria-hidden="true">
          <div class="pw-strength-fill"></div>
        </div>
        <p id="pw-strength-label" class="pw-strength-label muted"></p>
        <label class="field-label mt-md" for="msg-passphrase-confirm">Confirm</label>
        <input type="password" id="msg-passphrase-confirm" class="text-input" autocomplete="new-password" placeholder="Repeat passphrase">
        <p class="muted mt-sm">Works alone or together with recipient keys — either can open the message. Cleared after encrypt.</p>
      </div>
    </div>

    <details class="card encrypt-options${expertMode ? "" : " hidden"}" id="encrypt-options">
      <summary class="card-title enc-options-summary">Encryption options</summary>
      <div class="encrypt-options-body mt-md">
        <fieldset class="enc-preset-fieldset">
          <legend class="field-label">Preset</legend>
          <label class="enc-preset-option">
            <input type="radio" name="enc-preset" value="auto" checked>
            <span><strong>Auto</strong> — modern when recipients support it, otherwise compatible</span>
          </label>
          <label class="enc-preset-option">
            <input type="radio" name="enc-preset" value="compatible">
            <span><strong>Compatible</strong> — AES-256, SEIPD v1, iterated S2K</span>
          </label>
          <label class="enc-preset-option">
            <input type="radio" name="enc-preset" value="modern">
            <span><strong>Modern (RFC 9580)</strong> — AES-256-OCB, Argon2</span>
          </label>
          <p id="enc-preset-hint" class="muted mt-xs">Requests modern encryption; OpenPGP.js uses SEIPD v1 automatically when any recipient key lacks RFC 9580 support.</p>
        </fieldset>

        <label id="hide-recipients-row" class="enc-preset-option mt-md${expertMode ? "" : " hidden"}">
          <input type="checkbox" id="hide-recipients">
          <span><strong>Hide recipient key IDs</strong> — PKESK uses anonymous (all-zero) key IDs. Recipients must try all their keys; metadata of who can read the message is not leaked.</span>
        </label>

        <details class="enc-advanced mt-lg">
          <summary class="field-label pointer">Advanced</summary>
          <div class="enc-advanced-grid">
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
                <option value="off">Off (SEIPD v1)</option>
                <option value="gcm">GCM</option>
                <option value="ocb" selected>OCB</option>
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
                <option value="iterated">Iterated</option>
                <option value="argon2" selected>Argon2</option>
              </select>
            </div>
          </div>
          <p id="aead-interop-warn" class="status-row err hidden mt-md" role="status">
            AEAD (SEIPD v2) requires GnuPG 2.4+ or other modern OpenPGP clients. Older clients cannot decrypt.
          </p>
          <p id="compression-warn" class="status-row err hidden mt-md" role="status">
            Compression before encryption can leak plaintext length (CRIME-style) when attacker-influenced data is mixed with secrets. Prefer Off unless you need smaller ciphertext.
          </p>
        </details>
      </div>
    </details>

    <div class="btn-row my-lg">
      <button type="button" class="btn" id="encrypt-btn" disabled>Encrypt</button>
      <span id="encrypt-status" class="hidden"></span>
    </div>

    <div id="compose-output" class="card compose-output hidden"></div>

    <p class="muted mt-xl">
      Encrypt-only — no signing. Recipients decrypt with their private keys or the shared passphrase
      (<code>gpg --decrypt file.asc</code>).
    </p>
  `;

  renderPills();
  renderFiles();
  applyPreset("auto");
  applyExpertModeUI();
  updateEncryptButton();
}

function wireEvents() {
  app.addEventListener("input", (e) => {
    if (e.target && e.target.id === "compose-message") updateEncryptButton();
    if (e.target && (e.target.id === "msg-passphrase" || e.target.id === "msg-passphrase-confirm")) {
      updateEncryptButton();
      if (e.target.id === "msg-passphrase") updatePassphraseMeter();
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
    if (e.target && e.target.id === "expert-mode-toggle") {
      expertMode = !!e.target.checked;
      setExpertMode(expertMode);
      applyExpertModeUI();
      return;
    }
    if (e.target && e.target.id === "use-passphrase") {
      const fields = document.getElementById("passphrase-fields");
      if (fields) fields.classList.toggle("hidden", !e.target.checked);
      updateEncryptButton();
      updateEncryptOptionsUI();
      updatePassphraseMeter();
    }
    if (e.target && e.target.name === "enc-preset") {
      const val = e.target.value;
      if (val === "compatible" || val === "modern" || val === "auto") applyPreset(val);
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

/**
 * Entry point.  Shows the POST verification screen immediately (hiding the
 * compose UI), waits for all CASTs to complete, then either reveals the
 * composer (on pass) or renders a permanent error card (on failure).
 *
 * FIPS 140-3 §4.9.3: the module must "inhibit all data output" while in error
 * state — we achieve this by never calling init() (which renders the form) if
 * the POST fails.
 */
async function startEncryptPage() {
  // Show the POST verification screen immediately — app div is empty at this
  // point so no compose UI is visible to the user.
  app.innerHTML = `
    <div class="card crypto-post-pending" role="status" aria-live="polite" aria-busy="true">
      <div class="crypto-post-header">
        <div class="crypto-post-spinner" aria-hidden="true"></div>
        <div>
          <p class="card-title m-0-b-xs">Verifying crypto module</p>
          <p class="muted m-0 fs-md">
            Running pre-operational self-tests before enabling encryption services.
            This usually completes in under a second.
          </p>
        </div>
      </div>
    </div>
  `;

  const result = await runCryptoSelfTests();

  if (result.passed) {
    cryptoReady = true;

    // Brief confirmation flash before handing off to the composer.
    app.innerHTML = `
      <div class="status-row ok" role="status">
        Crypto module verified (${result.elapsed}\u202fms) — ${Object.keys(result.results).length} algorithm checks passed.
      </div>
    `;
    await new Promise((r) => setTimeout(r, 700));

    // Hand off to the regular init() path.
    await init();

    // Replace the status row with a dismissable banner inside the rendered app.
    const old = app.querySelector(".status-row.ok");
    if (old) old.remove();

  } else {
    // ── Permanent error state ─────────────────────────────────────────────
    // FIPS 140-3 §4.9.3: module must enter error state and inhibit all data
    // output.  We never call init(), so the compose form is never rendered.
    const failedChecks = Object.entries(result.results)
      .filter(([, v]) => !v)
      .map(([k]) => SELF_TEST_LABELS[k] || k);

    app.innerHTML = `
      <div class="card crypto-error-state" role="alert">
        <p class="card-title text-error m-0-b-sm">
          Crypto self-test failed
        </p>
        <p class="m-0-b-md">
          The cryptographic module failed its pre-operational self-test.
          <strong>All encryption services are disabled.</strong>
          Do not use this browser to encrypt sensitive data until this is resolved.
        </p>
        ${failedChecks.length
          ? `<p class="muted m-0-b-sm">
               Failed checks: ${failedChecks.map((s) => `<code>${escapeHtml(s)}</code>`).join(", ")}
             </p>`
          : ""}
        ${result.error
          ? `<p class="muted m-0-b-sm">
               Error: <code>${escapeHtml(result.error)}</code>
             </p>`
          : ""}
        <p class="muted mt-md fs-sm">
          This failure has been recorded in the browser console.
          Reloading the page will re-run the self-test.
          If the problem persists, the browser's cryptographic implementation
          may be corrupted or tampered with.
        </p>
      </div>
    `;
  }
}

startEncryptPage();
